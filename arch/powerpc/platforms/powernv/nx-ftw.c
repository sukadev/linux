/*
 * Copyright 2016-17 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/switch_to.h>
#include <asm/vas.h>
#include <uapi/asm/nx-ftw.h>

/*
 * NX-FTW is a device driver used to provide user space access to the
 * Core-to-Core aka Fast Thread Wakeup (FTW) functionality provided by
 * the Virtual Accelerator Subsystem (VAS) in POWER9 systems. See also
 * arch/powerpc/platforms/powernv/vas*.
 *
 * The driver creates the device /dev/crypto/nx-ftw that can be
 * used as follows:
 *
 *	fd = open("/dev/crypto/nx-ftw", O_RDWR);
 *	rc = ioctl(fd, VAS_FTW_SETUP, &attr);
 *	paste_addr = mmap(NULL, PAGE_SIZE, prot, MAP_SHARED, fd, 0ULL).
 *	vas_copy(&crb, 0, 1);
 *	vas_paste(paste_addr, 0, 1);
 *
 * where "vas_copy" and "vas_paste" are defined in copy-paste.h.
 */

static char		*nxftw_dev_name = "nx-ftw";
static atomic_t		nxftw_instid = ATOMIC_INIT(0);

/*
 * Wrapper object for the nx-ftw device - there is just one instance of
 * this node for the whole system.
 */
struct nxftw_dev {
	struct cdev cdev;
	struct device *device;
	char *name;
	dev_t devt;
	struct class *class;
} nxftw_device;

/*
 * One instance per open of a nx-ftw device. Each nxftw_instance is
 * associated with a VAS window after the caller issues VAS_FTW_SETUP
 * ioctl.
 */
struct nxftw_instance {
	int id;
	struct vas_window *rxwin;
	struct vas_window *txwin;
};

static char *nxftw_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "crypto/%s", dev_name(dev));
}

static int nxftw_open(struct inode *inode, struct file *fp)
{
	struct nxftw_instance *instance;

	instance = kzalloc(sizeof(*instance), GFP_KERNEL);
	if (!instance)
		return -ENOMEM;

	instance->id = atomic_inc_return(&nxftw_instid);

	fp->private_data = instance;
	return 0;
}

static int validate_ftw_setup_attr(struct vas_ftw_setup_attr *uattr)
{
	if (uattr->version != 1 || uattr->reserved || uattr->reserved1 ||
				   uattr->reserved2)
		return -EINVAL;

	if (uattr->flags & ~VAS_FLAGS_PIN_WINDOW)
		return -EINVAL;

	if (uattr->flags & VAS_FLAGS_PIN_WINDOW && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	return 0;
}

static int nxftw_ioc_ftw_setup(struct file *fp, unsigned long arg)
{
	int rc, vasid, cop;
	struct vas_rx_win_attr rxattr;
	struct vas_tx_win_attr txattr;
	struct vas_ftw_setup_attr uattr;
	void __user *uptr = (void *)arg;
	struct vas_window *rxwin, *txwin;
	struct nxftw_instance *instance = fp->private_data;

	rc = copy_from_user(&uattr, uptr, sizeof(uattr));
	if (rc) {
		pr_debug("%s(): copy_from_user() returns %d\n", __func__, rc);
		return -EFAULT;
	}

	rc = validate_ftw_setup_attr(&uattr);
	if (rc)
		return rc;

	cop = VAS_COP_TYPE_FTW;
	set_thread_tidr(current);
	vasid = uattr.vas_id;

	vas_init_rx_win_attr(&rxattr, cop);
	rxattr.lnotify_lpid = mfspr(SPRN_LPID);

	/*
	 * Only caller can own the window for now. Not sure if there is need
	 * for process P1 to make P2 the owner of a window. If so, we need to
	 * find P2, make sure we have permissions, get a reference etc.
	 */
	rxattr.lnotify_pid = mfspr(SPRN_PID);
	rxattr.lnotify_tid = mfspr(SPRN_TIDR);

	rxwin = vas_rx_win_open(vasid, cop, &rxattr);
	if (IS_ERR(rxwin)) {
		pr_devel("%s() vas_rx_win_open() failed, %ld\n", __func__,
				PTR_ERR(rxwin));
		return PTR_ERR(rxwin);
	}

	vas_init_tx_win_attr(&txattr, cop);

	txattr.lpid = mfspr(SPRN_LPID);
	txattr.pidr = mfspr(SPRN_PID);
	txattr.pid = task_pid_nr(current);
	txattr.pswid = vas_win_id(rxwin);

	txwin = vas_tx_win_open(vasid, cop, &txattr);
	if (IS_ERR(txwin)) {
		pr_debug("%s() vas_tx_win_open() failed, %ld\n", __func__,
					PTR_ERR(txwin));
		rc = PTR_ERR(txwin);
		goto close_rxwin;
	}

	instance->rxwin = rxwin;
	instance->txwin = txwin;

	return 0;

close_rxwin:
	vas_win_close(rxwin);
	return rc;
}

static int nxftw_release(struct inode *inode, struct file *fp)
{
	struct nxftw_instance *instance;

	instance = fp->private_data;

	if (instance->txwin)
		vas_win_close(instance->txwin);
	if (instance->rxwin)
		vas_win_close(instance->rxwin);
	/*
	 * TODO We don't know here if user has other receive windows
	 *      open, so we can't really call clear_thread_tidr().
	 *      So, once the process calls set_thread_tidr(), the
	 *      TIDR value sticks around until process exits, resulting
	 *      in an extra copy in restore_sprs().
	 */

	instance->rxwin = instance->txwin = NULL;

	kfree(instance);
	fp->private_data = NULL;
	atomic_dec(&nxftw_instid);

	return 0;
}

static int nxftw_mmap(struct file *fp, struct vm_area_struct *vma)
{
	int rc;
	u64 paste_addr;
	unsigned long pfn;
	struct nxftw_instance *instance = fp->private_data;

	if ((vma->vm_end - vma->vm_start) > PAGE_SIZE) {
		pr_devel("%s(): size 0x%zx, PAGE_SIZE 0x%zx\n", __func__,
				(vma->vm_end - vma->vm_start), PAGE_SIZE);
		return -EINVAL;
	}

	/* Ensure instance has an open send window */
	if (!instance->txwin) {
		pr_devel("%s(): No send window open?\n", __func__);
		return -EINVAL;
	}

	paste_addr = vas_win_paste_addr(instance->txwin);
	pfn = paste_addr >> PAGE_SHIFT;

	/* flags, page_prot from cxl_mmap(), except we want cachable */
	vma->vm_flags |= VM_IO | VM_PFNMAP;
	vma->vm_page_prot = pgprot_cached(vma->vm_page_prot);

	rc = remap_pfn_range(vma, vma->vm_start, pfn + vma->vm_pgoff,
			vma->vm_end - vma->vm_start,
			vma->vm_page_prot);

	pr_err("%s(): paste addr %llx at %lx, rc %d\n", __func__,
			paste_addr, vma->vm_start, rc);

	return rc;
}

static long nxftw_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {

	case VAS_FTW_SETUP:
		return nxftw_ioc_ftw_setup(fp, arg);

	default:
		return -EINVAL;
	}
}

const struct file_operations nxftw_fops = {
	.owner = THIS_MODULE,
	.open = nxftw_open,
	.release = nxftw_release,
	.mmap = nxftw_mmap,
	.unlocked_ioctl = nxftw_ioctl,
};


int nxftw_file_init(void)
{
	int rc;
	dev_t devno;

	rc = alloc_chrdev_region(&nxftw_device.devt, 1, 1, "nx-ftw");
	if (rc) {
		pr_err("Unable to allocate nxftw major number: %i\n", rc);
		return rc;
	}

	pr_devel("NX-FTW device allocated, dev [%i,%i]\n",
			MAJOR(nxftw_device.devt), MINOR(nxftw_device.devt));

	nxftw_device.class = class_create(THIS_MODULE, "nxftw");
	if (IS_ERR(nxftw_device.class)) {
		pr_err("Unable to create NX-FTW class\n");
		rc = PTR_ERR(nxftw_device.class);
		goto err;
	}
	nxftw_device.class->devnode = nxftw_devnode;

	cdev_init(&nxftw_device.cdev, &nxftw_fops);

	devno = MKDEV(MAJOR(nxftw_device.devt), 0);
	if (cdev_add(&nxftw_device.cdev, devno, 1)) {
		pr_err("NX-FTW: cdev_add() failed\n");
		goto err;
	}

	nxftw_device.device = device_create(nxftw_device.class, NULL,
			devno, NULL, nxftw_dev_name, MINOR(devno));
	if (IS_ERR(nxftw_device.device)) {
		pr_err("Unable to create nxftw-%d\n", MINOR(devno));
		goto err;
	}

	pr_devel("%s: Added dev [%d,%d]\n", __func__, MAJOR(devno),
			MINOR(devno));
	return 0;

err:
	unregister_chrdev_region(nxftw_device.devt, 1);
	return rc;
}

void nxftw_file_exit(void)
{
	dev_t devno;

	pr_devel("NX-FTW: %s entered\n", __func__);

	cdev_del(&nxftw_device.cdev);
	devno = MKDEV(MAJOR(nxftw_device.devt), MINOR(nxftw_device.devt));
	device_destroy(nxftw_device.class, devno);

	class_destroy(nxftw_device.class);
	unregister_chrdev_region(nxftw_device.devt, 1);
}

int __init nxftw_init(void)
{
	int rc;

	rc = nxftw_file_init();
	if (rc)
		return rc;

	pr_info("NX-FTW Device initialized\n");

	return 0;
}

void __init nxftw_exit(void)
{
	pr_devel("NX-FTW Device exiting\n");
	nxftw_file_exit();
}

module_init(nxftw_init);
module_exit(nxftw_exit);

MODULE_DESCRIPTION("IBM NX Fast Thread Wakeup Device");
MODULE_AUTHOR("Sukadev Bhattiprolu <sukadev@linux.vnet.ibm.com>");
MODULE_LICENSE("GPL");
