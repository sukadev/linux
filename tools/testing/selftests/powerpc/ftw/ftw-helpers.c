#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <asm/nx-ftw.h>

typedef unsigned int u32;

#include "copy-paste.h"
#include "ftw-helpers.h"

/*
 * For now allow different names for the device so we work better
 * with different kernel versions.
 */
static char *nx_devnames[] = { "/dev/crypto/nx-ftw", "/dev/crypto/nx-test" };
static bool verbose;

bool not_warned(void)
{
	static bool warned;
	return __sync_bool_compare_and_swap(&warned, false, true);
}

static int ftw_open(char *msg)
{
	char *devname;
	int i, rc, fd, n_names;

	n_names = sizeof(nx_devnames) / sizeof(char *);

	for (i = 0; i < n_names; i++) {
		devname = nx_devnames[i];

		if (i)
			printf("Trying alternate node %s\n", devname);

		fd = open(devname, O_RDWR);
		if (fd >= 0 || errno != -ENOENT)
			break;

		printf("%s: open(%s) failed %s\n", msg, devname, ERRMSG);
	}

	if (fd < 0) {
		printf("%s: No more devices to try\n", msg);
		fd = -errno;
	}

	return fd;
}

int ftw_setup_rxwin(char *msg, struct ftw_win *ftwin)
{
	char *devname;
	int i, rc, fd, cmd;
	struct vas_ftw_setup_attr ftwattr;

	fd = ftw_open(msg);
	if (fd < 0)
		return -errno;

	memset(&ftwattr, 0, sizeof(ftwattr));
	ftwattr.version = 1;

	cmd = VAS_FTW_SETUP;
	rc = ioctl(fd, cmd, (unsigned long)&ftwattr);
	if (rc < 0) {
		rc = -errno;
		printf("%s: ioctl(0x%x) error %s\n", msg, cmd, ERRMSG);
		return rc;
	}

	if (verbose)
		printf("%s: Opened window\n", msg);

	ftwin->fd = fd;

	return 0;
}

int ftw_setup_txwin(char *msg, struct ftw_win *ftwin)
{
	void *addr;
	char *devname;
	int i, rc, fd, cmd;
	int size;

	size = sysconf(_SC_PAGESIZE);
	size = 4096;

	fd = ftwin->fd;

	addr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0ULL);
	if (addr == MAP_FAILED) {
		rc = -errno;
		printf("%s: mmap() failed, error %s\n", msg, ERRMSG);
		return rc;
	}

	if (verbose)
		printf("%s: mapped @%p\n", msg, addr);

	ftwin->paste_addr = addr;
	ftwin->map_size = size;

	return 0;
}

void ftw_close_win(char *msg, struct ftw_win *ftwin)
{
	int rc;

	if (!ftwin->paste_addr) {
		rc = munmap(ftwin->paste_addr, ftwin->map_size);
		if (rc < 0) {
			printf("%s: munmap error %s\n", msg, ERRMSG);
		}
		ftwin->paste_addr = NULL;
	}

	close(ftwin->fd);
	ftwin->fd = -1;

	return;
}

int write_empty_crb(void *paste_addr, char *msg)
{

#ifndef skip_copy_paste
	int i, rc, ntries;
	void *crb;
	/*
	 * NULL crb fails with SIGSEGV and zeroed CRB fails with SIGBUS
	 * during copy on DD1. Wait for DD2.
	 */
	char crb_buf[256];

	crb = &crb_buf[0];
	memset(crb, 0, sizeof(crb_buf));

	rc = vas_copy(crb, 0);

	ntries = 5;
	for (i = 0; i < ntries; i++) {
		rc = vas_paste(paste_addr, 0);
		if (verbose) {
			printf("%s: vas_paste(i %d) rc 0x%x\n", msg, i, rc);
			fflush(stdout);
		}
		if (rc == 0x20000000)
			break;

		printf("Paste attempt %d/%d failed\n", i, ntries);
	}

	if (!rc) {
		printf("PASTE failed %d times, giving up\n", ntries);
		return -EAGAIN;
	}

	if (verbose)
		printf("%s: Issued copy/paste\n", msg);
#else
	if (not_warned())
		printf("%s: ===== SKIPPED copy/paste =====\n", msg);
#endif
}
