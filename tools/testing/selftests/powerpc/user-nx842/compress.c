#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <bits/endian.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "crb.h"
#include "nx.h"
#include "nx-842.h"
#include "nx-ftw.h"
#include "nx-helpers.h"
#include "copy-paste.h"

extern void *fault_storage_address;
#define WORKMEM_ALIGN	(CRB_ALIGN)
#define CSB_WAIT_MAX	(5) /* seconds */

#if 0
/* Restrictions on Data Descriptor List (DDL) and Entry (DDE) buffers
 *
 * From NX P8 workbook, sec 4.9.1 "842 details"
 *   Each DDE buffer is 128 byte aligned
 *   Each DDE buffer size is a multiple of 32 bytes (except the last)
 *   The last DDE buffer size is a multiple of 8 bytes
 */
#define DDE_BUFFER_ALIGN        (128)
#define DDE_BUFFER_SIZE_MULT    (32)
#define DDE_BUFFER_LAST_MULT    (8)

/* Arbitrary DDL length limit
 * Allows max buffer size of MAX-1 to MAX pages
 * (depending on alignment)
 */
#define DDL_LEN_MAX             (17)
#endif

#define barrier()

struct nx842_workmem {
	/* Below fields must be properly aligned */
	struct coprocessor_request_block crb; /* CRB_ALIGN align */
	struct data_descriptor_entry ddl_in[DDL_LEN_MAX]; /* DDE_ALIGN align */
	struct data_descriptor_entry ddl_out[DDL_LEN_MAX]; /* DDE_ALIGN align */
	/* Above fields must be properly aligned */

	struct timeval start;

	char padding[WORKMEM_ALIGN]; /* unused, to allow alignment */
} __packed __aligned(WORKMEM_ALIGN);

struct nx_handle {
	int fd;
	int function;
	void *paste_addr;
};


/**
 * setup_indirect_dde - Setup an indirect DDE
 *
 * The DDE is setup with the the DDE count, byte count, and address of
 * first direct DDE in the list.
 */
static void setup_indirect_dde(struct data_descriptor_entry *dde,
			       struct data_descriptor_entry *ddl,
			       unsigned int dde_count, unsigned int byte_count)
{
	dde->flags = 0;
	dde->count = dde_count;
	dde->index = 0;
	dde->length = cpu_to_be32(byte_count);
	dde->address = cpu_to_be64(nx842_get_pa(ddl));
}

/**
 * setup_direct_dde - Setup single DDE from buffer
 *
 * The DDE is setup with the buffer and length.  The buffer must be properly
 * aligned.  The used length is returned.
 * Returns:
 *   N    Successfully set up DDE with N bytes
 */
static unsigned int setup_direct_dde(struct data_descriptor_entry *dde,
				     unsigned long pa, unsigned int len)
{
	unsigned int l = min_t(unsigned int, len, LEN_ON_PAGE(pa));

	dde->flags = 0;
	dde->count = 0;
	dde->index = 0;
	dde->length = cpu_to_be32(l);
	dde->address = cpu_to_be64(pa);

#if 0
	printf("%s(): index %d, count %d, length %d\n", __func__,
			dde->index, dde->count, dde->length);
#endif

	return l;
}

/**
 * setup_ddl - Setup DDL from buffer
 *
 * Returns:
 *   0		Successfully set up DDL
 */
static int setup_ddl(struct data_descriptor_entry *dde,
		     struct data_descriptor_entry *ddl,
		     unsigned char *buf, unsigned int len,
		     bool in)
{
	unsigned long pa = nx842_get_pa(buf);
	int i, ret, total_len = len;

#if 0
	/* Disabled to see what the hardware does with improper alignment */

	if (!IS_ALIGNED(pa, DDE_BUFFER_ALIGN)) {
		pr_debug("%s buffer pa 0x%lx not 0x%x-byte aligned\n",
			 in ? "input" : "output", pa, DDE_BUFFER_ALIGN);
		return -EINVAL;
	}
#endif

#if 0
	printf("%s entered, len %d, DDE_BUFFER_LAST_MULT %d, "
			"LEN_ON_PAGE(pa) %d, DDL_LEN_MAX %d\n",
			__func__, len, DDE_BUFFER_LAST_MULT, LEN_ON_PAGE(pa),
			DDL_LEN_MAX);
#endif

	/* only need to check last mult; since buffer must be
	 * DDE_BUFFER_ALIGN aligned, and that is a multiple of
	 * DDE_BUFFER_SIZE_MULT, and pre-last page DDE buffers
	 * are guaranteed a multiple of DDE_BUFFER_SIZE_MULT.
	 */
	if (len % DDE_BUFFER_LAST_MULT) {
		pr_debug("%s buffer len 0x%x not a multiple of 0x%x\n",
			 in ? "input" : "output", len, DDE_BUFFER_LAST_MULT);
		if (in)
			return -EINVAL;
		len = round_down(len, DDE_BUFFER_LAST_MULT);
	}

	/* use a single direct DDE */
	if (len <= LEN_ON_PAGE(pa)) {
		ret = setup_direct_dde(dde, pa, len);
		if (ret < len)
			pr_debug("Warning ret %d, len %d\n", ret, len);

		return 0;
	}

	//printf("%s() setting up ddl, len %d\n", __func__, len);
	/* use the DDL */
	for (i = 0; i < DDL_LEN_MAX && len > 0; i++) {
		ret = setup_direct_dde(&ddl[i], pa, len);
		buf += ret;
		len -= ret;
		pa = nx842_get_pa(buf);
	}

	if (len > 0) {
		pr_debug("0x%x total %s bytes 0x%x too many for DDL.\n",
			 total_len, in ? "input" : "output", len);
		if (in)
			return -EMSGSIZE;
		total_len -= len;
	}
	setup_indirect_dde(dde, ddl, i, total_len);

	return 0;
}

#define CSB_ERR(csb, msg, ...)					\
	pr_err("ERROR: " msg " : %02x %02x %02x %02x %08x\n",	\
	       ##__VA_ARGS__, (csb)->flags,			\
	       (csb)->cs, (csb)->cc, (csb)->ce,			\
	       be32_to_cpu((csb)->count))

#define CSB_ERR_ADDR(csb, msg, ...)				\
	CSB_ERR(csb, msg " at %lx", ##__VA_ARGS__,		\
		(unsigned long)be64_to_cpu((csb)->address))

/**
 * wait_for_csb
 */
static int wait_for_csb(struct nx842_workmem *wmem,
			struct coprocessor_status_block *csb)
{
	struct timeval now, timeout;

	gettimeofday(&wmem->start, NULL);
	timerclear(&timeout);
	time_add(&wmem->start, CSB_WAIT_MAX, &timeout);

	gettimeofday(&now, NULL);

	while (!(csb->flags & CSB_V)) {
		usleep(10000);

		gettimeofday(&now, NULL);

		if (time_after(&timeout, &now))
			break;
		if (fault_storage_address)
			return -EAGAIN;
	}

	/* hw has updated csb and output buffer */
	barrier();

	/* check CSB flags */
	if (!(csb->flags & CSB_V)) {
		CSB_ERR(csb, "CSB still not valid after %ld us, giving up",
			(long)time_delta(&now, &wmem->start));
		return -ETIMEDOUT;
	}
	if (csb->flags & CSB_F) {
		CSB_ERR(csb, "Invalid CSB format");
		return -EPROTO;
	}
	if (csb->flags & CSB_CH) {
		CSB_ERR(csb, "Invalid CSB chaining state");
		return -EPROTO;
	}

	/* verify CSB completion sequence is 0 */
	if (csb->cs) {
		CSB_ERR(csb, "Invalid CSB completion sequence");
		return -EPROTO;
	}

	/* check CSB Completion Code */
	switch (csb->cc) {
	/* no error */
	case CSB_CC_SUCCESS:
		break;
	case CSB_CC_TPBC_GT_SPBC:
		/* not an error, but the compressed data is
		 * larger than the uncompressed data :(
		 */
		break;

	/* input data errors */
	case CSB_CC_OPERAND_OVERLAP:
		/* input and output buffers overlap */
		CSB_ERR(csb, "Operand Overlap error");
		return -EINVAL;
	case CSB_CC_INVALID_OPERAND:
		CSB_ERR(csb, "Invalid operand");
		return -EINVAL;
	case CSB_CC_NOSPC:
		/* output buffer too small */
		return -ENOSPC;
	case CSB_CC_ABORT:
		CSB_ERR(csb, "Function aborted");
		return -EINTR;
	case CSB_CC_CRC_MISMATCH:
		CSB_ERR(csb, "CRC mismatch");
		return -EINVAL;
	case CSB_CC_TEMPL_INVALID:
		CSB_ERR(csb, "Compressed data template invalid");
		return -EINVAL;
	case CSB_CC_TEMPL_OVERFLOW:
		CSB_ERR(csb, "Compressed data template shows data past end");
		return -EINVAL;

	/* these should not happen */
	case CSB_CC_INVALID_ALIGN:
		/* setup_ddl should have detected this */
		CSB_ERR_ADDR(csb, "Invalid alignment");
		return -EINVAL;
	case CSB_CC_DATA_LENGTH:
		/* setup_ddl should have detected this */
		CSB_ERR(csb, "Invalid data length");
		return -EINVAL;
	case CSB_CC_WR_TRANSLATION:
	case CSB_CC_TRANSLATION:
	case CSB_CC_TRANSLATION_DUP1:
	case CSB_CC_TRANSLATION_DUP2:
	case CSB_CC_TRANSLATION_DUP3:
	case CSB_CC_TRANSLATION_DUP4:
	case CSB_CC_TRANSLATION_DUP5:
	case CSB_CC_TRANSLATION_DUP6:
		/* should not happen, we use physical addrs */
		CSB_ERR_ADDR(csb, "Translation error");
		return -EPROTO;
	case CSB_CC_WR_PROTECTION:
	case CSB_CC_PROTECTION:
	case CSB_CC_PROTECTION_DUP1:
	case CSB_CC_PROTECTION_DUP2:
	case CSB_CC_PROTECTION_DUP3:
	case CSB_CC_PROTECTION_DUP4:
	case CSB_CC_PROTECTION_DUP5:
	case CSB_CC_PROTECTION_DUP6:
		/* should not happen, we use physical addrs */
		CSB_ERR_ADDR(csb, "Protection error");
		return -EPROTO;
	case CSB_CC_PRIVILEGE:
		/* shouldn't happen, we're in HYP mode */
		CSB_ERR(csb, "Insufficient Privilege error");
		return -EPROTO;
	case CSB_CC_EXCESSIVE_DDE:
		/* shouldn't happen, setup_ddl doesn't use many dde's */
		CSB_ERR(csb, "Too many DDEs in DDL");
		return -EINVAL;
	case CSB_CC_TRANSPORT:
		/* shouldn't happen, we setup CRB correctly */
		CSB_ERR(csb, "Invalid CRB");
		return -EINVAL;
	case CSB_CC_SEGMENTED_DDL:
		/* shouldn't happen, setup_ddl creates DDL right */
		CSB_ERR(csb, "Segmented DDL error");
		return -EINVAL;
	case CSB_CC_DDE_OVERFLOW:
		/* shouldn't happen, setup_ddl creates DDL right */
		CSB_ERR(csb, "DDE overflow error");
		return -EINVAL;
	case CSB_CC_SESSION:
		/* should not happen with ICSWX */
		CSB_ERR(csb, "Session violation error");
		return -EPROTO;
	case CSB_CC_CHAIN:
		/* should not happen, we don't use chained CRBs */
		CSB_ERR(csb, "Chained CRB error");
		return -EPROTO;
	case CSB_CC_SEQUENCE:
		/* should not happen, we don't use chained CRBs */
		CSB_ERR(csb, "CRB seqeunce number error");
		return -EPROTO;
	case CSB_CC_UNKNOWN_CODE:
		CSB_ERR(csb, "Unknown subfunction code");
		return -EPROTO;

	/* hardware errors */
	case CSB_CC_RD_EXTERNAL:
	case CSB_CC_RD_EXTERNAL_DUP1:
	case CSB_CC_RD_EXTERNAL_DUP2:
	case CSB_CC_RD_EXTERNAL_DUP3:
		CSB_ERR_ADDR(csb, "Read error outside coprocessor");
		return -EPROTO;
	case CSB_CC_WR_EXTERNAL:
		CSB_ERR_ADDR(csb, "Write error outside coprocessor");
		return -EPROTO;
	case CSB_CC_INTERNAL:
		CSB_ERR(csb, "Internal error in coprocessor");
		return -EPROTO;
	case CSB_CC_PROVISION:
		CSB_ERR(csb, "Storage provision error");
		return -EPROTO;
	case CSB_CC_HW:
		CSB_ERR(csb, "Correctable hardware error");
		return -EPROTO;

	default:
		CSB_ERR(csb, "Invalid CC %d", csb->cc);
		return -EPROTO;
	}

	/* check Completion Extension state */
	if (csb->ce & CSB_CE_TERMINATION) {
		CSB_ERR(csb, "CSB request was terminated");
		return -EPROTO;
	}
	if (csb->ce & CSB_CE_INCOMPLETE) {
		CSB_ERR(csb, "CSB request not complete");
		return -EPROTO;
	}

	/* successful completion */
	pr_debug_ratelimited("Processed %u bytes in %lu us\n",
			     be32_to_cpu(csb->count),
			     (unsigned long)time_delta(&now, &wmem->start));

	return 0;
}

static void *alloc_init_workmem(void)
{
	return alloc_aligned_mem(sizeof(struct nx842_workmem), WORKMEM_ALIGN,
			"Workmem");
}

int eftargs_to_fc(struct nx842_func_args *eftargs)
{
	int fc;

	if (eftargs->move_data)
		return CCW_FC_842_MOVE;

	if (eftargs->decompress) {
		if (eftargs->use_crc)
			fc = CCW_FC_842_DECOMP_CRC;
		else
			fc = CCW_FC_842_DECOMP_NOCRC;
	} else {
		if (eftargs->use_crc)
			fc = CCW_FC_842_COMP_CRC;
		else
			fc = CCW_FC_842_COMP_NOCRC;
	}
	return  fc;
}

static int nx842_function(void *handle, nxbuf_t *in, nxbuf_t *out, void *arg)
{
	int i, fc, ret, retries;
	u32 ccw;
	u64 csb_addr;
	struct nx842_workmem *wmem;
	struct coprocessor_request_block *crb;
	struct coprocessor_status_block *csb;
	struct nx842_func_args *eftargs = arg;
	struct nx_handle *nxhandle = handle;

	if (eftargs->move_data && eftargs->decompress)
		return -EINVAL;

	wmem = alloc_init_workmem();
	if (!wmem)
		return -ENOMEM;

	crb = &wmem->crb;
	csb = &crb->csb;

	/* set up DDLs */
	ret = setup_ddl(&crb->source, wmem->ddl_in, in->buf, in->len, 1);
	if (ret)
		goto out;

	ret = setup_ddl(&crb->target, wmem->ddl_out, out->buf, out->len, 0);
	if (ret)
		goto out;

	dump_dde(&crb->source, "Source DDE");
	dump_dde(&crb->target, "Target DDE");

	/*
	 * Set up CRB's CSB addr. We have a virtual address, so unlike
	 * kernel, we can skip following setting the CRB_CSB_AT bit?
	 */
	csb_addr = (u64)csb & CRB_CSB_ADDRESS;
	crb->csb_addr = __cpu_to_be64(csb_addr);
	printf("CRB %p, CSB %p [BE %lx]\n", crb, csb, crb->csb_addr);

#if 0
	printf("workmem addr %p size %d, crb %p, csb %p (%p)\n", wmem,
			sizeof(*wmem), crb, csb, crb->csb_addr);
#endif

	gettimeofday(&wmem->start, NULL);

	fc = eftargs_to_fc(eftargs);
	ccw = 0;

#if 0
	/*
	 * Unlike in P8 we don't need to set CCW_CT for P9.
	 * See also kernel code in nx-842-powernv.c
	 */
	ccw = SET_FIELD(CCW_CT, ccw, nx842_ct);
#endif
	ccw = SET_FIELD(CCW_CI_842, ccw, 0);
	ccw = SET_FIELD(CCW_FC_842, ccw, fc);

	crb->ccw = cpu_to_be32(ccw);

	i = 0;
	retries = 5;
	while (i++ < retries) {
		vas_copy(crb, 0);
		ret = vas_paste(nxhandle->paste_addr, 0);

		printf("Paste attempt %d/%d returns 0x%x\n", i, retries, ret);

		if (ret == 2) {
			ret = wait_for_csb(wmem, csb);
			printf("wait_for_csb() returns %d\n", ret);
			if (!ret) {
				out->len = be32_to_cpu(csb->count);
				goto out;
			} else if (ret == -EAGAIN) {
				printf("Touching address %p, 0x%lx\n",
					fault_storage_address,
					 *(long *)fault_storage_address);
				fault_storage_address = 0;
				continue;
			} else
				break;
		} else {
			pr_err("Paste attempt %d/%d, failed\n", i, retries);
			sleep(1);
			continue;
		}
	}

	return ret;
	/* return the error from paste or wait_for_csb */

out:
	free(wmem);
	return ret;
}

static int open_device_nodes(char *devname, int pri, struct nx_handle *handle)
{
	int rc, fd;
	void *addr;
	struct vas_ftw_setup_attr txattr;

	fd = open(devname, O_RDWR);
	if (fd < 0) {
		printf("open(%s) Error %s\n", devname, strerror(errno));
		return -errno;
	}

	memset(&txattr, 0, sizeof(txattr));
	txattr.version = 1;
	txattr.vas_id = -1;
	rc = ioctl(fd, VAS_842_TX_WIN_OPEN, (unsigned long)&txattr);
	if (rc < 0) {
		printf("ioctl() n %d, error %d\n", rc, errno);
		rc = -errno;
		goto out;
	}

	addr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0ULL);
	if (addr == MAP_FAILED) {
		printf("mmap() failed, errno %d\n", errno);
		rc = -errno;
		goto out;
	}
	printf("Window paste addr @%p\n", addr);

	handle->fd = fd;
	handle->paste_addr = addr + 0x400;

	rc = 0;
out:
	close(fd);
	return rc;
}

/*
 * Compress/decompress the input buffer @in and save the result in @out.
 * Use the algorithm @alg and the parameters to the algorithm specified
 * in @arg
 */
int nx_function(void *handle, nxbuf_t *in, nxbuf_t *out, void *arg)
{
	struct nx_handle *nxhandle = handle;

	if (nxhandle->function != NX_FUNC_COMP_842)
		return -ENOTSUP;

	return nx842_function(nxhandle, in, out, arg);
}


#ifdef debug
void *nx_function_begin(int function, int pri)
{
	struct nx_handle *nxhandle;

	if (function != NX_FUNC_COMP_842) {
		errno = EINVAL;
		return NULL;
	}

	nxhandle = malloc(sizeof(*nxhandle));
	if (!nxhandle) {
		errno = ENOMEM;
		return NULL;
	}

	nxhandle->function = function;
	nxhandle->fd = -1;
	nxhandle->paste_addr = NULL;

	return nxhandle;
}
void nx_function_end(void *handle)
{
	free(handle);
}
#else
void *nx_function_begin(int function, int pri)
{
	int rc;
	char *devname = "/dev/crypto/nx-ftw";
	struct nx_handle *nxhandle;

	if (function != NX_FUNC_COMP_842) {
		errno = EINVAL;
		return NULL;
	}

	nxhandle = malloc(sizeof(*nxhandle));
	if (!nxhandle) {
		errno = ENOMEM;
		return NULL;
	}

	nxhandle->function = function;
	rc = open_device_nodes(devname, 1, nxhandle);
	if (rc < 0) {
		errno = -rc;
		return NULL;
	}

	return nxhandle;
}

int nx_function_end(void *handle)
{
	struct nx_handle *nxhandle = handle;

	/* error check? */
	munmap(nxhandle->paste_addr, 4096);
	close(nxhandle->fd);
	free(nxhandle);
}

#endif
