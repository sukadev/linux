#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include "nx-helpers.h"

void get_payload(char *buf, int len)
{
	int n;
	char *data_str = "abcdefghijklmnopqrstuvwxyz0123456789";

	n = strlen(data_str);

	while(len > n) {
		memcpy(buf, data_str, (size_t)n);
		buf += n;
		len -= n;
	}

	memcpy(buf, data_str, len);
}

void *alloc_aligned_mem(int len, int align, char *msg)
{
	int rc;
	void *mem;

	rc = posix_memalign(&mem, align, len);
	if (rc < 0 || !mem) {
		pr_debug("%s(): Unable to allocate %d bytes\n", __func__, len);
		return NULL;
	}

#if 0
	pr_debug("Allocated %d bytes aligned to %d for %s at %p\n", len, align,
			msg, mem);
#endif

	memset(mem, 0, len);

	return mem;
}

static void print_direct_dde(struct data_descriptor_entry *dde, char *msg)
{
	printf("%s @ %p\n", msg, dde);
	printf("\t flags 0x%hx, ", dde->flags);
	printf("count %d, ", dde->count);
	printf("index %d, ", dde->index);
	printf("len %d, ", be32_to_cpu(dde->length));
	printf("addr 0x%lx\n", be64_to_cpu(dde->address));
}

void dump_dde(struct data_descriptor_entry *dde, char *msg)
{
	int i;
	char buf[64];
	struct data_descriptor_entry *ddl, *tmp;

	print_direct_dde(dde, msg);
	if (!dde->count)
		return;

	ddl = (struct data_descriptor_entry *)dde->address;
	for (i = 0; i < dde->count; i++) {
		tmp = &ddl[i];
		sprintf(buf, "Indirect DDE (index %d)", i);
		print_direct_dde(tmp, buf);
	}
}

static int copy_dde(struct data_descriptor_entry *src,
				struct data_descriptor_entry *tgt)
{
	memcpy((void *)tgt->address, (void *)src->address, src->length);

	tgt->flags = 0;
	tgt->count = src->count;
	tgt->length = src->length;
	tgt->index = src->index;

	return src->length;
}

void copy_paste_crb_data(struct coprocessor_request_block *crb)
{
	int i;
	struct data_descriptor_entry *src, *tgt, *ddlin, *ddlout;
	struct coprocessor_status_block *csb;

	csb = (struct coprocessor_status_block *)crb->csb_addr;
	csb->count = 0;

	if (!crb->source.count) {
		printf("Copying direct dde, len %d\n", crb->source.length);
		csb->count = copy_dde(&crb->source, &crb->target);
		goto out;
	}

	ddlin = (struct data_descriptor_entry *)crb->source.address;
	ddlout = (struct data_descriptor_entry *)crb->target.address;

	for (i = 0; i < crb->source.count; i++) {
		src = &ddlin[i];
		tgt = &ddlout[i];
		printf("Copy indirect dde %d, len %d\n", i, src->length);
		copy_dde(src, tgt);
		csb->count += copy_dde(src, tgt);
	}

out:
	csb->flags |= CSB_V;
	csb->cc = CSB_CC_SUCCESS;
}

void dump_buffer(char *msg, char *buf, int len)
{
	int i, n, nbytes = 128;

	if (len > nbytes)
		n = nbytes;

	printf("\n%s (first %d of %d bytes buf %p in hex)\n\t", msg, n, len, buf);
	for (i = 0; i < n / 4; i++) {
		if ((i % 8) == 0)
			printf("\n\t");
		printf("%.08x ", *(((int *)buf + i)));
	}

	n = len - n;
	if (n > nbytes)
		n = nbytes;

#if 0	
	/* Dump last N bytes of the buffer too */
	buf += (len - n);

	printf("\n%s (last %d bytes offset %d, buf %p in hex)\n\t", msg, n ,
				(len - n), buf);
	for (i = 0; i < n / 4; i++) {
		if ((i % 8) == 0)
			printf("\n\t");
		printf("%.08x ", *(((int *)buf + i)));
	}
#endif
	printf("\n");
}

void time_add(struct timeval *in, int seconds, struct timeval *out)
{
	struct timeval tmp;

	timerclear(&tmp);
	tmp.tv_sec = seconds;

	timeradd(in, &tmp, out);
}

bool time_after(struct timeval *a, struct timeval *b)
{
	struct timeval res;

	timersub(a, b, &res);

	return res.tv_sec <= 0;
}

long time_delta(struct timeval *a, struct timeval *b)
{
	struct timeval res;

	timersub(a, b, &res);

	return res.tv_sec * 1000000 + res.tv_usec;
}

