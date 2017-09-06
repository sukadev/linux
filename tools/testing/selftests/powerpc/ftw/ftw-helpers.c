/*
 * Copyright 2016-18 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <misc/ftw.h>

#include "copy-paste.h"
#include "ftw-helpers.h"

static char *devname = "/dev/ftw";
static bool verbose;

#ifdef skip_copy_paste
static void log_skipped_copy_paste(char *msg)
{
	static bool warned;

	if (__sync_bool_compare_and_swap(&warned, false, true))
		printf("%s: ===== SKIPPED copy/paste =====\n", msg);
}
#endif

static int ftw_open(char *msg)
{
	int fd;
	bool dummy = false;

	fd = open(devname, O_RDWR);
	if (fd < 0) {
		printf("%s: open(%s) failed, %s\n", msg, devname, ERRMSG);
		fd = -errno;
	}

	if (is_paste_done(&dummy))
		printf("Just silencing compiler!\n");

	return fd;
}

int ftw_setup_rxwin(char *msg, struct ftw_win *ftwin)
{
	int rc, fd, cmd;
	struct ftw_setup_attr ftwattr;

	fd = ftw_open(msg);
	if (fd < 0)
		return -errno;

	memset(&ftwattr, 0, sizeof(ftwattr));
	ftwattr.version = 1;
	ftwattr.vas_id = -1;

	cmd = FTW_SETUP;
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
	int rc, fd;
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

	/*
	 * Set REPORT_ENABLE bit (0x400) in the paste address always for now
	 */
	ftwin->paste_addr = addr + 0x400;
	ftwin->map_size = size;

	return 0;
}

void ftw_close_win(char *msg, struct ftw_win *ftwin)
{
	int rc;

	if (ftwin->paste_addr) {
		rc = munmap(ftwin->paste_addr, ftwin->map_size);
		if (rc < 0)
			printf("%s: munmap error %s\n", msg, ERRMSG);
		ftwin->paste_addr = NULL;
	}

	close(ftwin->fd);
	ftwin->fd = -1;
}

static void log_paste_attempt_fail(int i, int ntries)
{
	int c;
	static int fail_count[10];

	if (i >= 10)
		return;

	c = ++fail_count[i];

	if (!(c % 10000))
		printf("Paste attempt %d/%d failed %d times\n", i, ntries, c);
}

static void log_copy_paste_count(char *msg, int count)
{
#ifdef debug
	if (!(count % 100000))
		printf("%s: Copy/paste count: %'d\n", msg, count);
#endif
}

int write_crb(void *crb, void *paste_addr, char *msg)
{

#ifndef skip_copy_paste
	int i, rc, ntries;

	ntries = 50;
	for (i = 0; i < ntries; i++) {
		static int copy_paste_count;

		vas_copy(crb, 0);

		rc = vas_paste(paste_addr, 0);
		if (verbose) {
			printf("%s: vas_paste(i %d) rc 0x%x\n", msg, i, rc);
			fflush(stdout);
		}

		if (rc == 2) {
			log_copy_paste_count(msg, ++copy_paste_count);
			break;
		}

		log_paste_attempt_fail(i, ntries);
	}

	if (!rc) {
		printf("PASTE failed %d times, giving up\n", ntries);
		return -EAGAIN;
	}

	if (verbose)
		printf("%s: Issued copy/paste\n", msg);
#else
	log_skipped_copy_paste(msg);
#endif
	return 0;
}

void *alloc_init_crb(void)
{
	int rc;
	void *crb;
	int size = 65536;

	rc = posix_memalign(&crb, size, size);
	if (rc < 0 || !crb) {
		printf("%s: posix_memalign() failed\n", __func__);
		return NULL;
	}

	memset(crb, 0, size);

	return crb;
}

int write_empty_crb(void *paste_addr, char *msg)
{
	int rc;
	void *crb;

	crb = alloc_init_crb();
	if (!crb)
		return -ENOMEM;

	rc = write_crb(crb, paste_addr, msg);

	free(crb);

	return rc;
}
