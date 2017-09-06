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
#include <errno.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <assert.h>
#include "ftw-helpers.h"

/*
 * Create an UNIX domain socket connection between a parent-child pair.
 * Have the child:
 *	- setup the receive side of a FTW/VAS connection,
 *	- send the fd over to the parent
 *	- issue a WAIT instruction
 * Have the parent:
 *	- mmap() the received fd and,
 *	- issue copy/paste to wake up the child.
 *
 * Note that the 'paste_done' flag must be in mmapped region so both
 * processes can access it.
 */
int verbose = 1;

#define ERRMSG	strerror(errno)

#define FDSHARE_SOCKET	"/tmp/fdshare1.socket"
#define FDSHARE_DATA	"fdshare.data"
#define MAX_FDS		2

int send_fds(int sock, int *fdlist, int nfds)
{
	int rc, len;
	char iobuf[1];
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec io = {
			.iov_base = iobuf,
			.iov_len = sizeof(iobuf),
	};

	int *fdptr;
	union {
		char		buf[CMSG_SPACE(MAX_FDS * sizeof(int))];
		struct cmsghdr	align;
	} u;

	assert(nfds <= MAX_FDS);

	len = sizeof(int) * nfds;

	msg.msg_iov = &io;	/* Unused but needed? */
	msg.msg_iovlen = 1;
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(len);

	fdptr = (int *)CMSG_DATA(cmsg);
	memcpy(fdptr, fdlist, len);

	rc = sendmsg(sock, &msg, 0);
	if (rc < 0) {
		printf("Child: sendmsg() %d, error %s\n", rc, ERRMSG);
		_Exit(1);
	} else if (rc != sizeof(iobuf)) {
		printf("Child: sendmsg() sent %d of %lu bytes?\n", rc,
				sizeof(iobuf));
	}

	return 0;
}

int receive_fd(int sock)
{
	int n;
	struct msghdr msg =  { 0 };
	struct cmsghdr *cmsg;
	char ctlbuf[1024];
	char iobuf[1024];
	struct iovec io = {
			.iov_base = &iobuf,
			.iov_len = sizeof(iobuf)
	};
	int myfds[MAX_FDS];

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = ctlbuf;
	msg.msg_controllen = sizeof(ctlbuf);

	n = recvmsg(sock, &msg, 0);
	if (n <= 0) {
		printf("Parent recvmsg() %d, error %s\n", n, ERRMSG);
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);

	printf("Parent: CMSG lvl %d (%sSOL_SOCKET), type %d (%sSCM_RIGHTS)\n",
			cmsg->cmsg_level,
			cmsg->cmsg_level == SOL_SOCKET ? "" : "!",
			cmsg->cmsg_type,
			cmsg->cmsg_type == SCM_RIGHTS ? "" : "!");

	memcpy(myfds, (int *)CMSG_DATA(cmsg), MAX_FDS*sizeof(int));

	if (verbose)
		printf("Parent: Got fd %d\n", myfds[0]);

	return myfds[0];
}

static void wait_for_paste(bool *paste_donep)
{
	printf("Child: waiting for paste\n");
	while (!is_paste_done(paste_donep))
		do_wait();
}

int do_child(void *arg)
{
	int sock, myfds[2], nfds, rc;
	char *fname;
	bool *paste_donep = arg;
	struct ftw_win ftwin;
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	fname = FDSHARE_SOCKET;
	strncpy(addr.sun_path, fname, strlen(fname));

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf("Child: connect() error %s\n", ERRMSG);
		_Exit(1);
	}

	rc = ftw_setup_rxwin("Child", &ftwin);
	if (rc < 0) {
		printf("Child: file %s, error %s\n", FDSHARE_DATA, ERRMSG);
		_Exit(1);
	}

	myfds[0] = ftwin.fd;
	myfds[1] = ftwin.fd;
	nfds = 2;

	if (verbose)
		printf("Child: sending fd %d to sock %d\n", ftwin.fd, sock);

	send_fds(sock, myfds, nfds);

	wait_for_paste(paste_donep);

	printf("Child: exiting\n");
	return 0;

}

int main(int argc, char *argv[])
{
	int rc;
	int prot;
	int sock;
	int txfd, cfd, status;
	struct sockaddr_un addr;
	struct ftw_win ftwin;
	bool *paste_donep;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		printf("socketpair(): Error %s\n", ERRMSG);
		_Exit(1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, FDSHARE_SOCKET, sizeof(addr.sun_path) - 1);

	unlink(addr.sun_path);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf("bind() Error %s\n", ERRMSG);
		_Exit(1);
	}

	prot = PROT_READ|PROT_WRITE;
	paste_donep = mmap(NULL, 4096, prot, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (paste_donep == MAP_FAILED) {
		printf("Error %s with mmap()\n", ERRMSG);
		_Exit(1);
	}

	rc = fork();
	if (rc < 0) {
		printf("fork(): Error %s\n", ERRMSG);
		_Exit(1);
	}

	*paste_donep = false;
	if (rc == 0)
		return do_child(paste_donep);

	if (listen(sock, 5) < 0) {
		printf("listen(): Error %s\n", ERRMSG);
		_Exit(1);
	}

	cfd = accept(sock, NULL, NULL);
	if (cfd < 0) {
		printf("accept(): Error %s\n", ERRMSG);
		_Exit(1);
	}

	txfd = receive_fd(cfd);

	/*
	 * Proccesses share file pointer, so we should position it!
	 */
	memset(&ftwin, 0, sizeof(ftwin));
	ftwin.fd = txfd;

	rc = ftw_setup_txwin("Parent", &ftwin);
	if (rc < 0) {
		printf("Parent: Error %s setting up txwin\n", ERRMSG);
		_Exit(1);
	}

	printf("Parent: writing CRB\n");
	rc = write_empty_crb(ftwin.paste_addr, "Parent");
	if (rc < 0) {
		printf("Parent: ERROR writing crb, %d\n", rc);
		_Exit(1);
	}

	set_paste_done(paste_donep);

	wait(&status);
	if (WIFEXITED(status))
		printf("Parent: child exit status %d\n", WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		printf("Parent: child got signal %d\n", WTERMSIG(status));

	_Exit(0);

}

