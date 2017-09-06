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
#include <stdlib.h>
#include <pthread.h>

#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <asm/ioctl.h>

#include "ftw-helpers.h"

#define N_THREAD_PAIRS	1024

int skip_paste;
int skip_trace = 1;

struct ftw_thread_pair {
	int		tpid;
	bool		setup_done;
	bool		paste_done;
	pthread_t	receiver;
	pthread_t	sender;
	pthread_cond_t	cond;
	pthread_mutex_t mutex;

	struct ftw_win	ftwin;
} ftw_thread_pairs[N_THREAD_PAIRS];


/*
 * Fast Thread-wakeup Test case 1.
 *	Create N_THREAD_PAIRS pairs of threads - first thread in each pair
 *	creates a receive window and issue Wait. Second thread in the pair,
 *	creates a send window and pastes to wake up thread the first thread
 *	in the pair.
 */

static void *receiver_func(void *arg)
{
	int rc;
	char msg[256];
	struct ftw_win *ftwin;
	struct ftw_thread_pair *thrpair;

	thrpair = (struct ftw_thread_pair *)arg;
	ftwin = &thrpair->ftwin;
	snprintf(msg, sizeof(msg), "[Rx:%d,%d]", thrpair->tpid, gettid());

	rc = ftw_setup_rxwin(msg, ftwin);
	if (rc < 0)
		_Exit(1);

	pthread_mutex_lock(&thrpair->mutex);

	thrpair->setup_done = true;

	if (pthread_cond_signal(&thrpair->cond) < 0) {
		printf("%s: cond_signal failed, %s\n", msg, ERRMSG);
		_Exit(1);
	}

	pthread_mutex_unlock(&thrpair->mutex);

	while (!is_paste_done(&thrpair->paste_done))
		do_wait();

	pthread_exit(&rc);
}

static void *sender_func(void *arg)
{
	int rc;
	char msg[256];
	struct ftw_thread_pair *thrpair;

	thrpair = (struct ftw_thread_pair *)arg;
	snprintf(msg, sizeof(msg), "[Tx:%d,%d]", thrpair->tpid, gettid());

	pthread_mutex_lock(&thrpair->mutex);

	while (!thrpair->setup_done) {
		rc = pthread_cond_wait(&thrpair->cond, &thrpair->mutex);
		if (rc) {
			printf("cond_wait(): rc %d, %s\n", rc, ERRMSG);
			_Exit(1);
		}
	}
	pthread_mutex_unlock(&thrpair->mutex);

	rc = ftw_setup_txwin(msg, &thrpair->ftwin);
	if (rc < 0) {
		printf("%s: txwin failed\n", msg);
		_Exit(1);
	}

	if (!skip_paste) {
		rc = write_empty_crb(thrpair->ftwin.paste_addr, msg);
		if (rc < 0)
			printf("write_empty_crb() FAILED, rc %d\n", rc);
	}
	set_paste_done(&thrpair->paste_done);

	pthread_exit(&rc);
}
static void write_ftrace_pid(void)
{
	int fd;
	char *file_name;
	char buf[256];

	if (skip_trace)
		return;

	file_name = "/sys/kernel/debug/tracing/set_ftrace_pid";

	fd = open(file_name, O_RDWR|O_TRUNC);
	if (fd < 0) {
		printf("open(%s): Error %s\n", file_name, strerror(errno));
		_Exit(1);
	}

	sprintf(buf, "%d", getpid());
	write(fd, buf, strlen(buf));
	printf("Wrote %s to %s\n", buf, file_name);
}

int main(int argc, char *argv[])
{
	int i, rc;
	pthread_t thread;
	pthread_attr_t thr_attr;
	struct ftw_thread_pair *thrpair;


	write_ftrace_pid();

	pthread_attr_init(&thr_attr);

	/*
	 * First create all the receiver threads
	 */
	for (i = 0; i < N_THREAD_PAIRS; i++) {

		thrpair = &ftw_thread_pairs[i];
		thrpair->tpid = i;

		rc = pthread_cond_init(&thrpair->cond, NULL);
		if (rc) {
			printf("cond_init rc %d, %s\n", rc, ERRMSG);
			_Exit(1);
		}

		if (pthread_mutex_init(&thrpair->mutex, NULL) != 0) {
			printf("mutex_init rc %d, %s\n", rc, ERRMSG);
			_Exit(1);
		}

		rc = pthread_create(&thread, &thr_attr, receiver_func, thrpair);
		if (rc < 0) {
			printf("pthread_create(1): rc %d, %s\n", rc, ERRMSG);
			_Exit(1);
		}
		thrpair->receiver = thread;
	}

	/*
	 * Then create the sender threads
	 */
	for (i = 0; i < N_THREAD_PAIRS; i++) {
		thrpair = &ftw_thread_pairs[i];

		rc = pthread_create(&thread, &thr_attr, sender_func, thrpair);
		if (rc < 0) {
			printf("pthread_create(2): rc %d, %s\n", rc, ERRMSG);
			_Exit(1);
		}

		thrpair->sender = thread;
	}

	printf("ftw-1: Created %d thread pairs\n", N_THREAD_PAIRS);
	fflush(stdout);
	/*
	 * Finally wait for them to join
	 */
	for (i = 0; i < N_THREAD_PAIRS; i++) {
		thrpair = &ftw_thread_pairs[i];

		pthread_join(thrpair->receiver, NULL);

		pthread_join(thrpair->sender, NULL);
	}

	printf("ftw-1: %d thread pair joined %s\n", N_THREAD_PAIRS,
			skip_paste ? "(SKIPPED PASTE)" : "");
	fflush(stdout);
	_Exit(0);
}
