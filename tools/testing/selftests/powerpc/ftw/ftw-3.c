/*
 * Copyright 2016-18 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <locale.h>
#include "ftw-helpers.h"

static bool end_test;
#define NUM_ITER	200000

/*
 * FTW-3: Have a pair of threads wait for/wake up each other in a loop.
 *
 *	- Each thread sets up a FTW window pair (2 send windows, 2 receive
 *	  windows in all)
 *
 *	- Slave thread starts out in WAIT instruction.
 *
 *	- Master thread uses COPY/PASTE to wake up slave and proceeds to WAIT.
 *
 *	- Slave wakes up and issues a COPY/PASTE to wake up master and goes
 *	  back to WAIT.
 *
 *	- Repeat NUM_ITER times.
 */
static bool should_stop(void)
{
	__sync_synchronize();
	return end_test;
}

static void stop_test(void)
{
	__sync_bool_compare_and_swap(&end_test, 0, 1);
}

static void do_paste(void *crb, void *addr, char *msg, bool *paste_donep)
{
	if (write_crb(crb, addr, msg) == 0)
		__sync_bool_compare_and_swap(paste_donep, 0, 1);
	else
		printf("Paste FAILED, not setting condition\n");
}

double microseconds(void)
{
	struct timeval  curtime;

	gettimeofday(&curtime, NULL);
	return (double)1000000. * curtime.tv_sec + (double)curtime.tv_usec;
}

struct thread_state {
	bool		setup_done;
	bool		paste_done;
	bool		slave;
	void		*crb;
	void		*paste_addr;
	pthread_mutex_t	ready_mutex;
	pthread_cond_t  ready_cond;
};

struct thread_arg {
	struct thread_state *this;
	struct thread_state *peer;
};

static void do_slave(struct thread_state *this, struct thread_state *peer,
			char *msg)
{
	while (!should_stop()) {
		while (!is_paste_done(&this->paste_done) && !should_stop())
			do_wait();

		do_paste(peer->crb, peer->paste_addr, msg, &peer->paste_done);
	}
}

static void do_master(struct thread_state *this, struct thread_state *peer,
			char *msg)
{
	int i;
	double t0, t1;

	t0 = microseconds();

	for (i = 0; i < NUM_ITER; i++) {
		do_paste(peer->crb, peer->paste_addr, msg, &peer->paste_done);

		while (!is_paste_done(&this->paste_done) && !should_stop())
			do_wait();
	}

	do_paste(peer->crb, peer->paste_addr, msg, &peer->paste_done);
	stop_test();

	t1 = microseconds();

	printf("%'d operations in %lf microseconds ( %lf usec/itn)\n",
			NUM_ITER, (t1 - t0), (t1 - t0) / NUM_ITER);
}

static void *one_instance(void *arg)
{
	int rc;
	char msg[256];
	struct thread_arg *iarg = arg;
	struct thread_state *this = iarg->this;
	struct thread_state *peer = iarg->peer;

	struct ftw_win rxftwin, txftwin;

	if (this->slave)
		snprintf(msg, sizeof(msg), "Slave-%d", gettid());
	else
		snprintf(msg, sizeof(msg), "Master-%d", gettid());

	rc = ftw_setup_rxwin(msg, &rxftwin);
	if (rc < 0)
		_Exit(1);

	memcpy(&txftwin, &rxftwin, sizeof(txftwin));
	rc = ftw_setup_txwin(msg, &txftwin);
	if (rc < 0)
		pthread_exit(&rc);

	this->paste_addr = txftwin.paste_addr;

	this->crb = alloc_init_crb();
	if (!this->crb) {
		printf("Unable to allocate CRB\n");
		_Exit(1);
	}

	pthread_mutex_lock(&this->ready_mutex);

	this->setup_done = true;
	pthread_cond_signal(&this->ready_cond);

	pthread_mutex_unlock(&this->ready_mutex);

	pthread_mutex_lock(&peer->ready_mutex);

	/* wait for peer to setup */
	while (!peer->setup_done) {
		rc = pthread_cond_wait(&peer->ready_cond, &peer->ready_mutex);
		if (rc) {
			printf("pth_cond_wait(1): rc %d, %s\n", rc, ERRMSG);
			_Exit(1);
		}
	}

	pthread_mutex_unlock(&peer->ready_mutex);

	printf("%s: Peer is also ready\n", msg);

	if (this->slave)
		do_slave(this, peer, msg);
	else
		do_master(this, peer, msg);

	return NULL;
}

int main(int argc, char *argv[])
{
	int rc;
	pthread_attr_t thr_attr;
	pthread_t thr;
	struct thread_state master, slave;
	struct thread_arg marg, sarg;

	memset(&master, 0, sizeof(master));
	memset(&slave, 0, sizeof(slave));

	setlocale(LC_ALL, "");
	assert(pthread_cond_init(&master.ready_cond, NULL) == 0);
	assert(pthread_cond_init(&slave.ready_cond, NULL) == 0);
	assert(pthread_mutex_init(&master.ready_mutex, NULL) == 0);
	assert(pthread_mutex_init(&slave.ready_mutex, NULL) == 0);

	slave.slave = true;

	marg.this = &master;
	marg.peer = &slave;

	sarg.this = &slave;
	sarg.peer = &master;

	pthread_attr_init(&thr_attr);

	rc = pthread_create(&thr, &thr_attr, one_instance, &sarg);
	if (rc < 0) {
		printf("pthread_create(1): rc %d, error %s\n", rc, ERRMSG);
		_Exit(1);
	}

	(void)one_instance(&marg);

	pthread_join(thr, NULL);

	return 0;
}
