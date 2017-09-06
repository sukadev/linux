#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>

#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "ftw-helpers.h"

#define N_SENDER_THREADS	8

/*
 * Fast Thread-wakeup Test case 3.
 * 	Create a "receiver" thread that creates a receive window and repeatedly
 * 	issues a Wait. Create N_SENDER_THREADS that each open a send window
 * 	to the same receiver thread. Have each thread issue a paste to wake
 *	up the receiver thread.
 *
 * 	This mainly tests kernel handling of multiple senders to the same
 * 	receive window.
 */
static bool		setup_done;
static bool		paste_done;
static bool 		end_test;
static bool		verbose;
static pthread_cond_t	rxwin_ready;
static pthread_mutex_t	rxwin_mutex;
struct ftw_win rxftwin;

static bool should_stop()
{
	//bool rc;
	//rc = __sync_bool_compare_and_swap(&end_test, 1, 1);
	//return rc;
	__sync_synchronize();
	return end_test;
}

static void stop_test()
{
	__sync_bool_compare_and_swap(&end_test, 0, 1);
}

static void *receiver_func(void *arg)
{
	int rc, count;
	char msg[256];

	snprintf(msg, sizeof(msg), "Rx[%d]", gettid());
	rc = ftw_setup_rxwin(msg, &rxftwin);
	if (rc < 0)
		_Exit(1);

	pthread_mutex_lock(&rxwin_mutex);

	setup_done = true;
	pthread_cond_signal(&rxwin_ready);

	pthread_mutex_unlock(&rxwin_mutex);

	count = 0;
	while (!should_stop()) {
		while(!is_paste_done(&paste_done) && !should_stop())
			do_wait();

		count++;
		if (verbose) {
			printf("%s: woke up\n", msg, count);
			fflush(stdout);
		}
		sleep(1);
	}

	if (verbose) {
		printf("%s: woke up %d times, exiting\n", msg, count);
		 fflush(stdout);
	}
	pthread_exit(&rc);
}

static void *sender_func(void *arg)
{
	int fd, rc;
	struct ftw_win ftwin;
	char msg[256];

	snprintf(msg, sizeof(msg), "Tx[%d]", gettid());


	if (verbose)
		printf("%s(): starting\n", msg);

	memcpy(&ftwin, &rxftwin, sizeof(ftwin));
	rc = ftw_setup_txwin(msg, &ftwin);
	if (rc < 0)
		pthread_exit(&rc);

	write_empty_crb(ftwin.paste_addr + 0x400, msg);
	if (verbose)
		printf("%s(): wrote CRB\n", msg);
	set_paste_done(&paste_done);
	if (verbose)
		printf("%s(): set condition\n", msg);

	sleep(1);

	pthread_exit(&rc);
}

int main(int argc, char *argv[])
{
	int i, rc;
	pthread_attr_t thr_attr;
	pthread_t receiver;
	pthread_t sender[N_SENDER_THREADS];

	pthread_attr_init(&thr_attr);

	rc = pthread_cond_init(&rxwin_ready, NULL);
	if (rc) {
		fprintf(stderr,"Failed to initialize rxwin_ready\n");
		_Exit(1);
	}

	if (pthread_mutex_init(&rxwin_mutex, NULL) != 0) {
		fprintf(stderr,"Failed to initialize mutex\n");
		_Exit(1);
	}

	rc = pthread_create(&receiver, &thr_attr, receiver_func, NULL);
	if (rc < 0) {
		printf("pthread_create(1): rc %d, error %s\n", rc, ERRMSG);
		_Exit(1);
	}

	pthread_mutex_lock(&rxwin_mutex);

	while (!setup_done) {
		rc = pthread_cond_wait(&rxwin_ready, &rxwin_mutex);
		if (rc) {
			printf("pth_cond_wait(1): rc %d, %s\n", rc, ERRMSG);
			_Exit(1);
		}
	}

	pthread_mutex_unlock(&rxwin_mutex);


	for (i = 0; i < N_SENDER_THREADS; i++) {
		rc = pthread_create(&sender[i], &thr_attr, sender_func, NULL);
		if (rc < 0) {
			printf("pthread_create(%d): rc %d, error %s\n", i, rc,
					ERRMSG);
			_Exit(1);
		}
	}

	printf("%d: Created %d sender threads\n", getpid(), i);

	for (i = 0; i < N_SENDER_THREADS; i++)
		pthread_join(sender[i], NULL);

	stop_test();
	pthread_join(receiver, NULL);

	_Exit(0);
}
