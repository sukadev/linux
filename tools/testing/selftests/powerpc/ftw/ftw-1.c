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

#define N_THREAD_PAIRS	8

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
 * Fast Thread-wakeup Test case 2.
 * 	Create N_THREAD_PAIRS pairs of threads - first thread in each pair
 * 	creates a receive window and issue Wait. Second thread in the pair,
 * 	creates a send window and pastes to wake up thread the first thread
 * 	in the pair.
 */

static void *receiver_func(void *arg)
{
	int rc, fd;
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

	while(!is_paste_done(&thrpair->paste_done))
		do_wait();

	sleep(1);
	pthread_exit(&rc);
}

static void *sender_func(void *arg)
{
	int fd, rc;
	char msg[256];
	struct ftw_thread_pair *thrpair;
	void *addr;

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

	rc = write_empty_crb(thrpair->ftwin.paste_addr + 0x400, msg);
	if (rc < 0) {
		printf("write_empty_crb() FAILED, rc %d\n", rc);
	}
	set_paste_done(&thrpair->paste_done);

	sleep(1);

	pthread_exit(&rc);
}

int main(int argc, char *argv[])
{
	int i, rc, num_iterations;
	pthread_t thread;
	pthread_attr_t thr_attr;
	struct ftw_thread_pair *thrpair;

	num_iterations = 0;
	if (argc > 1)
		num_iterations = atoi(argv[1]);

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

	printf("ftw-2: Crated %d thread pairs\n", N_THREAD_PAIRS);
	/*
	 * Finally wait for them to join
	 */
	for (i = 0; i < N_THREAD_PAIRS; i++) {
		thrpair = &ftw_thread_pairs[i];

		pthread_join(thrpair->receiver, NULL);

		pthread_join(thrpair->sender, NULL);
	}

	printf("ftw-2: %d thread pair joined\n", N_THREAD_PAIRS);
	_Exit(0);
}
