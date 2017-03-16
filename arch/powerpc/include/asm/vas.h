/*
 * Copyright 2016 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _MISC_VAS_H
#define _MISC_VAS_H

#include <uapi/asm/vas.h>

/*
 * Min and max FIFO sizes are based on Version 1.05 Section 3.1.4.25
 * (Local FIFO Size Register) of the VAS workbook.
 */
#define VAS_RX_FIFO_SIZE_MIN	(1 << 10)	/* 1KB */
#define VAS_RX_FIFO_SIZE_MAX	(8 << 20)	/* 8MB */

/*
 * Co-processor Engine type.
 */
enum vas_cop_type {
	VAS_COP_TYPE_FAULT,
	VAS_COP_TYPE_842,
	VAS_COP_TYPE_842_HIPRI,
	VAS_COP_TYPE_GZIP,
	VAS_COP_TYPE_GZIP_HIPRI,
	VAS_COP_TYPE_MAX,
};

/*
 * Receive window attributes specified by the (in-kernel) owner of window.
 */
struct vas_rx_win_attr {
	void *rx_fifo;
	int rx_fifo_size;
	int wcreds_max;

	bool pin_win;
	bool rej_no_credit;
	bool tx_wcred_mode;
	bool rx_wcred_mode;
	bool tx_win_ord_mode;
	bool rx_win_ord_mode;
	bool data_stamp;
	bool nx_win;
	bool fault_win;
	bool notify_disable;
	bool intr_disable;
	bool notify_early;

	int lnotify_lpid;
	int lnotify_pid;
	int lnotify_tid;
	int pswid;

	int tc_mode;
};

/*
 * Window attributes specified by the in-kernel owner of a send window.
 */
struct vas_tx_win_attr {
	enum vas_cop_type cop;
	int wcreds_max;
	int lpid;
	int pidr;		/* hardware PID (from SPRN_PID) */
	int pid;		/* linux process id */
	int pswid;
	int rsvd_txbuf_count;
	int tc_mode;

	bool user_win;
	bool pin_win;
	bool rej_no_credit;
	bool rsvd_txbuf_enable;
	bool tx_wcred_mode;
	bool rx_wcred_mode;
	bool tx_win_ord_mode;
	bool rx_win_ord_mode;
};

/*
 * Helper to initialize receive window attributes to defaults for an
 * NX window.
 */
extern void vas_init_rx_win_attr(struct vas_rx_win_attr *rxattr,
				enum vas_cop_type cop);

/*
 * Open a VAS receive window for the instance of VAS identified by @vasid
 * Use @attr to initialize the attributes of the window.
 *
 * Return a handle to the window or ERR_PTR() on error.
 */
extern struct vas_window *vas_rx_win_open(int vasid, enum vas_cop_type cop,
			struct vas_rx_win_attr *attr);

/*
 * Helper to initialize send window attributes to defaults for an NX window.
 */
extern void vas_init_tx_win_attr(struct vas_tx_win_attr *txattr,
			enum vas_cop_type cop);

/*
 * Open a VAS send window for the instance of VAS identified by @vasid
 * and the co-processor type @cop. Use @attr to initialize attributes
 * of the window.
 *
 * Note: The instance of VAS must already have an open receive window for
 * the coprocessor type @cop.
 *
 * Return a handle to the send window or ERR_PTR() on error.
 */
struct vas_window *vas_tx_win_open(int vasid, enum vas_cop_type cop,
			struct vas_tx_win_attr *attr);

/*
 * Close the send or receive window identified by @win. For receive windows
 * return -EAGAIN if there are active send windows attached to this receive
 * window.
 */
int vas_win_close(struct vas_window *win);

#endif /* _MISC_VAS_H */
