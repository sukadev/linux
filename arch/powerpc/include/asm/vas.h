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

#endif /* _MISC_VAS_H */
