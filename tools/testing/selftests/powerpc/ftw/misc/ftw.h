/*
 * Copyright 2018 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _UAPI_MISC_FTW_H
#define _UAPI_MISC_FTW_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define FTW_FLAGS_PIN_WINDOW	0x1

/*
 * Note: The range 0x20-27 for letter 'v' are reserved for FTW ioctls in
 *	 Documentation/ioctl/ioctl-number.txt.
 */
#define FTW_SETUP		_IOW('v', 0x20, struct ftw_setup_attr)

struct ftw_setup_attr {
	__s16	version;
	__s16	vas_id;		/* specific instance of vas or -1 for default */
	__u32	reserved;

	__u64	reserved1;

	__u64	flags;
	__u64	reserved2;
};

#endif /* _UAPI_MISC_FTW_H */
