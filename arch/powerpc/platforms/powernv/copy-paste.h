/*
 * Copyright 2016 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

/*
 * Macros taken from tools/testing/selftests/powerpc/context_switch/cp_abort.c
 */
#define PASTE(RA, RB, L, RC) \
	.long (0x7c00070c | (RA) << (31-15) | (RB) << (31-20) \
			  | (L) << (31-10) | (RC) << (31-31))

#define COPY(RA, RB, L) \
	.long (0x7c00060c | (RA) << (31-15) | (RB) << (31-20) \
			  | (L) << (31-10))

#define CR0_FXM		"0x80"
#define CR0_SHIFT	28
#define CR0_MASK	0xF
/*
 * Copy/paste instructions:
 *
 *	copy RA,RB,L
 *		Copy contents of address (RA) + effective_address(RB)
 *		to internal copy-buffer.
 *
 *		L == 1 indicates this is the first copy.
 *
 *		L == 0 indicates its a continuation of a prior first copy.
 *
 *	paste RA,RB,L
 *		Paste contents of internal copy-buffer to the address
 *		(RA) + effective_address(RB)
 *
 *		L == 0 indicates its a continuation of a prior paste. i.e.
 *		don't wait for the completion or update status.
 *
 *		L == 1 indicates this is the last paste in the group (i.e.
 *		wait for the group to complete and update status in CR0).
 *
 *	For Power9, the L bit must be 'true' in both copy and paste.
 */

static inline int vas_copy(void *crb, int offset, int first)
{
	WARN_ON_ONCE(!first);

	__asm__ __volatile(stringify_in_c(COPY(%0, %1, %2))";"
		:
		: "b" (offset), "b" (crb), "i" (1)
		: "memory");

	return 0;
}

static inline int vas_paste(void *paste_address, int offset, int last)
{
	unsigned long long cr;

	WARN_ON_ONCE(!last);

	cr = 0;
	__asm__ __volatile(stringify_in_c(PASTE(%1, %2, 1, 1))";"
		"mfocrf %0," CR0_FXM ";"
		: "=r" (cr)
		: "b" (paste_address), "b" (offset)
		: "memory");

	return cr;
}
