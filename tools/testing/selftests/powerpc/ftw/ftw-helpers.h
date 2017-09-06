#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef STRINGIFY
#define STRINGIFY

/*
 * From arch/powerpc/include/asm/asm-compat.h
 */
#define __stringify_in_c(...) #__VA_ARGS__
#define stringify_in_c(...)   __stringify_in_c(__VA_ARGS__) " "

#endif


#define ERRMSG	strerror(errno)

//typedef unsigned long long u64;

#define __NR_gettid     207     /* powerpc */
static inline int gettid(void)
{
        return syscall(__NR_gettid);
}

/*
 * 1_1110 = 30d
 * From Power ISA 3.0 document, pages 1229 and 907.
 *	0111_1100  0wc0_0000  0000_0000  0011_1100
 *   0x   7    C    0    0     0    0     3    C
 *	where wc == 0b00 (only valid value) and 0b01:11 are reserved
 *	0x7C00003C
 */
#define WAIT	.long (0x7C00003C)

static inline int do_wait(void)
{
	__asm__ __volatile(stringify_in_c(WAIT)";");
}

/*
 * Check if paste_done is true
 */
static bool is_paste_done(bool *paste_donep)
{
	//return __sync_bool_compare_and_swap(paste_donep, 1, 0);
	__sync_synchronize();
	return *paste_donep;

}

/*
 * Set paste_done to true
 */
static inline void set_paste_done(bool *paste_donep)
{
	__sync_bool_compare_and_swap(paste_donep, 0, 1);
}

struct ftw_win {
	int 		fd;
	void		*paste_addr;
	int		map_size;
};

extern int ftw_setup_rxwin(char *msg, struct ftw_win *ftwin);
extern int ftw_setup_txwin(char *msg, struct ftw_win *ftwin);
extern void ftw_close_win(char *msg, struct ftw_win *ftwin);
extern int write_empty_crb(void *paste_addr, char *msg);
