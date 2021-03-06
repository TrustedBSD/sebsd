/*-
 * Kernel interface to machine-dependent clock driver.
 * Garrett Wollman, September 1994.
 * This file is in the public domain.
 *
 * $FreeBSD: src/sys/amd64/include/clock.h,v 1.51 2005/12/22 22:16:05 jhb Exp $
 */

#ifndef _MACHINE_CLOCK_H_
#define	_MACHINE_CLOCK_H_

#ifdef _KERNEL
/*
 * i386 to clock driver interface.
 * XXX large parts of the driver and its interface are misplaced.
 */
extern int	adjkerntz;
extern int	clkintr_pending;
extern int	disable_rtc_set;
extern int	pscnt;
extern int	psdiv;
extern int	statclock_disable;
extern u_int	timer_freq;
extern int	timer0_max_count;
extern uint64_t	tsc_freq;
extern int	tsc_is_broken;
extern int	wall_cmos_clock;

/*
 * Driver to clock driver interface.
 */

int	acquire_timer2(int mode);
int	release_timer2(void);
int	rtcin(int val);
int	sysbeep(int pitch, int period);
void	init_TSC(void);
void	init_TSC_tc(void);

#endif /* _KERNEL */

#endif /* !_MACHINE_CLOCK_H_ */
