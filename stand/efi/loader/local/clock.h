/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * clock.h -- the two clocks of a boot, and the stamps taken along the way.
 *
 * The RTC (EFI GetTime) says WHEN; the cycle counter (rdtsc) says HOW LONG,
 * monotonically and independent of anything a person can set in Setup. The
 * pair is the witness: a set-back RTC does not move the TSC. The TSC rate is
 * calibrated once at entry against BS->Stall, good to a few percent -- ample
 * for windows measured in seconds.
 *
 * clock_start() runs first thing in efi_main (before the heap exists it
 * needs nothing but the tables); the loader publishes nothing here -- the
 * providers in measure_time.c read the stamps.
 *
 * Not a catalog: internal to the local layer.
 */

#ifndef _LOCAL_CLOCK_H_
#define	_LOCAL_CLOCK_H_

#include <stdint.h>
#include <stdbool.h>

struct stamp {
	uint64_t	epoch;		/* RTC as seconds since 1970, 0 if unknown */
	uint32_t	nsec;		/* RTC nanosecond field (firmware-dependent) */
	uint64_t	tsc;		/* cycle counter */
};

void	clock_start(void);		/* the entry stamp; calibrates the TSC */
void	clock_now(struct stamp *);
const struct stamp *clock_entry(void);

uint64_t	clock_ms_between(const struct stamp *from, const struct stamp *to);
uint64_t	clock_ms_since_entry(void);
uint64_t	clock_tsc_per_ms(void);
bool		clock_rtc_ok(void);	/* GetTime answered at entry */

/* RTC calendar of a stamp, for diagnostics and the hour window */
void	clock_calendar(const struct stamp *, unsigned int *hour,
	    unsigned int *minute, char *iso, size_t isosz);

#endif /* _LOCAL_CLOCK_H_ */
