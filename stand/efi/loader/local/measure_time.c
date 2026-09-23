/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * measure_time.c -- the time providers (measurement.h): boot duration,
 * prompt dwell, RTC-against-TSC consistency, attempts. Windows are site.mk
 * baselines; a missing window makes the provider measure "absent", which
 * an armed claim reports.
 */

#include <stand.h>
#include <string.h>

#include <efi.h>

#include "measurement.h"
#include "clock.h"
#include "evidence.h"
#include "record.h"		/* record_answer_retries */

#ifdef LOADER_TRUST_TIME_BOOT_MAX_MS
struct measurement
measure_time_boot(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "BootWindow", .type = MEAS_BYTE,
	    .present = true };

	m.value.byte = clock_ms_since_entry() <= (uint64_t)LOADER_TRUST_TIME_BOOT_MAX_MS;
	return (m);
}
#else
struct measurement
measure_time_boot(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "BootWindow", .type = MEAS_BYTE };

	return (m);
}
#endif

#if defined(LOADER_TRUST_TIME_PROMPT_MIN_MS) && defined(LOADER_TRUST_TIME_PROMPT_MAX_MS)
struct measurement
measure_time_prompt(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "PromptWindow", .type = MEAS_BYTE,
	    .present = true };
	uint64_t ms = evidence()->prompt_ms;

	m.value.byte = ms >= (uint64_t)LOADER_TRUST_TIME_PROMPT_MIN_MS &&
	    ms <= (uint64_t)LOADER_TRUST_TIME_PROMPT_MAX_MS;
	return (m);
}
#else
struct measurement
measure_time_prompt(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "PromptWindow", .type = MEAS_BYTE };

	return (m);
}
#endif

#ifndef LOADER_TRUST_TIME_SKEW_MS
#define	LOADER_TRUST_TIME_SKEW_MS	2000
#endif

/*
 * RTC delta (seconds, from the two GetTime calls) against the TSC delta
 * since entry. Present iff both clocks answered at entry and now.
 */
struct measurement
measure_time_rtc_tsc(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "ClockAgree", .type = MEAS_BYTE };
	const struct stamp *e = clock_entry();
	struct stamp now;
	uint64_t rtc_ms, tsc_ms, diff;

	if (!clock_rtc_ok())
		return (m);
	clock_now(&now);
	if (now.epoch == 0 || now.epoch < e->epoch)
		return (m);
	rtc_ms = (now.epoch - e->epoch) * 1000;
	tsc_ms = clock_ms_between(e, &now);
	diff = rtc_ms > tsc_ms ? rtc_ms - tsc_ms : tsc_ms - rtc_ms;
	m.present = true;
	/* the RTC only has second resolution: allow one second of rounding */
	m.value.byte = diff <= (uint64_t)LOADER_TRUST_TIME_SKEW_MS + 1000;
	return (m);
}

/*
 * Attempts: the hidden lines typed that the boot did NOT
 * ask for -- all attempts minus the two the boot always takes (the
 * passphrase, the boot answer), minus one per interactive gate action
 * (an unlock counts as the boot's, not the owner's fault), minus the one
 * retry of the boot answer that record_load may ask for. 0 iff nothing
 * was typed twice: expectation 0.
 */
struct measurement
measure_attempts(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "Attempts", .type = MEAS_BYTE,
	    .present = true };
	const struct evidence *e = evidence();
	unsigned int n = e->attempts, owed = 2 + e->prompted + record_answer_retries();

	n = n > owed ? n - owed : 0;
	m.value.byte = n > 255 ? 255 : n;
	return (m);
}

/* --- diagnostics: the raw numbers behind the verdict bytes --- */

void
diagnose_time_boot(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	d->leaf = "time.boot.ms";
	snprintf(d->text, sizeof(d->text), "%llu",
	    (unsigned long long)clock_ms_since_entry());
}

void
diagnose_time_prompt(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	const struct evidence *e = evidence();

	d->leaf = "time.prompt";
	snprintf(d->text, sizeof(d->text), "dwell=%llu,cadence=%llu,attempts=%u,prompted=%u,retry=%u",
	    (unsigned long long)e->prompt_ms, (unsigned long long)e->cadence_ms,
	    e->attempts, e->prompted, record_answer_retries());
}

void
diagnose_time_rtc_tsc(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	const struct stamp *e = clock_entry();
	struct stamp now;
	char iso[32];

	clock_now(&now);
	clock_calendar(&now, NULL, NULL, iso, sizeof(iso));
	d->leaf = "time.now";
	snprintf(d->text, sizeof(d->text), "%s,rtc=%llu,tsc=%llu,tscpms=%llu",
	    iso, (unsigned long long)(now.epoch - e->epoch),
	    (unsigned long long)clock_ms_between(e, &now),
	    (unsigned long long)clock_tsc_per_ms());
}
