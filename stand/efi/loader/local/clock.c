/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * clock.c -- RTC and cycle counter, stamped at entry and on demand (clock.h).
 */

#include <stand.h>
#include <string.h>

#include <efi.h>
#include <efilib.h>

#include "clock.h"

static struct stamp entry;
static uint64_t tsc_per_ms;
static bool rtc_ok;
static bool started;

static uint64_t
rdtsc_now(void)
{
#if defined(__amd64__) || defined(__i386__)
	return (__builtin_ia32_rdtsc());
#else
	return (0);
#endif
}

/* days from civil, Howard Hinnant's algorithm; valid for years >= 1970 */
static uint64_t
days_from_civil(unsigned int y, unsigned int m, unsigned int d)
{
	unsigned int era, yoe, doy, doe;

	y -= m <= 2;
	era = y / 400;
	yoe = y - era * 400;
	doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
	doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return ((uint64_t)era * 146097 + doe - 719468);
}

static bool
rtc_read(struct stamp *s)
{
	EFI_TIME t;
	EFI_STATUS st;

	s->epoch = 0;
	s->nsec = 0;
	if (RS == NULL)
		return (false);
	st = RS->GetTime(&t, NULL);
	if (EFI_ERROR(st) || t.Year < 1970 || t.Month < 1 || t.Month > 12 ||
	    t.Day < 1 || t.Day > 31)
		return (false);
	s->epoch = days_from_civil(t.Year, t.Month, t.Day) * 86400ULL +
	    (uint64_t)t.Hour * 3600 + (uint64_t)t.Minute * 60 + t.Second;
	s->nsec = t.Nanosecond;
	return (true);
}

/*
 * Calibrate: cycles across a 10 ms Stall. Firmware Stall is microsecond
 * timer based; a few percent error is irrelevant for windows of seconds.
 */
void
clock_start(void)
{
	uint64_t a, b;

	if (started)
		return;
	started = true;
	rtc_ok = rtc_read(&entry);
	entry.tsc = rdtsc_now();
	if (BS != NULL) {
		a = rdtsc_now();
		BS->Stall(10000);
		b = rdtsc_now();
		if (b > a)
			tsc_per_ms = (b - a) / 10;
	}
	if (tsc_per_ms == 0)
		tsc_per_ms = 1;
}

void
clock_now(struct stamp *s)
{
	if (!started)
		clock_start();
	(void)rtc_read(s);
	s->tsc = rdtsc_now();
}

const struct stamp *
clock_entry(void)
{
	if (!started)
		clock_start();
	return (&entry);
}

uint64_t
clock_ms_between(const struct stamp *from, const struct stamp *to)
{
	if (to->tsc <= from->tsc)
		return (0);
	return ((to->tsc - from->tsc) / tsc_per_ms);
}

uint64_t
clock_ms_since_entry(void)
{
	struct stamp now;

	clock_now(&now);
	return (clock_ms_between(&entry, &now));
}

uint64_t
clock_tsc_per_ms(void)
{
	if (!started)
		clock_start();
	return (tsc_per_ms);
}

bool
clock_rtc_ok(void)
{
	if (!started)
		clock_start();
	return (rtc_ok);
}

/* civil from days, the inverse of days_from_civil */
static void
civil_from_days(uint64_t z, unsigned int *y, unsigned int *m, unsigned int *d)
{
	uint64_t era, doe, yoe, doy, mp;

	z += 719468;
	era = z / 146097;
	doe = z - era * 146097;
	yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	mp = (5 * doy + 2) / 153;
	*d = doy - (153 * mp + 2) / 5 + 1;
	*m = mp < 10 ? mp + 3 : mp - 9;
	*y = yoe + era * 400 + (*m <= 2);
}

void
clock_calendar(const struct stamp *s, unsigned int *hour, unsigned int *minute,
    char *iso, size_t isosz)
{
	unsigned int y, m, d, hh, mm, ss;
	uint64_t days, rem;

	days = s->epoch / 86400;
	rem = s->epoch % 86400;
	hh = rem / 3600;
	mm = (rem % 3600) / 60;
	ss = rem % 60;
	civil_from_days(days, &y, &m, &d);
	if (hour != NULL)
		*hour = hh;
	if (minute != NULL)
		*minute = mm;
	if (iso != NULL && isosz > 0) {
		if (s->epoch == 0)
			(void)strlcpy(iso, "unknown", isosz);
		else
			snprintf(iso, isosz, "%04u-%02u-%02uT%02u:%02u:%02u",
			    y, m, d, hh, mm, ss);
	}
}
