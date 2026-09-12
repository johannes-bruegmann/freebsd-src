/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * measure_record.c -- the boot record and its anchors as measurements
 * (measurement.h): record validity, counter step across TPM and NVMe, the
 * chain link on the medium, the gap since the last boot, the hour of day,
 * TPM presence and PCR bank, NVMe presence.
 */

#include <stand.h>
#include <string.h>

#include <efi.h>

#include "measurement.h"
#include "clock.h"
#include "record.h"
#include "tpm.h"
#include "nvme.h"

struct measurement
measure_record(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "RecordValid", .type = MEAS_BYTE };
	const struct record_state *rs = record_state();

	if (!record_secret_present())
		return (m);
	m.present = true;
	m.value.byte = rs->valid ? 1 : 0;
	return (m);
}

/*
 * Every anchor that answers must have advanced by exactly one since the
 * record: TPM resetCount (a power cycle = a boot), NVMe power cycles. The
 * loader's own NV counter is incremented at commit, so at measurement time
 * it must still EQUAL the recorded value. Present iff the record is valid
 * and at least one anchor answered.
 */
struct measurement
measure_counter_step(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "CounterStep", .type = MEAS_BYTE };
	const struct record_state *rs = record_state();
	struct tpm_clock tc;
	struct nvme_smart ns;
	uint64_t nv;
	bool any = false, ok = true;

	if (!rs->valid)
		return (m);
	if (tpm_read_clock(&tc)) {
		any = true;
		if ((uint64_t)tc.reset_count != rs->prev.tpm_reset + 1)
			ok = false;
		if (tc.clock < rs->prev.tpm_clock)
			ok = false;
		if (tpm_nv_counter_read(&nv) && nv != rs->prev.tpm_nvcount)
			ok = false;
	}
	if (nvme_smart(&ns)) {
		any = true;
		if (ns.power_cycles != rs->prev.nvme_cycles + 1)
			ok = false;
	}
	if (!any)
		return (m);
	m.present = true;
	m.value.byte = ok ? 1 : 0;
	return (m);
}

struct measurement
measure_chain(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "ChainOnMedium", .type = MEAS_BYTE };
	const struct record_state *rs = record_state();

	if (!rs->valid || !rs->medium_answered)
		return (m);
	m.present = true;
	m.value.byte = rs->chain_on_medium ? 1 : 0;
	return (m);
}

#ifndef LOADER_TRUST_TIME_GAP_MIN_S
#define	LOADER_TRUST_TIME_GAP_MIN_S	0
#endif

struct measurement
measure_lastboot_gap(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "LastBootGap", .type = MEAS_BYTE };
	const struct record_state *rs = record_state();
	struct stamp now;

	if (!rs->valid || !clock_rtc_ok())
		return (m);
	clock_now(&now);
	if (now.epoch == 0)
		return (m);
	m.present = true;
	m.value.byte = now.epoch >= rs->prev.boot_epoch &&
	    now.epoch - rs->prev.boot_epoch >= (uint64_t)LOADER_TRUST_TIME_GAP_MIN_S;
	return (m);
}

#if defined(LOADER_TRUST_TIME_HOUR_MIN) && defined(LOADER_TRUST_TIME_HOUR_MAX)
struct measurement
measure_time_of_day(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "HourWindow", .type = MEAS_BYTE };
	struct stamp now;
	unsigned int h;

	if (!clock_rtc_ok())
		return (m);
	clock_now(&now);
	if (now.epoch == 0)
		return (m);
	clock_calendar(&now, &h, NULL, NULL, 0);
	m.present = true;
	m.value.byte = h >= LOADER_TRUST_TIME_HOUR_MIN && h <= LOADER_TRUST_TIME_HOUR_MAX;
	return (m);
}
#else
struct measurement
measure_time_of_day(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "HourWindow", .type = MEAS_BYTE };

	return (m);
}
#endif

struct measurement
measure_tpm(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "TpmPresent", .type = MEAS_BYTE,
	    .present = true };

	m.value.byte = tpm_present() ? 1 : 0;
	return (m);
}

struct measurement
measure_pcr(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "PcrBank", .type = MEAS_SHA256 };

	if (tpm_pcr_bank(m.value.digest))
		m.present = true;
	return (m);
}

struct measurement
measure_nvme(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "NvmePresent", .type = MEAS_BYTE,
	    .present = true };
	struct nvme_smart ns;

	m.value.byte = nvme_smart(&ns) ? 1 : 0;
	return (m);
}

/* --- diagnostics --- */

void
diagnose_record(int argc __unused, CHAR16 *argv[] __unused, struct diagnosis *d)
{
	const struct record_state *rs = record_state();
	struct stamp s;
	char iso[32];

	char fp[9];

	d->leaf = "record";
	record_geli_fingerprint(fp);
	if (!rs->valid) {
		if (rs->present)
			snprintf(d->text, sizeof(d->text),
			    "present,invalid (geli=%s)", fp);
		else
			snprintf(d->text, sizeof(d->text), "absent (%s)",
			    record_reason());
		return;
	}
	s.epoch = rs->prev.boot_epoch;
	s.nsec = 0;
	s.tsc = 0;
	clock_calendar(&s, NULL, NULL, iso, sizeof(iso));
	snprintf(d->text, sizeof(d->text),
	    "geli=%s,counter=%llu,last=%s,bootms=%llu,flags=%u,chain=%s", fp,
	    (unsigned long long)rs->prev.counter, iso,
	    (unsigned long long)rs->prev.boot_ms, rs->prev.flags,
	    rs->medium_answered ? (rs->chain_on_medium ? "match" : "differs") :
	    "unread");
}

void
diagnose_counter_step(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	const struct record_state *rs = record_state();
	struct tpm_clock tc;
	struct nvme_smart ns;
	uint64_t nv = 0;
	char t[128], n[64];

	d->leaf = "anchors";
	if (tpm_read_clock(&tc)) {
		(void)tpm_nv_counter_read(&nv);
		/* now/previous each; the clock with the TPM's own safe flag */
		snprintf(t, sizeof(t),
		    "tpm.reset=%u/%llu,tpm.nv=%llu/%llu,tpm.clock=%llu/%llu,safe=%u",
		    tc.reset_count, (unsigned long long)rs->prev.tpm_reset,
		    (unsigned long long)nv, (unsigned long long)rs->prev.tpm_nvcount,
		    (unsigned long long)tc.clock,
		    (unsigned long long)rs->prev.tpm_clock, tc.safe ? 1 : 0);
	} else
		snprintf(t, sizeof(t), "tpm=none(%s)", tpm_last_error());
	if (nvme_smart(&ns))
		snprintf(n, sizeof(n), "nvme.cycles=%llu/%llu,unsafe=%llu",
		    (unsigned long long)ns.power_cycles,
		    (unsigned long long)rs->prev.nvme_cycles,
		    (unsigned long long)ns.unsafe_shutdowns);
	else
		snprintf(n, sizeof(n), "nvme=none");
	snprintf(d->text, sizeof(d->text), "%s,%s", t, n);
}

void
diagnose_lastboot_gap(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	const struct record_state *rs = record_state();
	struct stamp now;

	d->leaf = "lastboot.gap.s";
	clock_now(&now);
	if (!rs->valid || now.epoch == 0 || now.epoch < rs->prev.boot_epoch)
		(void)strlcpy(d->text, "unknown", sizeof(d->text));
	else
		snprintf(d->text, sizeof(d->text), "%llu",
		    (unsigned long long)(now.epoch - rs->prev.boot_epoch));
}

void
diagnose_tpm(int argc __unused, CHAR16 *argv[] __unused, struct diagnosis *d)
{
	struct tpm_clock tc;

	d->leaf = "tpm";
	if (tpm_read_clock(&tc))
		snprintf(d->text, sizeof(d->text),
		    "clock=%llu,reset=%u,restart=%u,safe=%u",
		    (unsigned long long)tc.clock, tc.reset_count,
		    tc.restart_count, tc.safe ? 1 : 0);
	else
		snprintf(d->text, sizeof(d->text), "none(%s)", tpm_last_error());
}

void
diagnose_nvme(int argc __unused, CHAR16 *argv[] __unused, struct diagnosis *d)
{
	struct nvme_smart ns;

	d->leaf = "nvme";
	if (nvme_smart(&ns))
		snprintf(d->text, sizeof(d->text),
		    "controllers=%u,cycles=%llu,hours=%llu,unsafe=%llu,written=%llu",
		    ns.controllers, (unsigned long long)ns.power_cycles,
		    (unsigned long long)ns.power_on_hours,
		    (unsigned long long)ns.unsafe_shutdowns,
		    (unsigned long long)ns.data_units_written);
	else
		(void)strlcpy(d->text, "none", sizeof(d->text));
}
