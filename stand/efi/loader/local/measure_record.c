/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * measure_record.c -- the boot record and its anchors as measurements
 * (measurement.h): record validity, counter step across TPM and NVMe, the
 * chain link on the medium, the gap since the last boot, the hour of day,
 * TPM presence and PCR bank, NVMe presence. B1 (Zeitanker): the unpowered
 * gap, the order of the clocks, the SMART step across the shutdown, the
 * machine-local anchor, the medium switch, the unsafe-shutdown step.
 *
 * Assumption of the threat model (Konzepte/zeitanker-lagerung.md): wall
 * time is the RTC, which anyone with the setup can set; the TPM clock and
 * the NVMe counters only ever grow. Nothing here can GUARANTEE that a
 * long storage is noticed -- what it guarantees is that a forged RTC has
 * to agree with two clocks the attacker cannot turn back.
 */

#include <stand.h>
#include <string.h>
#include <stdint.h>

#include <efi.h>

#include "measurement.h"
#include "clock.h"
#include "record.h"
#include "tpm.h"
#include "tpm_keyfile.h"
#include "geli_keys.h"
#include "geli_open.h"
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
	const char *sel = getenv("loader.trust.pcr.require");
	uint32_t mask = 0xff;			/* PCR 0..7 unless the leaf selects */

	if (sel != NULL && !tpm_parse_pcrs(sel, &mask))
		return (m);			/* a leaf that does not parse: absent */
	if (tpm_pcr_bank(mask, m.value.digest))
		m.present = true;
	return (m);
}

/*
 * HaltQuiet: sha256 over the 8-byte NV counter loader.trust.halt.nv --
 * the index earlboot's shutdown_act raises before a halt it was bound to
 * fire (a duress answer, a probe). The expectation is a kenv leaf the
 * owner learns (halt.expected, from the published halt.sha256), NOT the
 * record: a record can be deleted by root, the index cannot be lowered by
 * anyone, and the stage keeps the reference. So the boot after a halt
 * fails this claim until the owner relearns at the workbench -- whatever
 * an attacker learned from the halt, the next boot says so (JB 18.09.).
 * Absent without the leaf.
 */
static uint64_t halt_count;
static bool halt_read;

struct measurement
measure_halt(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "HaltQuiet", .type = MEAS_SHA256 };
	const char *nv = getenv("loader.trust.halt.nv");
	unsigned long index;
	char *end;
	uint8_t raw[8];
	int i;
	SHA256_CTX ctx;

	if (nv == NULL)
		return (m);
	index = strtoul(nv, &end, 0);
	if (end == nv || *end != '\0' || index > 0xffffffffUL)
		return (m);
	if (!tpm_nv_index_read((uint32_t)index, &halt_count))
		return (m);
	halt_read = true;
	for (i = 0; i < 8; i++)
		raw[i] = (uint8_t)(halt_count >> (8 * (7 - i)));
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, raw, sizeof(raw));
	SHA256_Final(m.value.digest, &ctx);
	m.present = true;
	return (m);
}

/*
 * halt_count_raise: NV_Increment on loader.trust.halt.nv under the storage
 * key's salted session -- the trace of a halt the owner chooses at a
 * report (x); the same index earlboot raises before its shutdown. Without
 * the leafs, or with a TPM that refuses: false, nothing raised.
 */
bool
halt_count_raise(void)
{
	const char *nv = getenv("loader.trust.halt.nv");
	const char *kh = getenv("loader.trust.tpm.key.handle");
	unsigned long index, key;
	char *end;

	if (nv == NULL || kh == NULL)
		return (false);
	index = strtoul(nv, &end, 0);
	if (end == nv || *end != '\0' || index > 0xffffffffUL)
		return (false);
	key = strtoul(kh, &end, 0);
	if (end == kh || *end != '\0' || key > 0xffffffffUL)
		return (false);
	return (tpm_nv_policy_increment((uint32_t)key, (uint32_t)index));
}

void
diagnose_halt(int argc __unused, CHAR16 *argv[] __unused, struct diagnosis *d)
{
	d->leaf = "halt.count";
	if (halt_read)
		snprintf(d->text, sizeof(d->text), "%llu", (unsigned long long)halt_count);
	else
		snprintf(d->text, sizeof(d->text), "unread (%s)", tpm_last_error());
}

/*
 * GeliSlot: 1 iff the disk opened through the slot of key files alone
 * (slot 0: the medium's file + the TPM's), 0 through a passphrase slot --
 * the recovery passphrase, slot 1. A recovery boot is legitimate and
 * rare; it must be loud, not silent (JB 19.09.). Absent until the dialog
 * opened a provider.
 */
struct measurement
measure_geli_slot(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "GeliSlot", .type = MEAS_BYTE };

	if (!geli_open_done())
		return (m);
	m.present = true;
	m.value.byte = geli_keys_files_slot() ? 1 : 0;
	return (m);
}

void
diagnose_geli_slot(int argc __unused, CHAR16 *argv[] __unused, struct diagnosis *d)
{
	d->leaf = "geli.slot";
	snprintf(d->text, sizeof(d->text), "%s",
	    !geli_open_done() ? "closed" : geli_keys_files_slot() ? "keyfiles" : "passphrase");
}

struct measurement
measure_tpm_keyfile(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "TpmKeyfile", .type = MEAS_BYTE };
	const struct tpm_keyfile_state *s = tpm_keyfile_state();

	if (!s->configured)
		return (m);
	m.present = true;
	m.value.byte = (s->unsealed && s->added == s->providers) ? 1 : 0;
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


/* ============================ B1: the time anchors ============================ */

/* A gate leaf as an unsigned number; false without it (the claim skips). */
static bool
leaf_u64(const char *name, uint64_t *out)
{
	const char *v = getenv(name);
	unsigned long long x;
	char *end;

	if (v == NULL)
		return (false);
	x = strtoull(v, &end, 0);
	if (end == v || *end != '\0')
		return (false);
	*out = x;
	return (true);
}

/*
 * The unpowered time since the last boot: the RTC advanced by rtc_diff,
 * the TPM clock (running only under power) by tpm_diff; the difference is
 * the time the machine spent without power. 1 iff at most N days
 * (loader.trust.storage.gap.max.days). Absent without a valid
 * record, a readable RTC and TPM, or the leaf; absent, too, when the RTC
 * lies BEHIND the record -- that is LastBootGap's finding, not this one's.
 */
static bool
storage_gap(uint64_t *gap_s, uint64_t *rtc_diff, uint64_t *tpm_diff)
{
	const struct record_state *rs = record_state();
	struct tpm_clock tc;
	struct stamp now;

	if (!rs->valid || !clock_rtc_ok() || !tpm_read_clock(&tc))
		return (false);
	clock_now(&now);
	if (now.epoch == 0 || now.epoch < rs->prev.boot_epoch ||
	    tc.clock < rs->prev.tpm_clock)
		return (false);
	*rtc_diff = now.epoch - rs->prev.boot_epoch;
	*tpm_diff = (tc.clock - rs->prev.tpm_clock) / 1000;
	*gap_s = *rtc_diff > *tpm_diff ? *rtc_diff - *tpm_diff : 0;
	return (true);
}

struct measurement
measure_storage_gap(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "StorageGap", .type = MEAS_BYTE };
	uint64_t gap, rtc, tpm, days;

	if (!leaf_u64("loader.trust.storage.gap.max.days", &days))
		return (m);
	if (!storage_gap(&gap, &rtc, &tpm))
		return (m);
	m.present = true;
	m.value.byte = gap <= days * 86400 ? 1 : 0;
	return (m);
}

void
diagnose_storage_gap(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	uint64_t gap, rtc, tpm;

	d->leaf = "storage.gap";
	if (storage_gap(&gap, &rtc, &tpm))
		snprintf(d->text, sizeof(d->text), "gap.s=%llu,rtc.diff.s=%llu,tpm.diff.s=%llu",
		    (unsigned long long)gap, (unsigned long long)rtc,
		    (unsigned long long)tpm);
	else
		(void)strlcpy(d->text, "unknown", sizeof(d->text));
}

/*
 * The clocks in order: a forged RTC must still have advanced at least as
 * far as the TPM clock and as the NVMe's power-on hours, both of which
 * only grow under power (skew: loader.trust.clock.skew.s).
 * 1 iff rtc_diff + skew >= tpm_diff and rtc_diff + skew >= hours_diff.
 */
static bool
clock_order(uint64_t *rtc_diff, uint64_t *tpm_diff, uint64_t *hours_diff_s)
{
	const struct record_state *rs = record_state();
	struct nvme_smart ns;
	uint64_t gap;

	if (!storage_gap(&gap, rtc_diff, tpm_diff))
		return (false);
	*hours_diff_s = 0;
	if (nvme_smart(&ns) && ns.power_on_hours >= rs->prev.nvme_hours)
		*hours_diff_s = (ns.power_on_hours - rs->prev.nvme_hours) * 3600;
	return (true);
}

struct measurement
measure_clock_order(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "ClockOrder", .type = MEAS_BYTE };
	uint64_t rtc, tpm, hours, skew;

	if (!leaf_u64("loader.trust.clock.skew.s", &skew))
		return (m);
	if (!clock_order(&rtc, &tpm, &hours))
		return (m);
	m.present = true;
	m.value.byte = (rtc + skew >= tpm && rtc + skew >= hours) ? 1 : 0;
	return (m);
}

void
diagnose_clock_order(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	uint64_t rtc, tpm, hours;

	d->leaf = "clock.order";
	if (clock_order(&rtc, &tpm, &hours))
		snprintf(d->text, sizeof(d->text), "rtc.diff.s=%llu,tpm.diff.s=%llu,nvme.hours.diff.s=%llu",
		    (unsigned long long)rtc, (unsigned long long)tpm,
		    (unsigned long long)hours);
	else
		(void)strlcpy(d->text, "unknown", sizeof(d->text));
}

/*
 * The step across the shutdown: what elvbootd left in the shutdown index
 * (power-on hours, data units read/written) against the NVMe now. Between
 * a clean shutdown and this boot the disks were powered for the boot
 * only: hours differ by at most 1, the units by at most
 * loader.trust.smart.step.units.max. A clone of the disks in
 * the owner's absence reads terabytes. Absent without a valid shutdown
 * index (first boot, a crash: BootMarker and UnsafeStep say so).
 */
static bool
smart_step(uint64_t *hours_diff, uint64_t *read_diff, uint64_t *written_diff)
{
	const struct anchor_state *sd = record_shutdown_state();
	struct nvme_smart ns;

	if (!sd->valid || !nvme_smart(&ns))
		return (false);
	*hours_diff = ns.power_on_hours >= sd->body.a ? ns.power_on_hours - sd->body.a : UINT64_MAX;
	*read_diff = ns.data_units_read >= sd->body.b ? ns.data_units_read - sd->body.b : UINT64_MAX;
	*written_diff = ns.data_units_written >= sd->body.c ? ns.data_units_written - sd->body.c : UINT64_MAX;
	return (true);
}

struct measurement
measure_smart_step(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "SmartStep", .type = MEAS_BYTE };
	uint64_t h, r, w, max;

	if (!leaf_u64("loader.trust.smart.step.units.max", &max))
		return (m);
	if (!smart_step(&h, &r, &w))
		return (m);
	m.present = true;
	m.value.byte = (h <= 1 && r <= max && w <= max) ? 1 : 0;
	return (m);
}

void
diagnose_smart_step(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	const struct anchor_state *sd = record_shutdown_state();
	uint64_t h, r, w;

	d->leaf = "smart.step";
	if (smart_step(&h, &r, &w))
		snprintf(d->text, sizeof(d->text), "hours.diff=%llu,units.read.diff=%llu,units.written.diff=%llu,medium=%c",
		    (unsigned long long)h, (unsigned long long)r,
		    (unsigned long long)w, sd->body.medium != 0 ? sd->body.medium : '-');
	else
		snprintf(d->text, sizeof(d->text), "%s", !sd->present ? "no shutdown index" :
		    !sd->valid ? "shutdown index unverified" : "nvme unread");
}

/*
 * The machine-local anchor: present, its tag under this boot's record
 * material, and equal to the previous record's pair. A card that carries
 * a record this TPM never saw -- a clone from another day, a rewritten
 * medium -- fails here even when its own chain is intact.
 */
struct measurement
measure_anchor_valid(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "AnchorValid", .type = MEAS_BYTE };
	const struct anchor_state *a = record_anchor_state();
	const struct record_state *rs = record_state();

	if (!rs->valid || getenv("loader.trust.tpm.anchor.nv") == NULL)
		return (m);
	if (!a->present && rs->prev.counter <= 1)
		return (m);		/* the first boot after the leaf arrived: nothing to compare */
	m.present = true;
	m.value.byte = (a->valid && a->matches) ? 1 : 0;
	return (m);
}

void
diagnose_anchor_valid(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	const struct anchor_state *a = record_anchor_state();

	d->leaf = "anchor";
	if (!a->present)
		(void)strlcpy(d->text, "absent", sizeof(d->text));
	else
		snprintf(d->text, sizeof(d->text), "%s,%s,counter=%llu,medium=%c",
		    a->valid ? "verified" : "unverified",
		    a->matches ? "matches" : "differs",
		    (unsigned long long)a->body.c,
		    a->body.medium != 0 ? a->body.medium : '-');
}

/*
 * The medium switch: the letter stamped on this medium against the letter
 * the anchor recorded as last booted. 1 iff equal. The owner rotates the
 * cards himself: a switch is a tell, never a prompt (gate tellwatch).
 */
struct measurement
measure_medium_switch(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "MediumSwitch", .type = MEAS_BYTE };
	const struct anchor_state *a = record_anchor_state();
	uint8_t now = record_medium_letter();

	if (now == 0 || !a->valid || a->body.medium == 0)
		return (m);
	m.present = true;
	m.value.byte = a->body.medium == now ? 1 : 0;
	return (m);
}

void
diagnose_medium_switch(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	const struct anchor_state *a = record_anchor_state();
	uint8_t now = record_medium_letter();

	d->leaf = "medium";
	snprintf(d->text, sizeof(d->text), "now=%c,last=%c",
	    now != 0 ? now : '-', a->valid && a->body.medium != 0 ? a->body.medium : '-');
}

/*
 * The unsafe-shutdown step: the NVMe's own count of power losses without
 * a shutdown notification, against the record. 1 iff unchanged. With
 * BootMarker it tells three stories apart: marker missing and count up =
 * power lost while running; marker missing, count same = a crash or reset
 * before sync; marker present, count up = the disk saw a power loss the
 * system never saw.
 */
struct measurement
measure_unsafe_step(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "UnsafeStep", .type = MEAS_BYTE };
	const struct record_state *rs = record_state();
	struct nvme_smart ns;

	if (!rs->valid || !nvme_smart(&ns))
		return (m);
	m.present = true;
	m.value.byte = ns.unsafe_shutdowns == rs->prev.nvme_unsafe ? 1 : 0;
	return (m);
}

void
diagnose_unsafe_step(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	const struct record_state *rs = record_state();
	struct nvme_smart ns;

	d->leaf = "unsafe";
	if (rs->valid && nvme_smart(&ns))
		snprintf(d->text, sizeof(d->text), "%llu/%llu",
		    (unsigned long long)ns.unsafe_shutdowns,
		    (unsigned long long)rs->prev.nvme_unsafe);
	else
		(void)strlcpy(d->text, "unknown", sizeof(d->text));
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
	    "geli=%s,counter=%llu,last=%s,bootms=%llu,flags=%u,chain=%s,medium=%c", fp,
	    (unsigned long long)rs->prev.counter, iso,
	    (unsigned long long)rs->prev.boot_ms,
	    (unsigned int)(rs->prev.flags & ~RECORD_F_DURESS),	/* the duress bit stays in the word (illyria 17.09.: flags=7 in kenv) */
	    rs->medium_answered ? (rs->chain_on_medium ? "match" : "differs") :
	    "unread", rs->prev.medium != 0 ? rs->prev.medium : '-');
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
diagnose_tpm_keyfile(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	const struct tpm_keyfile_state *s = tpm_keyfile_state();

	d->leaf = "tpm.keyfile";
	snprintf(d->text, sizeof(d->text), "unsealed=%u,providers=%u,added=%u,key=%s,%s",
	    s->unsealed ? 1 : 0, s->providers, s->added,
	    s->verified ? "verified" : "unverified",
	    s->reason != NULL ? s->reason : "not asked");
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
