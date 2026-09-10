/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * measure_kernel.c -- KERNEL-phase providers (measurement.h): the howto
 * flags the kernel will get, the guarded kenv variables, the preloaded
 * files against the manifest, libsecureboot's soft PCR, and the ledger.
 */

#include <stand.h>
#include <string.h>
#include <fcntl.h>
#include <sys/reboot.h>
#include <sys/boot.h>			/* boot_env_to_howto */

#include <efi.h>

#include <crypto/sha2/sha256.h>

#ifdef LOADER_VERIEXEC
#include <verify_file.h>
/* libsecureboot.h drags in bearssl.h, which the loader CFLAGS do not
 * reach; the one symbol used is declared here. */
ssize_t	ve_pcr_get(unsigned char *, size_t);
#endif

#include "bootstrap.h"			/* preloaded_files, boot_env_to_howto */
#include "measurement.h"
#include "claim.h"
#include "evidence.h"

/* --- howto --- */

#define	HOWTO_MASK	(RB_SINGLE | RB_KDB | RB_VERBOSE | RB_SERIAL | RB_MUTE | \
			 RB_GDB | RB_DFLTROOT | RB_ASKNAME)

static int
howto_now(void)
{
	const char *console;
	int howto;

	howto = boot_env_to_howto();
	console = getenv("console");
	if (console != NULL) {
		if (strcmp(console, "comconsole") == 0)
			howto |= RB_SERIAL;
		if (strcmp(console, "nullconsole") == 0)
			howto |= RB_MUTE;
	}
	return (howto & HOWTO_MASK);
}

struct measurement
measure_howto(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "BootHowto", .type = MEAS_BYTE,
	    .present = true };
	int h = howto_now();

	/* fold the flags into a byte: any set bit is a deviation from 0 */
	m.value.byte = h == 0 ? 0 : (uint8_t)((h & 0xff) | ((h >> 8) & 0xff) | 1);
	return (m);
}

void
diagnose_howto(int argc __unused, CHAR16 *argv[] __unused, struct diagnosis *d)
{
	int h = howto_now();

	d->leaf = "howto";
	snprintf(d->text, sizeof(d->text), "0x%x%s%s%s%s%s", h,
	    (h & RB_SINGLE) ? ",single" : "", (h & RB_KDB) ? ",kdb" : "",
	    (h & RB_VERBOSE) ? ",verbose" : "", (h & RB_SERIAL) ? ",serial" : "",
	    (h & RB_MUTE) ? ",mute" : "");
}

/* --- guarded kenv variables --- */

#ifndef LOADER_TRUST_KENV_GUARD
#define	LOADER_TRUST_KENV_GUARD	"vfs.root.mountfrom,vfs.root.mountfrom.options,init_path,init_shell,module_path,kernel,kernelname,loader_conf_files,init_script,init_chroot"
#endif

struct measurement
measure_kenv_guard(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "KenvGuard", .type = MEAS_SHA256 };
	const char *p = LOADER_TRUST_KENV_GUARD, *e, *v;
	char name[128];
	size_t n;
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	while (*p != '\0') {
		while (*p == ',' || *p == ' ')
			p++;
		if (*p == '\0')
			break;
		e = p;
		while (*e != '\0' && *e != ',' && *e != ' ')
			e++;
		n = (size_t)(e - p);
		if (n >= sizeof(name))
			n = sizeof(name) - 1;
		memcpy(name, p, n);
		name[n] = '\0';
		p = e;
		v = getenv(name);
		SHA256_Update(&ctx, name, n);
		SHA256_Update(&ctx, "=", 1);
		if (v != NULL)
			SHA256_Update(&ctx, v, strlen(v));
		SHA256_Update(&ctx, "\n", 1);
	}
	SHA256_Final(m.value.digest, &ctx);
	m.present = true;
	return (m);
}

/* --- preloaded files against the manifest --- */

/*
 * Provenance of the blobs the loader makes itself. file_addbuf() (module.c)
 * notes every buffer it turns into a preloaded "file": efi_rng_seed, the
 * platform entropy (main.c), and TSLOG, the timestamp log (boot.c). They
 * have no path and different contents every boot, so no manifest can name
 * them; what CAN be verified is that this loader made them. An entry that
 * is neither a manifest-verified file nor noted here is unverified -- and
 * so is everything past the table's capacity (the safe direction).
 */
#define	ADDBUF_MAX	8
static const struct preloaded_file *addbuf_made[ADDBUF_MAX];
static unsigned int addbuf_n;

void
local_note_addbuf(struct preloaded_file *fp)
{
	if (addbuf_n < ADDBUF_MAX)
		addbuf_made[addbuf_n++] = fp;
}

static bool
addbuf_made_here(const struct preloaded_file *fp)
{
	unsigned int i;

	for (i = 0; i < addbuf_n; i++)
		if (addbuf_made[i] == fp)
			return (true);
	return (false);
}

static unsigned int preload_total, preload_made, preload_bad;
static char preload_list[192];

static void
preload_walk(void)
{
	struct preloaded_file *fp;
#ifdef LOADER_VERIEXEC
	int fd, rc;
#endif

	preload_total = preload_made = preload_bad = 0;
	preload_list[0] = '\0';
	for (fp = preloaded_files; fp != NULL; fp = fp->f_next) {
		preload_total++;
		if (addbuf_made_here(fp)) {
			preload_made++;
			continue;
		}
#ifdef LOADER_VERIEXEC
		fd = open(fp->f_name, O_RDONLY);
		if (fd >= 0) {
			rc = verify_file(fd, fp->f_name, 0, VE_WANT, __func__);
			close(fd);
			if (rc == VE_VERIFIED)
				continue;
		}
#else
		continue;
#endif
		preload_bad++;
		if (preload_list[0] != '\0')
			(void)strlcat(preload_list, ",", sizeof(preload_list));
		(void)strlcat(preload_list, fp->f_name, sizeof(preload_list));
	}
}

struct measurement
measure_preload(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "PreloadVerified", .type = MEAS_BYTE };

	preload_walk();
	if (preload_total == 0)
		return (m);
	m.present = true;
	m.value.byte = preload_bad == 0 ? 1 : 0;
	return (m);
}

void
diagnose_preload(int argc __unused, CHAR16 *argv[] __unused, struct diagnosis *d)
{
	d->leaf = "preload";
	snprintf(d->text, sizeof(d->text), "total=%u,made=%u,unverified=%u%s%s",
	    preload_total, preload_made, preload_bad,
	    preload_bad > 0 ? ":" : "", preload_bad > 0 ? preload_list : "");
}

/* --- the soft PCR --- */

struct measurement
measure_softpcr(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "SoftPcr", .type = MEAS_SHA256 };
#ifdef LOADER_VERIEXEC
	unsigned char buf[SHA256_DIGEST_LENGTH * 2];
	ssize_t n;

	n = ve_pcr_get(buf, sizeof(buf));
	if (n <= 0)
		return (m);
	measurement_sha256(buf, (size_t)n, m.value.digest);
	m.present = true;
#endif
	return (m);
}

/* --- the ledger --- */

struct measurement
measure_ledger_failed(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "LedgerFailed", .type = MEAS_BYTE,
	    .present = true };
	unsigned int n = evidence()->failed_gates;

	m.value.byte = n > 255 ? 255 : n;
	return (m);
}

struct measurement
measure_ledger_prompted(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "LedgerPrompted", .type = MEAS_BYTE,
	    .present = true };
	unsigned int n = evidence()->prompted;

	m.value.byte = n > 255 ? 255 : n;
	return (m);
}

struct measurement
measure_ledger_unlocked(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "LedgerUnlocked", .type = MEAS_BYTE,
	    .present = true };
	unsigned int n = evidence()->unlocked;

	m.value.byte = n > 255 ? 255 : n;
	return (m);
}

void
diagnose_ledger(int argc __unused, CHAR16 *argv[] __unused, struct diagnosis *d)
{
	const struct evidence *e = evidence();
	unsigned int i;
	char item[64];

	d->leaf = "ledger";
	snprintf(d->text, sizeof(d->text), "gates=%u,failed=%u,prompted=%u,unlocked=%u",
	    e->ngates, e->failed_gates, e->prompted, e->unlocked);
	for (i = 0; i < e->ngates; i++) {
		snprintf(item, sizeof(item), ";%u:%s:%s", e->gates[i].phase,
		    e->gates[i].gate,
		    e->gates[i].verdict == VERDICT_PASS ? "pass" : "fail");
		(void)strlcat(d->text, item, sizeof(d->text));
	}
}
