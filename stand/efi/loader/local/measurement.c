/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * measurement.c -- generic operations on the datum and the provider catalog.
 * Providers are pure producers: measure_*() reads the firmware/argv and returns
 * a measurement, nothing else. diagnose_keys/diagnose_marker gather the extra
 * human-readable evidence (byte counts, argv record) from the same source into
 * a struct diagnosis. No provider publishes -- the gate does that.
 */

#include <stand.h>
#include <string.h>
#include <fcntl.h>			/* O_RDONLY */
#include <sys/stat.h>			/* stat */

#include <efi.h>
#include <efilib.h>
#include <efichar.h>			/* cpy16to8 */

#include <crypto/sha2/sha256.h>

#ifdef LOADER_VERIEXEC
#include <verify_file.h>		/* verify_file, VE_* (file_verifies) */
#endif

#include "measurement.h"

static EFI_GUID GlobalVariableGUID = EFI_GLOBAL_VARIABLE;
static EFI_GUID ImageSecurityDatabaseGUID =
    { 0xd719b2cb, 0x3d3a, 0x4596,
      { 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f } };

/* The Secure Boot key variables, in the order they are hashed and reported. */
static const struct { EFI_GUID *guid; const char *name; } sbkeys[] = {
	{ &GlobalVariableGUID, "PK" },
	{ &GlobalVariableGUID, "KEK" },
	{ &ImageSecurityDatabaseGUID, "db" },
};

/* ---------------------------------------------------- generic operations */

static void
hexencode(const uint8_t *digest, char *out)		/* out: 2*LEN + 1 */
{
	static const char hex[] = "0123456789abcdef";
	int i;

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		out[2 * i] = hex[digest[i] >> 4];
		out[2 * i + 1] = hex[digest[i] & 0x0f];
	}
	out[2 * SHA256_DIGEST_LENGTH] = '\0';
}

static void
sha256_bytes(const void *buf, size_t len, uint8_t out[static SHA256_DIGEST_LENGTH])
{
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, len);
	SHA256_Final(out, &ctx);
}

void
measurement_render(const struct measurement *m, char *out, size_t sz)
{
	switch (m->type) {
	case MEAS_BYTE:
		snprintf(out, sz, "%u", m->value.byte);
		break;
	case MEAS_SHA256:
		if (sz > 2 * SHA256_DIGEST_LENGTH)
			hexencode(m->value.digest, out);
		else if (sz > 0)
			out[0] = '\0';
		break;
	}
}

bool
measurement_equal(const struct measurement *a, const struct measurement *b)
{
	if (a->type != b->type)
		return (false);
	switch (a->type) {
	case MEAS_BYTE:
		return (a->value.byte == b->value.byte);
	case MEAS_SHA256:
		return (memcmp(a->value.digest, b->value.digest,
		    SHA256_DIGEST_LENGTH) == 0);
	}
	return (false);
}

/* ------------------------------------------------------- firmware reads */

static int
read_u8(const char *name, uint8_t *out)
{
	size_t len = sizeof(*out);

	if (EFI_ERROR(efi_global_getenv(name, out, &len)) || len != sizeof(*out))
		return (0);
	return (1);
}

static const char *
board_serial(void)
{
	static const char *const fields[] = { "smbios.system.uuid",
	    "smbios.planar.serial", "smbios.system.serial", NULL };
	static const char *const junk[] = { "Not Applicable", "Not Specified",
	    "None", "N/A", "Default string", "To Be Filled By O.E.M.",
	    "System Serial Number", "Unknown", "0", NULL };
	const char *v;
	unsigned int i, j;

	for (i = 0; fields[i] != NULL; i++) {
		if ((v = getenv(fields[i])) == NULL || v[0] == '\0')
			continue;
		for (j = 0; junk[j] != NULL && strcmp(v, junk[j]) != 0; j++)
			;
		if (junk[j] == NULL)
			return (v);
	}
	return (NULL);
}

/* Append one attacker-controlled argv token, escaped and length-capped. */
static void
add_token(char *out, size_t sz, const char *tok)
{
	size_t n = strlen(out);
	const char *p;

	if (n + 2 >= sz)
		return;
	if (n > 0)
		out[n++] = ' ';
	for (p = tok; *p != '\0' && n + 1 < sz; p++)
		out[n++] = (*p >= 0x20 && *p <= 0x7e) ? *p : '?';
	out[n] = '\0';
}

/* ----------------------------------------------------------- providers */

/*
 * Prerequisites: files the loader must find before it will trust the boot.
 * Absence is invisible to veriexec (nothing is read, so nothing is verified),
 * so it is checked here explicitly. Two lists (see measurement.h), each declared
 * [..._N] so the compiler keeps table and threshold in step.
 *
 * _exist: the interpreter's own .lua chain (VE_MUST -- strict already catches
 * tampering; existence catches deletion before the interpreter chokes).
 */
static const char *const
prerequisites_exist[LOADER_PREREQUISITES_EXIST_N] = {
	"/boot/lua/loader.lua",
	"/boot/lua/config.lua",
	"/boot/lua/core.lua",
	"/boot/lua/cli.lua",
	"/boot/lua/hook.lua",
	"/boot/lua/color.lua",
	"/boot/lua/screen.lua",
	"/boot/lua/password.lua",
	"/boot/lua/menu.lua",
	"/boot/lua/drawer.lua",
	"/boot/lua/gfx-beastie.lua",
	"/boot/lua/gfx-beastiebw.lua",
	"/boot/lua/gfx-fbsdbw.lua",
	"/boot/lua/gfx-orb.lua",
	"/boot/lua/gfx-orbbw.lua",
	"/boot/lua/gfx-install.lua",
};

/*
 * _verify: files strict does not fully cover -- loader.conf (VE_WANT, tolerated
 * without a fingerprint) and device.hints (VE_TRY, tolerated and unreported).
 * Checked with verify_file, so absence AND tamper both fail the claim.
 */
static const char *const
prerequisites_verify[LOADER_PREREQUISITES_VERIFY_N] = {
	"/boot/loader.conf",
	"/boot/device.hints",
};

static bool
file_exists(const char *fname)
{
	struct stat st;

	return (stat(fname, &st) == 0 && st.st_size > 0);
}

#ifdef LOADER_VERIEXEC
/*
 * Exists AND verifies against the manifest. Severity VE_WANT deliberately, not
 * VE_MUST: under strict a VE_MUST call would panic on a tampered file
 * (verify_file.c, severity > accept_no_fp), which would take the decision away
 * from the policy. VE_WANT returns a value instead, so the gate stays
 * report-only until a policy says otherwise. Only a genuine match is
 * VE_VERIFIED; absent/tampered/unlisted all fall short.
 */
static bool
file_verifies(const char *fname)
{
	int fd, rc;

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		return (false);
	rc = verify_file(fd, fname, 0, VE_WANT, __func__);
	close(fd);
	return (rc == VE_VERIFIED);
}
#endif

/*
 * The "soft guarantee" probes. FreeBSD's convention is that strict veriexec
 * should be in force and that a loader.ve.strict marker should be present. We
 * do not enforce either -- we measure them and let the gate publish, so
 * tampering with the soft guarantee is *noticed*, not prevented (detection,
 * not prevention). This also keeps maximum compatibility with stock behaviour:
 * a missing marker or inactive strict is not an error -- it never was.
 */
#define	LOADER_VE_STRICT_MARKER	"/boot/loader.ve.strict"

struct measurement
measure_strict(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "StrictActive", .type = MEAS_BYTE,
	    .present = true };

	/*
	 * Runtime read of Verifying -- mode-independent: reports the actual state
	 * whether or not this translation unit was built with
	 * LOADER_VERIEXEC_ELEVATED (measurement.c gets LOADER_VERIEXEC but not
	 * ELEVATED, which is only in the libsecureboot CFLAGS). Verifying >= 1
	 * means verification is on and the strict threshold is in force.
	 */
	m.value.byte = (ve_verifying_get() >= 1) ? 1 : 0;
	return (m);
}

struct measurement
measure_ve_strict(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "VeStrictPresent", .type = MEAS_BYTE,
	    .present = true };

	m.value.byte = file_exists(LOADER_VE_STRICT_MARKER) ? 1 : 0;
	return (m);
}

/*
 * Count how many prerequisites hold -- no short-circuit: the measurement records
 * what is, the gate decides. The claim's expected value is the full count
 * (LOADER_PREREQUISITES_*_N), so "all hold" is count == threshold.
 * diagnose_prerequisites_*() record which fell short.
 */
struct measurement
measure_prerequisites_exist(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "PrereqsExist", .type = MEAS_BYTE,
	    .present = true };
	unsigned int i;

	for (i = 0; i < LOADER_PREREQUISITES_EXIST_N; i++)
		if (file_exists(prerequisites_exist[i]))
			m.value.byte++;
	return (m);
}

struct measurement
measure_prerequisites_verify(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "PrereqsVerify", .type = MEAS_BYTE,
	    .present = true };
	unsigned int i;

	for (i = 0; i < LOADER_PREREQUISITES_VERIFY_N; i++)
#ifdef LOADER_VERIEXEC
		if (file_verifies(prerequisites_verify[i]))
			m.value.byte++;
#else
		if (file_exists(prerequisites_verify[i]))
			m.value.byte++;
#endif
	return (m);
}

struct measurement
measure_secureboot(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "SecureBoot", .type = MEAS_BYTE };

	if (read_u8("SecureBoot", &m.value.byte))
		m.present = true;
	return (m);
}

struct measurement
measure_setupmode(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "SetupMode", .type = MEAS_BYTE };

	if (read_u8("SetupMode", &m.value.byte))
		m.present = true;
	return (m);
}

struct measurement
measure_board(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "BoardIdentity", .type = MEAS_SHA256 };
	const char *serial = board_serial();

	if (serial != NULL) {
		sha256_bytes(serial, strlen(serial), m.value.digest);
		m.present = true;
	}
	return (m);
}

/* SHA256 over PK||KEK||db; present iff at least one variable was read. */
struct measurement
measure_keys(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "SecureBootKeys", .type = MEAS_SHA256 };
	SHA256_CTX ctx;
	unsigned char *buf;
	size_t len;
	unsigned int i;
	int any = 0;

	SHA256_Init(&ctx);
	for (i = 0; i < sizeof(sbkeys) / sizeof(sbkeys[0]); i++) {
		len = 0;
		if (efi_getenv(sbkeys[i].guid, sbkeys[i].name, NULL, &len) !=
		    EFI_BUFFER_TOO_SMALL || len == 0)
			continue;
		if ((buf = malloc(len)) == NULL)
			return (m);
		if (EFI_ERROR(efi_getenv(sbkeys[i].guid, sbkeys[i].name, buf,
		    &len))) {
			free(buf);
			continue;
		}
		SHA256_Update(&ctx, buf, len);
		free(buf);
		any = 1;
	}
	if (any) {
		SHA256_Final(m.value.digest, &ctx);
		m.present = true;
	}
	return (m);
}

/*
 * Boot entry marker, from the NVRAM boot entry's LoadOptions (argv). The
 * expected digest is compiled in, so the provider can recognise the marker
 * token; present iff it is found. A wiped Boot#### (empty LoadOptions) fails.
 */
struct measurement
measure_marker(int argc, CHAR16 *argv[])
{
	struct measurement m = { .name = "BootMarker", .type = MEAS_SHA256 };
#ifdef LOADER_TRUST_MARKER_DIGEST
	static const uint8_t want[] = { LOADER_TRUST_MARKER_DIGEST };
	uint8_t got[SHA256_DIGEST_LENGTH];
	char arg[128];
	int i;

	for (i = 0; i < argc; i++) {
		cpy16to8(argv[i], arg, sizeof(arg));
		sha256_bytes(arg, strlen(arg), got);
		if (sizeof(want) == SHA256_DIGEST_LENGTH &&
		    memcmp(got, want, SHA256_DIGEST_LENGTH) == 0) {
			m.present = true;
			memcpy(m.value.digest, got, SHA256_DIGEST_LENGTH);
			break;
		}
	}
#else
	(void)argc;
	(void)argv;
#endif
	return (m);
}

/* ----------------------------------------------------------- diagnostics */

/* Comma list of the _exist prerequisites NOT found (empty if all present). */
void
diagnose_prerequisites_exist(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	unsigned int i;

	d->leaf = "exist.missing";
	d->text[0] = '\0';
	for (i = 0; i < LOADER_PREREQUISITES_EXIST_N; i++) {
		if (file_exists(prerequisites_exist[i]))
			continue;
		if (d->text[0] != '\0')
			(void)strlcat(d->text, ",", sizeof(d->text));
		(void)strlcat(d->text, prerequisites_exist[i], sizeof(d->text));
	}
}

/* Comma list of the _verify prerequisites that did not verify (empty if all). */
void
diagnose_prerequisites_verify(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	unsigned int i;

	d->leaf = "verify.missing";
	d->text[0] = '\0';
	for (i = 0; i < LOADER_PREREQUISITES_VERIFY_N; i++) {
#ifdef LOADER_VERIEXEC
		if (file_verifies(prerequisites_verify[i]))
			continue;
#else
		if (file_exists(prerequisites_verify[i]))
			continue;
#endif
		if (d->text[0] != '\0')
			(void)strlcat(d->text, ",", sizeof(d->text));
		(void)strlcat(d->text, prerequisites_verify[i], sizeof(d->text));
	}
}

/* Per-variable byte counts of PK/KEK/db, e.g. "1590,1204,3841" or "none,...". */
void
diagnose_keys(int argc __unused, CHAR16 *argv[] __unused, struct diagnosis *d)
{
	char n[16];
	size_t len;
	unsigned int i;

	d->leaf = "keys.bytes";
	d->text[0] = '\0';
	for (i = 0; i < sizeof(sbkeys) / sizeof(sbkeys[0]); i++) {
		if (i > 0)
			(void)strlcat(d->text, ",", sizeof(d->text));
		len = 0;
		if (efi_getenv(sbkeys[i].guid, sbkeys[i].name, NULL, &len) !=
		    EFI_BUFFER_TOO_SMALL || len == 0) {
			(void)strlcat(d->text, "none", sizeof(d->text));
			continue;
		}
		snprintf(n, sizeof(n), "%llu", (unsigned long long)len);
		(void)strlcat(d->text, n, sizeof(d->text));
	}
}

/* The sanitised boot command line, marker token redacted as <marker>. */
void
diagnose_marker(int argc, CHAR16 *argv[], struct diagnosis *d)
{
	char arg[128];
	int i;
#ifdef LOADER_TRUST_MARKER_DIGEST
	static const uint8_t want[] = { LOADER_TRUST_MARKER_DIGEST };
	uint8_t got[SHA256_DIGEST_LENGTH];
#endif

	d->leaf = "argv";
	d->text[0] = '\0';
	for (i = 0; i < argc; i++) {
		cpy16to8(argv[i], arg, sizeof(arg));
#ifdef LOADER_TRUST_MARKER_DIGEST
		sha256_bytes(arg, strlen(arg), got);
		if (sizeof(want) == SHA256_DIGEST_LENGTH &&
		    memcmp(got, want, SHA256_DIGEST_LENGTH) == 0) {
			add_token(d->text, sizeof(d->text), "<marker>");
			continue;
		}
#endif
		add_token(d->text, sizeof(d->text), arg);
	}
}
