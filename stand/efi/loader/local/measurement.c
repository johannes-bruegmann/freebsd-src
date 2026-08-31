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
 * so it is checked here explicitly. The two LISTS are DECISIONS, not code
 * facts: elebake emits them into the generated foundation.c (arrays plus
 * their _n counters, see measurement.h) — this file only consumes them.
 */

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

/* ------------------------------------------------------------- origin */

/*
 * Where does the RUNNING code come from? The firmware records it: the
 * LoadedImage protocol of our own image handle carries the DeviceHandle
 * (whose device path names the partition, GUID included) and the FilePath
 * it loaded us from. Self-reporting, honestly: a hostile loader simply
 * lies or stays silent -- the value of these providers is that the HONEST
 * loader becomes a precise witness whose published origin the later
 * custody links (earlboot/elvbootd) can check, and that a forger has to
 * fake ever more, consistently.
 */

static EFI_GUID origin_imgid = LOADED_IMAGE_PROTOCOL;
static EFI_GUID origin_sfsid = SIMPLE_FILE_SYSTEM_PROTOCOL;

/* The GPT partition GUID of the device we were loaded from, canonical
 * lowercase text (matches `gpart list` rawuuid -- the site.mk side hashes
 * the SAME text form). Empty string when unknown. */
static void
origin_partition_guid(char *out, size_t outsz)
{
	EFI_LOADED_IMAGE *img;
	EFI_DEVICE_PATH *dp;
	HARDDRIVE_DEVICE_PATH *hd;
	const UINT8 *g;

	out[0] = '\0';
	if (EFI_ERROR(BS->HandleProtocol(IH, &origin_imgid, (void **)&img)))
		return;
	dp = efi_lookup_devpath(img->DeviceHandle);
	if (dp == NULL)
		return;
	for (; !IsDevicePathEndType(dp); dp = NextDevicePathNode(dp)) {
		if (DevicePathType(dp) != MEDIA_DEVICE_PATH ||
		    DevicePathSubType(dp) != MEDIA_HARDDRIVE_DP)
			continue;
		hd = (HARDDRIVE_DEVICE_PATH *)dp;
		if (hd->SignatureType != SIGNATURE_TYPE_GUID)
			continue;
		/* EFI GUID: first three fields little endian, rest as-is. */
		g = hd->Signature;
		(void)snprintf(out, outsz,
		    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
		    "%02x%02x%02x%02x%02x%02x",
		    g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6],
		    g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
		return;
	}
}

/* SHA256 over the canonical GUID text of our load origin. The site.mk
 * counterpart: sha256 of the ESP's gpart rawuuid (lowercase, no newline)
 * -> -DLOADER_TRUST_ORIGIN_DIGEST. */
struct measurement
measure_origin(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "LoadOrigin", .type = MEAS_SHA256 };
	char guid[37];

	origin_partition_guid(guid, sizeof(guid));
	if (guid[0] != '\0') {
		sha256_bytes(guid, strlen(guid), m.value.digest);
		m.present = true;
	}
	return (m);
}

/* sha256 of a bootfs file via the loader's own open/read; false on any
 * shortfall. Reads only -- nothing is loaded or executed. */
static bool
sha256_bootfs_file(const char *fname,
    uint8_t out[static SHA256_DIGEST_LENGTH])
{
	SHA256_CTX ctx;
	char buf[4096];
	ssize_t n;
	int fd;

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		return (false);
	SHA256_Init(&ctx);
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		SHA256_Update(&ctx, buf, (size_t)n);
	close(fd);
	if (n < 0)
		return (false);
	SHA256_Final(out, &ctx);
	return (true);
}

/* sha256 of the file the firmware SAYS it loaded us from, read over the
 * origin's own SimpleFileSystem (chunked; nothing is loaded). */
static bool
sha256_origin_file(uint8_t out[static SHA256_DIGEST_LENGTH])
{
	EFI_LOADED_IMAGE *img;
	EFI_FILE_IO_INTERFACE *fio;
	EFI_FILE_HANDLE root, f;
	EFI_DEVICE_PATH *dp;
	FILEPATH_DEVICE_PATH *fp;
	CHAR16 *path;
	SHA256_CTX ctx;
	UINTN sz, plen, off;
	char buf[4096];
	bool ok = false;

	if (EFI_ERROR(BS->HandleProtocol(IH, &origin_imgid, (void **)&img)))
		return (false);
	if (img->FilePath == NULL)
		return (false);
	/* Concatenate the FILEPATH nodes into one CHAR16 path. */
	plen = 0;
	for (dp = img->FilePath; !IsDevicePathEndType(dp);
	    dp = NextDevicePathNode(dp)) {
		if (DevicePathType(dp) != MEDIA_DEVICE_PATH ||
		    DevicePathSubType(dp) != MEDIA_FILEPATH_DP)
			continue;
		plen += (DevicePathNodeLength(dp) -
		    SIZE_OF_FILEPATH_DEVICE_PATH) / sizeof(CHAR16);
	}
	if (plen == 0)
		return (false);
	path = malloc((plen + 1) * sizeof(CHAR16));
	if (path == NULL)
		return (false);
	off = 0;
	for (dp = img->FilePath; !IsDevicePathEndType(dp);
	    dp = NextDevicePathNode(dp)) {
		UINTN i, n16;

		if (DevicePathType(dp) != MEDIA_DEVICE_PATH ||
		    DevicePathSubType(dp) != MEDIA_FILEPATH_DP)
			continue;
		fp = (FILEPATH_DEVICE_PATH *)dp;
		n16 = (DevicePathNodeLength(dp) -
		    SIZE_OF_FILEPATH_DEVICE_PATH) / sizeof(CHAR16);
		for (i = 0; i < n16 && fp->PathName[i] != 0; i++)
			path[off++] = fp->PathName[i];
	}
	path[off] = 0;

	if (!EFI_ERROR(BS->HandleProtocol(img->DeviceHandle, &origin_sfsid,
	    (void **)&fio)) &&
	    !EFI_ERROR(fio->OpenVolume(fio, &root))) {
		if (!EFI_ERROR(root->Open(root, &f, path,
		    EFI_FILE_MODE_READ, 0))) {
			SHA256_Init(&ctx);
			for (;;) {
				sz = sizeof(buf);
				if (EFI_ERROR(f->Read(f, &sz, buf)))
					break;
				if (sz == 0) {
					SHA256_Final(out, &ctx);
					ok = true;
					break;
				}
				SHA256_Update(&ctx, buf, sz);
			}
			f->Close(f);
		}
		root->Close(root);
	}
	free(path);
	return (ok);
}

/*
 * 1 iff the resting file at our own load origin is byte-identical (by
 * sha256) to /boot/loader.efi.signed -- the manifest-covered reserve.
 * Combined with the verify prerequisite on the reserve this chains the
 * origin file to the attested manifest without parsing it here.
 */
struct measurement
measure_origin_verified(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "OriginVerified", .type = MEAS_BYTE };
	uint8_t self[SHA256_DIGEST_LENGTH], reserve[SHA256_DIGEST_LENGTH];

	if (!sha256_origin_file(self))
		return (m);
	m.present = true;
	if (sha256_bootfs_file("/boot/loader.efi.signed", reserve) &&
	    memcmp(self, reserve, SHA256_DIGEST_LENGTH) == 0)
		m.value.byte = 1;
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

	for (i = 0; i < prerequisites_exist_n; i++)
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

	for (i = 0; i < prerequisites_verify_n; i++)
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
	for (i = 0; i < prerequisites_exist_n; i++) {
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
	for (i = 0; i < prerequisites_verify_n; i++) {
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

/* The load origin in clear text: "<partition-guid>:<file-path>". */
void
diagnose_origin(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	EFI_LOADED_IMAGE *img;
	CHAR16 *name;
	char guid[37];
	size_t off;

	d->leaf = "origin";
	d->text[0] = '\0';
	origin_partition_guid(guid, sizeof(guid));
	(void)strlcpy(d->text, guid[0] != '\0' ? guid : "unknown",
	    sizeof(d->text));
	(void)strlcat(d->text, ":", sizeof(d->text));
	off = strlen(d->text);
	if (!EFI_ERROR(BS->HandleProtocol(IH, &origin_imgid,
	    (void **)&img)) && img->FilePath != NULL &&
	    (name = efi_devpath_name(img->FilePath)) != NULL) {
		cpy16to8(name, d->text + off, sizeof(d->text) - off);
		efi_free_devpath_name(name);
	} else
		(void)strlcat(d->text, "unknown", sizeof(d->text));
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
