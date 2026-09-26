/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * tpm_keyfile.c -- the GELI key file the TPM releases (tpm_keyfile.h).
 *
 * Runs from the dialog, once per typed line, until the file is placed:
 * the kernel is loaded, so a buffer can become a preloaded file
 * (file_addbuf), and the derivation (geli_keys.c) runs right after, so
 * it sees the file. The bytes live in the loader only as long as it
 * takes to copy them into the preload area; the kernel's g_eli reads the
 * same file.
 */

#include <stand.h>
#include <string.h>
#include <bootstrap.h>			/* file_findfile, file_addbuf */

#include <crypto/sha2/sha256.h>

#include "tpm.h"
#include "tpm_keyfile.h"
#include "evidence.h"

#define	TPM_KEYFILE_MAX		128	/* a sealed blob is at most 128 bytes */
#define	TPM_KEYFILE_PROVLEN	16
#define	TPM_KEYFILE_STEPS(a)	(sizeof(a) / sizeof((a)[0]))

static struct tpm_keyfile_state st;

/* The next free key file index of a provider: after the ones preloaded. */
static int
next_index(const char *prov)
{
	char type[TPM_KEYFILE_PROVLEN + 24];
	int i;

	for (i = 0; ; i++) {
		snprintf(type, sizeof(type), "%s:geli_keyfile%d", prov, i);
		if (file_findfile(NULL, type) != NULL)
			continue;
		if (i == 0) {
			snprintf(type, sizeof(type), "%s:geli_keyfile", prov);
			if (file_findfile(NULL, type) != NULL)
				continue;
		}
		return (i);
	}
}

/* The storage key's digest baseline (site mk renders a digest as a byte
 * list, 0x.., 0x.. -- the form the MEASUREMENT_SHA256 initializers take);
 * false when the macro is not set or not 32 bytes. */
static bool
key_digest_baseline(uint8_t out[SHA256_DIGEST_LENGTH])
{
#ifdef LOADER_TRUST_TPM_KEY_DIGEST
	static const uint8_t d[] = { LOADER_TRUST_TPM_KEY_DIGEST };

	if (sizeof(d) != SHA256_DIGEST_LENGTH)
		return (false);
	memcpy(out, d, sizeof(d));
	return (true);
#else
	(void)out;
	return (false);
#endif
}

static void
hex_publish(const char *name, const uint8_t *d, size_t len)
{
	static const char hx[] = "0123456789abcdef";
	char buf[2 * SHA256_DIGEST_LENGTH + 1];
	size_t i;

	for (i = 0; i < len && i < SHA256_DIGEST_LENGTH; i++) {
		buf[2 * i] = hx[d[i] >> 4];
		buf[2 * i + 1] = hx[d[i] & 0x0f];
	}
	buf[2 * i] = '\0';
	setenv(name, buf, 1);
}

/* A handle or index leaf, "0x8101...": the whole string, 32 bits. */
static bool
parse_handle(const char *s, uint32_t *out)
{
	unsigned long v;
	char *end;

	if (s == NULL)
		return (false);
	v = strtoul(s, &end, 0);
	if (end == s || *end != '\0' || v > 0xffffffffUL)
		return (false);
	*out = (uint32_t)v;
	return (true);
}

static int
nibble(char c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

/* The sealed counter value: 16 hex characters, big-endian, as tpm2_nvread
 * prints the index's 8 bytes -- into the 8 bytes and the number. */
static bool
parse_sealed(const char *s, uint8_t out[8], uint64_t *v)
{
	size_t i;
	int hi, lo;

	if (s == NULL || strlen(s) != 16)
		return (false);
	*v = 0;
	for (i = 0; i < 8; i++) {
		hi = nibble(s[2 * i]);
		lo = nibble(s[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return (false);
		out[i] = (uint8_t)(hi << 4 | lo);
		*v = *v << 8 | out[i];
	}
	return (true);
}

/* The counter as it stands, for the diagnosis: read through the index
 * itself before any attempt, so a boot after a duress event still explains
 * itself. The PIN index reads only under the owner hierarchy, whose
 * password the boot path does not hold: elebake stage tpm status shows it. */
static void
read_indices(uint32_t count)
{
	uint64_t v;

	if (tpm_nv_index_read(count, &v)) {
		st.count_read = true;
		st.count = v;
	}
}

/* The secret into the preload area, once per named provider. */
static void
place(const char *p, uint8_t *secret, size_t len)
{
	char prov[TPM_KEYFILE_PROVLEN], type[TPM_KEYFILE_PROVLEN + 24];
	const char *q;
	size_t n;

	st.reason = *p == '\0' ? "unsealed, no provider named" : "ok";
	for (q = p; *q != '\0'; ) {
		while (*q == ' ')
			q++;
		if (*q == '\0')
			break;
		for (n = 0; q[n] != '\0' && q[n] != ' '; n++)
			;
		if (n >= sizeof(prov)) {
			st.reason = "provider name too long";
			q += n;
			continue;
		}
		memcpy(prov, q, n);
		prov[n] = '\0';
		q += n;
		st.providers++;
		snprintf(type, sizeof(type), "%s:geli_keyfile%d", prov,
		    next_index(prov));
		if (file_addbuf("tpm.keyfile", type, len, secret) == 0)
			st.added++;
		else
			st.reason = "no room for the key file";
	}
}

void
tpm_keyfile_prepare(const char *passphrase)
{
	const char *kh = getenv("loader.trust.tpm.key.handle");
	const char *h = getenv("loader.trust.tpm.keyfile.handles");
	const char *p = getenv("loader.trust.tpm.keyfile.providers");
	const char *pc = getenv("loader.trust.tpm.keyfile.pcrs");
	const char *nv = getenv("loader.trust.tpm.counter.nv");
	const char *pin = getenv("loader.trust.tpm.duress.nv");
	const char *cnt = getenv("loader.trust.tpm.duress.count.nv");
	const char *sealed = getenv("loader.trust.tpm.duress.count.sealed");
	const char *dp = getenv("loader.trust.tpm.decoy.providers");
	uint8_t secret[TPM_KEYFILE_MAX], auth[SHA256_DIGEST_LENGTH];
	uint8_t kd[SHA256_DIGEST_LENGTH], *kdp = NULL;
	uint8_t sealed8[8];
	char h1[16];
	const char *h2;
	uint32_t keyhandle, handle, duress = 0, nvindex = 0, pinindex, cntindex;
	uint32_t mask;
	size_t len, n;
	SHA256_CTX ctx;
	bool ok, duress_opened = false;

	if (st.unsealed)
		return;				/* placed on an earlier line */
	memset(&st, 0, sizeof(st));
	if (kh == NULL && h == NULL && p == NULL && pc == NULL &&
	    pin == NULL && cnt == NULL && sealed == NULL && dp == NULL) {
		st.reason = "not configured";
		return;
	}
	st.configured = true;
	if (kh == NULL || h == NULL || p == NULL || pc == NULL ||
	    pin == NULL || cnt == NULL || sealed == NULL) {
		st.reason = "incomplete: key.handle, keyfile.handles, providers, "
		    "pcrs, duress.nv, duress.count.nv, duress.count.sealed";
		return;
	}
	if (!parse_handle(kh, &keyhandle)) {
		st.reason = "bad key.handle";
		return;
	}
	/* handles: the owner's object, then the duress one */
	for (n = 0; h[n] != '\0' && h[n] != ' ' && n < sizeof(h1) - 1; n++)
		h1[n] = h[n];
	h1[n] = '\0';
	if (!parse_handle(h1, &handle)) {
		st.reason = "bad handles";
		return;
	}
	h2 = h + n;
	while (*h2 == ' ')
		h2++;
	if (*h2 != '\0' && !parse_handle(h2, &duress)) {
		st.reason = "bad handles";
		return;
	}
	if (nv != NULL && !parse_handle(nv, &nvindex)) {
		st.reason = "bad counter.nv";
		return;
	}
	if (!parse_handle(pin, &pinindex)) {
		st.reason = "bad duress.nv";
		return;
	}
	if (!parse_handle(cnt, &cntindex)) {
		st.reason = "bad duress.count.nv";
		return;
	}
	if (!parse_sealed(sealed, sealed8, &st.count_sealed)) {
		st.reason = "bad duress.count.sealed (16 hex characters)";
		return;
	}
	if (!tpm_parse_pcrs(pc, &mask)) {
		st.reason = "bad pcrs";
		return;
	}
	read_indices(cntindex);
	if (tpm_key_digest(keyhandle, kd))
		hex_publish("loader.trust.tpm.key.sha256", kd, sizeof(kd));
	if (key_digest_baseline(kd)) {
		kdp = kd;
		st.verified = true;
	}
	/* the auth value: SHA256 of the line, what tpm2_create -p and
	 * tpm2_nvdefine -p took (elebake stage tpm seal, stage tpm duress) */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, passphrase, strlen(passphrase));
	SHA256_Final(auth, &ctx);
	{
		/* owner: PCR, the object's auth value, the counter untouched
		 * (the PIN index is not in the policy: it reads only under
		 * the owner hierarchy, and a counter says the same, finally) */
		const struct tpm_policy_step owner[] = {
			{ .op = TPM_POLICY_PCR, .mask = mask },
			{ .op = TPM_POLICY_AUTHVALUE },
			{ .op = TPM_POLICY_NV, .index = cntindex, .oplen = 8,
			  .offset = 0, .eo = TPM_EO_EQ, .operand = { sealed8[0],
			  sealed8[1], sealed8[2], sealed8[3], sealed8[4],
			  sealed8[5], sealed8[6], sealed8[7] } },
		};
		/* duress: the PIN index proves the line (and counts), then PCR */
		const struct tpm_policy_step decoy[] = {
			{ .op = TPM_POLICY_SECRET, .index = pinindex,
			  .auth = auth, .authlen = sizeof(auth) },
			{ .op = TPM_POLICY_PCR, .mask = mask },
		};

		ok = tpm_unseal(keyhandle, kdp, handle, owner,
		    TPM_KEYFILE_STEPS(owner), auth, sizeof(auth), secret,
		    sizeof(secret), &len);
		if (!ok) {
			const char *why = tpm_last_error();

			if (duress != 0 && tpm_unseal(keyhandle, kdp, duress,
			    decoy, TPM_KEYFILE_STEPS(decoy), NULL, 0, secret,
			    sizeof(secret), &len)) {
				ok = true;
				duress_opened = true;
			} else
				st.reason = why;
		}
	}
	explicit_bzero(auth, sizeof(auth));
	if (!ok)
		return;
	st.unsealed = true;
	if (duress_opened) {
		evidence_set_duress();
		if (nvindex != 0)
			(void)tpm_nv_policy_increment(keyhandle, nvindex);
		/*
		 * The second counter too: the owner's object is sealed
		 * against its value, and a counter never goes back. The PIN
		 * index alone would leave the seal's death reversible --
		 * pinCount is an owner-writable cell, and the owner
		 * hierarchy's password is empty (a root anywhere on this
		 * machine writes it back to 0).
		 */
		(void)tpm_nv_policy_increment(keyhandle, cntindex);
		place(dp != NULL ? dp : "", secret, len);
	} else
		place(p, secret, len);
	explicit_bzero(secret, sizeof(secret));
}

const struct tpm_keyfile_state *
tpm_keyfile_state(void)
{
	return (&st);
}
