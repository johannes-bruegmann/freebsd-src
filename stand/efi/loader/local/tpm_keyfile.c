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

void
tpm_keyfile_prepare(const char *passphrase)
{
	const char *kh = getenv("loader.trust.tpm.key.handle");
	const char *h = getenv("loader.trust.tpm.keyfile.handle");
	const char *hd = getenv("loader.trust.tpm.keyfile.duress");
	const char *p = getenv("loader.trust.tpm.keyfile.providers");
	const char *pc = getenv("loader.trust.tpm.keyfile.pcrs");
	const char *nv = getenv("loader.trust.tpm.duress.nv");
	uint8_t secret[TPM_KEYFILE_MAX], auth[SHA256_DIGEST_LENGTH];
	uint8_t kd[SHA256_DIGEST_LENGTH], *kdp = NULL;
	char prov[TPM_KEYFILE_PROVLEN], type[TPM_KEYFILE_PROVLEN + 24];
	const char *q;
	char *end;
	unsigned long keyhandle, handle, duress = 0, nvindex = 0;
	uint32_t mask;
	size_t len, n;
	SHA256_CTX ctx;
	bool duress_opened = false;

	if (st.unsealed)
		return;				/* placed on an earlier line */
	memset(&st, 0, sizeof(st));
	if (kh == NULL && h == NULL && p == NULL && pc == NULL) {
		st.reason = "not configured";
		return;
	}
	st.configured = true;
	if (kh == NULL || h == NULL || p == NULL || pc == NULL) {
		st.reason = "incomplete: key.handle, keyfile.handle, providers and pcrs";
		return;
	}
	keyhandle = strtoul(kh, &end, 0);
	if (end == kh || *end != '\0' || keyhandle > 0xffffffffUL) {
		st.reason = "bad key.handle";
		return;
	}
	handle = strtoul(h, &end, 0);
	if (end == h || *end != '\0' || handle > 0xffffffffUL) {
		st.reason = "bad handle";
		return;
	}
	if (hd != NULL) {
		duress = strtoul(hd, &end, 0);
		if (end == hd || *end != '\0' || duress > 0xffffffffUL) {
			st.reason = "bad duress handle";
			return;
		}
	}
	if (nv != NULL) {
		nvindex = strtoul(nv, &end, 0);
		if (end == nv || *end != '\0' || nvindex > 0xffffffffUL) {
			st.reason = "bad duress.nv";
			return;
		}
	}
	if (!tpm_parse_pcrs(pc, &mask)) {
		st.reason = "bad pcrs";
		return;
	}
	if (tpm_key_digest((uint32_t)keyhandle, kd))
		hex_publish("loader.trust.tpm.key.sha256", kd, sizeof(kd));
	if (key_digest_baseline(kd)) {
		kdp = kd;
		st.verified = true;
	}
	/* the auth value: SHA256 of the line, what tpm2_create -p hex: took */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, passphrase, strlen(passphrase));
	SHA256_Final(auth, &ctx);
	if (!tpm_unseal((uint32_t)keyhandle, kdp, (uint32_t)handle, mask,
	    auth, sizeof(auth), secret, sizeof(secret), &len)) {
		const char *why = tpm_last_error();

		if (duress == 0 || !tpm_unseal((uint32_t)keyhandle, kdp, (uint32_t)duress,
		    mask, auth, sizeof(auth), secret, sizeof(secret), &len)) {
			st.reason = why;
			explicit_bzero(auth, sizeof(auth));
			return;
		}
		duress_opened = true;
	}
	explicit_bzero(auth, sizeof(auth));
	st.unsealed = true;
	if (duress_opened) {
		evidence_set_duress();
		if (nvindex != 0)
			(void)tpm_nv_policy_increment((uint32_t)keyhandle, (uint32_t)nvindex);
	}
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
	explicit_bzero(secret, sizeof(secret));
}

const struct tpm_keyfile_state *
tpm_keyfile_state(void)
{
	return (&st);
}
