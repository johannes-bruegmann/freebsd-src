/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * tpm_keyfile.c -- the GELI key file the TPM releases (tpm_keyfile.h).
 *
 * Runs as the action of a KERNEL-phase gate, once: the kernel is loaded,
 * so a buffer can become a preloaded file (file_addbuf), and the record's
 * key derivation (geli_keys.c) has not run yet -- it runs at the first
 * record claim, in a gate bound after the action's -- so it sees the
 * file. The bytes live in the loader only as long as it takes to copy
 * them into the preload area; the kernel's g_eli reads the same file.
 */

#include <stand.h>
#include <string.h>
#include <bootstrap.h>			/* file_findfile, file_addbuf */

#include "tpm.h"
#include "tpm_keyfile.h"

#define	TPM_KEYFILE_MAX		128	/* a sealed blob is at most 128 bytes */
#define	TPM_KEYFILE_PROVLEN	16

static struct tpm_keyfile_state st;

/* "0,2,7" -> bit mask of the PCR selection (SHA256 bank, 24 PCRs). */
static bool
parse_pcrs(const char *s, uint32_t *mask)
{
	unsigned long v;
	char *end;

	*mask = 0;
	while (*s != '\0') {
		v = strtoul(s, &end, 10);
		if (end == s || v > 23)
			return (false);
		*mask |= 1u << v;
		s = end;
		if (*s == ',')
			s++;
		else if (*s != '\0')
			return (false);
	}
	return (*mask != 0);
}

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

void
tpm_keyfile_prepare(const char *h, const char *p, const char *pc)
{
	static bool tried;
	uint8_t secret[TPM_KEYFILE_MAX];
	char prov[TPM_KEYFILE_PROVLEN], type[TPM_KEYFILE_PROVLEN + 24];
	const char *q;
	char *end;
	unsigned long handle;
	uint32_t mask;
	size_t len, n;

	if (tried)
		return;
	tried = true;
	if (h == NULL && p == NULL && pc == NULL) {
		st.reason = "not configured";
		return;
	}
	st.configured = true;
	if (h == NULL || p == NULL || pc == NULL) {
		st.reason = "incomplete: handle, providers and pcrs";
		return;
	}
	handle = strtoul(h, &end, 0);
	if (end == h || *end != '\0' || handle > 0xffffffffUL) {
		st.reason = "bad handle";
		return;
	}
	if (!parse_pcrs(pc, &mask)) {
		st.reason = "bad pcrs";
		return;
	}
	if (!tpm_unseal((uint32_t)handle, mask, secret, sizeof(secret), &len)) {
		st.reason = tpm_last_error();
		return;
	}
	st.unsealed = true;
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
