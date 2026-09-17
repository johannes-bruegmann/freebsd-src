/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * efi_tpm.c -- TPM 2.0 commands over EFI_TCG2_PROTOCOL.SubmitCommand
 * (efitpm.h).
 *
 * The protocol follows the TCG EFI Protocol Specification (family 2.0),
 * the command formats the TPM 2.0 Library, part 3. Only the fields this
 * file uses are built; everything is big-endian on the wire.
 */

#include <stand.h>
#include <string.h>

#include <efi.h>
#include <efilib.h>
#include <efitpm.h>

#include <Protocol/Tcg2Protocol.h>
#include <Protocol/Rng.h>

#include <crypto/sha2/sha256.h>

/*
 * The tags, handles, algorithms and command codes come from EDK2's
 * IndustryStandard/Tpm20.h (via Tcg2Protocol.h). TPMA_NV there is a bit
 * field; the attributes of the counter index are built as a mask here.
 */
#define	NV_ATTR_COUNTER		0x00000010u	/* TPMA_NV_COUNTER */
#define	NV_ATTR_OWNERWRITE	0x00000002u
#define	NV_ATTR_AUTHWRITE	0x00000004u
#define	NV_ATTR_OWNERREAD	0x00020000u
#define	NV_ATTR_AUTHREAD	0x00040000u
#define	NV_ATTR_NO_DA		0x02000000u

#define	NONCE_LEN		16

static EFI_GUID tcg2_guid = EFI_TCG2_PROTOCOL_GUID;
static EFI_GUID rng_guid = EFI_RNG_PROTOCOL_GUID;

static const char *last_error = "";

const char *
efi_tpm_error(void)
{
	return (last_error);
}

/* --- a small big-endian builder / parser --- */

struct bb { uint8_t *p; size_t n, cap; };

static void
put8(struct bb *b, uint8_t v)
{
	if (b->n < b->cap)
		b->p[b->n] = v;
	b->n++;
}

static void
put16(struct bb *b, uint16_t v)
{
	put8(b, v >> 8); put8(b, v);
}

static void
put32(struct bb *b, uint32_t v)
{
	put16(b, v >> 16); put16(b, v);
}

static void
putbuf(struct bb *b, const uint8_t *p, size_t n)
{
	while (n-- > 0)
		put8(b, *p++);
}

static uint16_t
get16(const uint8_t *p)
{
	return ((uint16_t)p[0] << 8 | p[1]);
}

static uint32_t
get32(const uint8_t *p)
{
	return ((uint32_t)get16(p) << 16 | get16(p + 2));
}

static uint64_t
get64(const uint8_t *p)
{
	return ((uint64_t)get32(p) << 32 | get32(p + 4));
}

/* An empty password authorization (TPMS_AUTH_COMMAND). */
static void
put_auth_pw(struct bb *b)
{
	put32(b, 9);			/* authorizationSize */
	put32(b, TPM_RS_PW);
	put16(b, 0);			/* nonce: empty */
	put8(b, 0);			/* sessionAttributes */
	put16(b, 0);			/* hmac: empty */
}

/* Finish the header: tag, size, code were reserved at offset 0. */
static void
finish(struct bb *b, uint16_t tag, uint32_t cc)
{
	b->p[0] = tag >> 8; b->p[1] = tag;
	b->p[2] = b->n >> 24; b->p[3] = b->n >> 16; b->p[4] = b->n >> 8; b->p[5] = b->n;
	b->p[6] = cc >> 24; b->p[7] = cc >> 16; b->p[8] = cc >> 8; b->p[9] = cc;
}

static EFI_TCG2_PROTOCOL *
tcg2(void)
{
	static EFI_TCG2_PROTOCOL *proto;
	static bool tried;

	if (!tried) {
		tried = true;
		if (EFI_ERROR(BS->LocateProtocol(&tcg2_guid, NULL,
		    (void **)&proto)))
			proto = NULL;
	}
	return (proto);
}

/* Submit; on success *rlen is the response length and the RC is SUCCESS. */
static bool
submit(struct bb *cmd, uint8_t *resp, size_t rcap, size_t *rlen)
{
	EFI_TCG2_PROTOCOL *t = tcg2();
	uint32_t rc, sz;

	if (t == NULL) {
		last_error = "no TCG2 protocol";
		return (false);
	}
	if (cmd->n > cmd->cap) {
		last_error = "command too long";
		return (false);
	}
	memset(resp, 0, rcap);
	if (EFI_ERROR(t->SubmitCommand(t, cmd->n, cmd->p, rcap, resp))) {
		last_error = "SubmitCommand failed";
		return (false);
	}
	sz = get32(resp + 2);
	rc = get32(resp + 6);
	if (sz < 10 || sz > rcap) {
		last_error = "bad response size";
		return (false);
	}
	if (rc != TPM_RC_SUCCESS) {
		static char rcbuf[24];

		snprintf(rcbuf, sizeof(rcbuf), "TPM_RC 0x%x", rc);
		last_error = rcbuf;
		return (false);
	}
	*rlen = sz;
	return (true);
}

/* The caller's nonce: from the firmware's RNG when there is one. */
static void
nonce(uint8_t *out, size_t n)
{
	EFI_RNG_PROTOCOL *rng;

	memset(out, 0, n);
	if (!EFI_ERROR(BS->LocateProtocol(&rng_guid, NULL, (void **)&rng)))
		(void)rng->GetRNG(rng, NULL, n, out);
}

/* --- read-only --- */

bool
efi_tpm_present(void)
{
	struct efi_tpm_clock c;

	return (efi_tpm_read_clock(&c));
}

bool
efi_tpm_read_clock(struct efi_tpm_clock *out)
{
	uint8_t c[16], r[64];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;

	finish(&b, TPM_ST_NO_SESSIONS, TPM_CC_ReadClock);
	if (!submit(&b, r, sizeof(r), &n) || n < 10 + 8 + 8 + 4 + 4 + 1)
		return (false);
	/* TPMS_TIME_INFO: time(8) clockInfo{clock(8) resetCount(4) restartCount(4) safe(1)} */
	out->clock = get64(r + 10 + 8);
	out->reset_count = get32(r + 10 + 16);
	out->restart_count = get32(r + 10 + 20);
	out->safe = r[10 + 24] != 0;
	return (true);
}

bool
efi_tpm_parse_pcrs(const char *s, uint32_t *mask)
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

bool
efi_tpm_pcr_read(uint32_t mask, uint8_t *out, size_t cap, size_t *len)
{
	uint8_t c[32], r[1024];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;
	uint32_t count, i, off, want = 0;

	for (i = 0; i < 24; i++)
		if (mask & (1u << i))
			want++;
	/* TPML_PCR_SELECTION: count=1, {hash=SHA256, sizeofSelect=3, select} */
	put32(&b, 1);
	put16(&b, TPM_ALG_SHA256);
	put8(&b, 3);
	put8(&b, mask & 0xff); put8(&b, (mask >> 8) & 0xff); put8(&b, (mask >> 16) & 0xff);
	finish(&b, TPM_ST_NO_SESSIONS, TPM_CC_PCR_Read);
	if (!submit(&b, r, sizeof(r), &n))
		return (false);
	/* pcrUpdateCounter(4) pcrSelectionOut(TPML: count(4) + sel(2+1+3)) pcrValues(TPML_DIGEST: count(4) digests) */
	off = 10 + 4;
	if (off + 4 > n)
		goto bad;
	count = get32(r + off);
	off += 4 + count * 6;
	if (off + 4 > n)
		goto bad;
	count = get32(r + off);
	off += 4;
	if (count != want) {
		last_error = "PCR bank incomplete (one PCR_Read reads at most eight)";
		return (false);
	}
	*len = 0;
	for (i = 0; i < count; i++) {
		uint16_t sz;

		if (off + 2 > n)
			goto bad;
		sz = get16(r + off);
		off += 2;
		if (off + sz > n || *len + sz > cap)
			goto bad;
		memcpy(out + *len, r + off, sz);
		*len += sz;
		off += sz;
	}
	return (true);
bad:
	last_error = "bad PCR_Read response";
	return (false);
}

bool
efi_tpm_pcr_bank_sha256(uint32_t mask, uint8_t out[32])
{
	uint8_t bank[8 * 32];
	size_t len;
	SHA256_CTX ctx;

	if (!efi_tpm_pcr_read(mask, bank, sizeof(bank), &len))
		return (false);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, bank, len);
	SHA256_Final(out, &ctx);
	return (true);
}

/* --- NV counters, owner hierarchy, empty owner password --- */

bool
efi_tpm_nv_counter_read(uint32_t index, uint64_t *out)
{
	uint8_t c[64], r[64];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;
	uint32_t psize;

	put32(&b, TPM_RH_OWNER);		/* authHandle */
	put32(&b, index);			/* nvIndex */
	put_auth_pw(&b);
	put16(&b, 8);				/* size */
	put16(&b, 0);				/* offset */
	finish(&b, TPM_ST_SESSIONS, TPM_CC_NV_Read);
	if (!submit(&b, r, sizeof(r), &n) || n < 10 + 4 + 2 + 8)
		return (false);
	psize = get32(r + 10);
	if (psize < 10 || get16(r + 14) != 8) {
		last_error = "bad NV_Read response";
		return (false);
	}
	*out = get64(r + 16);
	return (true);
}

bool
efi_tpm_nv_counter_increment(uint32_t index)
{
	uint8_t c[64], r[64];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;

	put32(&b, TPM_RH_OWNER);
	put32(&b, index);
	put_auth_pw(&b);
	finish(&b, TPM_ST_SESSIONS, TPM_CC_NV_Increment);
	return (submit(&b, r, sizeof(r), &n));
}

bool
efi_tpm_nv_counter_define(uint32_t index)
{
	uint8_t c[96], r[64];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;

	put32(&b, TPM_RH_OWNER);		/* authHandle */
	put_auth_pw(&b);
	put16(&b, 0);				/* auth: empty */
	/* TPM2B_NV_PUBLIC: size, then TPMS_NV_PUBLIC */
	put16(&b, 4 + 2 + 4 + 2 + 2);
	put32(&b, index);
	put16(&b, TPM_ALG_SHA256);
	put32(&b, NV_ATTR_COUNTER | NV_ATTR_OWNERWRITE | NV_ATTR_AUTHWRITE |
	    NV_ATTR_OWNERREAD | NV_ATTR_AUTHREAD | NV_ATTR_NO_DA);
	put16(&b, 0);				/* authPolicy: empty */
	put16(&b, 8);				/* dataSize */
	finish(&b, TPM_ST_SESSIONS, TPM_CC_NV_DefineSpace);
	return (submit(&b, r, sizeof(r), &n));
}

/* --- unsealing under a policy --- */

/* PolicyPCR: the TPM folds its current PCRs of the selection into the
 * session's policy digest (pcrDigest empty: computed by the TPM). */
static bool
policy_pcr(uint32_t session, uint32_t mask)
{
	uint8_t c[64], r[64];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;

	put32(&b, session);
	put16(&b, 0);				/* pcrDigest: the TPM's */
	put32(&b, 1);				/* TPML_PCR_SELECTION: count */
	put16(&b, TPM_ALG_SHA256);
	put8(&b, 3);				/* sizeofSelect */
	put8(&b, mask & 0xff);
	put8(&b, (mask >> 8) & 0xff);
	put8(&b, (mask >> 16) & 0xff);
	finish(&b, TPM_ST_NO_SESSIONS, TPM_CC_PolicyPCR);
	return (submit(&b, r, sizeof(r), &n));
}

/* PolicyAuthValue: the object's auth value joins the authorization. */
static bool
policy_authvalue(uint32_t session)
{
	uint8_t c[32], r[64];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;

	put32(&b, session);
	finish(&b, TPM_ST_NO_SESSIONS, TPM_CC_PolicyAuthValue);
	return (submit(&b, r, sizeof(r), &n));
}

static void
flush_context(uint32_t handle)
{
	uint8_t c[16], r[32];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;

	put32(&b, handle);
	finish(&b, TPM_ST_NO_SESSIONS, TPM_CC_FlushContext);
	(void)submit(&b, r, sizeof(r), &n);
}

/*
 * Unseal with the policy session. Without an auth value the HMAC is
 * empty; with one (PolicyAuthValue asserted) the session is unsalted and
 * unbound, so the HMAC key is the auth value alone and the HMAC is over
 * cpHash || nonceCaller || nonceTPM || attributes -- the session is not
 * continued, the TPM closes it with the command.
 */
static bool
unseal(uint32_t session, const uint8_t *nonce_tpm, size_t nonce_tpm_len,
    uint32_t handle, const uint8_t *name, size_t namelen,
    const uint8_t *auth, size_t authlen, uint8_t *out, size_t cap,
    size_t *len)
{
	uint8_t c[128], r[256], nc[NONCE_LEN], mac[SHA256_DIGEST_LENGTH];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;
	uint32_t psize;
	uint16_t sz;

	put32(&b, handle);			/* itemHandle */
	nonce(nc, sizeof(nc));
	if (authlen > 0) {
		SHA256_CTX ctx;
		uint8_t cphash[SHA256_DIGEST_LENGTH], k[64], pad[64], inner[SHA256_DIGEST_LENGTH];
		uint8_t ccb[4] = { 0, 0, 0x01, 0x5e }, attrs = 0;
		size_t i;

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, ccb, 4);
		SHA256_Update(&ctx, name, namelen);
		SHA256_Final(cphash, &ctx);
		/* HMAC-SHA256(auth, cpHash || nonceCaller || nonceTPM || attrs) */
		memset(k, 0, sizeof(k));
		memcpy(k, auth, authlen > sizeof(k) ? sizeof(k) : authlen);
		for (i = 0; i < sizeof(pad); i++)
			pad[i] = k[i] ^ 0x36;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, pad, sizeof(pad));
		SHA256_Update(&ctx, cphash, sizeof(cphash));
		SHA256_Update(&ctx, nc, sizeof(nc));
		SHA256_Update(&ctx, nonce_tpm, nonce_tpm_len);
		SHA256_Update(&ctx, &attrs, 1);
		SHA256_Final(inner, &ctx);
		for (i = 0; i < sizeof(pad); i++)
			pad[i] = k[i] ^ 0x5c;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, pad, sizeof(pad));
		SHA256_Update(&ctx, inner, sizeof(inner));
		SHA256_Final(mac, &ctx);
		explicit_bzero(k, sizeof(k));
		explicit_bzero(pad, sizeof(pad));
		explicit_bzero(inner, sizeof(inner));
		put32(&b, 4 + 2 + sizeof(nc) + 1 + 2 + sizeof(mac));
		put32(&b, session);
		put16(&b, sizeof(nc));
		putbuf(&b, nc, sizeof(nc));
		put8(&b, 0);
		put16(&b, sizeof(mac));
		putbuf(&b, mac, sizeof(mac));
		explicit_bzero(mac, sizeof(mac));
	} else {
		put32(&b, 4 + 2 + 1 + 2);	/* authorizationSize */
		put32(&b, session);
		put16(&b, 0);			/* nonce: empty */
		put8(&b, 0);			/* sessionAttributes */
		put16(&b, 0);			/* hmac: empty */
	}
	finish(&b, TPM_ST_SESSIONS, TPM_CC_Unseal);
	if (!submit(&b, r, sizeof(r), &n) || n < 10 + 4 + 2)
		return (false);
	/* parameterSize(4) outData(TPM2B: size(2) bytes) auth response */
	psize = get32(r + 10);
	sz = get16(r + 14);
	if (psize < 2 + (uint32_t)sz || sz == 0 || sz > cap || 16 + sz > n) {
		last_error = "bad Unseal response";
		explicit_bzero(r, sizeof(r));
		return (false);
	}
	memcpy(out, r + 16, sz);
	*len = sz;
	explicit_bzero(r, sizeof(r));
	return (true);
}

/* The object's name (TPM2B_NAME of ReadPublic), the HMAC's cpHash needs it. */
static bool
read_name(uint32_t handle, uint8_t *name, size_t cap, size_t *namelen)
{
	uint8_t c[16], r[1024];
	struct bb b = { c, 10, sizeof(c) };
	size_t n, off;
	uint16_t sz;

	put32(&b, handle);
	finish(&b, TPM_ST_NO_SESSIONS, TPM_CC_ReadPublic);
	if (!submit(&b, r, sizeof(r), &n))
		return (false);
	off = 10;
	if (off + 2 > n)
		goto bad;
	sz = get16(r + off);				/* outPublic */
	off += 2 + sz;
	if (off + 2 > n)
		goto bad;
	sz = get16(r + off);				/* name */
	off += 2;
	if (sz == 0 || sz > cap || off + sz > n)
		goto bad;
	memcpy(name, r + off, sz);
	*namelen = sz;
	return (true);
bad:
	last_error = "bad ReadPublic response";
	return (false);
}

bool
efi_tpm_unseal(uint32_t handle, uint32_t pcr_mask, const uint8_t *auth,
    size_t authlen, uint8_t *out, size_t cap, size_t *len)
{
	uint8_t c[64], r[64], nonce_tpm[64], name[2 + SHA256_DIGEST_LENGTH];
	struct bb b = { c, 10, sizeof(c) };
	size_t n, nonce_tpm_len = 0, namelen = 0;
	uint32_t s;
	uint16_t nsz;

	if (authlen > 0 && !read_name(handle, name, sizeof(name), &namelen))
		return (false);
	/* StartAuthSession, keeping nonceTPM for the HMAC */
	{
		uint8_t nc[NONCE_LEN];

		nonce(nc, sizeof(nc));
		put32(&b, TPM_RH_NULL);
		put32(&b, TPM_RH_NULL);
		put16(&b, sizeof(nc));
		putbuf(&b, nc, sizeof(nc));
		put16(&b, 0);
		put8(&b, TPM_SE_POLICY);
		put16(&b, TPM_ALG_NULL);
		put16(&b, TPM_ALG_SHA256);
		finish(&b, TPM_ST_NO_SESSIONS, TPM_CC_StartAuthSession);
		if (!submit(&b, r, sizeof(r), &n) || n < 10 + 4 + 2)
			return (false);
		s = get32(r + 10);
		nsz = get16(r + 14);
		if (nsz == 0 || nsz > sizeof(nonce_tpm) || 16 + nsz > n) {
			last_error = "bad session nonce";
			return (false);
		}
		memcpy(nonce_tpm, r + 16, nsz);
		nonce_tpm_len = nsz;
	}
	if (!policy_pcr(s, pcr_mask) || (authlen > 0 && !policy_authvalue(s))) {
		flush_context(s);
		return (false);
	}
	/*
	 * Every policy command returns a fresh nonceTPM; the HMAC of Unseal
	 * uses the one from the last response. Read it back with a
	 * PolicyAuthValue-free round trip: PolicyPCR and PolicyAuthValue
	 * carry no session area, so nonceTPM is unchanged since
	 * StartAuthSession (part 1, 19.6.15: the nonce rolls only on
	 * commands that use the session in an authorization).
	 */
	if (!unseal(s, nonce_tpm, nonce_tpm_len, handle, name, namelen, auth,
	    authlen, out, cap, len)) {
		flush_context(s);
		return (false);
	}
	return (true);
}
