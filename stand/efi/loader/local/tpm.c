/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * tpm.c -- TPM 2.0 commands over EFI_TCG2_PROTOCOL.SubmitCommand (tpm.h).
 *
 * The protocol and the command formats follow the TCG EFI Protocol
 * Specification (family 2.0) and the TPM 2.0 Library, part 3. Only the
 * fields this file uses are declared; everything is big-endian on the
 * wire.
 *
 * Every session that carries a secret is salted to the TPM's storage key
 * and encrypts its parameters (part 1, 19.6): the salt leaves this CPU
 * only RSA-OAEP-encrypted, the session key is derived from it on both
 * ends, the unsealed bytes come back AES-CFB-encrypted, and every command
 * and response carries an HMAC. Nothing readable crosses the bus, and a
 * TPM that is not the one the baseline names cannot answer (
 * the sealing concept asked for encrypted sessions from the start).
 */

#include <stand.h>
#include <string.h>

#include <efi.h>
#include <efilib.h>

#include <crypto/sha2/sha256.h>
#include <crypto/rijndael/rijndael-api-fst.h>	/* AES-128-CFB of the session */
#include <bearssl.h>				/* RSA-OAEP: the salt to the storage key */

#include "tpm.h"

/* --- EFI_TCG2_PROTOCOL, the two members used --- */

static EFI_GUID tcg2_guid = { 0x607f766c, 0x7455, 0x42be,
    { 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f } };

typedef struct _EFI_TCG2_PROTOCOL EFI_TCG2_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_TCG2_GET_CAPABILITY)(EFI_TCG2_PROTOCOL *,
    void *);
typedef EFI_STATUS (EFIAPI *EFI_TCG2_GET_EVENT_LOG)(EFI_TCG2_PROTOCOL *,
    UINT32, EFI_PHYSICAL_ADDRESS *, EFI_PHYSICAL_ADDRESS *, BOOLEAN *);
typedef EFI_STATUS (EFIAPI *EFI_TCG2_HASH_LOG_EXTEND_EVENT)(EFI_TCG2_PROTOCOL *,
    UINT64, EFI_PHYSICAL_ADDRESS, UINT64, void *);
typedef EFI_STATUS (EFIAPI *EFI_TCG2_SUBMIT_COMMAND)(EFI_TCG2_PROTOCOL *,
    UINT32 InputParameterBlockSize, UINT8 *InputParameterBlock,
    UINT32 OutputParameterBlockSize, UINT8 *OutputParameterBlock);

struct _EFI_TCG2_PROTOCOL {
	EFI_TCG2_GET_CAPABILITY		GetCapability;
	EFI_TCG2_GET_EVENT_LOG		GetEventLog;
	EFI_TCG2_HASH_LOG_EXTEND_EVENT	HashLogExtendEvent;
	EFI_TCG2_SUBMIT_COMMAND		SubmitCommand;
	/* GetActivePcrBanks, SetActivePcrBanks, GetResultOfSetActivePcrBanks */
};

/* --- TPM 2.0 constants --- */

#define	TPM_ST_NO_SESSIONS	0x8001
#define	TPM_ST_SESSIONS		0x8002
#define	TPM_RC_SUCCESS		0x000
#define	TPM_RS_PW		0x40000009u
#define	TPM_RH_OWNER		0x40000001u
#define	TPM_RH_NULL		0x40000007u
#define	TPM_SE_POLICY		0x01
#define	TPM_ALG_RSA		0x0001
#define	TPM_ALG_AES		0x0006
#define	TPM_ALG_NULL		0x0010
#define	TPM_ALG_SHA256		0x000b
#define	TPM_ALG_CFB		0x0043
#define	TPMA_SESSION_ENCRYPT	0x40
#define	TPM_CC_Unseal		0x0000015eu
#define	TPM_CC_FlushContext	0x00000165u
#define	TPM_CC_StartAuthSession	0x00000176u
#define	TPM_CC_PolicyPCR	0x0000017fu
#define	TPM_CC_PolicyAuthValue	0x0000016bu
#define	TPM_CC_PolicyCommandCode 0x0000016cu
#define	TPM_CC_ReadPublic	0x00000173u
#define	TPM_CC_NV_DefineSpace	0x0000012au
#define	TPM_CC_NV_Increment	0x00000134u
#define	TPM_CC_NV_Read		0x0000014eu
#define	TPM_CC_NV_Write		0x00000137u
#define	TPM_CC_PCR_Extend	0x00000182u
#define	TPM_CC_NV_ReadPublic	0x00000169u
#define	TPM_CC_PCR_Read		0x0000017eu
#define	TPM_CC_ReadClock	0x00000181u
#define	TPMA_NV_COUNTER		0x00000010u
#define	TPMA_NV_OWNERWRITE	0x00000002u
#define	TPMA_NV_AUTHWRITE	0x00000004u
#define	TPMA_NV_OWNERREAD	0x00020000u
#define	TPMA_NV_AUTHREAD	0x00040000u
#define	TPMA_NV_NO_DA		0x02000000u

static const char *last_error = "";

const char *
tpm_last_error(void)
{
	return (last_error);
}

/* "0,2,7" -> bit mask of the PCR selection (SHA256 bank, 24 PCRs). */
bool
tpm_parse_pcrs(const char *s, uint32_t *mask)
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
put64(struct bb *b, uint64_t v)
{
	put32(b, v >> 32); put32(b, v);
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

/* An empty password authorization session (TPMS_AUTH_COMMAND). */
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

bool
tpm_present(void)
{
	struct tpm_clock c;

	return (tpm_read_clock(&c));
}

bool
tpm_read_clock(struct tpm_clock *out)
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

/* sha256 over the SHA256 bank of the selected PCRs (a bit per PCR, 0..23),
 * read in one PCR_Read, in PCR order. */
bool
tpm_pcr_bank(uint32_t mask, uint8_t out[static SHA256_DIGEST_LENGTH])
{
	uint8_t c[32], r[512];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;
	uint32_t count, i, off, want = 0;
	SHA256_CTX ctx;

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
	/* pcrUpdateCounter(4) pcrSelectionOut(TPML: count(4) + 1 sel(2+1+3)) pcrValues(TPML_DIGEST: count(4) digests) */
	off = 10 + 4;
	if (off + 4 > n)
		return (false);
	count = get32(r + off);
	off += 4 + count * 6;
	if (off + 4 > n)
		return (false);
	count = get32(r + off);
	off += 4;
	if (count != want) {
		last_error = "PCR bank incomplete";
		return (false);
	}
	SHA256_Init(&ctx);
	for (i = 0; i < count; i++) {
		uint16_t sz;

		if (off + 2 > n)
			return (false);
		sz = get16(r + off);
		off += 2;
		if (off + sz > n)
			return (false);
		SHA256_Update(&ctx, r + off, sz);
		off += sz;
	}
	SHA256_Final(out, &ctx);
	return (true);
}

/* NV_Read of our 8-byte counter index; owner (empty password) authorizes. */
bool
tpm_nv_counter_read(uint64_t *out)
{
	uint8_t c[64], r[64];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;
	uint32_t psize;

	put32(&b, TPM_RH_OWNER);		/* authHandle */
	put32(&b, LOADER_TRUST_TPM_NV_INDEX);	/* nvIndex */
	put_auth_pw(&b);
	put16(&b, 8);				/* size */
	put16(&b, 0);				/* offset */
	finish(&b, TPM_ST_SESSIONS, TPM_CC_NV_Read);
	if (!submit(&b, r, sizeof(r), &n) || n < 10 + 4 + 2 + 8)
		return (false);
	psize = get32(r + 10);
	if (psize < 10 || get16(r + 14) != 8)
		return (false);
	*out = get64(r + 16);
	return (true);
}

bool
tpm_nv_counter_increment(void)
{
	uint8_t c[64], r[64];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;

	put32(&b, TPM_RH_OWNER);
	put32(&b, LOADER_TRUST_TPM_NV_INDEX);
	put_auth_pw(&b);
	finish(&b, TPM_ST_SESSIONS, TPM_CC_NV_Increment);
	return (submit(&b, r, sizeof(r), &n));
}

/* Define the counter index (once): owner-writable, owner-readable, no DA. */
bool
tpm_nv_define_counter(void)
{
	uint8_t c[96], r[64];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;

	put32(&b, TPM_RH_OWNER);		/* authHandle */
	put_auth_pw(&b);
	put16(&b, 0);				/* auth: empty */
	/* TPM2B_NV_PUBLIC: size, then TPMS_NV_PUBLIC */
	put16(&b, 4 + 2 + 4 + 2 + 2);
	put32(&b, LOADER_TRUST_TPM_NV_INDEX);
	put16(&b, TPM_ALG_SHA256);
	put32(&b, TPMA_NV_COUNTER | TPMA_NV_OWNERWRITE | TPMA_NV_AUTHWRITE |
	    TPMA_NV_OWNERREAD | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA);
	put16(&b, 0);				/* authPolicy: empty */
	put16(&b, 8);				/* dataSize */
	finish(&b, TPM_ST_SESSIONS, TPM_CC_NV_DefineSpace);
	return (submit(&b, r, sizeof(r), &n));
}


/* --- entropy: the salt and the nonces of a session, from this CPU --- */

/*
 * A salted session is only as secret as its salt: it must never cross the
 * TPM bus in clear (TPM2_GetRandom would), so it comes from RDRAND here.
 * amd64 only; a CPU without it refuses -- the loader does not fall back
 * to an unencrypted session, that would be the attack surface again.
 */
static bool
entropy(uint8_t *out, size_t n)
{
#if defined(__amd64__)
	uint64_t v;
	unsigned char ok;
	size_t i, tries;

	while (n > 0) {
		for (tries = 0; tries < 16; tries++) {
			__asm__ volatile("rdrand %0; setc %1" : "=r"(v), "=qm"(ok) :: "cc");
			if (ok)
				break;
		}
		if (!ok) {
			last_error = "no entropy (RDRAND)";
			return (false);
		}
		for (i = 0; i < 8 && n > 0; i++, n--)
			*out++ = (uint8_t)(v >> (8 * i));
	}
	return (true);
#else
	(void)out; (void)n;
	last_error = "no entropy on this architecture";
	return (false);
#endif
}

/* --- the primitives of a session: HMAC-SHA256, KDFa, AES-128-CFB --- */

static void
hmac256(const uint8_t *key, size_t klen, const uint8_t *m1, size_t l1,
    const uint8_t *m2, size_t l2, const uint8_t *m3, size_t l3,
    const uint8_t *m4, size_t l4, uint8_t out[SHA256_DIGEST_LENGTH])
{
	SHA256_CTX ctx;
	uint8_t k[64], pad[64], inner[SHA256_DIGEST_LENGTH];
	size_t i;

	memset(k, 0, sizeof(k));
	if (klen > sizeof(k)) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key, klen);
		SHA256_Final(k, &ctx);
	} else
		memcpy(k, key, klen);
	for (i = 0; i < sizeof(pad); i++)
		pad[i] = k[i] ^ 0x36;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, pad, sizeof(pad));
	if (l1) SHA256_Update(&ctx, m1, l1);
	if (l2) SHA256_Update(&ctx, m2, l2);
	if (l3) SHA256_Update(&ctx, m3, l3);
	if (l4) SHA256_Update(&ctx, m4, l4);
	SHA256_Final(inner, &ctx);
	for (i = 0; i < sizeof(pad); i++)
		pad[i] = k[i] ^ 0x5c;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, pad, sizeof(pad));
	SHA256_Update(&ctx, inner, sizeof(inner));
	SHA256_Final(out, &ctx);
	explicit_bzero(k, sizeof(k));
	explicit_bzero(pad, sizeof(pad));
	explicit_bzero(inner, sizeof(inner));
}

/*
 * KDFa (TPM 2.0 part 1, 11.4.10; SP800-108 counter mode with HMAC-SHA256):
 * HMAC(key, [i]32 || label || 00 || contextU || contextV || [bits]32), one
 * block of 32 bytes per counter value; out holds bits/8 bytes, at most 64.
 */
static void
kdfa(const uint8_t *key, size_t klen, const char *label,
    const uint8_t *cu, size_t culen, const uint8_t *cv, size_t cvlen,
    uint32_t bits, uint8_t *out)
{
	uint8_t hdr[4], lab[8], tail[4], blk[SHA256_DIGEST_LENGTH];
	size_t lablen = strlen(label) + 1, want = bits / 8, got = 0;
	uint32_t i = 1;

	memcpy(lab, label, lablen);		/* the label with its NUL */
	tail[0] = bits >> 24; tail[1] = bits >> 16; tail[2] = bits >> 8; tail[3] = bits;
	while (got < want) {
		uint8_t ctx[128];
		size_t n = 0;

		hdr[0] = i >> 24; hdr[1] = i >> 16; hdr[2] = i >> 8; hdr[3] = i;
		memcpy(ctx + n, cu, culen); n += culen;
		memcpy(ctx + n, cv, cvlen); n += cvlen;
		hmac256(key, klen, hdr, 4, lab, lablen, ctx, n, tail, 4, blk);
		memcpy(out + got, blk, want - got < sizeof(blk) ? want - got : sizeof(blk));
		got += sizeof(blk);
		i++;
	}
	explicit_bzero(blk, sizeof(blk));
}

/* AES-128-CFB decrypt in place: keystream = AES(prev cipher block), first the IV. */
static bool
cfb_decrypt(const uint8_t key[16], const uint8_t iv[16], uint8_t *buf, size_t len)
{
	keyInstance k;
	cipherInstance c;
	uint8_t prev[16], ks[16];
	size_t i, j;

	if (rijndael_makeKey(&k, DIR_ENCRYPT, 128, (const char *)key) < 0 ||
	    rijndael_cipherInit(&c, MODE_ECB, NULL) < 0) {
		last_error = "AES setup failed";
		return (false);
	}
	memcpy(prev, iv, 16);
	for (i = 0; i < len; i += 16) {
		size_t n = len - i < 16 ? len - i : 16;

		if (rijndael_blockEncrypt(&c, &k, prev, 128, ks) != 128) {
			last_error = "AES failed";
			return (false);
		}
		memcpy(prev, buf + i, n);		/* the cipher block feeds the next */
		for (j = 0; j < n; j++)
			buf[i + j] ^= ks[j];
	}
	explicit_bzero(&k, sizeof(k));
	explicit_bzero(ks, sizeof(ks));
	explicit_bzero(prev, sizeof(prev));
	return (true);
}

/* --- the TPM's storage key: ReadPublic, its name, the OAEP salt --- */

/* BearSSL's PRNG interface over entropy(): the OAEP padding draws from it. */
struct rdrand_prng { const br_prng_class *vt; };

static void
rdrand_init(const br_prng_class **ctx __unused, const void *params __unused,
    const void *seed __unused, size_t seed_len __unused)
{
}

static void
rdrand_generate(const br_prng_class **ctx __unused, void *out, size_t len)
{
	if (!entropy(out, len))
		memset(out, 0, len);		/* refused later: entropy() set last_error */
}

static void
rdrand_update(const br_prng_class **ctx __unused, const void *seed __unused,
    size_t seed_len __unused)
{
}

static const br_prng_class rdrand_vtable = {
	sizeof(struct rdrand_prng), rdrand_init, rdrand_generate, rdrand_update
};

struct tpm_key {
	uint8_t		 name[2 + SHA256_DIGEST_LENGTH];	/* TPM2B_NAME body: alg || digest */
	size_t		 namelen;
	uint8_t		 n[512];		/* the RSA modulus, big-endian */
	size_t		 nlen;
	uint32_t	 e;
};

/*
 * ReadPublic of the storage key the sessions are salted to: its RSA
 * public key for the salt, its name for the command HMACs and for the
 * comparison against the baseline. Only an RSA key with SHA256 as name
 * algorithm is taken.
 */
static bool
read_public(uint32_t handle, struct tpm_key *k)
{
	uint8_t c[16], r[1024];
	struct bb b = { c, 10, sizeof(c) };
	size_t n, off, pub_end;
	uint16_t sz, type, alg, sym, scheme, nsz;
	uint32_t attrs;

	put32(&b, handle);
	finish(&b, TPM_ST_NO_SESSIONS, TPM_CC_ReadPublic);
	if (!submit(&b, r, sizeof(r), &n))
		return (false);
	/* outPublic: TPM2B_PUBLIC{size, TPMT_PUBLIC{type, nameAlg, attrs, authPolicy 2B, parameters, unique}} */
	off = 10;
	if (off + 2 > n)
		goto bad;
	sz = get16(r + off); off += 2;
	pub_end = off + sz;
	if (pub_end > n || sz < 2 + 2 + 4 + 2)
		goto bad;
	type = get16(r + off); alg = get16(r + off + 2); attrs = get32(r + off + 4);
	off += 8;
	(void)attrs;
	if (alg != TPM_ALG_SHA256) {
		last_error = "object name is not SHA256";
		return (false);
	}
	k->nlen = 0;
	k->e = 0;
	if (type == TPM_ALG_RSA) {
		off += 2 + get16(r + off);			/* authPolicy */
		/* TPMS_RSA_PARMS: symmetric{alg [keyBits mode]} scheme{alg [hash]} keyBits exponent */
		if (off + 2 > pub_end)
			goto bad;
		sym = get16(r + off); off += 2;
		if (sym != TPM_ALG_NULL)
			off += 4;
		if (off + 2 > pub_end)
			goto bad;
		scheme = get16(r + off); off += 2;
		if (scheme != TPM_ALG_NULL)
			off += 2;
		if (off + 2 + 4 + 2 > pub_end)
			goto bad;
		off += 2;					/* keyBits */
		k->e = get32(r + off); off += 4;
		if (k->e == 0)
			k->e = 65537;
		nsz = get16(r + off); off += 2;
		if (nsz == 0 || nsz > sizeof(k->n) || off + nsz > pub_end)
			goto bad;
		memcpy(k->n, r + off, nsz);
		k->nlen = nsz;
	}
	/* name: TPM2B_NAME (any object type: the sealed ones too) */
	off = pub_end;
	if (off + 2 > n)
		goto bad;
	nsz = get16(r + off); off += 2;
	if (nsz != sizeof(k->name) || off + nsz > n)
		goto bad;
	memcpy(k->name, r + off, nsz);
	k->namelen = nsz;
	return (true);
bad:
	last_error = "bad ReadPublic response";
	return (false);
}

bool
tpm_key_digest(uint32_t handle, uint8_t out[static SHA256_DIGEST_LENGTH])
{
	struct tpm_key k;

	if (!read_public(handle, &k))
		return (false);
	memcpy(out, k.name + 2, SHA256_DIGEST_LENGTH);	/* the name minus its algorithm */
	return (true);
}

/* --- the session --- */

struct session {
	uint32_t	 handle;
	uint8_t		 key[SHA256_DIGEST_LENGTH];	/* sessionKey */
	uint8_t		 nonce_caller[32];
	uint8_t		 nonce_tpm[32];
	size_t		 nonce_tpm_len;
	uint8_t		 auth[SHA256_DIGEST_LENGTH];	/* the object's authValue */
	size_t		 authlen;
};

/*
 * A policy session, salted to the storage key and set up for parameter
 * encryption (AES-128-CFB): the salt is OAEP-encrypted to the key with
 * the label "SECRET", the session key is KDFa(salt, "ATH", nonces). What
 * the TPM returns to this session is encrypted with a key nobody on the
 * bus can derive, and every command carries an HMAC only the two ends can
 * compute.
 */
static bool
session_start(const struct tpm_key *k, uint32_t keyhandle, struct session *s)
{
	uint8_t c[1024], r[128], salt[32], enc[512];
	struct bb b = { c, 10, sizeof(c) };
	struct rdrand_prng prng = { &rdrand_vtable };
	const br_prng_class **rnd = &prng.vt;
	br_rsa_public_key pk;
	size_t n, enclen, i;
	uint16_t nsz;
	static const char label[] = "SECRET";

	memset(s, 0, sizeof(*s));
	if (!entropy(salt, sizeof(salt)) || !entropy(s->nonce_caller, sizeof(s->nonce_caller)))
		return (false);
	pk.n = (unsigned char *)(uintptr_t)k->n;
	pk.nlen = k->nlen;
	{
		static uint8_t ebuf[4];
		ebuf[0] = k->e >> 24; ebuf[1] = k->e >> 16; ebuf[2] = k->e >> 8; ebuf[3] = k->e;
		pk.e = ebuf; pk.elen = 4;
	}
	enclen = br_rsa_i31_oaep_encrypt(rnd, &br_sha256_vtable, label, sizeof(label),
	    &pk, enc, sizeof(enc), salt, sizeof(salt));
	if (enclen == 0 || enclen != k->nlen) {
		last_error = "salt encryption failed";
		explicit_bzero(salt, sizeof(salt));
		return (false);
	}
	put32(&b, keyhandle);			/* tpmKey: the salt goes to it */
	put32(&b, TPM_RH_NULL);			/* bind: none */
	put16(&b, sizeof(s->nonce_caller));
	for (i = 0; i < sizeof(s->nonce_caller); i++)
		put8(&b, s->nonce_caller[i]);
	put16(&b, enclen);			/* encryptedSalt */
	for (i = 0; i < enclen; i++)
		put8(&b, enc[i]);
	put8(&b, TPM_SE_POLICY);
	put16(&b, TPM_ALG_AES);			/* symmetric: AES-128-CFB */
	put16(&b, 128);
	put16(&b, TPM_ALG_CFB);
	put16(&b, TPM_ALG_SHA256);		/* authHash */
	finish(&b, TPM_ST_NO_SESSIONS, TPM_CC_StartAuthSession);
	if (!submit(&b, r, sizeof(r), &n) || n < 10 + 4 + 2) {
		explicit_bzero(salt, sizeof(salt));
		return (false);
	}
	s->handle = get32(r + 10);
	nsz = get16(r + 14);
	if (nsz == 0 || nsz > sizeof(s->nonce_tpm) || 16 + nsz > n) {
		last_error = "bad session nonce";
		explicit_bzero(salt, sizeof(salt));
		return (false);
	}
	memcpy(s->nonce_tpm, r + 16, nsz);
	s->nonce_tpm_len = nsz;
	kdfa(salt, sizeof(salt), "ATH", s->nonce_tpm, s->nonce_tpm_len,
	    s->nonce_caller, sizeof(s->nonce_caller), 256, s->key);
	explicit_bzero(salt, sizeof(salt));
	explicit_bzero(enc, sizeof(enc));
	return (true);
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

static void
session_end(struct session *s)
{
	flush_context(s->handle);
	explicit_bzero(s, sizeof(*s));
}

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

/* PolicyAuthValue: the object's authValue joins the session's HMAC key. */
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

/* PolicyCommandCode: the session authorizes exactly this command. */
static bool
policy_command_code(uint32_t session, uint32_t cc)
{
	uint8_t c[32], r[64];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;

	put32(&b, session);
	put32(&b, cc);
	finish(&b, TPM_ST_NO_SESSIONS, TPM_CC_PolicyCommandCode);
	return (submit(&b, r, sizeof(r), &n));
}

/*
 * The authorization area of a command under the session: a fresh
 * nonceCaller, the attributes, and HMAC(sessionKey || authValue,
 * cpHash || nonceCaller || nonceTPM || attributes) with cpHash =
 * H(commandCode || names || parameters).
 */
static bool
put_auth_session(struct bb *b, struct session *s, uint8_t attrs,
    uint32_t cc, const uint8_t *names, size_t nameslen,
    const uint8_t *params, size_t paramslen)
{
	SHA256_CTX ctx;
	uint8_t cphash[SHA256_DIGEST_LENGTH], mac[SHA256_DIGEST_LENGTH];
	uint8_t key[2 * SHA256_DIGEST_LENGTH], ccb[4];
	size_t i;

	if (!entropy(s->nonce_caller, sizeof(s->nonce_caller)))
		return (false);
	ccb[0] = cc >> 24; ccb[1] = cc >> 16; ccb[2] = cc >> 8; ccb[3] = cc;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, ccb, 4);
	SHA256_Update(&ctx, names, nameslen);
	if (paramslen)
		SHA256_Update(&ctx, params, paramslen);
	SHA256_Final(cphash, &ctx);
	memcpy(key, s->key, sizeof(s->key));
	memcpy(key + sizeof(s->key), s->auth, s->authlen);
	hmac256(key, sizeof(s->key) + s->authlen, cphash, sizeof(cphash),
	    s->nonce_caller, sizeof(s->nonce_caller), s->nonce_tpm, s->nonce_tpm_len,
	    &attrs, 1, mac);
	put32(b, 4 + 2 + sizeof(s->nonce_caller) + 1 + 2 + sizeof(mac));
	put32(b, s->handle);
	put16(b, sizeof(s->nonce_caller));
	for (i = 0; i < sizeof(s->nonce_caller); i++)
		put8(b, s->nonce_caller[i]);
	put8(b, attrs);
	put16(b, sizeof(mac));
	for (i = 0; i < sizeof(mac); i++)
		put8(b, mac[i]);
	explicit_bzero(key, sizeof(key));
	return (true);
}

/*
 * The response under the session: parameterSize, the parameters, then
 * nonceTPM, attributes, HMAC(sessionKey || authValue, rpHash || nonceTPM
 * || nonceCaller || attributes) with rpHash = H(rc || cc || parameters).
 * The parameters stay in r; poff and plen locate them. A wrong HMAC is a
 * TPM that is not the one the session was started with.
 */
static bool
check_response(struct session *s, uint32_t cc, const uint8_t *r, size_t n,
    size_t *poff, size_t *plen)
{
	SHA256_CTX ctx;
	uint8_t rphash[SHA256_DIGEST_LENGTH], mac[SHA256_DIGEST_LENGTH];
	uint8_t key[2 * SHA256_DIGEST_LENGTH], hdr[8], attrs;
	uint32_t psize;
	size_t off;
	uint16_t nsz, msz;

	if (n < 10 + 4)
		goto bad;
	psize = get32(r + 10);
	*poff = 14;
	*plen = psize;
	off = 14 + psize;
	if (off + 2 > n)
		goto bad;
	nsz = get16(r + off); off += 2;
	if (nsz == 0 || nsz > sizeof(s->nonce_tpm) || off + nsz + 1 + 2 > n)
		goto bad;
	memcpy(s->nonce_tpm, r + off, nsz);
	s->nonce_tpm_len = nsz;
	off += nsz;
	attrs = r[off]; off += 1;
	msz = get16(r + off); off += 2;
	if (msz != sizeof(mac) || off + msz > n)
		goto bad;
	memcpy(hdr, r + 6, 4);				/* responseCode */
	hdr[4] = cc >> 24; hdr[5] = cc >> 16; hdr[6] = cc >> 8; hdr[7] = cc;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, hdr, 8);
	SHA256_Update(&ctx, r + *poff, *plen);
	SHA256_Final(rphash, &ctx);
	memcpy(key, s->key, sizeof(s->key));
	memcpy(key + sizeof(s->key), s->auth, s->authlen);
	hmac256(key, sizeof(s->key) + s->authlen, rphash, sizeof(rphash),
	    s->nonce_tpm, s->nonce_tpm_len, s->nonce_caller, sizeof(s->nonce_caller),
	    &attrs, 1, mac);
	explicit_bzero(key, sizeof(key));
	if (memcmp(mac, r + off, sizeof(mac)) != 0) {
		last_error = "response HMAC wrong (not the TPM the session was started with)";
		return (false);
	}
	return (true);
bad:
	last_error = "bad session response";
	return (false);
}

/*
 * Unseal under the session, the first response parameter encrypted by
 * the TPM with KDFa(sessionKey || authValue, "CFB", nonceTPM,
 * nonceCaller) -- decrypted here, never in clear on the bus.
 */
static bool
unseal(struct session *s, uint32_t handle, const uint8_t *name, size_t namelen,
    uint8_t *out, size_t cap, size_t *len)
{
	uint8_t c[256], r[512], kiv[32];
	struct bb b = { c, 10, sizeof(c) };
	size_t n, poff, plen;
	uint16_t sz;
	uint8_t key[2 * SHA256_DIGEST_LENGTH];

	put32(&b, handle);			/* itemHandle */
	if (!put_auth_session(&b, s, TPMA_SESSION_ENCRYPT, TPM_CC_Unseal, name, namelen, NULL, 0))
		return (false);
	finish(&b, TPM_ST_SESSIONS, TPM_CC_Unseal);
	if (!submit(&b, r, sizeof(r), &n))
		return (false);
	if (!check_response(s, TPM_CC_Unseal, r, n, &poff, &plen))
		goto out;
	/* outData: TPM2B, its size in clear, its bytes encrypted */
	if (plen < 2)
		goto bad;
	sz = get16(r + poff);
	if (sz == 0 || sz > cap || 2 + (size_t)sz > plen)
		goto bad;
	memcpy(key, s->key, sizeof(s->key));
	memcpy(key + sizeof(s->key), s->auth, s->authlen);
	kdfa(key, sizeof(s->key) + s->authlen, "CFB", s->nonce_tpm, s->nonce_tpm_len,
	    s->nonce_caller, sizeof(s->nonce_caller), 256, kiv);
	explicit_bzero(key, sizeof(key));
	memcpy(out, r + poff + 2, sz);
	if (!cfb_decrypt(kiv, kiv + 16, out, sz))
		goto out;
	*len = sz;
	explicit_bzero(kiv, sizeof(kiv));
	explicit_bzero(r, sizeof(r));
	return (true);
bad:
	last_error = "bad unseal response";
out:
	explicit_bzero(kiv, sizeof(kiv));
	explicit_bzero(r, sizeof(r));
	return (false);
}

bool
tpm_unseal(uint32_t keyhandle, const uint8_t *key_digest, uint32_t handle,
    uint32_t pcr_mask, const uint8_t *auth, size_t authlen,
    uint8_t *out, size_t cap, size_t *len)
{
	struct tpm_key k;
	struct tpm_key obj;
	struct session s;
	bool ok;

	if (!read_public(keyhandle, &k))
		return (false);
	if (k.nlen == 0) {
		last_error = "storage key is not RSA";
		return (false);
	}
	if (key_digest != NULL && memcmp(key_digest, k.name + 2, SHA256_DIGEST_LENGTH) != 0) {
		last_error = "storage key is not the one in the baseline";
		return (false);
	}
	if (!read_public(handle, &obj))	/* the sealed object's name, for the HMAC */
		return (false);
	if (!session_start(&k, keyhandle, &s))
		return (false);
	if (authlen > sizeof(s.auth))
		authlen = sizeof(s.auth);
	memcpy(s.auth, auth, authlen);
	s.authlen = authlen;
	ok = policy_pcr(s.handle, pcr_mask) &&
	    (authlen == 0 || policy_authvalue(s.handle)) &&
	    unseal(&s, handle, obj.name, obj.namelen, out, cap, len);
	session_end(&s);			/* the TPM closed it with Unseal; a failure leaves it */
	return (ok);
}

/*
 * NV_Increment of an index whose policy is PolicyCommandCode(NV_Increment):
 * under a salted session, the index authorizing itself (empty authValue).
 * Its name comes from NV_ReadPublic.
 */
/* NV_ReadPublic: the index's name (2 + 32 bytes) for the cpHash. */
static bool
nv_name(uint32_t index, uint8_t nvname[static 2 + SHA256_DIGEST_LENGTH])
{
	uint8_t c[64], r[256];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;
	uint16_t sz, nsz;

	/* NV_ReadPublic: nvPublic (2B), nvName (2B) */
	put32(&b, index);
	finish(&b, TPM_ST_NO_SESSIONS, TPM_CC_NV_ReadPublic);
	if (!submit(&b, r, sizeof(r), &n) || n < 12)
		return (false);
	sz = get16(r + 10);
	if (12 + sz + 2 > n)
		return (false);
	nsz = get16(r + 12 + sz);
	if (nsz != 2 + SHA256_DIGEST_LENGTH || 14 + sz + nsz > n) {
		last_error = "bad NV name";
		return (false);
	}
	memcpy(nvname, r + 14 + sz, nsz);
	return (true);
}

bool
tpm_nv_policy_increment(uint32_t keyhandle, uint32_t index)
{
	uint8_t c[256], r[256], names[2 * (2 + SHA256_DIGEST_LENGTH)], nvname[2 + SHA256_DIGEST_LENGTH];
	struct bb b = { c, 10, sizeof(c) };
	struct tpm_key k;
	struct session s;
	size_t n, poff, plen;
	bool ok;

	if (!read_public(keyhandle, &k) || k.nlen == 0) {
		last_error = "storage key is not RSA";
		return (false);
	}
	if (!nv_name(index, nvname))
		return (false);
	if (!session_start(&k, keyhandle, &s))
		return (false);
	memcpy(names, nvname, sizeof(nvname));			/* authHandle: the index */
	memcpy(names + sizeof(nvname), nvname, sizeof(nvname));	/* nvIndex */
	b.n = 10;
	put32(&b, index);				/* authHandle */
	put32(&b, index);				/* nvIndex */
	ok = policy_command_code(s.handle, TPM_CC_NV_Increment) &&
	    put_auth_session(&b, &s, 0, TPM_CC_NV_Increment, names, sizeof(names), NULL, 0);
	if (ok) {
		finish(&b, TPM_ST_SESSIONS, TPM_CC_NV_Increment);
		ok = submit(&b, r, sizeof(r), &n) &&
		    check_response(&s, TPM_CC_NV_Increment, r, n, &poff, &plen);
	}
	session_end(&s);
	return (ok);
}

/* NV_Read of a counter index that reads with its own empty auth (AUTHREAD). */
bool
tpm_nv_index_read(uint32_t index, uint64_t *out)
{
	uint8_t c[64], r[64];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;
	uint32_t psize;

	put32(&b, index);			/* authHandle: the index itself */
	put32(&b, index);			/* nvIndex */
	put_auth_pw(&b);
	put16(&b, 8);				/* size */
	put16(&b, 0);				/* offset */
	finish(&b, TPM_ST_SESSIONS, TPM_CC_NV_Read);
	if (!submit(&b, r, sizeof(r), &n) || n < 10 + 4 + 2 + 8)
		return (false);
	psize = get32(r + 10);
	if (psize < 10 || get16(r + 14) != 8)
		return (false);
	*out = get64(r + 16);
	return (true);
}

/*
 * NV_Write of a whole index under a salted session whose policy is
 * PolicyPCR over the selection (the anchor indices: the loader
 * writes while the cap PCR still holds its boot value). The index
 * authorizes itself (empty authValue); the data go as one TPM2B at offset 0.
 */
bool
tpm_nv_policy_write(uint32_t keyhandle, uint32_t index, uint32_t pcr_mask,
    const uint8_t *data, uint16_t len)
{
	uint8_t c[512], r[256], names[2 * (2 + SHA256_DIGEST_LENGTH)], nvname[2 + SHA256_DIGEST_LENGTH];
	uint8_t params[4 + 256];
	struct bb b = { c, 10, sizeof(c) };
	struct tpm_key k;
	struct session s;
	size_t n, poff, plen, i;
	bool ok;

	if (len == 0 || len > 256) {
		last_error = "NV write size";
		return (false);
	}
	if (!read_public(keyhandle, &k) || k.nlen == 0) {
		last_error = "storage key is not RSA";
		return (false);
	}
	if (!nv_name(index, nvname))
		return (false);
	if (!session_start(&k, keyhandle, &s))
		return (false);
	memcpy(names, nvname, sizeof(nvname));			/* authHandle: the index */
	memcpy(names + sizeof(nvname), nvname, sizeof(nvname));	/* nvIndex */
	/* parameters as hashed into cpHash: TPM2B data, UINT16 offset */
	params[0] = len >> 8; params[1] = len & 0xff;
	memcpy(params + 2, data, len);
	params[2 + len] = 0; params[3 + len] = 0;
	b.n = 10;
	put32(&b, index);				/* authHandle */
	put32(&b, index);				/* nvIndex */
	ok = policy_pcr(s.handle, pcr_mask) &&
	    put_auth_session(&b, &s, 0, TPM_CC_NV_Write, names, sizeof(names),
	    params, 4 + len);
	if (ok) {
		put16(&b, len);
		for (i = 0; i < len; i++)
			put8(&b, data[i]);
		put16(&b, 0);				/* offset */
		finish(&b, TPM_ST_SESSIONS, TPM_CC_NV_Write);
		ok = submit(&b, r, sizeof(r), &n) &&
		    check_response(&s, TPM_CC_NV_Write, r, n, &poff, &plen);
	}
	session_end(&s);
	return (ok);
}

/* NV_Read of len bytes from an index that reads with its own empty auth. */
bool
tpm_nv_read_bytes(uint32_t index, uint8_t *out, uint16_t len)
{
	uint8_t c[64], r[64 + 256];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;
	uint32_t psize;

	if (len == 0 || len > 256)
		return (false);
	put32(&b, index);			/* authHandle: the index itself */
	put32(&b, index);			/* nvIndex */
	put_auth_pw(&b);
	put16(&b, len);				/* size */
	put16(&b, 0);				/* offset */
	finish(&b, TPM_ST_SESSIONS, TPM_CC_NV_Read);
	if (!submit(&b, r, sizeof(r), &n) || n < 10 + 4 + 2 + (size_t)len)
		return (false);
	psize = get32(r + 10);
	if (psize < 2 + (uint32_t)len || get16(r + 14) != len)
		return (false);
	memcpy(out, r + 16, len);
	return (true);
}

/*
 * PCR_Extend with one sha256 digest, the PCR authorizing itself (empty
 * password): the cap that ends this boot's write permission on the anchor
 * index -- and, extended once more by elvbootd at shutdown, the one that
 * opens the shutdown index for the runtime only.
 */
bool
tpm_pcr_extend(uint32_t pcr, const uint8_t digest[static SHA256_DIGEST_LENGTH])
{
	uint8_t c[128], r[64];
	struct bb b = { c, 10, sizeof(c) };
	size_t n, i;

	if (pcr > 23) {
		last_error = "PCR index";
		return (false);
	}
	put32(&b, pcr);				/* pcrHandle */
	put_auth_pw(&b);
	put32(&b, 1);				/* TPML_DIGEST_VALUES: count */
	put16(&b, TPM_ALG_SHA256);
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		put8(&b, digest[i]);
	finish(&b, TPM_ST_SESSIONS, TPM_CC_PCR_Extend);
	return (submit(&b, r, sizeof(r), &n));
}
