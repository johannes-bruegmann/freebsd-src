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
 */

#include <stand.h>
#include <string.h>

#include <efi.h>
#include <efilib.h>

#include <crypto/sha2/sha256.h>

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
#define	TPM_ALG_SHA256		0x000b
#define	TPM_CC_NV_DefineSpace	0x0000012au
#define	TPM_CC_NV_Increment	0x00000134u
#define	TPM_CC_NV_Read		0x0000014eu
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
		last_error = "TPM_RC error";
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

/* sha256 over the SHA256 bank of PCR 0..7, read in one PCR_Read. */
bool
tpm_pcr_bank(uint8_t out[static SHA256_DIGEST_LENGTH])
{
	uint8_t c[32], r[512];
	struct bb b = { c, 10, sizeof(c) };
	size_t n;
	uint32_t count, i, off;
	SHA256_CTX ctx;

	/* TPML_PCR_SELECTION: count=1, {hash=SHA256, sizeofSelect=3, select=ff 00 00} */
	put32(&b, 1);
	put16(&b, TPM_ALG_SHA256);
	put8(&b, 3);
	put8(&b, 0xff); put8(&b, 0x00); put8(&b, 0x00);
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
	if (count != 8) {
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
