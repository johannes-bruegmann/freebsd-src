/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * tpm.h -- a TPM 2.0 through the firmware's TCG2 protocol.
 *
 * No driver stack: EFI_TCG2_PROTOCOL.SubmitCommand
 * carries raw TPM2 commands, the firmware owns the transport (Intel PTT on
 * this laptop). Three things are read: ReadClock (resetCount = a hardware
 * boot counter no software resets; clock = a monotonic persisted
 * millisecond clock), the SHA256 bank of PCR 0..7 (the firmware's own
 * measured boot), and elvboot's NV counter index, which the loader
 * increments once per boot (NV_Increment cannot be undone). One thing
 * is unsealed (tpm_unseal): a persistent sealed object under a policy
 * -- the GELI key file of tpm_keyfile.c. The policy is replayed step by
 * step into a salted session (struct tpm_policy_step: PCR, the object's
 * auth value, a PolicySecret against an NV index, a PolicyNV over an
 * index's bytes); the TPM alone decides whether the digest comes out,
 * the loader never sees a policy digest.
 *
 * Assumes: a TPM 2.0 is enabled in Setup and the firmware publishes the
 * TCG2 protocol. Absent TPM -> every call reports failure and the
 * corresponding claim is not present. The NV counter index is defined
 * once (tpm_nv_define_counter, owner auth empty) -- a firmware "clear
 * TPM" destroys it, which the next boot reports as a missing anchor.
 *
 * Not a catalog: internal to the local layer.
 */

#ifndef _LOCAL_TPM_H_
#define	_LOCAL_TPM_H_

#include <stdint.h>
#include <stdbool.h>

#include <crypto/sha2/sha256.h>

#ifndef LOADER_TRUST_TPM_NV_INDEX
#define	LOADER_TRUST_TPM_NV_INDEX	0x01c10e1fu	/* owner range, "elv" */
#endif

struct tpm_clock {
	uint64_t	clock;		/* ms, monotonic, persisted */
	uint32_t	reset_count;	/* TPM resets (power cycles) */
	uint32_t	restart_count;	/* resumes since the last reset */
	bool		safe;
};

bool	tpm_present(void);
bool	tpm_read_clock(struct tpm_clock *);
bool	tpm_parse_pcrs(const char *list, uint32_t *mask);		/* "0,2,7" -> bits */
bool	tpm_pcr_bank(uint32_t mask, uint8_t out[static SHA256_DIGEST_LENGTH]);	/* sha256 over the selected PCRs */
bool	tpm_nv_counter_read(uint64_t *);
bool	tpm_nv_counter_increment(void);
bool	tpm_nv_define_counter(void);
/* The storage key the sessions are salted to: its name's digest (baseline). */
bool	tpm_key_digest(uint32_t keyhandle, uint8_t out[static SHA256_DIGEST_LENGTH]);

/*
 * A policy is replayed step by step into the session, in the order the
 * object was sealed to (elebake `stage tpm seal` defines it; the digest
 * depends on the order). PCR: PolicyPCR over mask. AUTHVALUE: the object's
 * own auth (tpm_unseal's auth) joins the session HMAC. SECRET:
 * PolicySecret against an NV index whose authValue is auth -- proven by a
 * second salted HMAC session, the value never crosses the bus; a PIN_PASS
 * index counts it. NV: PolicyNV, operand <eo> the index's oplen bytes at
 * offset, the owner reading (empty auth). The NV operand is part of the
 * policy digest: it must be the value the object was sealed against.
 */
enum tpm_policy_op {
	TPM_POLICY_PCR = 1,
	TPM_POLICY_AUTHVALUE,
	TPM_POLICY_SECRET,
	TPM_POLICY_NV,
};

#define	TPM_EO_EQ		0x0000
#define	TPM_EO_NEQ		0x0001
#define	TPM_EO_UNSIGNED_GT	0x0003
#define	TPM_EO_UNSIGNED_LT	0x0005

struct tpm_policy_step {
	enum tpm_policy_op op;
	uint32_t	 mask;		/* PCR: bit i = PCR i, SHA256 bank */
	uint32_t	 index;		/* SECRET, NV: the NV index */
	const uint8_t	*auth;		/* SECRET: the index's authValue */
	size_t		 authlen;
	uint8_t		 operand[8];	/* NV: operandB, big-endian as stored */
	uint16_t	 oplen;		/* NV: 4 for pinCount, 8 for a counter */
	uint16_t	 offset;
	uint16_t	 eo;		/* NV: TPM_EO_* */
};

/* Unseal <handle> under a salted, encrypting policy session that replays
 * <steps>; auth is the object's own authValue (AUTHVALUE step), else NULL.
 * key_digest, when given, must be the storage key's; a refusal or a wrong
 * HMAC is reported by tpm_last_error. */
bool	tpm_unseal(uint32_t keyhandle, const uint8_t *key_digest, uint32_t handle,
	    const struct tpm_policy_step *steps, size_t nsteps,
	    const uint8_t *auth, size_t authlen,
	    uint8_t *out, size_t cap, size_t *len);
/* NV counters of the local layer: increment under a policy session
 * (PolicyCommandCode), read with the index's own empty auth. */
bool	tpm_nv_policy_increment(uint32_t keyhandle, uint32_t index);
bool	tpm_nv_index_read(uint32_t index, uint64_t *out);
/* the time anchors: whole-index write under PolicyPCR, generic read, the cap */
bool	tpm_nv_policy_write(uint32_t keyhandle, uint32_t index, uint32_t pcr_mask,
	    const uint8_t *data, uint16_t len);
bool	tpm_nv_read_bytes(uint32_t index, uint8_t *out, uint16_t len);
bool	tpm_pcr_extend(uint32_t pcr, const uint8_t digest[static SHA256_DIGEST_LENGTH]);
const char *tpm_last_error(void);

#endif /* _LOCAL_TPM_H_ */
