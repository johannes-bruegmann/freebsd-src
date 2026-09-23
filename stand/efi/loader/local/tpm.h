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
 * is unsealed (tpm_unseal, since 15.09.2026): a persistent sealed object
 * under a PCR policy -- the GELI key file of tpm_keyfile.c. The policy
 * session is the TPM's own (PolicyPCR against its current PCRs); the
 * loader never sees a policy digest or an auth value, the object carries
 * no auth value by design, so an empty HMAC authorizes.
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
/* Unseal <handle> under a policy session bound to the PCRs of <pcr_mask>
 * (bit i = PCR i, SHA256 bank); the bytes go to out (at most cap). */
/* The storage key the sessions are salted to: its name's digest (baseline). */
bool	tpm_key_digest(uint32_t keyhandle, uint8_t out[static SHA256_DIGEST_LENGTH]);
/* Unseal under a salted, encrypting policy session (PCR policy; with an
 * auth value also PolicyAuthValue). key_digest, when given, must be the
 * storage key's; a refusal or a wrong HMAC is reported by tpm_last_error. */
bool	tpm_unseal(uint32_t keyhandle, const uint8_t *key_digest, uint32_t handle,
	    uint32_t pcr_mask, const uint8_t *auth, size_t authlen,
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
