/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * A TPM 2.0 client for the EFI loader, over EFI_TCG2_PROTOCOL.SubmitCommand
 * (libefi/efi_tpm.c). Read-only use of the TPM -- the clock, the PCR
 * banks, NV indices -- and the unsealing of a persistent object under a
 * PCR policy, optionally with an auth value: enough for a key file the
 * TPM releases only when the firmware measured the boot the owner sealed
 * it under.
 *
 * Every call returns false on failure and leaves the reason in
 * efi_tpm_error(); a TPM response code is reported as "TPM_RC 0x...".
 */

#ifndef _EFITPM_H_
#define	_EFITPM_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct efi_tpm_clock {
	uint64_t	clock;		/* ms, monotonic, persisted across resets */
	uint32_t	reset_count;	/* TPM resets (power cycles) */
	uint32_t	restart_count;	/* resumes since the last reset */
	bool		safe;		/* the clock is known not to have gone back */
};

/* A TPM answers (ReadClock succeeds). */
bool	efi_tpm_present(void);
/* The last failure, for messages. */
const char *efi_tpm_error(void);

bool	efi_tpm_read_clock(struct efi_tpm_clock *);

/*
 * The PCR selection: "0,2,7" into a bit mask of PCR 0..23 (false: a
 * PCR out of range or a stray character). The SHA256 bank of the
 * selected PCRs, in PCR order, into out: every digest is 32 bytes, *len
 * the total; and their sha256, a value that names the state of the
 * selected registers in one line.
 */
bool	efi_tpm_parse_pcrs(const char *list, uint32_t *mask);
bool	efi_tpm_pcr_read(uint32_t mask, uint8_t *out, size_t cap, size_t *len);
bool	efi_tpm_pcr_bank_sha256(uint32_t mask, uint8_t out[32]);

/*
 * An 8-byte NV counter index (TPMA_NV_COUNTER) under the owner
 * hierarchy with an empty owner password: define once, read, increment.
 */
bool	efi_tpm_nv_counter_define(uint32_t index);
bool	efi_tpm_nv_counter_read(uint32_t index, uint64_t *out);
bool	efi_tpm_nv_counter_increment(uint32_t index);

/*
 * Unseal the persistent object handle under a policy session that
 * asserts PolicyPCR over the selected PCRs and, when authlen > 0,
 * PolicyAuthValue with auth as the object's auth value (the SHA256 of a
 * passphrase, say). The session is neither salted nor bound: the bytes
 * cross the bus as the TPM returns them, which is what a plain
 * tpm2_unseal does as well; parameter encryption is a follow-up.
 */
bool	efi_tpm_unseal(uint32_t handle, uint32_t pcr_mask, const uint8_t *auth,
	    size_t authlen, uint8_t *out, size_t cap, size_t *len);

#endif /* _EFITPM_H_ */
