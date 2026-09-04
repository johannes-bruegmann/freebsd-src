/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * tpm.h -- read-only use of a TPM 2.0 through the firmware's TCG2 protocol.
 *
 * No sealing, no keys, no driver stack: EFI_TCG2_PROTOCOL.SubmitCommand
 * carries raw TPM2 commands, the firmware owns the transport (Intel PTT on
 * this laptop). Three things are read: ReadClock (resetCount = a hardware
 * boot counter no software resets; clock = a monotonic persisted
 * millisecond clock), the SHA256 bank of PCR 0..7 (the firmware's own
 * measured boot), and elvboot's NV counter index, which the loader
 * increments once per boot (NV_Increment cannot be undone).
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
bool	tpm_pcr_bank(uint8_t out[static SHA256_DIGEST_LENGTH]);	/* sha256 over PCR0..7 */
bool	tpm_nv_counter_read(uint64_t *);
bool	tpm_nv_counter_increment(void);
bool	tpm_nv_define_counter(void);
const char *tpm_last_error(void);

#endif /* _LOCAL_TPM_H_ */
