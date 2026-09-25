/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * tpm_keyfile.h -- the GELI key file the TPM releases (tpm_keyfile.c).
 *
 * The device factor of the encrypted root: 32 bytes sealed in the TPM
 * under a policy (firmware code, option ROMs, Secure Boot keys, and the
 * TPM's own counters), the reflected copy of a seed-derived secret.
 * Unsealed once per boot, before the record derives its keys, and added
 * as a preloaded key file of every configured provider --
 * <prov>:geli_keyfile<n> after the medium's own -- so the loader's
 * derivation (geli_keys.c) and the kernel's (g_eli) both see it. Without
 * this TPM the disk does not open; without this loader the TPM releases
 * nothing. Recovery is the disk's other slot (a passphrase alone) and
 * the seed.
 *
 * Released for the passphrase the dialog reads (geli_open.c): the TPM
 * decides by its policy AND by the passphrase, whose SHA256 is the auth
 * value the policy asks for -- so the TPM checks the passphrase, and
 * nothing in the loader binary does. Two objects, two policies, two
 * fates (the order of the steps is the order elebake sealed them in):
 *
 *   owner (handle):  PolicyPCR, PolicyAuthValue(owner passphrase),
 *                    PolicyNV(duress.nv: pinCount == 0),
 *                    PolicyNV(duress.count.nv: value == duress.count.sealed)
 *                    -> the production root's key file (keyfile.providers)
 *   duress (duress): PolicySecret(duress.nv, duress passphrase), PolicyPCR
 *                    -> the decoy root's key file (decoy.providers)
 *
 * duress.nv is a TPM_NT_PIN_PASS index (pinLimit 1) whose authValue is
 * the duress passphrase: the TPM itself counts the one successful
 * PolicySecret, and from then on the owner's PolicyNV(pinCount == 0)
 * fails -- the owner object is dead, in the TPM, without a script. The
 * second index, duress.count.nv, is an ordinary counter earlboot raises
 * for a boot answer of the coercion class; the owner object is sealed
 * against its value at seal time (a counter never reads 0 and never goes
 * back). The way back after either is the disk's recovery slot, then
 * elebake's reset and reseal.
 *
 * The duress opening is the decoy boot: the loader marks the evidence
 * ledger (evidence_set_duress), raises counter.nv (the trace, an
 * increment-only index), places the DECOY key file, and policy.c takes
 * the short way out -- no record, no further gate, the root becomes
 * loader.trust.tpm.decoy.root. Nothing on the console differs until the
 * decoy system is up; by then the seal is dead, which was the point.
 *
 * Leafs, loader.trust.tpm.*: key.handle (the storage key the sessions
 * salt to, 0x81000001), keyfile.handles ("0x81010001 0x81010002": the
 * owner's object, then the duress one -- the role is the position),
 * keyfile.providers (nda0p1 nda2p1; empty: unseal only), keyfile.pcrs
 * (0,2,7), counter.nv (the increment-only trace index; optional),
 * duress.nv (the PIN index), duress.count.nv (the second counter),
 * duress.count.sealed (its value at seal time, 16 hex characters as
 * tpm2_nvread prints them), decoy.providers (nda1p1), decoy.root (read by
 * policy.c). The baseline LOADER_TRUST_TPM_KEY_DIGEST pins the storage
 * key; without it the key is used unverified and the diagnosis says so;
 * the digest is published as loader.trust.tpm.key.sha256 to be learned.
 * A leaf that does not parse, a TPM that refuses, a provider that cannot
 * take the file: the claim TpmKeyfile measures 0 and the diagnosis says
 * why; no leaf at all: the claim is absent. The diagnosis names the two
 * indices' state (duress.pin=<count>/<limit>, duress.count=<now>/<sealed>)
 * and never which object answered.
 *
 * Not a catalog: internal to the local layer.
 */

#ifndef _LOCAL_TPM_KEYFILE_H_
#define	_LOCAL_TPM_KEYFILE_H_

#include <stdbool.h>
#include <stdint.h>

struct tpm_keyfile_state {
	bool		 configured;	/* at least one leaf is set */
	bool		 unsealed;	/* the TPM released the bytes */
	bool		 verified;	/* ... under the storage key of the baseline */
	unsigned int	 providers;	/* providers configured (of the root that opened) */
	unsigned int	 added;		/* ... that got the key file */
	const char	*reason;	/* what happened, for the diagnosis */
	bool		 pin_read;	/* duress.nv answered the owner's read */
	uint32_t	 pin_count;	/* its pinCount */
	uint32_t	 pin_limit;	/* its pinLimit */
	bool		 count_read;	/* duress.count.nv answered */
	uint64_t	 count;		/* its value now */
	uint64_t	 count_sealed;	/* the leaf: its value at seal time */
};

/* One attempt with this passphrase; once the file is placed, a no-op. */
void	tpm_keyfile_prepare(const char *passphrase);
const struct tpm_keyfile_state *tpm_keyfile_state(void);

#endif /* _LOCAL_TPM_KEYFILE_H_ */
