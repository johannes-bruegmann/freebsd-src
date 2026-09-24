/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * tpm_keyfile.h -- the GELI key file the TPM releases (tpm_keyfile.c).
 *
 * The device factor of the encrypted root: 32 bytes sealed in the TPM
 * under a PCR policy (firmware code, option ROMs, Secure Boot keys), the
 * reflected copy of a seed-derived secret. Unsealed once per boot, before
 * the record derives its keys, and added as a preloaded key file of every
 * configured provider -- <prov>:geli_keyfile<n> after the medium's own --
 * so the loader's derivation (geli_keys.c) and the kernel's (g_eli) both
 * see it. Without this TPM the disk does not open; without this loader
 * the TPM releases nothing. Recovery is the disk's other slot (a
 * passphrase alone) and the seed.
 *
 * Released for the passphrase the dialog reads (geli_open.c): the TPM
 * decides by its PCR policy AND by the passphrase, whose SHA256 is the
 * auth value of the sealed object (PolicyAuthValue) -- so the TPM checks
 * the passphrase, and nothing in the loader binary does. Two objects
 * hold the same bytes under the same policy: the owner's (handle) and
 * the duress one (duress), whose auth value is the duress passphrase. The
 * loader tries the typed line against the first, then the second; the
 * second opening is the duress tell -- the loader increments the duress
 * counter in the TPM NV (an increment-only index, a trace root cannot
 * undo) and sets the bit the handover word carries to earlboot; nothing
 * on the console differs. Offline there is nothing to test: the auth
 * values live in the TPM.
 *
 * Leafs, loader.trust.tpm.*: key.handle (the storage key the sessions
 * salt to, 0x81000001), keyfile.handles ("0x81010001 0x81010002": the
 * owner's object, then the one whose opening counts -- the role is the
 * position, no leaf names it), keyfile.providers (nda0p1 nda2p1; empty:
 * unseal only), keyfile.pcrs (0,2,7), counter.nv (the increment-only
 * index; optional). The baseline LOADER_TRUST_TPM_KEY_DIGEST pins the storage
 * key; without it the key is used unverified and the diagnosis says so;
 * the digest is published as loader.trust.tpm.key.sha256 to be learned.
 * A leaf that does not parse, a TPM that refuses, a provider that cannot
 * take the file: the claim TpmKeyfile measures 0 and the diagnosis says
 * why; no leaf at all: the claim is absent.
 *
 * Not a catalog: internal to the local layer.
 */

#ifndef _LOCAL_TPM_KEYFILE_H_
#define	_LOCAL_TPM_KEYFILE_H_

#include <stdbool.h>

struct tpm_keyfile_state {
	bool		 configured;	/* at least one leaf is set */
	bool		 unsealed;	/* the TPM released the bytes */
	bool		 verified;	/* ... under the storage key of the baseline */
	unsigned int	 providers;	/* providers configured */
	unsigned int	 added;		/* ... that got the key file */
	const char	*reason;	/* what happened, for the diagnosis */
};

/* One attempt with this passphrase; once the file is placed, a no-op. */
void	tpm_keyfile_prepare(const char *passphrase);
const struct tpm_keyfile_state *tpm_keyfile_state(void);

#endif /* _LOCAL_TPM_KEYFILE_H_ */
