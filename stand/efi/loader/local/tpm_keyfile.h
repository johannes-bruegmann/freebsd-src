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
 * The FIRST step of the KERNEL phase (policy.c local_run), before any
 * gate measures and before anything is asked: no input precedes it, no
 * input can influence it -- the TPM decides by its PCR policy alone
 * (JB 16.09.). Three leafs, loader.trust.tpm.keyfile.*: handle (the
 * persistent object, 0x81010001), providers (nda0p1 nda2p1; empty:
 * unseal only), pcrs (0,2,7 -- the policy the object was sealed under).
 * The dialog that applies the file (geli_open.c) and the record's claims
 * come later in the phase. A leaf that does not parse, a TPM that
 * refuses, a provider that cannot take the file: the claim TpmKeyfile
 * measures 0 and the diagnosis says why; no leaf at all: the claim is
 * absent.
 *
 * Not a catalog: internal to the local layer.
 */

#ifndef _LOCAL_TPM_KEYFILE_H_
#define	_LOCAL_TPM_KEYFILE_H_

#include <stdbool.h>

struct tpm_keyfile_state {
	bool		 configured;	/* at least one leaf is set */
	bool		 unsealed;	/* the TPM released the bytes */
	unsigned int	 providers;	/* providers configured */
	unsigned int	 added;		/* ... that got the key file */
	const char	*reason;	/* what happened, for the diagnosis */
};

void	tpm_keyfile_prepare(void);		/* once per boot, from kenv */
const struct tpm_keyfile_state *tpm_keyfile_state(void);

#endif /* _LOCAL_TPM_KEYFILE_H_ */
