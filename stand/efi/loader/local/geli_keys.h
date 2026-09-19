/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * geli_keys.h -- the user keys of the encrypted providers, derived in the
 * loader (geli_keys.c) from a passphrase the dialog hands over
 * (geli_open.c) and the key files loader.conf and the TPM preloaded.
 *
 * Not a catalog: internal to the local layer.
 */

#ifndef _LOCAL_GELI_KEYS_H_
#define	_LOCAL_GELI_KEYS_H_

/* Derive for every GELI provider seen; the number that opened. With
 * keyfiles_only (the TPM released its file) the slot of key files alone
 * is tried first, before the passphrase slots. */
unsigned int	 geli_keys_prepare(const char *passphrase, bool keyfiles_only);
/* Why the last attempt ended as it did (diagnose_record, the dialog). */
const char	*geli_keys_reason(void);
/* true iff the last derivation opened through the slot of key files alone
 * (slot 0, the medium's file + the TPM's); false: a passphrase slot, i.e. the
 * recovery passphrase (slot 1) -- the loud special case (JB 19.09.) */
bool		 geli_keys_files_slot(void);

#endif /* _LOCAL_GELI_KEYS_H_ */
