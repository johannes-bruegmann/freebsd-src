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

/* Derive for every GELI provider seen; the number that opened. */
unsigned int	 geli_keys_prepare(const char *passphrase);
/* Why the last attempt ended as it did (diagnose_record, the dialog). */
const char	*geli_keys_reason(void);

#endif /* _LOCAL_GELI_KEYS_H_ */
