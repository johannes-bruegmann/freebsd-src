/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * geli_open.h -- the one dialog of the boot: the passphrase, applied.
 *
 * The loader checks no password. It asks the GELI passphrase and applies
 * the three factors as they are -- the passphrase (knowledge), the key
 * file on the medium (possession), the key file the TPM released
 * (this device, unchanged firmware) -- to the encrypted providers
 * (geli_keys.c): with the TPM's file the disk's slot of key files alone
 * opens, and the typed line was the TPM's to judge -- the owner's and the
 * duress passphrase both end at the same disk. A provider that opens is the only proof there is; a
 * hash to compare against would be a hash an attacker can compare
 * against, at home, with a passphrase in hand. Wrong: asked again, up
 * to loader.trust.geli.tries (default 3); then the boot halts, and the
 * retry is the reboot -- the whole chain, from the start. The derived
 * keys travel to the kernel in the keybuf (geliboot), so the kernel asks
 * nothing; without a key there is no root, and that is the end.
 *
 * Runs once per boot, in the KERNEL phase: lazily at the first record
 * claim (record.c needs the key material), else after the phase's
 * policies (policy.c), so the kernel always gets its keys. Recovery
 * after a legitimate firmware change (the TPM keeps its file) is the
 * disk's other slot, a passphrase alone, typed at this same prompt.
 *
 * Not a catalog: internal to the local layer.
 */

#ifndef _LOCAL_GELI_OPEN_H_
#define	_LOCAL_GELI_OPEN_H_

#include <stdbool.h>

void	geli_open_ensure(void);		/* the dialog, once per boot; halts */
bool	geli_open_done(void);		/* a provider opened this boot */

#endif /* _LOCAL_GELI_OPEN_H_ */
