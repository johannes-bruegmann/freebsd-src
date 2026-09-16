/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * geli_open.c -- the one dialog of the boot (geli_open.h).
 *
 * A typed line is applied, never cached: it goes into the derivation
 * (geli_keys_prepare) and is wiped. What remains are the user keys of
 * the providers that opened, in geliboot's key buffer, for the record
 * (geli_ikm_digest) and for the kernel (geli_export_key_buffer). The
 * empty line is a passphrase too: a slot with key files only (geli
 * setkey -P) opens with it.
 */

#include <stand.h>
#include <string.h>

#include "action.h"			/* readsecret, halt_boot */
#include "geli_keys.h"
#include "geli_open.h"

#define	GELI_OPEN_TRIES_DEFAULT	3
#define	GELI_OPEN_TRIES_MAX	99
#define	GELI_OPEN_PW_MAX	128

static bool ran;			/* the dialog ran this boot */
static bool opened;			/* ... and a provider opened */

/* loader.trust.geli.tries, else the default; never 0. */
static unsigned int
tries_allowed(void)
{
	const char *v = getenv("loader.trust.geli.tries");
	unsigned long n;
	char *end;

	if (v == NULL)
		return (GELI_OPEN_TRIES_DEFAULT);
	n = strtoul(v, &end, 10);
	if (end == v || *end != '\0' || n == 0 || n > GELI_OPEN_TRIES_MAX)
		return (GELI_OPEN_TRIES_DEFAULT);
	return ((unsigned int)n);
}

void
geli_open_ensure(void)
{
	char pw[GELI_OPEN_PW_MAX];
	unsigned int max = tries_allowed(), t;

	if (ran)
		return;
	ran = true;
	for (t = 1; t <= max; t++) {
		printf("\nGELI passphrase: ");
		readsecret(pw, sizeof(pw));
		printf("\n");
		if (geli_keys_prepare(pw) > 0) {
			explicit_bzero(pw, sizeof(pw));
			opened = true;
			return;
		}
		explicit_bzero(pw, sizeof(pw));
		printf("no provider opened (%s)\n", geli_keys_reason());
	}
	halt_boot("no provider opened");
}

bool
geli_open_done(void)
{
	return (opened);
}
