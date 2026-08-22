/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * claim.c -- weigh a claim's expected against a transient actual.
 */

#include <stand.h>
#include <string.h>

#include "measurement.h"
#include "claim.h"

#ifndef LOADER_TRUST_SKIP		/* comma-separated claim names to disarm */
#define	LOADER_TRUST_SKIP	""
#endif

/* True if the build disarmed this claim by name. */
static int
disarmed(const char *name)
{
	const char *p = LOADER_TRUST_SKIP;
	size_t n = strlen(name);

	while (*p != '\0') {
		if (strncmp(p, name, n) == 0 && (p[n] == '\0' || p[n] == ','))
			return (1);
		while (*p != '\0' && *p != ',')
			p++;
		while (*p == ',')
			p++;
	}
	return (0);
}

enum verdict
claim_verdict(const struct claim *c, const struct measurement *actual)
{
	if (!c->expected.present || disarmed(c->expected.name))
		return (VERDICT_SKIP);		/* unprovisioned / disarmed */
	if (!actual->present)
		return (VERDICT_FAIL);		/* armed, but nothing measured */
	return (measurement_equal(&c->expected, actual) ?
	    VERDICT_PASS : VERDICT_FAIL);
}
