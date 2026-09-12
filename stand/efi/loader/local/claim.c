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
#include "gate.h"

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
claim_verdict(const struct gate *g, const struct claim *c,
    const struct measurement *actual)
{
	struct measurement expected = c->expected;
	char name[64];
	const char *text;

	if (expected.key != NULL) {
		/*
		 * From loader.trust.<gate>.<key>: the stage's conf, not the
		 * binary. No value: unprovisioned, skipped. A value that does
		 * not parse: provisioned and broken, a failure, never a skip.
		 */
		if (disarmed(expected.name))
			return (VERDICT_SKIP);
		gate_var(g, expected.key, name, sizeof(name));
		text = getenv(name);
		if (text == NULL)
			return (VERDICT_SKIP);
		expected.type = actual->type;
		if (!measurement_parse(&expected, text))
			return (VERDICT_FAIL);
	}
	if (!expected.present || disarmed(expected.name))
		return (VERDICT_SKIP);		/* unprovisioned / disarmed */
	if (!actual->present)
		return (VERDICT_FAIL);		/* armed, but nothing measured */
	return (measurement_equal(&expected, actual) ?
	    VERDICT_PASS : VERDICT_FAIL);
}
