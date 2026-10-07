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
#include "evidence.h"

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

/*
 * The rescue path's own expectation of a claim: loader.trust.<gate>.rescue.
 * <claim name, lower case> in the stage's conf. NULL when the boot is not a
 * rescue boot or the conf says nothing; "skip" disarms the claim there.
 */
static const char *
rescue_expectation(const struct gate *g, const char *claim)
{
	char leaf[64], name[96];
	size_t i;

	if (!evidence()->rescue)
		return (NULL);
	snprintf(leaf, sizeof(leaf), "rescue.%s", claim);
	for (i = 0; leaf[i] != '\0'; i++)
		if (leaf[i] >= 'A' && leaf[i] <= 'Z')
			leaf[i] = leaf[i] - 'A' + 'a';
	gate_var(g, leaf, name, sizeof(name));
	return (getenv(name));
}

enum verdict
claim_verdict(const struct gate *g, const struct claim *c,
    const struct measurement *actual)
{
	struct measurement expected = c->expected;
	char name[64];
	const char *text;

	text = rescue_expectation(g, expected.name);
	if (text != NULL) {
		if (strcmp(text, "skip") == 0 || disarmed(expected.name))
			return (VERDICT_SKIP);
		expected.key = NULL;
		expected.type = actual->type;
		if (!measurement_parse(&expected, text))
			return (VERDICT_FAIL);
		if (!actual->present)
			return (VERDICT_FAIL);
		return (measurement_equal(&expected, actual) ?
		    VERDICT_PASS : VERDICT_FAIL);
	}
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
