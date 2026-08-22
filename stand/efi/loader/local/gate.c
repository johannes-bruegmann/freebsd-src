/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * gate.c -- appraise a gate's claims. Pure mechanism: gate_appraise walks the
 * CLAIM_END-terminated claims, measures each (and diagnoses where offered),
 * weighs it (claim_verdict) and records a claim_result in lockstep. It has no
 * side effects -- publishing the results is the publish action's job. gate_var
 * owns the one naming convention, loader.trust.<gate>.<leaf>.
 */

#include <stand.h>

#include <efi.h>			/* CHAR16 */

#include "measurement.h"
#include "claim.h"
#include "gate.h"

void
gate_var(const struct gate *g, const char *leaf, char *buf, size_t sz)
{
	snprintf(buf, sz, "loader.trust.%s.%s", g->name, leaf);
}

enum verdict
gate_appraise(const struct gate *g, int argc, CHAR16 *argv[],
    struct claim_result *results)
{
	const struct claim *c;
	struct claim_result *r;
	bool sawfail = false, sawpass = false;

	for (c = g->claims, r = results; c->measure != NULL; c++, r++) {
		struct measurement actual = c->measure(argc, argv);

		r->actual = actual;			/* value copy */
		r->verdict = claim_verdict(c, &actual);
		r->diag.leaf = NULL;
		if (c->diagnose != NULL)
			c->diagnose(argc, argv, &r->diag);

		if (r->verdict == VERDICT_PASS)
			sawpass = true;
		else if (r->verdict == VERDICT_FAIL)
			sawfail = true;
	}

	/* Degraded iff something failed or nothing was checked. */
	return ((!sawfail && sawpass) ? VERDICT_PASS : VERDICT_FAIL);
}
