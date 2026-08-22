/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * policy.c -- run the policies of a phase. Selection is the layer's
 * (phase_policies); execution is here: appraise the gate into its results,
 * bundle an appraisal, then run each binding whose predicate fires.
 */

#include <efi.h>			/* CHAR16 */

#include "claim.h"
#include "gate.h"
#include "action.h"
#include "policy.h"

/* --- firing predicates (open catalog) --- */

bool
when_always(const struct appraisal *a __unused)
{
	return (true);
}

bool
when_fail(const struct appraisal *a)
{
	return (a->verdict == VERDICT_FAIL);
}

bool
when_pass(const struct appraisal *a)
{
	return (a->verdict == VERDICT_PASS);
}

/* --- execution --- */

static void
policy_run(const struct policy *p, int argc, CHAR16 *argv[])
{
	struct appraisal a;
	const struct binding *b;

	a.gate = p->gate;
	a.results = p->results;
	a.verdict = gate_appraise(p->gate, argc, argv, p->results);
	for (b = p->bindings; b->action != NULL; b++)
		if (b->fires(&a))
			b->action->execute(&a);
}

void
local_run(enum phase ph, int argc, CHAR16 *argv[])
{
	const struct policy *p;

	for (p = phase_policies(ph); p->gate != NULL; p++)
		policy_run(p, argc, argv);
}
