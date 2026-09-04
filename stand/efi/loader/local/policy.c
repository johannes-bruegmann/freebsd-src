/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * policy.c -- run the policies of a phase. Selection is the layer's
 * (phase_policies); execution is here: appraise the gate into its results,
 * note it in the ledger, bundle an appraisal, then run each binding whose
 * predicate fires. The BOOT phase first loads the previous boot's record,
 * the KERNEL phase last commits this boot's -- so every gate of a boot
 * sees the previous record and the committed one describes this boot.
 */

#include <stand.h>

#include <efi.h>			/* CHAR16 */

#include "claim.h"
#include "gate.h"
#include "action.h"
#include "policy.h"
#include "evidence.h"
#include "record.h"

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

bool
when_skipped(const struct appraisal *a)
{
	const struct claim *c;
	const struct claim_result *r;

	for (c = a->gate->claims, r = a->results; c->measure != NULL; c++, r++)
		if (r->verdict == VERDICT_SKIP)
			return (true);
	return (false);
}

/*
 * xorshift64*, seeded once from the cycle counter. Noise, not cryptography:
 * the point is that an observer cannot time the spot check.
 */
bool
when_maybe(const struct appraisal *a __unused)
{
	static uint64_t s;

	if (s == 0) {
#if defined(__amd64__) || defined(__i386__)
		s = __builtin_ia32_rdtsc();
#endif
		if (s == 0)
			s = 0x9e3779b97f4a7c15ULL;
	}
	s ^= s >> 12;
	s ^= s << 25;
	s ^= s >> 27;
	return (((s * 2685821657736338717ULL) >> 62) == 0);	/* 1 in 4 */
}

bool
when_tainted(const struct appraisal *a __unused)
{
	return (evidence()->taint);
}

bool
when_duress(const struct appraisal *a __unused)
{
	return (evidence()->duress);
}

bool
when_prompted(const struct appraisal *a __unused)
{
	return (evidence()->prompted > 0);
}

/* --- execution --- */

static void
policy_run(enum phase ph, const struct policy *p, int argc, CHAR16 *argv[])
{
	struct appraisal a;
	const struct binding *b;

	a.gate = p->gate;
	a.results = p->results;
	a.verdict = gate_appraise(p->gate, argc, argv, p->results);
	evidence_note_appraisal(ph, &a);
	for (b = p->bindings; b->action != NULL; b++)
		if (b->fires(&a)) {
			evidence_note_action(b->action->name);
			b->action->execute(&a);
		}
}

static uint8_t
record_flags(void)
{
	const struct evidence *e = evidence();
	uint8_t f = 0;

	if (e->taint)
		f |= RECORD_F_TAINT;
	if (e->duress)
		f |= RECORD_F_DURESS;
	if (e->prompted > 0)
		f |= RECORD_F_PROMPTED;
	return (f);
}

void
local_run(enum phase ph, int argc, CHAR16 *argv[])
{
	const struct policy *p;

	evidence_args(argc, argv);
	if (ph == PHASE_BOOT)
		(void)record_load();
	for (p = phase_policies(ph); p->gate != NULL; p++)
		policy_run(ph, p, argc, argv);
	if (ph == PHASE_KERNEL)
		(void)record_commit(record_flags());
}

void
local_run_kernel(void)
{
	const struct evidence *e = evidence();

	local_run(PHASE_KERNEL, e->argc, e->argv);
}
