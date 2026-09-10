/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * policy.h -- the policy that binds a gate to its actions, per phase.
 *
 * "Appraisal policy" (RFC 9334): given the evidence a gate appraises, what to
 * do. Mechanism/policy split -- the gate is the test, the policy the response.
 *
 * An action is an UNCONDITIONAL verb (it always does its thing when run); the
 * policy decides WHEN it fires, via a predicate over the appraisal. A binding
 * is one (predicate, action) pair. The firing condition is an open set -- a
 * function, not an enum -- so a new condition is a new predicate, no model
 * change. A report-only binding is a legitimate policy: this stays tamper
 * DETECTION.
 *
 * POLICY(id, ...) wires the gate and its exact-sized results array by name, at
 * compile time (both emitted by GATE_DEFINE(id) in the same file). The phase is
 * structural (see phase_policies), so it is not a field. Policy tables are
 * POLICY_END-terminated; a policy's bindings are terminated by a NULL action.
 *
 * Phases and the ledger. Every appraisal a phase runs is noted in the
 * evidence ledger (evidence.h) before the next phase starts, so a later
 * phase can weigh what an earlier one saw: "a claim failed in BOOT", "a
 * prompt was shown in LOADER", "an unlock happened" are ordinary
 * measurements in KERNEL (measure_ledger_*). The KERNEL phase runs after
 * the interactive window has closed and before ExitBootServices -- it is
 * the last place where the loader can still refuse the kernel, divert
 * into the rescue system, or hand the boot evidence over (handover_act).
 */

#ifndef _LOCAL_POLICY_H_
#define	_LOCAL_POLICY_H_

#include <efi.h>			/* CHAR16 */

#include "claim.h"			/* struct claim_result */
#include "gate.h"			/* struct gate, struct appraisal */
#include "action.h"

/*
 * A phase is one local_run() call site, named for what it guards entry INTO
 * (convention: PHASE_<x> runs just before <x> is engaged). A phase may host
 * several gates -- phase_policies() returns them as a list. Phase names are
 * kept distinct from gate names (bootlock/loaderlock/strictwatch) on purpose.
 */
enum phase {
	PHASE_BOOT,		/* platform layer: before the boot medium is engaged
				   (main.c, before currdev). Hosts: bootlock. */
	PHASE_BOOT_POST,
	PHASE_LOADER,		/* before the interactive loader (interact()); we are
				   already in the loader binary. Hosts: loaderlock,
				   strictwatch. */
	PHASE_LOADER_POST,
	PHASE_KERNEL,		/* before the kernel is entered (elf64_exec, before
				   dev_cleanup/ExitBootServices): the interactive
				   window is closed, the final howto/kenv are known,
				   every earlier appraisal is in the ledger. Hosts:
				   kernellock. */
	PHASE_KERNEL_POST,
};

/*
 * Every phase has an after-phase, PHASE_<x>_POST, that local_run() runs
 * once the actions of PHASE_<x> are done: its claims measure what those
 * actions produced -- the prompt's attempts and dwell, the ledger, the
 * duress tell -- which the phase itself cannot see (it measures before it
 * acts). PHASE_KERNEL_POST is the last thing before the record is committed.
 * The enum keeps each after-phase right behind its phase (post_of).
 */

/* A (predicate, action) pair: run the action iff the predicate fires. */
struct binding {
	bool			(*fires)(const struct appraisal *);
	const struct action	*action;
};

struct policy {
	const struct gate	*gate;
	struct claim_result	*results;	/* the gate's scratch, 1:1 */
	const struct binding	*bindings;	/* terminated by { .action = NULL } */
};

/*
 * Firing predicates -- an open catalog (policy.c); add one as needed.
 *
 *   when_always   every time
 *   when_fail     the gate's overall verdict is FAIL
 *   when_pass     the gate's overall verdict is PASS
 *   when_skipped  at least one claim of the gate was SKIPPED (no expectation
 *                 provisioned, or disarmed): unprovisioned baselines stop
 *                 being silent
 *   when_maybe    probabilistically (about one boot in four): spot checks an
 *                 observer cannot time. Noise, not cryptography -- a xorshift
 *                 PRNG seeded from the cycle counter. Only ever ADDS a spot
 *                 check; no critical check may exist solely behind it.
 *   when_tainted  the evidence ledger carries a taint (taint_act fired, or
 *                 an earlier phase failed)
 *   when_duress   a duress tell was observed at a prompt (evidence.h). Bind
 *                 only SILENT actions here: the point of duress is that the
 *                 coercer sees nothing.
 *   when_prompted an interactive action ran in this or an earlier phase
 */
bool	when_always(const struct appraisal *);
bool	when_fail(const struct appraisal *);
bool	when_pass(const struct appraisal *);
bool	when_skipped(const struct appraisal *);
bool	when_maybe(const struct appraisal *);
bool	when_tainted(const struct appraisal *);
bool	when_duress(const struct appraisal *);
bool	when_prompted(const struct appraisal *);

#define	FIRE(pred, act)		{ .fires = (pred), .action = (act) }
#define	POLICY(id, ...)							\
	{ .gate = &id##_gate, .results = id##_results,			\
	  .bindings = (const struct binding[]){ __VA_ARGS__,		\
	      { .action = NULL } } }
#define	POLICY_END		{ .gate = NULL }

/* A layer supplies its policies for a phase (POLICY_END-terminated). */
const struct policy	*phase_policies(enum phase);

/*
 * Run every policy of this phase: appraise its gate, note the appraisal in
 * the ledger, then run each binding whose predicate fires. argv is the boot
 * entry's LoadOptions; the first call keeps them (evidence.h) so a later
 * phase without its own argv (KERNEL) measures the same record.
 */
void	local_run(enum phase, int argc, CHAR16 *argv[]);

/* The KERNEL phase from the exec path, which has no argv of its own. */
void	local_run_kernel(void);

#endif /* _LOCAL_POLICY_H_ */
