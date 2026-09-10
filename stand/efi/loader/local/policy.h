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

/*
 * A (predicate, action) pair: run the action iff the predicate fires. Both
 * slots hold a pointer; a composed when or a composed action (below) is a
 * generated object of the same kind, so the runtime never sees the
 * composition.
 */
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

/*
 * The bindings of a policy are one POLICY_TABLE_DEFINE(name, binding1, ...):
 * every binding a FIRE(when, action). A when is a catalog name, or a
 * composition AND(x, y), OR(x, y), NOT(x) nested at will; an action is a
 * catalog name (without &), or COMPOSE(a, b, ...) to run several in order.
 *
 * A composition is unbound -- no catalog object carries it -- and starts
 * with a parenthesis, which is how the macros tell it from a name. The
 * table is written twice from the same list: the first pass defines an
 * object for every unbound slot (a static bool function for a when, a
 * static struct action for an action), named by the table and the
 * binding's position; the second pass writes the rows, referring to
 * the generated objects by the same name. Nothing here runs: the runtime
 * sees function and action pointers as it always did (JB 10.09.).
 *
 *   POLICY_TABLE_DEFINE(loaderlock_bindings,
 *       FIRE(when_always, publish_act),
 *       FIRE(AND(when_fail, NOT(when_skipped)), unlock_act),
 *       FIRE(when_duress, COMPOSE(taint_act, silence_act)));
 */
#define	CAT_(x, y)		x ## y
#define	CAT(x, y)		CAT_(x, y)
#define	UNPAREN(...)		__VA_ARGS__
#define	PROBE()			~, 1,
#define	CHECK_N(x, n, ...)	n
#define	CHECK(...)		CHECK_N(__VA_ARGS__, 0,)
#define	IS_PAREN_P(...)		PROBE()
#define	IS_PAREN(x)		CHECK(IS_PAREN_P x)	/* 1 iff x starts with ( */
#define	IIF(c)			CAT(IIF_, c)
#define	IIF_1(t, f)		t
#define	IIF_0(t, f)		f
#define	ARGC_(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, n, ...)	n
#define	ARGC(...)		ARGC_(__VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1)

/* the when: a leaf is applied to the appraisal, a node is passed through */
#define	W(x)			IIF(IS_PAREN(x))(x, x(a))
#define	AND(x, y)		(W(x) && W(y))
#define	OR(x, y)		(W(x) || W(y))
#define	NOT(x)			(!W(x))
#define	WHEN_NAME(n, i)		CAT(CAT(n, _when_), i)
#define	WHEN_DEFINE(n, i, x)						\
	static bool							\
	WHEN_NAME(n, i)(const struct appraisal *a)			\
	{								\
		return x;						\
	}
#define	WHEN_REF(n, i, x)	IIF(IS_PAREN(x))(WHEN_NAME(n, i), x)

/* the action: COMPOSE runs its members in order, each noted by name */
#define	COMPOSE(...)		(__VA_ARGS__)
#define	ACTION_NAME(n, i)	CAT(CAT(n, _action_), i)
#define	RUN_1(x)		action_run(a, &x);
#define	RUN_2(x, ...)		action_run(a, &x); RUN_1(__VA_ARGS__)
#define	RUN_3(x, ...)		action_run(a, &x); RUN_2(__VA_ARGS__)
#define	RUN_4(x, ...)		action_run(a, &x); RUN_3(__VA_ARGS__)
#define	RUN_5(x, ...)		action_run(a, &x); RUN_4(__VA_ARGS__)
#define	RUN_6(x, ...)		action_run(a, &x); RUN_5(__VA_ARGS__)
#define	RUN_7(x, ...)		action_run(a, &x); RUN_6(__VA_ARGS__)
#define	RUN_8(x, ...)		action_run(a, &x); RUN_7(__VA_ARGS__)
#define	RUN(...)		CAT(RUN_, ARGC(__VA_ARGS__))(__VA_ARGS__)
#define	COMPOSED_ACTION_DEFINE(n, i, x)					\
	static void							\
	CAT(ACTION_NAME(n, i), _execute)(const struct appraisal *a)	\
	{								\
		RUN x							\
	}								\
	static const struct action ACTION_NAME(n, i) =			\
	    { .name = "composed", .execute = CAT(ACTION_NAME(n, i), _execute) };
#define	ACTION_REF(n, i, x)	IIF(IS_PAREN(x))(&ACTION_NAME(n, i), &x)

/* a binding, and the two passes over the list */
#define	FIRE(w, x)		(w, x)
#define	DEF_(n, i, w, x)	IIF(IS_PAREN(w))(WHEN_DEFINE(n, i, w), )	\
				IIF(IS_PAREN(x))(COMPOSED_ACTION_DEFINE(n, i, x), )
#define	DEF_X(...)		DEF_(__VA_ARGS__)
#define	DEF(n, i, b)		DEF_X(n, i, UNPAREN b)
#define	ROW_(n, i, w, x)	{ .fires = WHEN_REF(n, i, w), .action = ACTION_REF(n, i, x) },
#define	ROW_X(...)		ROW_(__VA_ARGS__)
#define	ROW(n, i, b)		ROW_X(n, i, UNPAREN b)
#define	DEFS_1(n, b)		DEF(n, 1, b)
#define	DEFS_2(n, b, ...)	DEF(n, 2, b) DEFS_1(n, __VA_ARGS__)
#define	DEFS_3(n, b, ...)	DEF(n, 3, b) DEFS_2(n, __VA_ARGS__)
#define	DEFS_4(n, b, ...)	DEF(n, 4, b) DEFS_3(n, __VA_ARGS__)
#define	DEFS_5(n, b, ...)	DEF(n, 5, b) DEFS_4(n, __VA_ARGS__)
#define	DEFS_6(n, b, ...)	DEF(n, 6, b) DEFS_5(n, __VA_ARGS__)
#define	DEFS_7(n, b, ...)	DEF(n, 7, b) DEFS_6(n, __VA_ARGS__)
#define	DEFS_8(n, b, ...)	DEF(n, 8, b) DEFS_7(n, __VA_ARGS__)
#define	DEFS_9(n, b, ...)	DEF(n, 9, b) DEFS_8(n, __VA_ARGS__)
#define	DEFS_10(n, b, ...)	DEF(n, 10, b) DEFS_9(n, __VA_ARGS__)
#define	DEFS_11(n, b, ...)	DEF(n, 11, b) DEFS_10(n, __VA_ARGS__)
#define	DEFS_12(n, b, ...)	DEF(n, 12, b) DEFS_11(n, __VA_ARGS__)
#define	DEFS_13(n, b, ...)	DEF(n, 13, b) DEFS_12(n, __VA_ARGS__)
#define	DEFS_14(n, b, ...)	DEF(n, 14, b) DEFS_13(n, __VA_ARGS__)
#define	DEFS_15(n, b, ...)	DEF(n, 15, b) DEFS_14(n, __VA_ARGS__)
#define	DEFS_16(n, b, ...)	DEF(n, 16, b) DEFS_15(n, __VA_ARGS__)
#define	ROWS_1(n, b)		ROW(n, 1, b)
#define	ROWS_2(n, b, ...)	ROW(n, 2, b) ROWS_1(n, __VA_ARGS__)
#define	ROWS_3(n, b, ...)	ROW(n, 3, b) ROWS_2(n, __VA_ARGS__)
#define	ROWS_4(n, b, ...)	ROW(n, 4, b) ROWS_3(n, __VA_ARGS__)
#define	ROWS_5(n, b, ...)	ROW(n, 5, b) ROWS_4(n, __VA_ARGS__)
#define	ROWS_6(n, b, ...)	ROW(n, 6, b) ROWS_5(n, __VA_ARGS__)
#define	ROWS_7(n, b, ...)	ROW(n, 7, b) ROWS_6(n, __VA_ARGS__)
#define	ROWS_8(n, b, ...)	ROW(n, 8, b) ROWS_7(n, __VA_ARGS__)
#define	ROWS_9(n, b, ...)	ROW(n, 9, b) ROWS_8(n, __VA_ARGS__)
#define	ROWS_10(n, b, ...)	ROW(n, 10, b) ROWS_9(n, __VA_ARGS__)
#define	ROWS_11(n, b, ...)	ROW(n, 11, b) ROWS_10(n, __VA_ARGS__)
#define	ROWS_12(n, b, ...)	ROW(n, 12, b) ROWS_11(n, __VA_ARGS__)
#define	ROWS_13(n, b, ...)	ROW(n, 13, b) ROWS_12(n, __VA_ARGS__)
#define	ROWS_14(n, b, ...)	ROW(n, 14, b) ROWS_13(n, __VA_ARGS__)
#define	ROWS_15(n, b, ...)	ROW(n, 15, b) ROWS_14(n, __VA_ARGS__)
#define	ROWS_16(n, b, ...)	ROW(n, 16, b) ROWS_15(n, __VA_ARGS__)
#define	DEFS(n, ...)		CAT(DEFS_, ARGC(__VA_ARGS__))(n, __VA_ARGS__)
#define	ROWS(n, ...)		CAT(ROWS_, ARGC(__VA_ARGS__))(n, __VA_ARGS__)

#define	POLICY_TABLE_DEFINE(name, binding1, ...)			\
	DEFS(name, binding1, ##__VA_ARGS__)				\
	static const struct binding name[] = {				\
		ROWS(name, binding1, ##__VA_ARGS__)			\
		{ .action = NULL }					\
	}

/* a phase table names its policies: the gate and the bindings */
#define	POLICY(id, tbl)							\
	{ .gate = &id##_gate, .results = id##_results, .bindings = (tbl) }
#define	POLICY_END		{ .gate = NULL }

/* run one action of a binding: noted in the ledger by its name, then executed */
void	action_run(const struct appraisal *, const struct action *);

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
