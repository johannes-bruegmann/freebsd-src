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
	PHASE_LOADER,		/* before the interactive loader (interact()); we are
				   already in the loader binary. Hosts: loaderlock,
				   strictwatch. */
};

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

/* Firing predicates -- an open catalog (policy.c); add one as needed. */
bool	when_always(const struct appraisal *);
bool	when_fail(const struct appraisal *);
bool	when_pass(const struct appraisal *);

#define	FIRE(pred, act)		{ .fires = (pred), .action = (act) }
#define	POLICY(id, ...)							\
	{ .gate = &id##_gate, .results = id##_results,			\
	  .bindings = (const struct binding[]){ __VA_ARGS__,		\
	      { .action = NULL } } }
#define	POLICY_END		{ .gate = NULL }

/* A layer supplies its policies for a phase (POLICY_END-terminated). */
const struct policy	*phase_policies(enum phase);

/* Run every policy of this phase: appraise its gate, then its bindings. */
void	local_run(enum phase, int argc, CHAR16 *argv[]);

#endif /* _LOCAL_POLICY_H_ */
