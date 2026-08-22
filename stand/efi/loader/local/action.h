/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * action.h -- a named response, run over a gate's appraisal.
 *
 * Actions are a shared, const catalog (action.c), referenced by the policies of
 * any layer. An action is UNCONDITIONAL: it always does its thing when run.
 * WHETHER it runs is the policy's decision, via a firing predicate (policy.h) --
 * the mechanism/policy split. The handler receives the whole appraisal (gate,
 * verdict, per-claim results); action-specific parameters (secret, message,
 * question) it sources from the gate's kenv namespace. The set is open --
 * adding one is a new {name, handler}.
 *
 * publish writes the results to kenv (loader.trust.<gate>.*); proceed is the
 * baseline no-op. No action inspects the verdict to decide whether to run --
 * that lives in the policy's predicate.
 */

#ifndef _LOCAL_ACTION_H_
#define	_LOCAL_ACTION_H_

struct appraisal;

struct action {
	const char	*name;
	void		(*execute)(const struct appraisal *);
};

/* Define a catalog entry; external linkage, const -- policies reference it. */
#define	ACTION_DEFINE(id, execfn)					\
	const struct action id##_act =					\
	    { .name = #id, .execute = (execfn) }

/*
 * The catalog. Baseline: proceed. Exposure: publish (kenv). Evidence: report,
 * message, prompt (free-text, recorded). Response: confirm (y/N), lock
 * (verified secret), halt/panic/reboot.
 */
extern const struct action	proceed_act;
extern const struct action	publish_act;
extern const struct action	report_act;
extern const struct action	message_act;
extern const struct action	prompt_act;
extern const struct action	confirm_act;
extern const struct action	lock_act;
extern const struct action	unlock_act;
extern const struct action	halt_act;
extern const struct action	panic_act;
extern const struct action	reboot_act;

#endif /* _LOCAL_ACTION_H_ */
