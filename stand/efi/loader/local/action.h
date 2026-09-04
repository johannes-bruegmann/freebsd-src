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
 *
 * The catalog, by family. Every entry names what it assumes.
 *
 * Baseline     proceed
 * Exposure     publish   results to kenv. silence  suppress every later
 *              publish of this boot -- the duress mode: the evidence still
 *              reaches the handover word, nothing reaches the console or a
 *              readable kenv leaf.
 * Evidence     report, message, prompt (free-text, recorded), sentinel
 *              (question; publishes ONLY a salted hash of the answer and of
 *              its first character -- classification lives in earlboot
 *              behind the encrypted root; requires loader.trust.<gate>.question
 *              and .salt), record (append the appraisal to the boot medium's
 *              ESP under /EFI/elvboot/ and to an NVRAM variable; assumes the
 *              medium is writable and that the reader is earlboot/elvbootd,
 *              which verify the record's MAC).
 * Response     confirm (y/N), lock (secret from kenv), unlock (compiled-in
 *              secret and duress secret, 3 tries), tarpit (sleep 2^attempts
 *              seconds before a prompt; assumes the coercer cannot afford to
 *              wait), lockout (halt once attempts reach loader.trust.<gate>.
 *              attempts), reveal (show four words derived from the gate
 *              secret and the ledger so the HUMAN can recognise the honest
 *              loader before typing a passphrase -- Qubes AEM inverted;
 *              assumes the words are read off a card the owner keeps and
 *              that a copied loader binary can also compute them, so this
 *              proves the BINARY, not the medium), taint (mark the ledger;
 *              the handover word carries it), expire (halt when the boot
 *              is later than loader.trust.<gate>.deadline, an epoch; the
 *              dead man's switch against a forgotten baseline), single
 *              (RB_SINGLE: the kernel stops in single user for inspection),
 *              divert (boot the rescue root instead: vfs.root.mountfrom from
 *              loader.trust.<gate>.rescue; the KERNEL stays the verified
 *              one from the boot medium, GELI of the production root is
 *              never attached), nextboot (write an NVRAM one-shot that
 *              makes the NEXT boot divert, then reboot), handover (compute
 *              the handover word: HMAC over the ledger digest, the record
 *              counter and the duress/taint bits with the compiled-in WORD
 *              secret (record.h), published as loader.trust.<gate>.word for
 *              earlboot, which holds the same secret; assumes Secure Boot
 *              with the owner db only and mac_bootlock making loader.trust.*
 *              immutable in the kernel),
 *              halt, panic, reboot, poweroff (EfiResetShutdown).
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

extern const struct action	proceed_act;
extern const struct action	publish_act;
extern const struct action	silence_act;
extern const struct action	report_act;
extern const struct action	message_act;
extern const struct action	prompt_act;
extern const struct action	sentinel_act;
extern const struct action	record_act;
extern const struct action	confirm_act;
extern const struct action	lock_act;
extern const struct action	unlock_act;
extern const struct action	tarpit_act;
extern const struct action	lockout_act;
extern const struct action	reveal_act;
extern const struct action	taint_act;
extern const struct action	expire_act;
extern const struct action	single_act;
extern const struct action	divert_act;
extern const struct action	nextboot_act;
extern const struct action	handover_act;
extern const struct action	halt_act;
extern const struct action	panic_act;
extern const struct action	reboot_act;
extern const struct action	poweroff_act;

#endif /* _LOCAL_ACTION_H_ */
