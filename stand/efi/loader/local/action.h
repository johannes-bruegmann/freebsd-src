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
 * The catalog, one entry per action. Every entry names what it assumes.
 *
 * proceed_act   the baseline no-op
 * publish_act   write the appraisal to kenv (loader.trust.<gate>.*)
 * silence_act   suppress every later publish of this boot -- the duress
 *               mode: the evidence still reaches the handover word, nothing
 *               reaches the console or a readable kenv leaf
 * report_act    print the appraisal (verdict, per-claim results) on the
 *               console
 * message_act   print loader.trust.<gate>.message on the console
 * display_act   show the context line the owner recognises: the items
 *               loader.trust.<gate>.display names (bootcount lastboot
 *               cycles unclean gates attempts) from the record and the
 *               ledger; not interactive; without a valid record it says
 *               which (none, or not verified). The coercer reads it too:
 *               only harmless items
 * prompt_act    ask loader.trust.<gate>.question as free text; the answer is
 *               recorded as evidence, never compared
 * sentinel_act  ask loader.trust.<gate>.question and publish ONLY a salted
 *               hash of the answer and of its first character (requires
 *               .salt) -- the classification lives in earlboot, behind the
 *               encrypted root; no visible difference for any input.
 *               Shows display_act's context line first when .display
 *               names items, so the owner reads before answering
 * record_act    append the appraisal to the boot medium's ESP under
 *               /EFI/elvboot/ and to an NVRAM variable; assumes a writable
 *               medium and that earlboot/elvbootd verify the record's MAC
 * confirm_act   ask y/N on the console before going on
 * lock_act      demand the secret loader.trust.<gate>.secret at a prompt
 * unlock_act    demand the compiled-in secret (or the duress secret), three
 *               tries; a duress entry proceeds silently marked
 * tarpit_act    sleep 2^attempts seconds before a prompt; assumes the
 *               coercer cannot afford to wait
 * lockout_act   halt once the attempts reach loader.trust.<gate>.attempts
 * reveal_act    show four words derived from the gate secret and the ledger
 *               so the HUMAN recognises the honest loader before typing a
 *               passphrase (Qubes AEM inverted); assumes the words are read
 *               off a card the owner keeps -- a copied loader binary
 *               computes them too, so this proves the BINARY, not the medium
 * taint_act     mark the ledger; the handover word carries it
 * expire_act    halt when the boot is later than loader.trust.<gate>.deadline
 *               (an epoch): the dead man's switch against a forgotten
 *               baseline
 * single_act    RB_SINGLE: the kernel stops in single user for inspection
 * divert_act    boot the rescue root instead (vfs.root.mountfrom from
 *               loader.trust.<gate>.rescue); the KERNEL stays the verified
 *               one from the boot medium, GELI of the production root is
 *               never attached
 * nextboot_act  write an NVRAM one-shot that makes the NEXT boot divert,
 *               then reboot
 * handover_act  compute the handover word: HMAC over the ledger digest, the
 *               record counter and the duress/taint bits with the
 *               compiled-in WORD secret (record.h), published as
 *               loader.trust.<gate>.word for earlboot, which holds the same
 *               secret; assumes Secure Boot with the owner db only and
 *               mac_bootlock making loader.trust.* immutable in the kernel
 * halt_act      halt the machine
 * panic_act     panic the loader
 * reboot_act    warm reset
 * poweroff_act  power off (EfiResetShutdown)
 */

#ifndef _LOCAL_ACTION_H_
#define	_LOCAL_ACTION_H_

struct appraisal;

/*
 * The hidden line read every prompt of this layer shares (action.c): no
 * echo, dwell and cadence into the ledger, one attempt counted. Also the
 * boot answer prompt of the record (record.c).
 */
void	readsecret(char *buf, size_t sz);
void	readsecret_confirm(char *buf, size_t sz);

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
extern const struct action	display_act;
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
