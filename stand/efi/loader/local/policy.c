/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * policy.c -- run the policies of a phase. Selection is the layer's
 * (phase_policies); execution is here: appraise the gate into its results,
 * note it in the ledger, bundle an appraisal, then run each binding whose
 * predicate fires. The KERNEL phase first loads the previous boot's record
 * (its keys come from the passphrase typed in the LOADER phase) and last
 * commits this boot's -- so every KERNEL gate sees the previous record and
 * the committed one describes this boot.
 */

#include <stand.h>
#include <string.h>
#include <efi.h>			/* CHAR16 */

#include "claim.h"
#include "gate.h"
#include "action.h"
#include "policy.h"
#include "evidence.h"
#include "record.h"
#include "geli_open.h"

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
when_prompted(const struct appraisal *a __unused)
{
	return (evidence()->prompted > 0);
}

bool
when_duress(const struct appraisal *a __unused)
{
	return (evidence()->duress);
}

/* --- execution --- */

void
action_run(const struct appraisal *a, const struct action *act)
{
	evidence_note_action(act->name);
	act->execute(a);
}

/*
 * The decoy boot (tpm_keyfile.h): once the duress object has answered,
 * no policy fires any more -- not the bindings of the gate whose claim
 * ran the dialog, none of the gates behind it. The owner's seal is dead
 * in the TPM at that moment; what follows is only the decoy root coming
 * up, and a prompt, a halt or a publication here would tell the coercer
 * more than the decoy does.
 */
static void
policy_run(enum phase ph, const struct policy *p, int argc, CHAR16 *argv[])
{
	struct appraisal a;
	const struct binding *b;

	if (evidence()->duress)
		return;
	a.gate = p->gate;
	a.results = p->results;
	a.verdict = gate_appraise(p->gate, argc, argv, p->results);
	if (evidence()->duress)
		return;
	evidence_note_appraisal(ph, &a);
	for (b = p->bindings; b->action != NULL; b++)
		if (b->fires(&a))
			action_run(&a, b->action);
}

/*
 * The decoy root instead of the production one: vfs.root.mountfrom from
 * loader.trust.tpm.decoy.root (e.g. zfs:zempty/ROOT/default); the kernel
 * and modules stay the verified ones from the medium. The production
 * providers carry the BOOT flag and their key file is not there: the
 * kernel would stop at "Enter passphrase for nda0p1:" -- boot_prompt=0
 * (sys/geom/eli) leaves them detached instead. No leaf: a halt, loud,
 * the only misconfiguration this path can have.
 */
static void
decoy_divert(void)
{
	const char *root = getenv("loader.trust.tpm.decoy.root");
	char note[128];

	if (root == NULL)
		halt_boot("no decoy root (loader.trust.tpm.decoy.root)");
	strlcpy(note, root, sizeof(note));	/* a getenv() pointer dies with setenv() */
	setenv("vfs.root.mountfrom", note, 1);
	unsetenv("vfs.root.mountfrom.options");
	setenv("kern.geom.eli.boot_prompt", "0", 1);
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
	if (e->unlocked)
		f |= RECORD_F_UNLOCKED;
	return (f);
}

/* The after-phase of a phase (policy.h): the enum keeps it right behind. */
static enum phase
post_of(enum phase ph)
{
	return ((enum phase)(ph + 1));
}

/*
 * The policies bound in this build, over every phase. Zero is the
 * checkout's own foundation.c (no gate, no claim): a loader that would
 * measure nothing and still open the root. It refuses before the dialog.
 */
static unsigned int
policies_bound(void)
{
	const struct policy *p;
	enum phase ph;
	unsigned int n = 0;

	for (ph = PHASE_BOOT; ph <= PHASE_KERNEL_POST; ph++)
		for (p = phase_policies(ph); p->gate != NULL; p++)
			n++;
	return (n);
}

void
local_run(enum phase ph, int argc, CHAR16 *argv[])
{
	const struct policy *p;
	enum phase post = post_of(ph);

	evidence_args(argc, argv);
	if (ph == PHASE_KERNEL && policies_bound() == 0)
		halt_boot("no gate bound: this loader was built from the checkout's "
		    "empty foundation.c (stage foundation make, then stage make)");
	/*
	 * KERNEL: the gates measure; none of them halts or asks for a
	 * password (unlock_act, bound where the owner wants an informed
	 * decision, is the one exception, and it compares the one hash
	 * left). The record loads at its first claim (record_state), which
	 * runs the one dialog of the boot (geli_open.c) if it has not run:
	 * the line goes to the TPM, which decides by PCR policy and auth
	 * value which object opens (tpm_keyfile.c), then to GELI. The dialog
	 * runs at the latest after the policies, so the kernel always gets
	 * its keys.
	 */
	for (p = phase_policies(ph); p->gate != NULL; p++)
		policy_run(ph, p, argc, argv);
	for (p = phase_policies(post); p->gate != NULL; p++)
		policy_run(post, p, argc, argv);
	if (ph == PHASE_KERNEL) {
		geli_open_ensure();
		if (evidence()->duress) {
			decoy_divert();
			return;
		}
		(void)record_commit(record_flags());
	}
}

void
local_run_kernel(void)
{
	const struct evidence *e = evidence();

	local_run(PHASE_KERNEL, e->argc, e->argv);
}
