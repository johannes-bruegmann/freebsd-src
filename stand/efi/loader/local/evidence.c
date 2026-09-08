/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * evidence.c -- the ledger of this boot (evidence.h).
 */

#include <stand.h>
#include <string.h>

#include <efi.h>

#include "measurement.h"
#include "claim.h"
#include "gate.h"
#include "evidence.h"

static struct evidence E;

const struct evidence *
evidence(void)
{
	return (&E);
}

void
evidence_args(int argc, CHAR16 *argv[])
{
	if (E.argv == NULL && argv != NULL) {
		E.argc = argc;
		E.argv = argv;
	}
}

void
evidence_note_appraisal(unsigned int phase, const struct appraisal *a)
{
	struct evidence_entry *e;
	const struct claim *c;
	const struct claim_result *r;

	if (E.ngates >= EVIDENCE_GATES_MAX)
		return;
	e = &E.gates[E.ngates++];
	e->phase = phase;
	e->gate = a->gate->name;
	e->verdict = a->verdict;
	e->failed = e->skipped = 0;
	for (c = a->gate->claims, r = a->results; c->measure != NULL; c++, r++) {
		if (r->verdict == VERDICT_FAIL)
			e->failed++;
		else if (r->verdict == VERDICT_SKIP)
			e->skipped++;
	}
	if (a->verdict == VERDICT_FAIL) {
		E.failed_gates++;
		E.taint = true;
	}
}

/* The interactive members of the catalog: their run is itself evidence. */
void
evidence_note_action(const char *name)
{
	/*
	 * Only actions at which a SECRET is typed count: the prompted bit of
	 * the handover word means "a hidden line was read", not "a key was
	 * pressed" -- report_act's pause and reveal_act's words do not.
	 */
	static const char *const interactive[] = { "prompt", "sentinel",
	    "confirm", "lock", "unlock", NULL };
	unsigned int i;

	for (i = 0; interactive[i] != NULL; i++)
		if (strcmp(interactive[i], name) == 0) {
			E.prompted++;
			return;
		}
}

void
evidence_note_unlock(void)
{
	E.unlocked++;
}

void
evidence_note_attempt(void)
{
	E.attempts++;
}

void
evidence_note_prompt(uint64_t dwell_ms, uint64_t cadence_ms)
{
	E.prompt_ms += dwell_ms;
	if (cadence_ms > E.cadence_ms)
		E.cadence_ms = cadence_ms;
}

void
evidence_set_duress(void)
{
	E.duress = true;
}

void
evidence_set_taint(void)
{
	E.taint = true;
}

void
evidence_set_silence(void)
{
	E.silence = true;
}

/*
 * The canonical rendering: one line per gate "phase:gate:verdict:failed:
 * skipped", then the counters. Deterministic for a given boot, so two
 * derivations (the handover word, the reveal words) agree.
 */
void
evidence_digest(uint8_t out[static SHA256_DIGEST_LENGTH])
{
	SHA256_CTX ctx;
	char line[128];
	unsigned int i;

	SHA256_Init(&ctx);
	for (i = 0; i < E.ngates; i++) {
		snprintf(line, sizeof(line), "%u:%s:%u:%u:%u\n",
		    E.gates[i].phase, E.gates[i].gate, E.gates[i].verdict,
		    E.gates[i].failed, E.gates[i].skipped);
		SHA256_Update(&ctx, line, strlen(line));
	}
	snprintf(line, sizeof(line), "f=%u p=%u u=%u a=%u t=%u d=%u\n",
	    E.failed_gates, E.prompted, E.unlocked, E.attempts,
	    E.taint ? 1 : 0, E.duress ? 1 : 0);
	SHA256_Update(&ctx, line, strlen(line));
	SHA256_Final(out, &ctx);
}
