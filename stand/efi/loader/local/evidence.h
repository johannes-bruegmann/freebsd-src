/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * evidence.h -- the ledger: what this boot has seen so far, across phases.
 *
 * Gates appraise, actions react, and both leave a trace here: per phase the
 * appraised gates and their verdicts, the actions that fired, and the
 * interactive facts a prompt produces (attempts, dwell, the duress tell).
 * The ledger is the input of the KERNEL-phase providers (measure_ledger_*,
 * measure_time_prompt, measure_attempts) and of the handover word; it is
 * never published in clear -- the duress and taint bits in particular
 * reach earlboot only inside the word.
 *
 * Not a catalog: internal to the local layer.
 */

#ifndef _LOCAL_EVIDENCE_H_
#define	_LOCAL_EVIDENCE_H_

#include <stdbool.h>
#include <stdint.h>

#include <efi.h>			/* CHAR16 */
#include <crypto/sha2/sha256.h>

struct appraisal;

#define	EVIDENCE_GATES_MAX	16

struct evidence_entry {
	unsigned int	 phase;		/* enum phase */
	const char	*gate;
	unsigned int	 verdict;	/* enum verdict */
	unsigned int	 failed;	/* claims that failed */
	unsigned int	 skipped;	/* claims that skipped */
};

struct evidence {
	struct evidence_entry	 gates[EVIDENCE_GATES_MAX];
	unsigned int		 ngates;
	unsigned int		 failed_gates;	/* verdict FAIL, all phases */
	unsigned int		 prompted;	/* interactive actions fired */
	unsigned int		 unlocked;	/* successful unlocks */
	unsigned int		 attempts;	/* passphrase entries, all prompts */
	uint64_t		 prompt_ms;	/* summed dwell at prompts */
	uint64_t		 cadence_ms;	/* longest pause between two keys */
	bool			 duress;	/* a duress tell was observed */
	bool			 taint;		/* taint_act or a failed gate */
	bool			 silence;	/* silence_act: no publish */
	int			 argc;		/* the LoadOptions, kept from BOOT */
	CHAR16			**argv;
};

const struct evidence	*evidence(void);

/* --- notes, written by policy.c and the actions --- */
void	evidence_args(int argc, CHAR16 *argv[]);
void	evidence_note_appraisal(unsigned int phase, const struct appraisal *);
void	evidence_note_action(const char *name);	/* counts the interactive ones */
void	evidence_note_unlock(void);
void	evidence_note_attempt(void);
void	evidence_note_prompt(uint64_t dwell_ms, uint64_t cadence_ms);
void	evidence_set_duress(void);
void	evidence_set_taint(void);
void	evidence_set_silence(void);

/* sha256 over the ledger's canonical rendering (the handover word's input) */
void	evidence_digest(uint8_t out[static SHA256_DIGEST_LENGTH]);

#endif /* _LOCAL_EVIDENCE_H_ */
