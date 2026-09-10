#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Johannes Brügmann
#
# earlboot -- the userland custody link of the platform-trust chain, phases
# and firing predicates. This directory is a CATALOG SOURCE for elebake
# (elebake stage measure|action|when <stage> earlboot): the functions here
# are what a stage may bind; `elebake stage earlboot mk <stage>` composes
# the referenced ones with the stage's gates and policies into ONE
# hardened rc.d script (readonly PATH, absolute paths, sealed environment).
# Nothing here runs by itself.
#
# Container contract (shared with elvbootd/):
#   measure_<name> <label>   print the measured value (one line) on stdout,
#                            nothing when absent; exit 0 either way
#   diagnose_<name> <label>  optional human-readable text for the same source
#   when_<name>              predicate over the current gate: $GATE,
#                            $GATE_VERDICT (pass|fail), $PASSED $FAILED
#                            $SKIPPED (space lists), and the boot flags
#                            $ELV_WORD_OK $ELV_TAINT $ELV_DURESS $ELV_PROMPTED
#   <name>_act <gate>        unconditional response
# The emitter provides the constants (readonly, from the stage's records):
#   ELV_STATE      /var/db/elvboot            appraisal, book, heartbeat, spool
#   ELV_WORD_SECRET  the compiled WORD secret (baseline LOADER_TRUST_WORD_SECRET)
#   ELV_GATE_LOADER  the loader gate that published the handover word
#   ELV_LOADER_DIGEST  sha256 of the deployed loader.efi (stage record)
#   ELV_ESP        the ESP device of the boot medium (stage media record)
#   ELV_ARM_DIR    the configuration set arm_act installs, disarm_act removes
#   ELV_BEACON     host:port of the silent beacon (stage conf), may be empty
#
# Phases of this container (elebake reads this line):
PHASES="SYSINIT MOUNTED"
#   SYSINIT  first thing after mountcritlocal: kenv, read-only root, the word
#   MOUNTED  file systems are up: files, manifests, EFI variables, the medium

# --- the handover word: recompute HMAC(HMAC(secret,"handover"), msg) for
# every flag combination and learn the flags from the one that matches.
# Runs once from the prologue; the results are globals the whens read.
elv_word_check() {
	local word ledger counter key try msg f
	ELV_WORD_OK=0; ELV_TAINT=0; ELV_DURESS=0; ELV_PROMPTED=0
	word=$($KENV -q "loader.trust.$ELV_GATE_LOADER.word" 2>/dev/null) || return 0
	ledger=$($KENV -q "loader.trust.$ELV_GATE_LOADER.ledger" 2>/dev/null) || return 0
	counter=$($KENV -q "loader.trust.$ELV_GATE_LOADER.counter" 2>/dev/null) || return 0
	[ -n "$word" ] && [ -n "$ledger" ] && [ -n "$counter" ] || return 0
	key=$(printf '%s' handover | $OPENSSL dgst -sha256 -mac HMAC -macopt "key:$ELV_WORD_SECRET" -r 2>/dev/null | $CUT -c1-64)
	for f in 0 1 2 3 4 5 6 7; do
		msg="$ledger|$counter|$f"
		try=$(printf '%s' "$msg" | $OPENSSL dgst -sha256 -mac HMAC -macopt "hexkey:$key" -r 2>/dev/null | $CUT -c1-64)
		if [ "$try" = "$word" ]; then
			ELV_WORD_OK=1
			[ $((f & 1)) -ne 0 ] && ELV_TAINT=1
			[ $((f & 2)) -ne 0 ] && ELV_DURESS=1
			[ $((f & 4)) -ne 0 ] && ELV_PROMPTED=1
			return 0
		fi
	done
	return 0
}

# elv_prologue -- what the generated script runs after the functions and
# before the phases (every container defines one; the emitter calls it)
elv_prologue() {
	elv_word_check
	ELV_ANSWER_MATCHED=0
}

# --- firing predicates ---

# Composition: a trigger record may combine these -- and(a,b), or(a,b),
# not(a) -- and name several actions, compose(a,b). The emitter renders the
# combination as { a && b; }, { a || b; }, ! a, and the actions in order;
# nothing here needs to know.
# when_always -- every time
when_always() { return 0; }
# when_fail -- the gate's overall verdict is fail
when_fail()   { [ "$GATE_VERDICT" = fail ]; }
# when_pass -- the gate's overall verdict is pass
when_pass()   { [ "$GATE_VERDICT" = pass ]; }
# when_skipped -- at least one claim of the gate was skipped: its measurement
# returned nothing, so no verdict was possible
when_skipped() { [ -n "$SKIPPED" ]; }

# when_maybe -- about one run in four, a spot check an observer cannot time.
# xorshift32 seeded from the entropy device: about one run in four. Noise,
# not cryptography; only ever ADDS a spot check.
when_maybe() {
	local s
	s=$($OD -An -tu4 -N4 /dev/urandom | $TR -d ' ')
	[ -n "$s" ] || s=2463534242
	s=$(( (s ^ (s << 13)) & 0xffffffff )); s=$(( (s ^ (s >> 17)) & 0xffffffff )); s=$(( (s ^ (s << 5)) & 0xffffffff ))
	[ $((s & 3)) -eq 0 ]
}

# when_tainted -- the handover word carried taint, or this gate failed
when_tainted()  { [ "$ELV_TAINT" = 1 ] || [ "$GATE_VERDICT" = fail ]; }
# when_duress -- the handover word carried the duress bit; bind only SILENT
# actions here, the coercer must see nothing
when_duress()   { [ "$ELV_DURESS" = 1 ]; }
# when_prompted -- an interactive action ran in the loader
when_prompted() { [ "$ELV_PROMPTED" = 1 ]; }
