/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * foundation.c -- layer 0: the earliest local platform checks for the EFI
 * loader. It defines the bootlock gate (which claims, weighed against which
 * compiled baselines) and pairs it with actions per phase; it measures nothing
 * itself -- the providers (measurement.c) do, the gate drives them.
 *
 * The expected baselines arrive from the build as byte lists (site.mk):
 *   CFLAGS.foundation.c += -DLOADER_TRUST_BOARD_DIGEST='0xab,0x12,...'  (32 bytes)
 * A missing baseline -> MEASUREMENT_NONE -> that claim skips (unprovisioned).
 * The marker digest additionally reaches measurement.c (CFLAGS.measurement.c).
 *
 * bootlock  : appraise the platform, publish the evidence, and on a failure
 *             report it. Detection, not enforcement -- the loader PW is Lua.
 * loaderlock: nothing here (the loader prompt lock is password.lua).
 */

#include "measurement.h"
#include "claim.h"
#include "policy.h"			/* pulls gate.h (gates) + action.h (actions) */

/* --- expected baselines (build-provided byte lists; absent -> claim skips) --- */

#ifdef LOADER_TRUST_BOARD_DIGEST
#define	BOARD_EXPECTED	MEASUREMENT_SHA256("BoardIdentity", LOADER_TRUST_BOARD_DIGEST)
#else
#define	BOARD_EXPECTED	MEASUREMENT_NONE("BoardIdentity", MEAS_SHA256)
#endif

#ifdef LOADER_TRUST_KEYS_DIGEST
#define	KEYS_EXPECTED	MEASUREMENT_SHA256("SecureBootKeys", LOADER_TRUST_KEYS_DIGEST)
#else
#define	KEYS_EXPECTED	MEASUREMENT_NONE("SecureBootKeys", MEAS_SHA256)
#endif

#ifdef LOADER_TRUST_MARKER_DIGEST
#define	MARKER_EXPECTED	MEASUREMENT_SHA256("BootMarker", LOADER_TRUST_MARKER_DIGEST)
#else
#define	MARKER_EXPECTED	MEASUREMENT_NONE("BootMarker", MEAS_SHA256)
#endif

/*
 * The loaderlock recovery secret (hex sha256 of a passphrase), compiled in via
 * site.mk if provisioned. It lives in the SIGNED loader, not in loader.conf --
 * loader.conf is exactly the object that may be missing/tampered when the gate
 * fires. Absent -> NULL -> the gate reports and continues (report-only).
 */
#ifdef LOADER_TRUST_LOADERLOCK_SECRET
#define	LOADERLOCK_SECRET	LOADER_TRUST_LOADERLOCK_SECRET
#else
#define	LOADERLOCK_SECRET	NULL
#endif

/*
 * The bootlock recovery secret -- conceptually a separate value from the
 * loaderlock one (they may diverge), provisioned from the same passphrase for
 * now. Absent -> NULL -> bootlock reports and continues.
 */
#ifdef LOADER_TRUST_BOOTLOCK_SECRET
#define	BOOTLOCK_SECRET		LOADER_TRUST_BOOTLOCK_SECRET
#else
#define	BOOTLOCK_SECRET		NULL
#endif

/* --- the platform-trust gate, publishing loader.trust.bootlock.* --- */

GATE_DEFINE(bootlock, BOOTLOCK_SECRET,
    CLAIM(measure_secureboot, NULL,            NULL,           MEASUREMENT_BYTE("SecureBoot", 1)),
    CLAIM(measure_setupmode,  NULL,            NULL,           MEASUREMENT_BYTE("SetupMode", 0)),
    CLAIM(measure_marker,     diagnose_marker, NULL,           MARKER_EXPECTED),
    CLAIM(measure_board,      NULL,            "board.sha256", BOARD_EXPECTED),
    CLAIM(measure_keys,       diagnose_keys,   "keys.sha256",  KEYS_EXPECTED));

/* --- the loaderlock gate, publishing loader.trust.loaderlock.* --- */
/*
 * Prerequisites must be in place before the interpreter runs -- absence is
 * invisible to veriexec, so it is checked here. Two claims: the .lua chain by
 * existence, loader.conf/device.hints by verified read (strict does not fully
 * cover those). Each measured value is the count that held; the expected value
 * is the whole count, so a claim passes only when all hold. diagnose_* publish
 * which fell short (exist.missing / verify.missing).
 */
GATE_DEFINE(loaderlock, LOADERLOCK_SECRET,
    CLAIM(measure_prerequisites_exist,  diagnose_prerequisites_exist,  "exist.count",
        MEASUREMENT_BYTE("PrereqsExist", LOADER_PREREQUISITES_EXIST_N)),
    CLAIM(measure_prerequisites_verify, diagnose_prerequisites_verify, "verify.count",
        MEASUREMENT_BYTE("PrereqsVerify", LOADER_PREREQUISITES_VERIFY_N)));

/*
 * =====================================================================
 *  The policy tables, one per phase -- read these first.
 * =====================================================================
 */
static const struct policy bootlock_policies[] = {
	POLICY(bootlock,
	    FIRE(when_always, &publish_act),	/* always expose the evidence */
	    FIRE(when_fail,   &unlock_act)),	/* on tamper: report + compiled-in
						   PW (config-independent), else the
						   Lua PW would vanish with a lost
						   loader.conf. NULL secret ->
						   report + proceed */
	POLICY_END,
};

static const struct policy loaderlock_policies[] = {
	POLICY(loaderlock,
	    FIRE(when_always, &publish_act),	/* expose count + missing list */
	    FIRE(when_fail,   &unlock_act)),	/* report failed claims, then demand
						   the compiled-in passphrase (if
						   provisioned) before the prompt;
						   NULL secret -> report + proceed */
	POLICY_END,
};

const struct policy *
phase_policies(enum phase ph)
{
	switch (ph) {
	case PHASE_BOOTLOCK:
		return (bootlock_policies);
	case PHASE_LOADERLOCK:
		return (loaderlock_policies);
	}
	return (loaderlock_policies);	/* unreachable; keeps the compiler happy */
}
