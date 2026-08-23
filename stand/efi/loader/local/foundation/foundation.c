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

/* --- the strict-watch gate, publishing loader.trust.strictwatch.* --- */
/*
 * The soft guarantee, watched not enforced: strict should be active and the
 * loader.ve.strict marker should exist. Both claims expect 1; a shortfall is
 * published, never halted (see the publish-only policy below). This is the
 * point of the whole exercise -- we know the medium can be tampered, so we
 * limit ourselves to *noticing*. secret = NULL: nothing to unlock, it only
 * reports.
 */
GATE_DEFINE(strictwatch, NULL,
    CLAIM(measure_strict,    NULL, "strict.active", MEASUREMENT_BYTE("StrictActive", 1)),
    CLAIM(measure_ve_strict, NULL, "strict.marker", MEASUREMENT_BYTE("VeStrictPresent", 1)));

/*
 * =====================================================================
 *  The policy tables, one per phase -- read these first.
 * =====================================================================
 */
static const struct policy boot_policies[] = {
	POLICY(bootlock,
	    FIRE(when_always, &publish_act)),	/* publish-only: record the platform
						   evidence. Enforcement is the Lua
						   path (bootlock_require); the C
						   backstop lives at PHASE_LOADER,
						   tied to the loader.conf path. */
	POLICY_END,
};

static const struct policy loader_policies[] = {
	POLICY(loaderlock,
	    FIRE(when_always, &publish_act),	/* expose count + missing list */
	    FIRE(when_fail,   &unlock_act)),	/* config-independent BACKSTOP: fires
						   when prereqs/loader.conf are unusable,
						   i.e. when the Lua path cannot run (no
						   trust_hash). unlock_act sets
						   <gate>.unlocked so the Lua does not
						   re-ask. NULL secret -> report + proceed */
	POLICY(strictwatch,
	    FIRE(when_always, &publish_act)),	/* watch only: publish the soft-
						   guarantee state, never halt --
						   keeps stock compatibility */
	POLICY_END,
};

const struct policy *
phase_policies(enum phase ph)
{
	switch (ph) {
	case PHASE_BOOT:
		return (boot_policies);
	case PHASE_LOADER:
		return (loader_policies);
	}
	return (loader_policies);	/* unreachable; keeps the compiler happy */
}
