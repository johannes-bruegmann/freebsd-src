/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * claim.h -- an asserted name/value weighed against a measurement, plus the
 * per-claim result.
 *
 * A claim is immutable: an expected measurement (compiled in), an optional
 * kenv leaf under which the gate publishes the measured value, a provider that
 * measures, and an optional provider that gathers a diagnostic. The actual
 * measurement is transient -- gate_appraise obtains it, weighs it (claim_verdict)
 * and records a claim_result. Claims are built inline into gates (CLAIM/CLAIMS,
 * gate.h); results are stored 1:1 alongside them.
 */

#ifndef _LOCAL_CLAIM_H_
#define	_LOCAL_CLAIM_H_

#include <efi.h>			/* CHAR16 */

#include "measurement.h"

enum verdict { VERDICT_SKIP, VERDICT_PASS, VERDICT_FAIL };

struct claim {
	struct measurement	expected;
	const char		*publish;	/* kenv leaf for actual, or NULL */
	struct measurement	(*measure)(int, CHAR16 *[]);
	void			(*diagnose)(int, CHAR16 *[], struct diagnosis *);
};

/* The runtime result of one claim -- 1:1 with the claim (positional). */
struct claim_result {
	enum verdict		verdict;	/* pass / fail / skip */
	struct measurement	actual;		/* what was measured */
	struct diagnosis	diag;		/* diag.leaf == NULL if none */
};

/*
 * Build a claim initializer for use inside CLAIMS() (gate.h): the measure
 * provider, an optional diagnose provider (NULL if none), the publish leaf
 * (NULL if the value is not exposed), and the expected MEASUREMENT_* (its inner
 * commas ride in the variadic tail).
 */
#define	CLAIM(measurefn, diagnfn, pub, ...)				\
	{ .measure = (measurefn), .diagnose = (diagnfn), .publish = (pub), \
	  .expected = __VA_ARGS__ }
#define	CLAIM_END	{ .measure = NULL }

/*
 * No expectation (unprovisioned or build-disarmed) skips; an armed claim whose
 * measurement is absent fails; otherwise expected vs actual.
 */
enum verdict	claim_verdict(const struct claim *,
		    const struct measurement *actual);

#endif /* _LOCAL_CLAIM_H_ */
