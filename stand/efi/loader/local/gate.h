/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * gate.h -- an appraisal over a set of claims.
 *
 * A gate is pure const configuration: a name and a CLAIM_END-terminated claim
 * array (the sentinel is the sole length source). gate_appraise() measures each
 * claim, weighs it, and fills a caller-provided results array 1:1 with the
 * claims -- it has no side effects, it does not publish. The appraisal bundles
 * the gate, the overall verdict and those results for the actions to consume.
 *
 * GATE_DEFINE(id, ...) emits, at file scope, the const claim array, an
 * exact-sized results scratch, and the gate. Because the results array is sized
 * by the same macro, it can never be too short -- overflow is impossible by
 * construction, not caught at runtime. Publishing is loader.trust.<name>.<leaf>.
 */

#ifndef _LOCAL_GATE_H_
#define	_LOCAL_GATE_H_

#include <efi.h>			/* CHAR16 */

#include "claim.h"

struct gate {
	const char		*name;		/* publishes under loader.trust.<name> */
	const char		*secret;	/* compiled-in unlock hash (hex sha256), or NULL */
	const struct claim	*claims;	/* CLAIM_END-terminated */
};

/* The runtime result of appraising a gate; results is 1:1 with gate->claims. */
struct appraisal {
	const struct gate	*gate;
	enum verdict		 verdict;	/* overall; binary PASS/FAIL */
	struct claim_result	*results;
};

/*
 * Emit a gate's const claims, its exact-sized results scratch, and the gate.
 * sec is the compiled-in unlock secret (hex sha256) or NULL for a gate with no
 * lock; an action (action_unlock) reads it from a->gate->secret.
 */
#define	GATE_DEFINE(id, sec, ...)					\
	static const struct claim id##_claims[] = { __VA_ARGS__, CLAIM_END }; \
	static struct claim_result					\
	    id##_results[sizeof(id##_claims) / sizeof((id##_claims)[0]) - 1]; \
	static const struct gate id##_gate =				\
	    { .name = #id, .secret = (sec), .claims = id##_claims }

/* Measure every claim into results[], return the overall verdict. Pure. */
enum verdict	gate_appraise(const struct gate *, int argc, CHAR16 *argv[],
		    struct claim_result *results);

/* Compose the kenv name "loader.trust.<gate>.<leaf>" into buf. */
void		gate_var(const struct gate *, const char *leaf,
		    char *buf, size_t);

#endif /* _LOCAL_GATE_H_ */
