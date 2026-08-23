/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * measurement.h -- evidence: the datum, its generic operations, and the
 * catalog of providers that obtain one.
 *
 * A measurement carries its own identity (name) and its value in native form,
 * discriminated by type. The canonical string is a rendering at the boundary
 * (compare, publish), never the storage. Providers are pure producers of
 * evidence: measure_*() only measures. A few observations also yield a
 * human-readable diagnostic (byte counts, the argv record) that is not part of
 * the compared value; a separate diagnose_*() produces it into a struct
 * diagnosis. Neither measure nor diagnose publishes -- that is the gate's job.
 */

#ifndef _LOCAL_MEASUREMENT_H_
#define	_LOCAL_MEASUREMENT_H_

#include <sys/types.h>
#include <stdbool.h>

#include <efi.h>			/* CHAR16 */
#include <crypto/sha2/sha256.h>

enum meas_type { MEAS_BYTE, MEAS_SHA256 };

struct measurement {
	const char	*name;		/* what was observed */
	enum meas_type	 type;		/* selects the union arm */
	bool		 present;
	union {
		uint8_t	byte;
		uint8_t	digest[SHA256_DIGEST_LENGTH];
	} value;
};

#define	MEASUREMENT_NONE(nm, ty)					\
	{ .name = (nm), .type = (ty), .present = false }
#define	MEASUREMENT_BYTE(nm, v)						\
	{ .name = (nm), .type = MEAS_BYTE, .present = true, .value.byte = (v) }
#define	MEASUREMENT_SHA256(nm, ...)					\
	{ .name = (nm), .type = MEAS_SHA256, .present = true,		\
	  .value.digest = { __VA_ARGS__ } }

/*
 * A diagnostic: extra human-readable evidence from the same observation,
 * separate from the compared value. leaf == NULL means "none"; the gate
 * publishes text under loader.trust.<gate>.<leaf>.
 */
struct diagnosis {
	const char	*leaf;		/* kenv leaf, or NULL for none */
	char		 text[256];	/* the value, e.g. "1590,1204,3841" */
};

/* generic operations on the datum */
void	measurement_render(const struct measurement *, char *out, size_t);
bool	measurement_equal(const struct measurement *,
	    const struct measurement *);

/*
 * Provider catalog. Producers of evidence, before parse_args/interact(): only
 * EFI variables, SMBIOS and the boot entry's LoadOptions (argv) are available.
 * measure_*() only measures; diagnose_*() (where offered) gathers the matching
 * human-readable diagnostic from the same source.
 */
/*
 * Prerequisites the loader must find before it will trust the boot; each count
 * is a pass threshold (all must be present/verified). Two lists, two probes:
 *   _EXIST  -- interpreter .lua chain, checked for existence (stat). VE_MUST, so
 *              strict already catches tampering; the gap is deletion.
 *   _VERIFY -- loader.conf (VE_WANT) and device.hints (VE_TRY), checked with
 *              verify_file: strict does not fully cover these, so absence AND
 *              tamper are caught here.
 * The tables in measurement.c are declared [..._N], so the compiler keeps each
 * list and its threshold in step.
 */
#define	LOADER_PREREQUISITES_EXIST_N	16
#define	LOADER_PREREQUISITES_VERIFY_N	2

struct measurement	measure_prerequisites_exist(int argc, CHAR16 *argv[]);
struct measurement	measure_prerequisites_verify(int argc, CHAR16 *argv[]);
struct measurement	measure_secureboot(int argc, CHAR16 *argv[]);
struct measurement	measure_setupmode(int argc, CHAR16 *argv[]);
struct measurement	measure_board(int argc, CHAR16 *argv[]);
struct measurement	measure_keys(int argc, CHAR16 *argv[]);
struct measurement	measure_marker(int argc, CHAR16 *argv[]);
struct measurement	measure_strict(int argc, CHAR16 *argv[]);
struct measurement	measure_ve_strict(int argc, CHAR16 *argv[]);

void	diagnose_prerequisites_exist(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_prerequisites_verify(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_keys(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_marker(int argc, CHAR16 *argv[], struct diagnosis *);

#endif /* _LOCAL_MEASUREMENT_H_ */
