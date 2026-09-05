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
 *
 * Windows and counters are measured as VERDICT BYTES: a provider that
 * checks "within the provisioned window" returns 1/0 and puts the raw
 * numbers into its diagnosis, so the claim model (expected == actual)
 * stays one model. The windows themselves are site.mk baselines
 * (-DLOADER_TRUST_*), never runtime input.
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
void	measurement_sha256(const void *, size_t,
	    uint8_t out[static SHA256_DIGEST_LENGTH]);

/*
 * Provider catalog. Producers of evidence. Before parse_args/interact() only
 * EFI variables, SMBIOS and the boot entry's LoadOptions (argv) are available;
 * the KERNEL-phase providers (measure_howto ... measure_ledger_*) read state
 * that exists only after the interactive window. measure_*() only measures;
 * diagnose_*() (where offered) gathers the matching human-readable diagnostic
 * from the same source.
 */
/*
 * Prerequisites the loader must find before it will trust the boot; each count
 * is a pass threshold (all must be present/verified). Two lists, two probes:
 *   _EXIST  -- interpreter .lua chain, checked for existence (stat). VE_MUST, so
 *              strict already catches tampering; the gap is deletion.
 *   _VERIFY -- loader.conf (VE_WANT) and device.hints (VE_TRY), checked with
 *              verify_file: strict does not fully cover these, so absence AND
 *              tamper are caught here.
 * The lists themselves are emitted by elebake into the generated
 * foundation.c together with the LOADER_PREREQUISITES_*_N constants the
 * expectations are built from; here only the extern view the consumers
 * loop over. Curation lives in the database (stage prerequisites
 * exist|verify add), never in this source.
 */
extern const char *const	prerequisites_exist[];
extern const char *const	prerequisites_verify[];
extern const unsigned int	prerequisites_exist_n;
extern const unsigned int	prerequisites_verify_n;

/*
 * --- platform (measurement.c): firmware state, key store, board, marker ---
 * measure_prerequisites_exist  number of EXIST prerequisites (the interpreter
 *                    .lua chain, VE_MUST) found on the boot file system;
 *                    the claim expects the full count. Deletion is the gap
 *                    strict veriexec does not close.
 * measure_prerequisites_verify number of VERIFY prerequisites (loader.conf,
 *                    device.hints, the loader's reserve) that verify against
 *                    the manifest; the claim expects the full count.
 * measure_secureboot the firmware's SecureBoot variable (1 = enforcing).
 *                    Absent when the variable does not exist -- an armed
 *                    expectation reports that.
 * measure_setupmode  the firmware's SetupMode variable (0 = user mode, the
 *                    owner's keys are enrolled; 1 = anyone may enroll keys)
 * measure_board      sha256 of the board serial from SMBIOS -- THIS machine.
 *                    Assumes the firmware exposes SMBIOS and that rewriting
 *                    it means opening the case (the seal tells).
 * measure_keys       sha256 over PK||KEK||db -- the owner's key store; a
 *                    re-enrolled or added certificate moves it. Absent when
 *                    none of the three variables can be read.
 * measure_marker     1 iff the boot entry's LoadOptions (argv) carry the
 *                    owner's marker token (expected digest compiled in): the
 *                    boot went through the provisioned Boot####, not a
 *                    fallback path. A wiped entry fails.
 * measure_strict     1 iff veriexec is verifying with the strict threshold
 *                    in force (runtime read of Verifying, mode-independent)
 * measure_ve_strict  1 iff /boot/loader.ve.strict exists, the marker file
 *                    FreeBSD's convention expects; measured, never enforced
 * measure_origin     sha256 over the canonical GUID text of our load origin
 *                    (the partition the firmware loaded us from); site mk
 *                    hashes the ESP's rawuuid the same way
 * measure_origin_verified  1 iff the file at our own load origin is byte-
 *                    identical to /boot/loader.efi.signed, the manifest-
 *                    covered reserve: chains the ESP copy to the attested
 *                    manifest without parsing it here
 */
struct measurement	measure_prerequisites_exist(int argc, CHAR16 *argv[]);
struct measurement	measure_prerequisites_verify(int argc, CHAR16 *argv[]);
struct measurement	measure_secureboot(int argc, CHAR16 *argv[]);
struct measurement	measure_setupmode(int argc, CHAR16 *argv[]);
struct measurement	measure_board(int argc, CHAR16 *argv[]);
struct measurement	measure_keys(int argc, CHAR16 *argv[]);
struct measurement	measure_marker(int argc, CHAR16 *argv[]);
struct measurement	measure_strict(int argc, CHAR16 *argv[]);
struct measurement	measure_ve_strict(int argc, CHAR16 *argv[]);
struct measurement	measure_origin(int argc, CHAR16 *argv[]);
struct measurement	measure_origin_verified(int argc, CHAR16 *argv[]);

/*
 * --- inventory (measure_platform.c): what else the firmware loaded ---
 * measure_image      sha256 of OUR running image (ImageBase..ImageSize).
 *                    No compiled-in expectation is possible (the loader
 *                    cannot contain its own hash): publish-only; earlboot
 *                    compares it with the digest elebake deployed.
 * measure_images     sha256 over every EFI_LOADED_IMAGE the firmware holds
 *                    (base, size, image bytes, in handle order): an injected
 *                    DXE/runtime driver -- the bootkit class -- changes it.
 *                    Baseline: learned from a trusted boot (stage baseline
 *                    learn), the firmware update changes it legitimately.
 * measure_acpi       sha256 over every ACPI table (XSDT order). Baseline
 *                    learned; a BIOS update or a Setup change moves it.
 * measure_efivars    sha256 over every NON-VOLATILE EFI variable (name,
 *                    GUID, attributes, data; our own record excluded).
 *                    Baseline learned; BootOrder edits move it.
 * measure_pci        sha256 over the PCI device list (segment/bus/device/
 *                    function, vendor:device) -- a hardware implant is a
 *                    new device. Assumes the implant enumerates; a purely
 *                    passive bus tap does not.
 */
struct measurement	measure_image(int argc, CHAR16 *argv[]);
struct measurement	measure_images(int argc, CHAR16 *argv[]);
struct measurement	measure_acpi(int argc, CHAR16 *argv[]);
struct measurement	measure_efivars(int argc, CHAR16 *argv[]);
struct measurement	measure_pci(int argc, CHAR16 *argv[]);

/*
 * --- disks (measure_disk.c) ---
 * measure_geli       sha256 over the GELI metadata sectors (last sector) of
 *                    the partitions named by LOADER_TRUST_GELI_PARTS (GPT
 *                    partition GUIDs, comma list). site mk hashes the same
 *                    sectors from userland. Moves on every legitimate
 *                    setkey/delkey -- then the baseline is renewed.
 * measure_gpt        sha256 over the GPT header (LBA 1) and the partition
 *                    entry array of every disk that carries one of those
 *                    partitions. Detects the moved/added/replaced partition.
 */
struct measurement	measure_geli(int argc, CHAR16 *argv[]);
struct measurement	measure_gpt(int argc, CHAR16 *argv[]);

/*
 * --- the boot record and its anchors (measure_record.c, KERNEL phase) ---
 * The loader keeps a record in NVRAM (record.h): boot counter, last boot
 * time, the TPM's reset count and clock, the NVMe's power-cycle count, and
 * a hash chain whose last link also lives on the boot medium. Every field
 * is encrypt-then-MAC under keys HKDF-derived from the GELI passphrase the
 * owner types at boot plus a compiled-in salt: the binary holds no key, a
 * stolen medium forges nothing. What a rollback (snapshot the NVRAM before
 * a foreign boot, restore it after) cannot fake are the anchors: the TPM's
 * resetCount, the NVMe's power cycles, and the chain link the medium
 * remembers. Assumes: GELI passphrase entered in the loader; the case seal
 * (SPI flash) holds; a TPM (Intel PTT) and an NVMe are present -- without
 * them the respective claim is absent, which an armed expectation reports.
 * All record claims belong to the KERNEL phase (the passphrase exists from
 * the LOADER phase on).
 *
 * measure_record        1 iff the NVRAM record exists and its MAC verifies
 * measure_counter_step  1 iff every available anchor advanced by exactly
 *                       one since the record: TPM resetCount, NVMe power
 *                       cycles, and (after handover) the record counter.
 *                       Two boots the owner did not make, or a restored
 *                       record, break the step.
 * measure_chain         1 iff the chain link on the boot medium equals
 *                       the record's link (the medium remembers)
 * measure_lastboot_gap  1 iff at least LOADER_TRUST_TIME_GAP_MIN_S seconds
 *                       passed since the recorded last boot
 * measure_time_of_day   1 iff the RTC hour lies within
 *                       [LOADER_TRUST_TIME_HOUR_MIN, LOADER_TRUST_TIME_HOUR_MAX]
 * measure_tpm           1 iff a TPM answered (TCG2 protocol, ReadClock)
 * measure_pcr           sha256 over the PCR 0..7 SHA256 bank -- the
 *                       firmware's own measured boot (Boot Guard/PTT
 *                       event log). Baseline learned; BIOS/Setup changes
 *                       move it. Read-only use of the TPM: no sealing, no
 *                       key material.
 * measure_nvme          1 iff an NVMe answered the SMART log page
 */
struct measurement	measure_record(int argc, CHAR16 *argv[]);
struct measurement	measure_counter_step(int argc, CHAR16 *argv[]);
struct measurement	measure_chain(int argc, CHAR16 *argv[]);
struct measurement	measure_lastboot_gap(int argc, CHAR16 *argv[]);
struct measurement	measure_time_of_day(int argc, CHAR16 *argv[]);
struct measurement	measure_tpm(int argc, CHAR16 *argv[]);
struct measurement	measure_pcr(int argc, CHAR16 *argv[]);
struct measurement	measure_nvme(int argc, CHAR16 *argv[]);

/*
 * --- time (measure_time.c; clock.h keeps the stamps) ---
 * measure_time_boot     1 iff the time from efi_main entry to now is at
 *                       most LOADER_TRUST_TIME_BOOT_MAX_MS (KERNEL phase:
 *                       "how long did this boot take")
 * measure_time_prompt   1 iff the summed dwell at passphrase prompts lies
 *                       within [LOADER_TRUST_TIME_PROMPT_MIN_MS, _MAX_MS].
 *                       The duress signal JB named first: typing under
 *                       coercion takes longer.
 * measure_time_rtc_tsc  1 iff the RTC delta and the cycle-counter delta
 *                       since entry agree within LOADER_TRUST_TIME_SKEW_MS
 *                       -- a set-back RTC does not move the TSC
 * measure_attempts      the number of passphrase entries at the gate
 *                       prompts of this boot (expected 1; 2 is a tell)
 */
struct measurement	measure_time_boot(int argc, CHAR16 *argv[]);
struct measurement	measure_time_prompt(int argc, CHAR16 *argv[]);
struct measurement	measure_time_rtc_tsc(int argc, CHAR16 *argv[]);
struct measurement	measure_attempts(int argc, CHAR16 *argv[]);

/*
 * --- KERNEL phase (measure_kernel.c) ---
 * measure_howto         the RB_* flags the kernel will receive, masked to
 *                       the ones that change its behaviour (single user,
 *                       kdb, verbose, serial, mute); expected 0
 * measure_kenv_guard    sha256 over the current values of the guarded
 *                       kenv variables (LOADER_TRUST_KENV_GUARD, comma
 *                       list: vfs.root.mountfrom, init_path, module_path,
 *                       kernel ...). Baseline learned; a `set` at the
 *                       prompt moves it.
 * measure_preload       1 iff every preloaded file verified against the
 *                       manifest (the S10 finding: typed blobs such as
 *                       /boot/entropy are loaded without a manifest entry)
 * measure_softpcr       sha256 of libsecureboot's soft PCR -- the extend-
 *                       only aggregate over every verified file, in load
 *                       order. Baseline learned; moves with every legitimate
 *                       kernel/module update and every prompt-side load.
 * measure_ledger_failed   number of gates that FAILED in earlier phases
 * measure_ledger_prompted number of interactive actions that ran so far
 * measure_ledger_unlocked number of unlocks so far
 */
struct measurement	measure_howto(int argc, CHAR16 *argv[]);
struct measurement	measure_kenv_guard(int argc, CHAR16 *argv[]);
struct measurement	measure_preload(int argc, CHAR16 *argv[]);
struct measurement	measure_softpcr(int argc, CHAR16 *argv[]);
struct measurement	measure_ledger_failed(int argc, CHAR16 *argv[]);
struct measurement	measure_ledger_prompted(int argc, CHAR16 *argv[]);
struct measurement	measure_ledger_unlocked(int argc, CHAR16 *argv[]);

/*
 * --- diagnostics: human-readable evidence next to a verdict, published
 * under loader.trust.<gate>.<leaf> when the claim names the diagnose ---
 * diagnose_origin              origin: "<partition-guid>:<file-path>"
 * diagnose_prerequisites_exist exist.missing: comma list of the EXIST
 *                              prerequisites not found (empty = all present)
 * diagnose_prerequisites_verify verify.missing: comma list of the VERIFY
 *                              prerequisites that did not verify
 * diagnose_keys                keys.bytes: byte counts of PK,KEK,db
 * diagnose_marker              argv: the boot command line, marker redacted
 * diagnose_images              images.count: number of loaded EFI images
 * diagnose_pci                 pci.count: number of PCI devices
 * diagnose_record              record: what the NVRAM record holds
 * diagnose_counter_step        anchors: recorded/current TPM reset count, NV
 *                              counter and NVMe power cycles
 * diagnose_lastboot_gap        lastboot.gap.s: seconds since the recorded
 *                              last boot, or unknown
 * diagnose_tpm                 tpm: what the TPM answered, or none(<error>)
 * diagnose_nvme                nvme: what the SMART page answered, or none
 * diagnose_time_boot           time.boot.ms: entry-to-now in milliseconds
 * diagnose_time_prompt         time.prompt: dwell, cadence, attempts
 * diagnose_time_rtc_tsc        time.now: RTC, TSC and ticks per millisecond
 * diagnose_howto               howto: the RB_* flags in hex and by name
 * diagnose_preload             preload: total and unverified preloaded files
 * diagnose_ledger              ledger: gates, failed, prompted, unlocked
 *                              counts and the per-gate entries
 */
void	diagnose_origin(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_prerequisites_exist(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_prerequisites_verify(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_keys(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_marker(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_images(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_pci(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_record(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_counter_step(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_lastboot_gap(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_tpm(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_nvme(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_time_boot(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_time_prompt(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_time_rtc_tsc(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_howto(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_preload(int argc, CHAR16 *argv[], struct diagnosis *);
void	diagnose_ledger(int argc, CHAR16 *argv[], struct diagnosis *);

#endif /* _LOCAL_MEASUREMENT_H_ */
