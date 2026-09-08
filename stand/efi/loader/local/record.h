/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * record.h -- the boot record: what the last boot left behind, sealed.
 *
 * One NVRAM variable (ElvRecord, elvboot's own GUID) carries the previous
 * boot's counter, its time, the hardware anchors it saw (TPM reset count and
 * clock, NVMe power cycles and unsafe shutdowns) and the last link of a hash
 * chain. It is encrypt-then-MAC: AES-256-CTR under a key derived (HKDF-
 * SHA256) from the compiled-in record secret, then HMAC-SHA256 over the
 * ciphertext under a second derived key. A record that does not verify is
 * absent -- there is no "partially trusted" record.
 *
 * The same chain link is appended to a file on the boot medium's ESP
 * (/EFI/elvboot/chain, one sealed link per boot). NVRAM lives in the laptop,
 * the file lives on the medium the owner carries: a rollback of the one
 * disagrees with the other.
 *
 * Keys: HKDF-SHA256 with IKM = SHA256 of GELI's derived user key (the PBKDF2
 * output geliboot computed from passphrase and keyfiles -- a guess at the
 * record costs what a guess at GELI costs), optionally followed by the BOOT
 * ANSWER (loader.conf elvboot_answer_prompt="YES": one hidden line asked in
 * the KERNEL phase, kept nowhere, so a record proves the PAIR and an observed
 * passphrase opens GELI but not the record); salt = LOADER_TRUST_RECORD_SALT
 * from site.mk, 32 random bytes that live on the boot medium, not on the
 * laptop. Nothing in the loader binary unlocks a record. Assumes: the boot
 * is GELI-protected and unlocked in the loader; the anchors are read-only
 * facts of hardware the loader does not control (tpm.h, nvme.h). Absence of
 * any of them is reported, never silently accepted.
 *
 * record_load() runs at the start of PHASE_KERNEL (the passphrase exists
 * from the LOADER phase on), record_commit() at its end, after every gate
 * of the boot has spoken: the committed record describes THIS boot, the
 * loaded one the previous.
 *
 * Not a catalog: internal to the local layer.
 */

#ifndef _LOCAL_RECORD_H_
#define	_LOCAL_RECORD_H_

#include <stdint.h>
#include <stdbool.h>

#include <crypto/sha2/sha256.h>

#define	RECORD_MAGIC	0x454c5652u	/* "ELVR" */
#define	RECORD_VERSION	1u

struct record_body {
	uint32_t	magic;
	uint32_t	version;
	uint64_t	counter;	/* boots this loader committed */
	uint64_t	boot_epoch;	/* RTC at commit, seconds since 1970 */
	uint64_t	boot_ms;	/* entry-to-commit of that boot */
	uint64_t	tpm_reset;	/* TPM2 resetCount at commit */
	uint64_t	tpm_clock;	/* TPM2 clock (ms) at commit */
	uint64_t	tpm_nvcount;	/* our NV counter after increment */
	uint64_t	nvme_cycles;	/* NVMe power cycles at commit */
	uint64_t	nvme_unsafe;	/* NVMe unsafe shutdowns at commit */
	uint8_t		chain[SHA256_DIGEST_LENGTH];	/* this boot's link */
	uint8_t		flags;		/* RECORD_F_* of that boot */
	uint8_t		pad[7];
};

#define	RECORD_F_TAINT		0x01
#define	RECORD_F_DURESS		0x02
#define	RECORD_F_PROMPTED	0x04

/* The sealed form as stored: nonce || ciphertext(body) || mac */
#define	RECORD_NONCE_LEN	16
#define	RECORD_MAC_LEN		32
#define	RECORD_SEALED_LEN	(RECORD_NONCE_LEN + sizeof(struct record_body) + RECORD_MAC_LEN)

/* The record of the PREVIOUS boot, if it verified. */
struct record_state {
	bool			present;	/* variable existed */
	bool			valid;		/* and its MAC verified */
	struct record_body	prev;		/* meaningful iff valid */
	bool			chain_on_medium; /* the ESP file's last link == prev.chain */
	bool			medium_answered; /* the ESP file could be read */
};

const struct record_state	*record_load(void);	/* once; cached */
const struct record_state	*record_state(void);
bool				 record_secret_present(void);

/* geli_keys.c: derive the root's user key in the loader (see there) */
int	geli_keys_prepare(void);

/* Seal and write this boot's record; append the link to the medium. */
bool	record_commit(uint8_t flags);

/* Derived-key helper of the record itself (keys from the passphrase). */
void	record_hmac(const char *purpose, const void *msg, size_t len,
	    uint8_t out[static SHA256_DIGEST_LENGTH]);

/*
 * The WORD secret (LOADER_TRUST_WORD_SECRET, a string baseline) is the one
 * secret that IS compiled in: earlboot must recompute the handover word
 * and the reveal words without the passphrase. HMAC(HMAC(secret, purpose),
 * msg) -- the same two steps a shell can do with openssl. Assumes: Secure
 * Boot with the owner's db only -- a medium thief learns the secret but
 * cannot run any other loader on this machine, and the owner's loader
 * always records the truth. What the word proves is "the owner's loader
 * ran through the KERNEL phase", not the medium's custody.
 */
bool	word_secret_present(void);
void	word_hmac(const char *purpose, const void *msg, size_t len,
	    uint8_t out[static SHA256_DIGEST_LENGTH]);

/* Append to a file under /EFI/elvboot/ on the medium we were loaded from. */
bool	record_medium_append(const char *name, const void *buf, size_t len);

/* Write/read a small NVRAM variable in elvboot's namespace. */
bool	record_var_set(const char *name, const void *buf, size_t len);
bool	record_var_get(const char *name, void *buf, size_t *len);

/* The one-shot NVRAM note nextboot_act leaves and divert honours. */
bool	record_nextboot_get(char *buf, size_t sz);
void	record_nextboot_set(const char *root);
void	record_nextboot_clear(void);

#endif /* _LOCAL_RECORD_H_ */
