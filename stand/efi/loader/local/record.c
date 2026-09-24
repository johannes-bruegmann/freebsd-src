/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * record.c -- the sealed boot record in NVRAM and its link on the medium
 * (record.h).
 *
 * Crypto is what libsa already carries for GELI and veriexec: SHA256
 * (sys/crypto/sha2) and Rijndael (sys/crypto/rijndael). HMAC and HKDF are
 * the textbook constructions over SHA256, written out here (some forty
 * lines) rather than pulling BearSSL's mac/kdf sources into libsa.
 */

#include <stand.h>
#include <stddef.h>
#include <uuid.h>
#include <string.h>

#include <efi.h>
#include <efilib.h>

#include <crypto/sha2/sha256.h>
#include <crypto/rijndael/rijndael.h>

/* efiprot.h spells SIZE_OF_EFI_FILE_INFO with the gnu-efi EFI_FIELD_OFFSET,
 * which this tree does not define. */
#ifndef EFI_FIELD_OFFSET
#define	EFI_FIELD_OFFSET(type, field)	((UINTN)offsetof(type, field))
#endif

#include "clock.h"
#include "evidence.h"
#include "tpm.h"
#include "nvme.h"
#include "record.h"
#include "geli_keys.h"
#include "geli_open.h"
#include "action.h"		/* readsecret */
#include "geliboot.h"		/* geli_ikm_digest */

/* elvboot's variable namespace: {e1b00747-5e1f-4c0d-9a0e-000000e1b007} */
static EFI_GUID elv_guid = { 0xe1b00747, 0x5e1f, 0x4c0d,
    { 0x9a, 0x0e, 0x00, 0x00, 0x00, 0xe1, 0xb0, 0x07 } };

#define	RECORD_VAR	"ElvRecord"
#define	NEXTBOOT_VAR	"ElvNextBoot"
#define	NV_ATTRS	(EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | \
			 EFI_VARIABLE_RUNTIME_ACCESS)

static struct record_state S;
static bool loaded;

static EFI_FILE_HANDLE medium_open(const char *name, bool write);

/* ------------------------------------------------------------ crypto */

static void
hmac_sha256(const uint8_t *key, size_t klen, const void *msg, size_t mlen,
    uint8_t out[static SHA256_DIGEST_LENGTH])
{
	SHA256_CTX ctx;
	uint8_t k[64], ipad[64], opad[64], inner[SHA256_DIGEST_LENGTH];
	size_t i;

	memset(k, 0, sizeof(k));
	if (klen > sizeof(k)) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key, klen);
		SHA256_Final(k, &ctx);
	} else
		memcpy(k, key, klen);
	for (i = 0; i < sizeof(k); i++) {
		ipad[i] = k[i] ^ 0x36;
		opad[i] = k[i] ^ 0x5c;
	}
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, ipad, sizeof(ipad));
	SHA256_Update(&ctx, msg, mlen);
	SHA256_Final(inner, &ctx);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, opad, sizeof(opad));
	SHA256_Update(&ctx, inner, sizeof(inner));
	SHA256_Final(out, &ctx);
	explicit_bzero(k, sizeof(k));
	explicit_bzero(ipad, sizeof(ipad));
	explicit_bzero(opad, sizeof(opad));
}

/* HKDF-SHA256 (RFC 5869), one block of output: PRK = HMAC(salt, IKM); OKM =
 * HMAC(PRK, info || 0x01). */
static void
hkdf_sha256(const uint8_t *salt, size_t slen, const uint8_t *ikm, size_t ilen,
    const char *info, uint8_t out[static SHA256_DIGEST_LENGTH])
{
	uint8_t prk[SHA256_DIGEST_LENGTH], t[128];
	size_t n = strlen(info);

	hmac_sha256(salt, slen, ikm, ilen, prk);
	if (n > sizeof(t) - 1)
		n = sizeof(t) - 1;
	memcpy(t, info, n);
	t[n] = 0x01;
	hmac_sha256(prk, sizeof(prk), t, n + 1, out);
	explicit_bzero(prk, sizeof(prk));
}

/*
 * The key material is NOT in the binary, and it is NOT the passphrase.
 *
 * IKM = SHA256 of GELI's first user key (geli_ikm_digest): the PBKDF2 output
 * over the passphrase and the keyfiles that geliboot computed to unlock the
 * root. Every guess at a record therefore costs an attacker exactly what a
 * guess at GELI costs -- the record is never the cheaper way to the
 * passphrase. Optionally the BOOT ANSWER is appended: a second secret from
 * the owner's head, asked once per boot in the KERNEL phase when loader.conf
 * says elvboot_answer_prompt="YES", stored nowhere -- not even hashed. With
 * it a record proves the PAIR (passphrase, answer); a passphrase that was
 * observed opens GELI but not the record, and a wrong answer makes the
 * record invalid without saying which of the two was wrong.
 *
 * Salt = LOADER_TRUST_RECORD_SALT (site.mk): 32 random bytes compiled into
 * the loader on the boot medium. We do not rely on its secrecy, but it
 * lives where the record does not -- the NVRAM-only attacker lacks it.
 *
 * Three possessions, three parts: the head (passphrase, answer), the boot
 * medium (salt), the laptop (record, marker, TPM, NVMe). One of them alone
 * yields no oracle; all of them together face GELI's per-guess price.
 *
 * Consequence: keys exist only once GELI unlocked, i.e. from the KERNEL
 * phase on -- record_load() runs there, every record claim is a KERNEL-phase
 * claim; record_commit() is the last user of the material and wipes it
 * before ExitBootServices. No unlocked provider -> no record (reported as
 * absent, never silently accepted). A passphrase change changes the IKM and
 * invalidates the previous record once -- a new chain starts.
 */
#ifdef LOADER_TRUST_RECORD_SALT
static const char record_salt[] = LOADER_TRUST_RECORD_SALT;
#else
static const char record_salt[] = "";
#endif

#define	ANSWER_MAX	128
static uint8_t ikm[SHA256_DIGEST_LENGTH + ANSWER_MAX];
static size_t ikm_len;		/* 0: not (yet) available */
static bool asked;		/* the boot answer prompt ran */

static void ikm_wipe(void);

static bool
answer_wanted(void)
{
	const char *v = getenv("elvboot_answer_prompt");

	return (v != NULL && (strcmp(v, "YES") == 0 || strcmp(v, "yes") == 0));
}

/* Why there is no keying material yet: read by diagnose_record. */
static const char *reason = "not tried";

const char *
record_reason(void)
{
	return (reason);
}

/*
 * Gather the material: GELI's digest, then -- once, and only when GELI
 * already unlocked, so never before the passphrase -- the boot answer.
 */
static bool
ikm_gather(void)
{
	char answer[ANSWER_MAX];
	size_t n;

	if (ikm_len > 0)
		return (true);
	if (record_salt[0] == '\0') {
		reason = "no record salt compiled in (LOADER_TRUST_RECORD_SALT)";
		return (false);
	}
	/* The loader may not have opened the root yet: the dialog (geli_open.c). */
	if (!geli_ikm_digest(ikm))
		geli_open_ensure();
	if (!geli_ikm_digest(ikm)) {
		reason = geli_keys_reason();
		return (false);
	}
	reason = "keying material ready";
	ikm_len = SHA256_DIGEST_LENGTH;
	if (answer_wanted() && !asked) {
		asked = true;
		/*
		 * Typed ONCE: the previous record is the proof --
		 * it verifies only under the answer it was written with, so
		 * record_load() checks the answer against it and asks again
		 * once if it does not (answer_retry). A chain without a usable
		 * record (its first boot, a new record version) has nothing to
		 * check against: record_commit() then asks for the confirmation
		 * before sealing (answer_confirm: a slip would break
		 * the new chain silently).
		 */
		printf("\nBoot answer: ");
		readsecret(answer, sizeof(answer));
		printf("\n");
		n = strlen(answer);
		memcpy(ikm + ikm_len, answer, n);
		ikm_len += n;
		explicit_bzero(answer, sizeof(answer));
	}
	return (true);
}

/* The one retry of the boot answer: new material from GELI's digest + the new answer. */
static unsigned int answer_retries;

static void
answer_retry(void)
{
	char answer[ANSWER_MAX];
	size_t n;

	answer_retries++;
	printf("the previous record does not verify under this answer\n");
	printf("\nBoot answer, once more: ");
	readsecret(answer, sizeof(answer));
	printf("\n");
	ikm_len = SHA256_DIGEST_LENGTH;		/* keep GELI's digest, drop the answer */
	n = strlen(answer);
	memcpy(ikm + ikm_len, answer, n);
	ikm_len += n;
	explicit_bzero(answer, sizeof(answer));
}

unsigned int
record_answer_retries(void)
{
	return (answer_retries);
}

/*
 * A new chain starts on an answer typed once and proven against nothing:
 * confirm it before the first record is sealed with it (a slip
 * would break the chain silently). Three mismatches: the material is
 * wiped, nothing is committed.
 */
static bool
answer_confirm(void)
{
	char again[ANSWER_MAX];
	size_t n = ikm_len - SHA256_DIGEST_LENGTH;
	int tries;
	bool ok = false;

	for (tries = 0; tries < 3 && !ok; tries++) {
		printf("\nBoot answer, again (a new chain starts): ");
		readsecret_confirm(again, sizeof(again));
		printf("\n");
		ok = strlen(again) == n && memcmp(again, ikm + SHA256_DIGEST_LENGTH, n) == 0;
		if (!ok)
			printf("the two answers differ\n");
	}
	explicit_bzero(again, sizeof(again));
	if (!ok) {
		ikm_wipe();
		reason = "boot answer not confirmed (three mismatches)";
	}
	return (ok);
}

bool
record_secret_present(void)
{
	return (ikm_gather());
}

/*
 * 8 hex of an HMAC over the GELI part of the material, keyed from the
 * material: equal across boots iff the GELI-derived key is the same. When a
 * record is present but invalid, this tells whether the key or the answer
 * moved. Reveals nothing about either. "-" without material.
 */
void
record_geli_fingerprint(char out[9])
{
	uint8_t mac[SHA256_DIGEST_LENGTH];

	if (ikm_len < SHA256_DIGEST_LENGTH) {
		out[0] = '-';
		out[1] = '\0';
		return;
	}
	record_hmac("geli-fingerprint", ikm, SHA256_DIGEST_LENGTH, mac);
	snprintf(out, 9, "%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3]);
	explicit_bzero(mac, sizeof(mac));
}

/* Wipe: the material's last user was record_commit(). */
static void
ikm_wipe(void)
{
	explicit_bzero(ikm, sizeof(ikm));
	ikm_len = 0;
}

/* HKDF(salt = site salt, IKM = GELI digest || answer, info = purpose). */
static void
derive(const char *purpose, uint8_t out[static SHA256_DIGEST_LENGTH])
{
	if (!ikm_gather()) {
		memset(out, 0, SHA256_DIGEST_LENGTH);
		return;
	}
	hkdf_sha256((const uint8_t *)record_salt, strlen(record_salt), ikm,
	    ikm_len, purpose, out);
}

void
record_hmac(const char *purpose, const void *msg, size_t len,
    uint8_t out[static SHA256_DIGEST_LENGTH])
{
	uint8_t key[SHA256_DIGEST_LENGTH];

	derive(purpose, key);
	hmac_sha256(key, sizeof(key), msg, len, out);
	explicit_bzero(key, sizeof(key));
}

#ifdef LOADER_TRUST_WORD_SECRET
static const char word_secret[] = LOADER_TRUST_WORD_SECRET;
#else
static const char word_secret[] = "";
#endif

bool
word_secret_present(void)
{
	return (word_secret[0] != '\0');
}

void
word_hmac(const char *purpose, const void *msg, size_t len,
    uint8_t out[static SHA256_DIGEST_LENGTH])
{
	uint8_t key[SHA256_DIGEST_LENGTH];

	hmac_sha256((const uint8_t *)word_secret, strlen(word_secret), purpose,
	    strlen(purpose), key);
	hmac_sha256(key, sizeof(key), msg, len, out);
	explicit_bzero(key, sizeof(key));
}

/* AES-256-CTR in place: nonce is 16 bytes, counter in the last 4 (big endian). */
static void
aes_ctr(const uint8_t key[static 32], const uint8_t nonce[static 16],
    uint8_t *buf, size_t len)
{
	rijndael_ctx ctx;
	uint8_t ctr[16], ks[16];
	size_t i, off = 0;
	uint32_t c = 0;

	rijndael_set_key(&ctx, key, 256);
	memcpy(ctr, nonce, 16);
	while (off < len) {
		ctr[12] = c >> 24; ctr[13] = c >> 16; ctr[14] = c >> 8; ctr[15] = c;
		rijndael_encrypt(&ctx, ctr, ks);
		for (i = 0; i < 16 && off < len; i++, off++)
			buf[off] ^= ks[i];
		c++;
	}
	explicit_bzero(&ctx, sizeof(ctx));
	explicit_bzero(ks, sizeof(ks));
}

/* sealed = nonce || AES-CTR(body) || HMAC(nonce || ciphertext) */
static void
seal(const struct record_body *body, uint8_t sealed[static RECORD_SEALED_LEN])
{
	uint8_t enc[SHA256_DIGEST_LENGTH], mac[SHA256_DIGEST_LENGTH];
	uint8_t *nonce = sealed, *ct = sealed + RECORD_NONCE_LEN;
	uint8_t seed[SHA256_DIGEST_LENGTH];
	struct stamp now;
	unsigned int i;

	/* nonce: sha256(counter || tsc || epoch) truncated -- unique per boot */
	clock_now(&now);
	{
		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, &body->counter, sizeof(body->counter));
		SHA256_Update(&ctx, &now.tsc, sizeof(now.tsc));
		SHA256_Update(&ctx, &now.epoch, sizeof(now.epoch));
		SHA256_Final(seed, &ctx);
	}
	memcpy(nonce, seed, RECORD_NONCE_LEN);
	for (i = 12; i < 16; i++)
		nonce[i] = 0;
	memcpy(ct, body, sizeof(*body));
	derive("record-enc", enc);
	aes_ctr(enc, nonce, ct, sizeof(*body));
	record_hmac("record-mac", sealed, RECORD_NONCE_LEN + sizeof(*body), mac);
	memcpy(sealed + RECORD_NONCE_LEN + sizeof(*body), mac, RECORD_MAC_LEN);
	explicit_bzero(enc, sizeof(enc));
}

static bool
unseal(const uint8_t sealed[static RECORD_SEALED_LEN], struct record_body *body)
{
	uint8_t enc[SHA256_DIGEST_LENGTH], mac[SHA256_DIGEST_LENGTH];
	unsigned int i, diff = 0;

	record_hmac("record-mac", sealed, RECORD_NONCE_LEN + sizeof(*body), mac);
	for (i = 0; i < RECORD_MAC_LEN; i++)
		diff |= mac[i] ^ sealed[RECORD_NONCE_LEN + sizeof(*body) + i];
	if (diff != 0)
		return (false);
	memcpy(body, sealed + RECORD_NONCE_LEN, sizeof(*body));
	derive("record-enc", enc);
	aes_ctr(enc, sealed, (uint8_t *)body, sizeof(*body));
	explicit_bzero(enc, sizeof(enc));
	return (body->magic == RECORD_MAGIC && body->version == RECORD_VERSION);
}

/* ------------------------------------------------------- NVRAM access */

bool
record_var_set(const char *name, const void *buf, size_t len)
{
	return (!EFI_ERROR(efi_setenv(&elv_guid, name, NV_ATTRS,
	    __DECONST(void *, buf), len)));
}

bool
record_var_get(const char *name, void *buf, size_t *len)
{
	return (!EFI_ERROR(efi_getenv(&elv_guid, name, buf, len)));
}

/* -------------------------------------------------------- the anchors */

/* sha256("elvboot cap"): what every cap extends; elvbootd extends the same. */
const uint8_t record_cap_digest[SHA256_DIGEST_LENGTH] = {
	0xe7, 0x7d, 0x35, 0xbc, 0x1f, 0x1b, 0x86, 0xc4, 0x26, 0x7b, 0xfb, 0xa0,
	0xd4, 0xb8, 0x74, 0xaf, 0xad, 0x6e, 0xbc, 0x96, 0x4b, 0x83, 0x67, 0xb0,
	0x5b, 0x81, 0x7e, 0xe5, 0x57, 0xa7, 0x0e, 0x8f
};

static bool
leaf_u32(const char *name, uint32_t *out)
{
	const char *v = getenv(name);
	unsigned long x;
	char *end;

	if (v == NULL)
		return (false);
	x = strtoul(v, &end, 0);
	if (end == v || *end != '\0' || x > 0xffffffffUL)
		return (false);
	*out = (uint32_t)x;
	return (true);
}

static struct anchor_state A, D;
static bool a_loaded, d_loaded;

/* The anchor index, verified with the record material; matches iff == prev. */
const struct anchor_state *
record_anchor_state(void)
{
	uint32_t index;
	uint8_t tag[SHA256_DIGEST_LENGTH];
	const struct record_state *rs;

	if (a_loaded)
		return (&A);
	if (!record_secret_present())
		return (&A);		/* before GELI unlocked: tried again later */
	a_loaded = true;
	memset(&A, 0, sizeof(A));
	if (!leaf_u32("loader.trust.tpm.anchor.nv", &index))
		return (&A);
	if (!tpm_nv_read_bytes(index, (uint8_t *)&A.body, sizeof(A.body)))
		return (&A);
	A.present = true;
	record_hmac("anchor", &A.body, offsetof(struct record_anchor, tag), tag);
	if (memcmp(tag, A.body.tag, sizeof(tag)) != 0)
		return (&A);
	A.valid = true;
	rs = record_load();
	A.matches = rs->valid && A.body.a == rs->prev.boot_epoch &&
	    A.body.b == rs->prev.tpm_clock && A.body.c == rs->prev.counter;
	return (&A);
}

/* The shutdown index, elvbootd's; its tag is a plain sha256 (no secret at runtime). */
const struct anchor_state *
record_shutdown_state(void)
{
	uint32_t index;
	uint8_t tag[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;

	if (d_loaded)
		return (&D);
	d_loaded = true;
	memset(&D, 0, sizeof(D));
	if (!leaf_u32("loader.trust.tpm.shutdown.nv", &index))
		return (&D);
	if (!tpm_nv_read_bytes(index, (uint8_t *)&D.body, sizeof(D.body)))
		return (&D);
	D.present = true;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, &D.body, offsetof(struct record_anchor, tag));
	SHA256_Final(tag, &ctx);
	D.valid = memcmp(tag, D.body.tag, sizeof(tag)) == 0;
	return (&D);
}

/*
 * Write this boot's anchor under the cap PCR's boot-state policy, then
 * cap: one extend, and the write permission is gone for this boot.
 * Without the leafs nothing is written and nothing capped (the claim
 * AnchorValid then skips, stage require names the leafs).
 */
static void
anchor_commit(const struct record_body *b)
{
	struct record_anchor a;
	uint32_t index, key, pcr;

	if (!leaf_u32("loader.trust.tpm.anchor.nv", &index) ||
	    !leaf_u32("loader.trust.tpm.key.handle", &key) ||
	    !leaf_u32("loader.trust.tpm.cap.pcr", &pcr) || pcr > 23)
		return;
	memset(&a, 0, sizeof(a));
	a.a = b->boot_epoch;
	a.b = b->tpm_clock;
	a.c = b->counter;
	a.medium = b->medium;
	record_hmac("anchor", &a, offsetof(struct record_anchor, tag), a.tag);
	(void)tpm_nv_policy_write(key, index, 1u << pcr, (const uint8_t *)&a, sizeof(a));
	(void)tpm_pcr_extend(pcr, record_cap_digest);
	explicit_bzero(&a, sizeof(a));
}

/* --------------------------------------- a firmware variable's slice */

bool
record_efivar_slice(const char *spec, uint64_t *out)
{
	char guidtext[37], name[64];
	uuid_t uuid;
	uint32_t status;
	const char *p, *q;
	unsigned long off, len;
	char *end;
	uint8_t buf[512];
	size_t sz = sizeof(buf), i;
	uint64_t v = 0;

	if (spec == NULL || strlen(spec) < 38 || spec[36] != '-')
		return (false);
	memcpy(guidtext, spec, 36);
	guidtext[36] = '\0';
	uuid_from_string(guidtext, &uuid, &status);
	if (status != uuid_s_ok)
		return (false);
	p = spec + 37;
	q = strchr(p, ':');
	if (q == NULL || q == p || (size_t)(q - p) >= sizeof(name))
		return (false);
	memcpy(name, p, q - p);
	name[q - p] = '\0';
	off = strtoul(q + 1, &end, 10);
	if (end == q + 1 || *end != ':')
		return (false);
	len = strtoul(end + 1, &end, 10);
	if (*end != '\0' || len < 1 || len > 8)
		return (false);
	if (EFI_ERROR(efi_getenv((EFI_GUID *)&uuid, name, buf, &sz)))
		return (false);
	if (off + len > sz)
		return (false);
	for (i = 0; i < len; i++)
		v |= (uint64_t)buf[off + i] << (8 * i);
	*out = v;
	return (true);
}

/* -------------------------------------------------- the medium letter */

static uint8_t medium_letter;
static bool medium_read;

uint8_t
record_medium_letter(void)
{
	EFI_FILE_HANDLE f;
	UINTN sz = 1;
	uint8_t c = 0;

	if (medium_read)
		return (medium_letter);
	medium_read = true;
	f = medium_open("medium", false);
	if (f == NULL)
		return (0);
	if (!EFI_ERROR(f->Read(f, &sz, &c)) && sz == 1 &&
	    ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
		medium_letter = c;
	f->Close(f);
	return (medium_letter);
}

/* ------------------------------------------------------ medium access */

static EFI_GUID imgid = LOADED_IMAGE_PROTOCOL;
static EFI_GUID sfsid = SIMPLE_FILE_SYSTEM_PROTOCOL;

/* Open (create) \EFI\elvboot\<name> on our load origin; NULL on failure. */
static EFI_FILE_HANDLE
medium_open(const char *name, bool write)
{
	EFI_LOADED_IMAGE *img;
	EFI_FILE_IO_INTERFACE *fio;
	EFI_FILE_HANDLE root, dir, f;
	CHAR16 wname[64];
	UINT64 mode = EFI_FILE_MODE_READ;
	size_t i;

	if (EFI_ERROR(BS->HandleProtocol(IH, &imgid, (void **)&img)))
		return (NULL);
	if (EFI_ERROR(BS->HandleProtocol(img->DeviceHandle, &sfsid,
	    (void **)&fio)))
		return (NULL);
	if (EFI_ERROR(fio->OpenVolume(fio, &root)))
		return (NULL);
	if (write)
		mode |= EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE;
	dir = NULL;
	if (EFI_ERROR(root->Open(root, &dir, (CHAR16 *)L"\\EFI\\elvboot",
	    mode, EFI_FILE_DIRECTORY))) {
		root->Close(root);
		return (NULL);
	}
	for (i = 0; name[i] != '\0' && i < sizeof(wname) / sizeof(wname[0]) - 1; i++)
		wname[i] = (CHAR16)name[i];
	wname[i] = 0;
	f = NULL;
	if (EFI_ERROR(dir->Open(dir, &f, wname, mode, 0)))
		f = NULL;
	dir->Close(dir);
	root->Close(root);
	return (f);
}

bool
record_medium_append(const char *name, const void *buf, size_t len)
{
	EFI_FILE_HANDLE f;
	UINTN sz = len;
	bool ok;

	f = medium_open(name, true);
	if (f == NULL)
		return (false);
	ok = !EFI_ERROR(f->SetPosition(f, 0xFFFFFFFFFFFFFFFFULL)) &&
	    !EFI_ERROR(f->Write(f, &sz, __DECONST(void *, buf))) && sz == len;
	f->Flush(f);
	f->Close(f);
	return (ok);
}

/* The last RECORD_MAC_LEN bytes of \EFI\elvboot\chain, if any. */
static bool
medium_last_link(uint8_t out[static SHA256_DIGEST_LENGTH], bool *answered)
{
	EFI_FILE_HANDLE f;
	EFI_FILE_INFO *info;
	EFI_GUID infoid = EFI_FILE_INFO_ID;
	UINTN sz;
	uint8_t ibuf[SIZE_OF_EFI_FILE_INFO + 128];
	bool ok = false;

	*answered = false;
	f = medium_open("chain", false);
	if (f == NULL)
		return (false);
	*answered = true;
	sz = sizeof(ibuf);
	info = (EFI_FILE_INFO *)ibuf;
	if (!EFI_ERROR(f->GetInfo(f, &infoid, &sz, info)) &&
	    info->FileSize >= SHA256_DIGEST_LENGTH &&
	    !EFI_ERROR(f->SetPosition(f, info->FileSize - SHA256_DIGEST_LENGTH))) {
		sz = SHA256_DIGEST_LENGTH;
		ok = !EFI_ERROR(f->Read(f, &sz, out)) && sz == SHA256_DIGEST_LENGTH;
	}
	f->Close(f);
	return (ok);
}

/* --------------------------------------------------------- lifecycle */

const struct record_state *
record_load(void)
{
	uint8_t sealed[RECORD_SEALED_LEN], link[SHA256_DIGEST_LENGTH];
	size_t len = sizeof(sealed);

	if (loaded)
		return (&S);
	memset(&S, 0, sizeof(S));
	if (!record_secret_present())
		return (&S);	/* before GELI unlocked: not loaded, tried again later */
	loaded = true;
	if (!record_var_get(RECORD_VAR, sealed, &len))
		return (&S);
	S.present = true;
	if (len == sizeof(sealed) && !unseal(sealed, &S.prev) &&
	    answer_wanted() && answer_retries == 0) {
		answer_retry();
		/* the same sealed bytes under the new material */
	}
	if (len != sizeof(sealed) || !unseal(sealed, &S.prev))
		return (&S);
	S.valid = true;
	if (medium_last_link(link, &S.medium_answered))
		S.chain_on_medium = memcmp(link, S.prev.chain,
		    SHA256_DIGEST_LENGTH) == 0;
	return (&S);
}

const struct record_state *
record_state(void)
{
	return (record_load());
}

/*
 * This boot's record: counter + 1, the anchors as they are NOW (after the
 * TPM NV counter was incremented), and the chain link = HMAC(previous link
 * || body-without-link). Written to NVRAM, appended to the medium.
 */
bool
record_commit(uint8_t flags)
{
	struct record_body b;
	struct tpm_clock tc;
	struct nvme_smart ns;
	struct stamp now;
	uint8_t sealed[RECORD_SEALED_LEN], msg[SHA256_DIGEST_LENGTH +
	    sizeof(struct record_body)];
	uint64_t nv = 0;
	bool ok;

	if (!record_secret_present())
		return (false);
	(void)record_load();
	if (!S.valid && answer_wanted() && asked && !answer_confirm())
		return (false);
	memset(&b, 0, sizeof(b));
	b.magic = RECORD_MAGIC;
	b.version = RECORD_VERSION;
	b.counter = S.valid ? S.prev.counter + 1 : 1;
	clock_now(&now);
	b.boot_epoch = now.epoch;
	b.boot_ms = clock_ms_since_entry();
	if (tpm_read_clock(&tc)) {
		b.tpm_reset = tc.reset_count;
		b.tpm_clock = tc.clock;
		if (!tpm_nv_counter_read(&nv))
			(void)tpm_nv_define_counter();
		if (tpm_nv_counter_increment() && tpm_nv_counter_read(&nv))
			b.tpm_nvcount = nv;
	}
	if (nvme_smart(&ns)) {
		b.nvme_cycles = ns.power_cycles;
		b.nvme_unsafe = ns.unsafe_shutdowns;
		b.nvme_hours = ns.power_on_hours;
		b.nvme_units_read = ns.data_units_read;
		b.nvme_units_written = ns.data_units_written;
	}
	b.medium = record_medium_letter();
	{
		uint64_t v;
		int i;

		if (record_efivar_slice(getenv("loader.trust.firmware.counter.var"), &v))
			b.fw_counter = v;
		/* the moving part: this boot's value first, the previous boots' behind it */
		if (S.valid)
			for (i = 1; i < RECORD_FW_HISTORY; i++)
				b.fw_moving[i] = S.prev.fw_moving[i - 1];
		if (record_efivar_slice(getenv("loader.trust.firmware.moving.var"), &v))
			b.fw_moving[0] = v;
	}
	b.flags = flags;
	memcpy(msg, S.valid ? S.prev.chain : (const uint8_t[SHA256_DIGEST_LENGTH]){ 0 },
	    SHA256_DIGEST_LENGTH);
	memcpy(msg + SHA256_DIGEST_LENGTH, &b, sizeof(b));
	record_hmac("chain", msg, sizeof(msg), b.chain);
	seal(&b, sealed);
	ok = record_var_set(RECORD_VAR, sealed, sizeof(sealed));
	(void)record_medium_append("chain", b.chain, sizeof(b.chain));
	anchor_commit(&b);			/* needs the material: before the wipe */
	ikm_wipe();
	explicit_bzero(&b, sizeof(b));
	return (ok);
}

/* ---------------------------------------------------------- nextboot */

bool
record_nextboot_get(char *buf, size_t sz)
{
	size_t len = sz - 1;

	if (!record_var_get(NEXTBOOT_VAR, buf, &len))
		return (false);
	buf[len] = '\0';
	return (buf[0] != '\0');
}

void
record_nextboot_set(const char *root)
{
	(void)record_var_set(NEXTBOOT_VAR, root, strlen(root));
}

void
record_nextboot_clear(void)
{
	(void)efi_delenv(&elv_guid, NEXTBOOT_VAR);
}
