/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * measure_disk.c -- GELI metadata and GPT digests (measurement.h), read
 * through the firmware's Block I/O on the handles whose device path names
 * one of the provisioned partition GUIDs (LOADER_TRUST_GELI_PARTS, a
 * comma-separated string of lowercase GPT partition UUIDs, in the order
 * site mk hashed them).
 *
 * GELI keeps its metadata in the LAST sector of the provider; site mk reads
 * the same sector with dd from userland. GPT: the header at LBA 1 and the
 * entry array it points to, on the parent disk of each listed partition
 * (each disk once).
 */

#include <stand.h>
#include <string.h>

#include <efi.h>
#include <efilib.h>

#include <crypto/sha2/sha256.h>

#include "geliboot.h"
#include "measurement.h"
#include "tpm.h"

#ifndef LOADER_TRUST_GELI_PARTS
#define	LOADER_TRUST_GELI_PARTS	""
#endif

static EFI_GUID blkio_guid = BLOCK_IO_PROTOCOL;

/* The GPT partition GUID of a handle's device path as lowercase text. */
static bool
handle_part_guid(EFI_HANDLE h, char *out, size_t outsz)
{
	EFI_DEVICE_PATH *dp;
	HARDDRIVE_DEVICE_PATH *hd;
	const UINT8 *g;

	dp = efi_lookup_devpath(h);
	if (dp == NULL)
		return (false);
	for (; !IsDevicePathEndType(dp); dp = NextDevicePathNode(dp)) {
		if (DevicePathType(dp) != MEDIA_DEVICE_PATH ||
		    DevicePathSubType(dp) != MEDIA_HARDDRIVE_DP)
			continue;
		hd = (HARDDRIVE_DEVICE_PATH *)dp;
		if (hd->SignatureType != SIGNATURE_TYPE_GUID)
			continue;
		g = hd->Signature;
		(void)snprintf(out, outsz,
		    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
		    "%02x%02x%02x%02x%02x%02x",
		    g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6],
		    g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
		return (true);
	}
	return (false);
}

/* Find the Block I/O handle of the partition with this GUID. */
static bool
find_partition(const char *guid, EFI_HANDLE *out)
{
	EFI_HANDLE *handles = NULL;
	UINTN n = 0, i;
	char g[40];
	bool found = false;

	if (EFI_ERROR(BS->LocateHandleBuffer(ByProtocol, &blkio_guid, NULL,
	    &n, &handles)))
		return (false);
	for (i = 0; i < n && !found; i++)
		if (handle_part_guid(handles[i], g, sizeof(g)) &&
		    strcmp(g, guid) == 0) {
			*out = handles[i];
			found = true;
		}
	BS->FreePool(handles);
	return (found);
}

/* The parent (whole-disk) handle of a partition handle: same path minus the HD node. */
static bool
find_parent(EFI_HANDLE part, EFI_HANDLE *out)
{
	EFI_DEVICE_PATH *dp, *copy, *node;
	EFI_HANDLE h;

	dp = efi_lookup_devpath(part);
	if (dp == NULL)
		return (false);
	copy = efi_devpath_trim(dp);
	if (copy == NULL)
		return (false);
	for (node = copy; !IsDevicePathEndType(node); node = NextDevicePathNode(node))
		;
	h = efi_devpath_handle(copy);
	free(copy);
	if (h == NULL)
		return (false);
	*out = h;
	return (true);
}

static bool
read_blocks(EFI_HANDLE h, uint64_t lba, void *buf, size_t len)
{
	EFI_BLOCK_IO *bio;

	if (EFI_ERROR(BS->HandleProtocol(h, &blkio_guid, (void **)&bio)))
		return (false);
	return (!EFI_ERROR(bio->ReadBlocks(bio, bio->Media->MediaId, lba, len,
	    buf)));
}

static bool
block_geometry(EFI_HANDLE h, uint32_t *bsize, uint64_t *last)
{
	EFI_BLOCK_IO *bio;

	if (EFI_ERROR(BS->HandleProtocol(h, &blkio_guid, (void **)&bio)))
		return (false);
	*bsize = bio->Media->BlockSize;
	*last = bio->Media->LastBlock;
	return (*bsize >= 512 && *bsize <= 65536);
}

/* Walk the comma list; returns false when the list is empty. */
static bool
next_guid(const char **cursor, char *out, size_t outsz)
{
	const char *p = *cursor, *e;
	size_t n;

	while (*p == ',' || *p == ' ')
		p++;
	if (*p == '\0')
		return (false);
	e = p;
	while (*e != '\0' && *e != ',' && *e != ' ')
		e++;
	n = (size_t)(e - p);
	if (n >= outsz)
		n = outsz - 1;
	memcpy(out, p, n);
	out[n] = '\0';
	*cursor = e;
	return (true);
}

struct measurement
measure_geli(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "GeliHeaders", .type = MEAS_SHA256 };
	const char *cursor = LOADER_TRUST_GELI_PARTS;
	char guid[40];
	EFI_HANDLE h;
	SHA256_CTX ctx;
	uint32_t bsize;
	uint64_t last;
	uint8_t *buf;
	unsigned int n = 0;

	SHA256_Init(&ctx);
	while (next_guid(&cursor, guid, sizeof(guid))) {
		if (!find_partition(guid, &h) || !block_geometry(h, &bsize, &last))
			return (m);
		buf = malloc(bsize);
		if (buf == NULL)
			return (m);
		if (!read_blocks(h, last, buf, bsize)) {
			free(buf);
			return (m);
		}
		/* GELI metadata occupies the last 512 bytes of the last sector */
		SHA256_Update(&ctx, buf + bsize - 512, 512);
		free(buf);
		n++;
	}
	if (n == 0)
		return (m);
	SHA256_Final(m.value.digest, &ctx);
	m.present = true;
	return (m);
}

/* Little-endian readers for the GPT header fields. */
static uint32_t
le32(const uint8_t *p)
{
	return ((uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	    (uint32_t)p[3] << 24);
}

static uint64_t
le64(const uint8_t *p)
{
	return ((uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32);
}

/* sha256-update with LBA 1 and the entry array of one disk; false on shortfall. */
static bool
gpt_update(SHA256_CTX *ctx, EFI_HANDLE disk)
{
	uint32_t bsize, entries, entsz;
	uint64_t last, table_lba, bytes, lba;
	uint8_t *buf;
	bool ok = true;

	if (!block_geometry(disk, &bsize, &last))
		return (false);
	buf = malloc(bsize);
	if (buf == NULL)
		return (false);
	if (!read_blocks(disk, 1, buf, bsize) ||
	    memcmp(buf, "EFI PART", 8) != 0) {
		free(buf);
		return (false);
	}
	SHA256_Update(ctx, buf, 92);		/* the header proper */
	table_lba = le64(buf + 72);
	entries = le32(buf + 80);
	entsz = le32(buf + 84);
	free(buf);
	if (entsz < 128 || entries == 0 || entries > 1024)
		return (false);
	bytes = (uint64_t)entries * entsz;
	buf = malloc(bsize);
	if (buf == NULL)
		return (false);
	for (lba = table_lba; bytes > 0; lba++) {
		size_t take = bytes < bsize ? (size_t)bytes : bsize;

		if (!read_blocks(disk, lba, buf, bsize)) {
			ok = false;
			break;
		}
		SHA256_Update(ctx, buf, take);
		bytes -= take;
	}
	free(buf);
	return (ok);
}

struct measurement
measure_gpt(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "PartitionTables", .type = MEAS_SHA256 };
	const char *cursor = LOADER_TRUST_GELI_PARTS;
	char guid[40];
	EFI_HANDLE h, disk, seen[8];
	SHA256_CTX ctx;
	unsigned int n = 0, i;
	bool dup;

	SHA256_Init(&ctx);
	while (next_guid(&cursor, guid, sizeof(guid))) {
		if (!find_partition(guid, &h) || !find_parent(h, &disk))
			return (m);
		dup = false;
		for (i = 0; i < n; i++)
			if (seen[i] == disk)
				dup = true;
		if (dup)
			continue;
		if (n < sizeof(seen) / sizeof(seen[0]))
			seen[n] = disk;
		n++;
		if (!gpt_update(&ctx, disk))
			return (m);
	}
	if (n == 0)
		return (m);
	SHA256_Final(m.value.digest, &ctx);
	m.present = true;
	return (m);
}

/*
 * --- witnesses, from loader.trust.conf ---
 *
 * loader.trust.inventory.witnesses names them, comma-separated; each has
 * loader.trust.inventory.witness.<name>.guid (the GPT partition uuid),
 * .medium and .digest (64 hex each). The conf travels in the signed
 * manifest like pcr.expected: a rollout of a card -- every rescue push
 * moves its labels -- is a new receipt in the conf, no rebuild.
 *
 * The medium is the sha256 of the GELI metadata (the last 512 bytes of the
 * partition's last sector): the owner's cards are dd clones with one GPT
 * uuid, but every card init wrote its own metadata, so the partition the
 * guid finds is the witness's card only when its metadata hashes to the
 * medium -- otherwise the other card is in the slot and the witness is
 * absent.
 *
 * The regions elebake hashes (stage witness digest), in this order: labels
 * 0 and 1 (the first 512 KiB of the provider), labels 2 and 3 (the last
 * 512 KiB of the provider size aligned down to 256 KiB), the partition's
 * last sector (the GELI metadata). With authentication a logical sector of
 * the provider occupies bytes_per_sector physical bytes -- the geometry of
 * g_eli (eli_metadata_softc), computed from the metadata sector here as
 * there -- so the physical regions are the logical ones scaled.
 */

#define	WITNESS_MAX	8
#define	VDEV_LABEL	262144ULL
#define	LABEL_PAIR	(2 * VDEV_LABEL)

struct witness {
	char	name[24];
	char	guid[40];
	uint8_t	medium[SHA256_DIGEST_LENGTH];
	uint8_t	digest[SHA256_DIGEST_LENGTH];
};

enum witness_state { WITNESS_ABSENT, WITNESS_MATCH, WITNESS_DIFFER };

static bool
hex_digest(const char *p, size_t n, uint8_t out[SHA256_DIGEST_LENGTH])
{
	unsigned int i, v;
	char ch;

	if (n != 2 * SHA256_DIGEST_LENGTH)
		return (false);
	for (i = 0; i < n; i++) {
		ch = p[i];
		if (ch >= '0' && ch <= '9')
			v = ch - '0';
		else if (ch >= 'a' && ch <= 'f')
			v = ch - 'a' + 10;
		else
			return (false);
		if (i % 2 == 0)
			out[i / 2] = v << 4;
		else
			out[i / 2] |= v;
	}
	return (true);
}

/* The leaf loader.trust.inventory.witness.<name>.<field>, or NULL. */
static const char *
witness_leaf(const char *name, const char *field)
{
	static char key[128];

	snprintf(key, sizeof(key), "loader.trust.inventory.witness.%s.%s",
	    name, field);
	return (getenv(key));
}

/*
 * The next name of loader.trust.inventory.witnesses and its leaves; false
 * at the end of the list or when a leaf is missing or malformed.
 */
static bool
next_witness(const char **cursor, struct witness *w)
{
	const char *p = *cursor, *e, *v;
	size_t n;

	while (*p == ',' || *p == ' ')
		p++;
	if (*p == '\0')
		return (false);
	e = p;
	while (*e != '\0' && *e != ',' && *e != ' ')
		e++;
	*cursor = e;
	n = (size_t)(e - p);
	if (n == 0 || n >= sizeof(w->name))
		return (false);
	memcpy(w->name, p, n);
	w->name[n] = '\0';
	v = witness_leaf(w->name, "guid");
	if (v == NULL || strlen(v) == 0 || strlen(v) >= sizeof(w->guid))
		return (false);
	strlcpy(w->guid, v, sizeof(w->guid));
	v = witness_leaf(w->name, "medium");
	if (v == NULL || !hex_digest(v, strlen(v), w->medium))
		return (false);
	v = witness_leaf(w->name, "digest");
	return (v != NULL && hex_digest(v, strlen(v), w->digest));
}

/* The medium of a partition: sha256 of its GELI metadata, the last 512 bytes of the last sector. */
static bool
witness_medium(EFI_HANDLE h, uint8_t out[SHA256_DIGEST_LENGTH])
{
	uint32_t bsize;
	uint64_t last;
	uint8_t *buf;

	if (!block_geometry(h, &bsize, &last) || bsize < 512)
		return (false);
	buf = malloc(bsize);
	if (buf == NULL)
		return (false);
	if (!read_blocks(h, last, buf, bsize)) {
		free(buf);
		return (false);
	}
	measurement_sha256(buf + bsize - 512, 512, out);
	free(buf);
	return (true);
}

/* sha256-update with [lba, lba + blocks) of the handle; false on a read error. */
static bool
hash_blocks(SHA256_CTX *ctx, EFI_HANDLE h, uint64_t lba, uint64_t blocks,
    uint32_t bsize)
{
	uint8_t *buf;
	uint64_t take, chunk = 64;

	buf = malloc(chunk * bsize);
	if (buf == NULL)
		return (false);
	while (blocks > 0) {
		take = blocks < chunk ? blocks : chunk;
		if (!read_blocks(h, lba, buf, (size_t)(take * bsize))) {
			free(buf);
			return (false);
		}
		SHA256_Update(ctx, buf, (size_t)(take * bsize));
		lba += take;
		blocks -= take;
	}
	free(buf);
	return (true);
}

/*
 * The digest of a present witness: the geometry from its GELI metadata
 * sector, then the three regions. False when the sector decodes to no
 * GELI metadata or a read fails.
 */
static bool
witness_digest(EFI_HANDLE h, uint8_t out[SHA256_DIGEST_LENGTH])
{
	struct g_eli_metadata md;
	SHA256_CTX ctx;
	uint32_t bsize;
	uint64_t last, msz, bps, media, aligned, pair_blocks, dps;
	uint8_t *buf;
	bool ok;

	if (!block_geometry(h, &bsize, &last))
		return (false);
	msz = (last + 1) * bsize;
	buf = malloc(bsize);
	if (buf == NULL)
		return (false);
	if (!read_blocks(h, last, buf, bsize)) {
		free(buf);
		return (false);
	}
	if (eli_metadata_decode(buf, &md) != 0 &&
	    (bsize <= 512 || eli_metadata_decode(buf + bsize - 512, &md) != 0)) {
		free(buf);
		return (false);
	}
	free(buf);
	if (md.md_sectorsize == 0 || md.md_sectorsize > LABEL_PAIR ||
	    msz <= bsize)
		return (false);
	if (md.md_flags & G_ELI_FLAG_AUTH) {
		dps = bsize - g_eli_hashlen(md.md_aalgo);
		dps -= dps % 16;
		if (dps == 0)
			return (false);
		bps = ((md.md_sectorsize - 1) / dps + 1) * bsize;
		media = (msz - bsize) / bps * md.md_sectorsize;
	} else {
		bps = md.md_sectorsize;
		media = (msz - bsize) - (msz - bsize) % md.md_sectorsize;
	}
	aligned = media - media % VDEV_LABEL;
	if (aligned < LABEL_PAIR)
		return (false);
	pair_blocks = LABEL_PAIR / md.md_sectorsize * bps / bsize;
	SHA256_Init(&ctx);
	ok = hash_blocks(&ctx, h, 0, pair_blocks, bsize) &&
	    hash_blocks(&ctx, h, (aligned - LABEL_PAIR) / md.md_sectorsize *
	    bps / bsize, pair_blocks, bsize) &&
	    hash_blocks(&ctx, h, last, 1, bsize);
	if (!ok)
		return (false);
	SHA256_Final(out, &ctx);
	return (true);
}

static enum witness_state
witness_state(const struct witness *w)
{
	EFI_HANDLE h;
	uint8_t digest[SHA256_DIGEST_LENGTH];

	if (!find_partition(w->guid, &h))
		return (WITNESS_ABSENT);
	if (!witness_medium(h, digest))
		return (WITNESS_DIFFER);	/* present, but not readable as the receipt describes */
	if (memcmp(digest, w->medium, sizeof(digest)) != 0)
		return (WITNESS_ABSENT);	/* the other card in the slot: this witness is not here */
	if (!witness_digest(h, digest))
		return (WITNESS_DIFFER);	/* present, but not the container the receipt describes */
	return (memcmp(digest, w->digest, sizeof(digest)) == 0 ?
	    WITNESS_MATCH : WITNESS_DIFFER);
}

/* The states of every listed witness, once per boot; the count listed. */
static unsigned int
witness_states(struct witness ws[WITNESS_MAX], enum witness_state st[WITNESS_MAX])
{
	static struct witness cache[WITNESS_MAX];
	static enum witness_state cache_st[WITNESS_MAX];
	static unsigned int cache_n;
	static bool done;
	const char *cursor;
	unsigned int i;

	if (!done) {
		done = true;
		cache_n = 0;
		cursor = getenv("loader.trust.inventory.witnesses");
		if (cursor == NULL)
			cursor = "";
		while (cache_n < WITNESS_MAX &&
		    next_witness(&cursor, &cache[cache_n])) {
			cache_st[cache_n] = witness_state(&cache[cache_n]);
			cache_n++;
		}
	}
	for (i = 0; i < cache_n; i++) {
		ws[i] = cache[i];
		st[i] = cache_st[i];
	}
	return (cache_n);
}

struct measurement
measure_witness_labels(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "WitnessLabels", .type = MEAS_BYTE };
	struct witness ws[WITNESS_MAX];
	enum witness_state st[WITNESS_MAX];
	unsigned int n, i, present = 0;
	bool ok = true;

	n = witness_states(ws, st);
	for (i = 0; i < n; i++) {
		if (st[i] == WITNESS_ABSENT)
			continue;
		present++;
		if (st[i] != WITNESS_MATCH)
			ok = false;
	}
	if (present == 0)
		return (m);
	m.present = true;
	m.value.byte = ok ? 1 : 0;
	return (m);
}

struct measurement
measure_witness_present(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "WitnessPresent", .type = MEAS_BYTE };
	struct witness ws[WITNESS_MAX];
	enum witness_state st[WITNESS_MAX];
	unsigned int n, i;
	bool all = true;

	n = witness_states(ws, st);
	if (n == 0)
		return (m);
	for (i = 0; i < n; i++)
		if (st[i] == WITNESS_ABSENT)
			all = false;
	m.present = true;
	m.value.byte = all ? 1 : 0;
	return (m);
}

/*
 * The digest of the witness table as the conf carries it: sha256 over
 * "<name>:<medium>:<digest>\n" for every name of
 * loader.trust.inventory.witnesses, in that order, the hex strings as
 * published. False without a witness. elebake (stage witness anchor) and
 * elvbootd (witness_anchor_act) compute the same bytes.
 */
static bool
witness_table_digest(uint8_t out[SHA256_DIGEST_LENGTH])
{
	SHA256_CTX ctx;
	const char *cursor, *p, *e, *v;
	char name[64];
	size_t n;
	unsigned int count = 0;

	cursor = getenv("loader.trust.inventory.witnesses");
	if (cursor == NULL)
		return (false);
	SHA256_Init(&ctx);
	p = cursor;
	for (;;) {
		while (*p == ',' || *p == ' ')
			p++;
		if (*p == '\0')
			break;
		e = p;
		while (*e != '\0' && *e != ',' && *e != ' ')
			e++;
		n = (size_t)(e - p);
		if (n == 0 || n >= sizeof(name))
			return (false);
		memcpy(name, p, n);
		name[n] = '\0';
		p = e;
		SHA256_Update(&ctx, name, n);
		SHA256_Update(&ctx, ":", 1);
		v = witness_leaf(name, "medium");
		if (v == NULL)
			return (false);
		SHA256_Update(&ctx, v, strlen(v));
		SHA256_Update(&ctx, ":", 1);
		v = witness_leaf(name, "digest");
		if (v == NULL)
			return (false);
		SHA256_Update(&ctx, v, strlen(v));
		SHA256_Update(&ctx, "\n", 1);
		count++;
	}
	if (count == 0)
		return (false);
	SHA256_Final(out, &ctx);
	return (true);
}

/*
 * The anchor's state: the NV index loader.trust.tpm.witness.nv holds the
 * table digest the production last wrote (stage witness anchor: under
 * PolicyPCR of the production and the owner's passphrase as the index's
 * auth value). 1 = the table of this boot is the anchored one; 0 = it
 * differs (a conf rewritten on the medium, or an anchor not taken after a
 * rollout); absent without the leaf, without a TPM, without the index or
 * without witnesses -- a rescue on another board reports absent, never
 * fails.
 */
static int
witness_anchor_state(void)
{
	static int state = -2;
	const char *v;
	uint32_t index;
	uint8_t have[SHA256_DIGEST_LENGTH], want[SHA256_DIGEST_LENGTH];

	if (state != -2)
		return (state);
	state = -1;
	v = getenv("loader.trust.tpm.witness.nv");
	if (v == NULL || !witness_table_digest(have))
		return (state);
	index = (uint32_t)strtoul(v, NULL, 0);
	if (index == 0 || !tpm_present() ||
	    !tpm_nv_read_bytes(index, want, sizeof(want)))
		return (state);
	state = memcmp(have, want, sizeof(have)) == 0 ? 1 : 0;
	return (state);
}

struct measurement
measure_witness_anchor(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "WitnessAnchor", .type = MEAS_BYTE };
	int st = witness_anchor_state();

	if (st < 0)
		return (m);
	m.present = true;
	m.value.byte = st;
	return (m);
}

void
diagnose_witness_anchor(int argc __unused, CHAR16 *argv[] __unused,
    struct diagnosis *d)
{
	static const char *const word[] = { "absent", "differ", "match" };

	d->leaf = "witness.anchor";
	snprintf(d->text, sizeof(d->text), "%s", word[witness_anchor_state() + 1]);
}

void
diagnose_witness(int argc __unused, CHAR16 *argv[] __unused, struct diagnosis *d)
{
	struct witness ws[WITNESS_MAX];
	enum witness_state st[WITNESS_MAX];
	unsigned int n, i;
	size_t len = 0;
	static const char *const word[] = { "absent", "match", "differ" };

	d->leaf = "witness.state";
	d->text[0] = '\0';
	n = witness_states(ws, st);
	for (i = 0; i < n && len < sizeof(d->text); i++)
		len += snprintf(d->text + len, sizeof(d->text) - len, "%s%s=%s",
		    i > 0 ? "," : "", ws[i].name, word[st[i]]);
}
