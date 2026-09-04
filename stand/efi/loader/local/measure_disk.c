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

#include "measurement.h"

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
