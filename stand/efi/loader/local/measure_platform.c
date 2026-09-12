/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * measure_platform.c -- what else the firmware brought up (measurement.h):
 * our own image, every loaded EFI image, the ACPI tables, the non-volatile
 * variables, the PCI device list. All are "learned" baselines: site mk
 * cannot compute them from userland, elebake records the value a trusted
 * boot published (stage baseline learn).
 */

#include <stand.h>
#include <string.h>

#include <efi.h>
#include <efilib.h>
#include <efichar.h>
#include <efipciio.h>

#include <crypto/sha2/sha256.h>

#include "measurement.h"

static EFI_GUID imgid = LOADED_IMAGE_PROTOCOL;
static EFI_GUID pciio_guid = EFI_PCI_IO_PROTOCOL_GUID;

/* --- our own image --- */

struct measurement
measure_image(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "RunningImage", .type = MEAS_SHA256 };
	EFI_LOADED_IMAGE *img;

	if (EFI_ERROR(BS->HandleProtocol(IH, &imgid, (void **)&img)))
		return (m);
	if (img->ImageBase == NULL || img->ImageSize == 0)
		return (m);
	measurement_sha256(img->ImageBase, (size_t)img->ImageSize, m.value.digest);
	m.present = true;
	return (m);
}

/* --- every loaded image, in handle order --- */

static unsigned int images_n;

struct measurement
measure_images(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "LoadedImages", .type = MEAS_SHA256 };
	EFI_HANDLE *handles = NULL;
	UINTN n = 0, i;
	EFI_LOADED_IMAGE *img;
	SHA256_CTX ctx;
	uint64_t sz;

	if (EFI_ERROR(BS->LocateHandleBuffer(ByProtocol, &imgid, NULL, &n,
	    &handles)))
		return (m);
	SHA256_Init(&ctx);
	images_n = 0;
	for (i = 0; i < n; i++) {
		if (handles[i] == IH)
			continue;		/* ourselves: measure_image */
		if (EFI_ERROR(BS->HandleProtocol(handles[i], &imgid,
		    (void **)&img)))
			continue;
		if (img->ImageBase == NULL || img->ImageSize == 0)
			continue;
		sz = img->ImageSize;
		SHA256_Update(&ctx, &sz, sizeof(sz));
		SHA256_Update(&ctx, img->ImageBase, (size_t)sz);
		images_n++;
	}
	BS->FreePool(handles);
	if (images_n == 0)
		return (m);
	SHA256_Final(m.value.digest, &ctx);
	m.present = true;
	return (m);
}

void
diagnose_images(int argc __unused, CHAR16 *argv[] __unused, struct diagnosis *d)
{
	d->leaf = "images.count";
	snprintf(d->text, sizeof(d->text), "%u", images_n);
}

/*
 * --- sets, and the lists behind them ---
 *
 * AcpiTables and EfiVariables claim a SET the stage names (JB 12.09.: add
 * semantics, never an exclusion): LOADER_TRUST_ACPI_SET and
 * LOADER_TRUST_EFIVARS_SET, comma-separated identities -- an ACPI table as
 * <signature>/<OEM table id> (thirty SSDTs tell apart only so), an EFI
 * variable as <guid's first word>/<name>. The digest runs over the members'
 * digests in the set's order, so neither the firmware's enumeration order
 * nor an item outside the set can move it; a member the firmware no longer
 * shows hashes as missing. An empty set measures nothing: not configured is
 * not claimed, the claim is skipped.
 *
 * For choosing the set, every item the firmware shows is published, one
 * entry each with an 8-hex digest -- members and non-members alike, the
 * digest is the evidence of what moves -- comma-joined into
 * loader.trust.list.<what>.<n> of at most LIST_CHUNK characters (the kernel
 * drops longer loader strings). elvbootd's inventory_record_act files them
 * per boot; stage inventory show/add work from those.
 */
#define	LIST_CHUNK	200

#ifndef LOADER_TRUST_ACPI_SET
#define	LOADER_TRUST_ACPI_SET		""
#endif
#ifndef LOADER_TRUST_EFIVARS_SET
#define	LOADER_TRUST_EFIVARS_SET	""
#endif

#define	ITEM_IDLEN	56

struct item {
	char		id[ITEM_IDLEN];
	uint32_t	size;
	uint32_t	attrs;
	uint8_t		digest[SHA256_DIGEST_LENGTH];
};

/* True if the comma-separated list names the item (claim.c's disarmed()). */
static bool
listed(const char *list, const char *item)
{
	const char *p = list;
	size_t n = strlen(item);

	while (*p != '\0') {
		if (strncmp(p, item, n) == 0 && (p[n] == '\0' || p[n] == ','))
			return (true);
		while (*p != '\0' && *p != ',')
			p++;
		while (*p == ',')
			p++;
	}
	return (false);
}

struct kenv_list {
	const char	*what;
	unsigned int	 seq;
	size_t		 len;
	char		 buf[LIST_CHUNK + 1];
};

static void
list_flush(struct kenv_list *l)
{
	char name[48];

	if (l->len == 0)
		return;
	snprintf(name, sizeof(name), "loader.trust.list.%s.%u", l->what,
	    l->seq++);
	setenv(name, l->buf, 1);
	l->len = 0;
	l->buf[0] = '\0';
}

static void
list_add(struct kenv_list *l, const char *entry)
{
	size_t n = strlen(entry);

	if (n > LIST_CHUNK)
		return;
	if (l->len + (l->len ? 1 : 0) + n > LIST_CHUNK)
		list_flush(l);
	if (l->len)
		l->buf[l->len++] = ',';
	memcpy(l->buf + l->len, entry, n + 1);
	l->len += n;
}

/* 8 hex digits of a digest: enough to tell boots apart in a list. */
static void
hex8(const uint8_t d[SHA256_DIGEST_LENGTH], char out[9])
{
	snprintf(out, 9, "%02x%02x%02x%02x", d[0], d[1], d[2], d[3]);
}

/*
 * The set's digest over the items: each member's digest in the set's
 * order, a member not among the items as "missing:<id>". false iff the set
 * is empty. Publishes loader.trust.list.<what>.set = members=N,missing=M.
 */
static bool
set_digest(const char *what, const char *set, const struct item *items,
    unsigned int n, uint8_t out[SHA256_DIGEST_LENGTH])
{
	SHA256_CTX ctx;
	const char *p = set;
	char id[ITEM_IDLEN], name[48], text[48];
	size_t k;
	unsigned int i, members = 0, missing = 0;

	if (*set == '\0')
		return (false);
	SHA256_Init(&ctx);
	while (*p != '\0') {
		for (k = 0; p[k] != '\0' && p[k] != ','; k++)
			;
		if (k > 0 && k < sizeof(id)) {
			memcpy(id, p, k);
			id[k] = '\0';
			for (i = 0; i < n; i++)
				if (strcmp(items[i].id, id) == 0)
					break;
			if (i < n)
				SHA256_Update(&ctx, items[i].digest,
				    SHA256_DIGEST_LENGTH);
			else {
				SHA256_Update(&ctx, "missing:", 8);
				SHA256_Update(&ctx, id, k);
				missing++;
			}
			members++;
		}
		p += k;
		while (*p == ',')
			p++;
	}
	SHA256_Final(out, &ctx);
	snprintf(name, sizeof(name), "loader.trust.list.%s.set", what);
	snprintf(text, sizeof(text), "members=%u,missing=%u", members, missing);
	setenv(name, text, 1);
	return (true);
}

/* --- ACPI tables --- */

static EFI_GUID acpi20_guid = ACPI_20_TABLE_GUID;
static EFI_GUID acpi10_guid = ACPI_TABLE_GUID;

#define	ACPI_MAX	96
static struct item acpi_items[ACPI_MAX];

static uint32_t
rd32(const uint8_t *p)
{
	return ((uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	    (uint32_t)p[3] << 24);
}

static uint64_t
rd64(const uint8_t *p)
{
	return ((uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32);
}

/*
 * <signature>/<OEM table id>: the table header's bytes 0-3 and 16-23, the
 * id without trailing blanks, anything but [A-Za-z0-9_.-] as '_'.
 */
static void
acpi_item_id(const uint8_t *t, char *id, size_t sz)
{
	size_t n = 0, i, end = 24;
	unsigned char c;

	for (i = 0; i < 4 && n + 2 < sz; i++) {
		c = t[i];
		id[n++] = (c >= 0x21 && c < 0x7f && c != ',' && c != '/') ?
		    (char)c : '_';
	}
	id[n++] = '/';
	while (end > 16 && (t[end - 1] == ' ' || t[end - 1] == '\0'))
		end--;
	for (i = 16; i < end && n + 1 < sz; i++) {
		c = t[i];
		id[n++] = ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-') ?
		    (char)c : '_';
	}
	if (id[n - 1] == '/' && n + 1 < sz)
		id[n++] = '-';
	id[n] = '\0';
}

/* One table into the items and the list: its digest over the Length bytes. */
static void
acpi_table_note(uint64_t phys, unsigned int *n, struct kenv_list *l)
{
	const uint8_t *t = (const uint8_t *)(uintptr_t)phys;
	struct item *it;
	uint32_t len;
	char entry[ITEM_IDLEN + 24], d8[9];

	if (t == NULL || *n >= ACPI_MAX)
		return;
	len = rd32(t + 4);
	if (len < 36 || len > 16 * 1024 * 1024)
		return;
	it = &acpi_items[(*n)++];
	acpi_item_id(t, it->id, sizeof(it->id));
	it->size = len;
	it->attrs = 0;
	measurement_sha256(t, len, it->digest);
	hex8(it->digest, d8);
	snprintf(entry, sizeof(entry), "%s:%u:%s", it->id, len, d8);
	list_add(l, entry);
}

struct measurement
measure_acpi(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "AcpiTables", .type = MEAS_SHA256 };
	struct kenv_list l = { .what = "acpi" };
	const uint8_t *rsdp, *xsdt, *rsdt;
	uint32_t len, i, cnt;
	uint64_t addr;
	unsigned int n = 0;

	rsdp = efi_get_table(&acpi20_guid);
	if (rsdp == NULL)
		rsdp = efi_get_table(&acpi10_guid);
	if (rsdp == NULL || memcmp(rsdp, "RSD PTR ", 8) != 0)
		return (m);
	/* revision 2: XSDT with 64-bit pointers; else RSDT with 32-bit */
	if (rsdp[15] >= 2 && (addr = rd64(rsdp + 24)) != 0) {
		xsdt = (const uint8_t *)(uintptr_t)addr;
		len = rd32(xsdt + 4);
		if (len < 36)
			return (m);
		cnt = (len - 36) / 8;
		for (i = 0; i < cnt; i++)
			acpi_table_note(rd64(xsdt + 36 + 8 * i), &n, &l);
	} else {
		rsdt = (const uint8_t *)(uintptr_t)rd32(rsdp + 16);
		if (rsdt == NULL)
			return (m);
		len = rd32(rsdt + 4);
		if (len < 36)
			return (m);
		cnt = (len - 36) / 4;
		for (i = 0; i < cnt; i++)
			acpi_table_note(rd32(rsdt + 36 + 4 * i), &n, &l);
	}
	list_flush(&l);
	if (!set_digest("acpi", LOADER_TRUST_ACPI_SET, acpi_items, n,
	    m.value.digest))
		return (m);
	m.present = true;
	return (m);
}

/* --- non-volatile EFI variables --- */

/* elvboot's own variables change every boot by design: excluded. */
static EFI_GUID elv_guid = { 0xe1b00747, 0x5e1f, 0x4c0d,
    { 0x9a, 0x0e, 0x00, 0x00, 0x00, 0xe1, 0xb0, 0x07 } };

#define	EFIVARS_MAX	400
static struct item efi_items[EFIVARS_MAX];

struct measurement
measure_efivars(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "EfiVariables", .type = MEAS_SHA256 };
	struct kenv_list l = { .what = "efivars" };
	struct item *it;
	char entry[ITEM_IDLEN + 32], ascii[41], d8[9];
	CHAR16 *name;
	EFI_GUID guid;
	UINTN nsz, dsz, cap = 1024;
	UINT32 attrs;
	uint8_t *data;
	EFI_STATUS st;
	unsigned int n = 0;
	bool overflow = false;

	name = malloc(cap * sizeof(CHAR16));
	if (name == NULL)
		return (m);
	name[0] = 0;
	for (;;) {
		nsz = cap * sizeof(CHAR16);
		st = RS->GetNextVariableName(&nsz, name, &guid);
		if (st == EFI_NOT_FOUND)
			break;
		if (st == EFI_BUFFER_TOO_SMALL) {
			CHAR16 *bigger;

			cap = nsz / sizeof(CHAR16) + 16;
			bigger = malloc(cap * sizeof(CHAR16));
			if (bigger == NULL)
				break;
			memcpy(bigger, name, nsz > cap * sizeof(CHAR16) ?
			    cap * sizeof(CHAR16) : nsz);
			free(name);
			name = bigger;
			continue;
		}
		if (EFI_ERROR(st))
			break;
		if (memcmp(&guid, &elv_guid, sizeof(guid)) == 0)
			continue;
		dsz = 0;
		st = RS->GetVariable(name, &guid, &attrs, &dsz, NULL);
		if (st != EFI_BUFFER_TOO_SMALL)
			continue;
		if ((attrs & EFI_VARIABLE_NON_VOLATILE) == 0)
			continue;
		if (n >= EFIVARS_MAX) {
			overflow = true;
			break;
		}
		data = malloc(dsz);
		if (data == NULL)
			break;
		if (!EFI_ERROR(RS->GetVariable(name, &guid, &attrs, &dsz, data))) {
			UINTN i;

			for (i = 0; name[i] != 0; i++) {
				if (i < sizeof(ascii) - 1)
					ascii[i] = (name[i] >= 0x21 &&
					    name[i] < 0x7f && name[i] != ',' &&
					    name[i] != '/' && name[i] != ':') ?
					    (char)name[i] : '_';
			}
			ascii[i < sizeof(ascii) - 1 ? i : sizeof(ascii) - 1] = '\0';
			it = &efi_items[n++];
			snprintf(it->id, sizeof(it->id), "%08x/%s",
			    (unsigned int)guid.Data1, ascii);
			it->size = (uint32_t)dsz;
			it->attrs = attrs;
			measurement_sha256(data, dsz, it->digest);
			hex8(it->digest, d8);
			/* <guid's first word>/<name>:<attrs>:<size>:<digest> */
			snprintf(entry, sizeof(entry), "%s:%x:%u:%s", it->id,
			    (unsigned int)attrs, (unsigned int)dsz, d8);
			list_add(&l, entry);
		}
		free(data);
	}
	free(name);
	list_flush(&l);
	if (overflow)
		return (m);		/* an incomplete inventory claims nothing */
	if (!set_digest("efivars", LOADER_TRUST_EFIVARS_SET, efi_items, n,
	    m.value.digest))
		return (m);
	m.present = true;
	return (m);
}

/* --- PCI devices --- */

static unsigned int pci_n;

struct measurement
measure_pci(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "PciDevices", .type = MEAS_SHA256 };
	EFI_HANDLE *handles = NULL;
	UINTN n = 0, i;
	EFI_PCI_IO_PROTOCOL *pci;
	UINTN seg, bus, dev, fn;
	UINT32 id, cls;
	SHA256_CTX ctx;
	uint8_t rec[16];

	if (EFI_ERROR(BS->LocateHandleBuffer(ByProtocol, &pciio_guid, NULL,
	    &n, &handles)))
		return (m);
	SHA256_Init(&ctx);
	pci_n = 0;
	for (i = 0; i < n; i++) {
		if (EFI_ERROR(BS->HandleProtocol(handles[i], &pciio_guid,
		    (void **)&pci)))
			continue;
		if (EFI_ERROR(pci->GetLocation(pci, &seg, &bus, &dev, &fn)))
			continue;
		if (EFI_ERROR(pci->Pci.Read(pci, EfiPciIoWidthUint32, 0, 1, &id)))
			continue;
		if (EFI_ERROR(pci->Pci.Read(pci, EfiPciIoWidthUint32, 8, 1, &cls)))
			cls = 0;
		rec[0] = seg; rec[1] = bus; rec[2] = dev; rec[3] = fn;
		memcpy(rec + 4, &id, 4);
		memcpy(rec + 8, &cls, 4);
		memset(rec + 12, 0, 4);
		SHA256_Update(&ctx, rec, sizeof(rec));
		pci_n++;
	}
	BS->FreePool(handles);
	if (pci_n == 0)
		return (m);
	SHA256_Final(m.value.digest, &ctx);
	m.present = true;
	return (m);
}

void
diagnose_pci(int argc __unused, CHAR16 *argv[] __unused, struct diagnosis *d)
{
	d->leaf = "pci.count";
	snprintf(d->text, sizeof(d->text), "%u", pci_n);
}
