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
 * --- the lists behind a digest ---
 *
 * A digest that falls says nothing about which table or variable moved.
 * For learning what the firmware rewrites per boot (JB 11.09.: record
 * first, decide the claim's scope after), the measurements below also
 * publish one entry per item, comma-joined into kenv variables
 * loader.trust.list.<what>.<n> of at most LIST_CHUNK characters -- the
 * kernel drops any loader string longer than KENV_MNAMELEN+KENV_MVALLEN.
 * elvbootd's inventory_record_act files them per boot.
 */
#define	LIST_CHUNK	200

/*
 * What the digests leave out, decided per stage from those lists (JB
 * 12.09.: two boots of illyria moved exactly PHAT and MotherBoardHealth):
 * comma-separated ACPI signatures, and EFI variables as <guid's first
 * word>/<name> -- the form the list entries carry. Empty means nothing is
 * left out: a stage states its exclusions, the loader assumes none.
 */
#ifndef LOADER_TRUST_ACPI_EXCLUDE
#define	LOADER_TRUST_ACPI_EXCLUDE	""
#endif
#ifndef LOADER_TRUST_EFIVARS_EXCLUDE
#define	LOADER_TRUST_EFIVARS_EXCLUDE	""
#endif

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

/* 8 hex digits of a SHA256 over the bytes: enough to tell boots apart. */
static void
digest8(const void *p, size_t n, char out[9])
{
	SHA256_CTX ctx;
	uint8_t d[SHA256_DIGEST_LENGTH];

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, p, n);
	SHA256_Final(d, &ctx);
	snprintf(out, 9, "%02x%02x%02x%02x", d[0], d[1], d[2], d[3]);
}

/* --- ACPI tables --- */

static EFI_GUID acpi20_guid = ACPI_20_TABLE_GUID;
static EFI_GUID acpi10_guid = ACPI_TABLE_GUID;

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

/* Hash one table: its header and body as the Length field says; list it. */
static void
acpi_table_update(SHA256_CTX *ctx, uint64_t phys, struct kenv_list *l)
{
	const uint8_t *t = (const uint8_t *)(uintptr_t)phys;
	uint32_t len;
	char entry[32], d8[9];

	char sig[5];

	if (t == NULL)
		return;
	len = rd32(t + 4);
	memcpy(sig, t, 4);
	sig[4] = '\0';
	/*
	 * Tables the firmware rewrites every boot are not the platform's
	 * identity (illyria: FPDT with the last boot's timings, BGRT the
	 * boot logo's address, PHAT the platform health record). The stage
	 * names them in LOADER_TRUST_ACPI_EXCLUDE; they are listed with "-"
	 * for the digest: seen, not counted.
	 */
	if (listed(LOADER_TRUST_ACPI_EXCLUDE, sig)) {
		snprintf(entry, sizeof(entry), "%s:%u:-", sig, len);
		list_add(l, entry);
		return;
	}
	if (len < 36 || len > 16 * 1024 * 1024)
		return;
	SHA256_Update(ctx, t, len);
	digest8(t, len, d8);
	snprintf(entry, sizeof(entry), "%s:%u:%s", sig, len, d8);
	list_add(l, entry);
}

struct measurement
measure_acpi(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "AcpiTables", .type = MEAS_SHA256 };
	struct kenv_list l = { .what = "acpi" };
	const uint8_t *rsdp, *xsdt, *rsdt;
	SHA256_CTX ctx;
	uint32_t len, i, n;
	uint64_t addr;

	rsdp = efi_get_table(&acpi20_guid);
	if (rsdp == NULL)
		rsdp = efi_get_table(&acpi10_guid);
	if (rsdp == NULL || memcmp(rsdp, "RSD PTR ", 8) != 0)
		return (m);
	SHA256_Init(&ctx);
	/* revision 2: XSDT with 64-bit pointers; else RSDT with 32-bit */
	if (rsdp[15] >= 2 && (addr = rd64(rsdp + 24)) != 0) {
		xsdt = (const uint8_t *)(uintptr_t)addr;
		len = rd32(xsdt + 4);
		if (len < 36)
			return (m);
		SHA256_Update(&ctx, xsdt, 36);
		n = (len - 36) / 8;
		for (i = 0; i < n; i++)
			acpi_table_update(&ctx, rd64(xsdt + 36 + 8 * i), &l);
	} else {
		rsdt = (const uint8_t *)(uintptr_t)rd32(rsdp + 16);
		if (rsdt == NULL)
			return (m);
		len = rd32(rsdt + 4);
		if (len < 36)
			return (m);
		SHA256_Update(&ctx, rsdt, 36);
		n = (len - 36) / 4;
		for (i = 0; i < n; i++)
			acpi_table_update(&ctx, rd32(rsdt + 36 + 4 * i), &l);
	}
	list_flush(&l);
	SHA256_Final(m.value.digest, &ctx);
	m.present = true;
	return (m);
}

/* --- non-volatile EFI variables --- */

/* elvboot's own variables change every boot by design: excluded. */
static EFI_GUID elv_guid = { 0xe1b00747, 0x5e1f, 0x4c0d,
    { 0x9a, 0x0e, 0x00, 0x00, 0x00, 0xe1, 0xb0, 0x07 } };

struct measurement
measure_efivars(int argc __unused, CHAR16 *argv[] __unused)
{
	struct measurement m = { .name = "EfiVariables", .type = MEAS_SHA256 };
	struct kenv_list l = { .what = "efivars" };
	char entry[96], ascii[41], item[52], d8[9];
	CHAR16 *name;
	EFI_GUID guid;
	UINTN nsz, dsz, cap = 1024;
	UINT32 attrs;
	uint8_t *data;
	SHA256_CTX ctx;
	EFI_STATUS st;
	unsigned int n = 0;

	name = malloc(cap * sizeof(CHAR16));
	if (name == NULL)
		return (m);
	name[0] = 0;
	SHA256_Init(&ctx);
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
		data = malloc(dsz);
		if (data == NULL)
			break;
		if (!EFI_ERROR(RS->GetVariable(name, &guid, &attrs, &dsz, data))) {
			UINTN i;

			for (i = 0; name[i] != 0; i++) {
				if (i < sizeof(ascii) - 1)
					ascii[i] = (name[i] >= 0x20 &&
					    name[i] < 0x7f) ? (char)name[i] : '?';
			}
			ascii[i < sizeof(ascii) - 1 ? i : sizeof(ascii) - 1] = '\0';
			snprintf(item, sizeof(item), "%08x/%s",
			    (unsigned int)guid.Data1, ascii);
			/*
			 * A variable the firmware rewrites per boot (illyria:
			 * MotherBoardHealth) is named by the stage in
			 * LOADER_TRUST_EFIVARS_EXCLUDE: listed with "-", not
			 * counted.
			 */
			if (listed(LOADER_TRUST_EFIVARS_EXCLUDE, item)) {
				snprintf(entry, sizeof(entry), "%s:%x:%u:-", item,
				    (unsigned int)attrs, (unsigned int)dsz);
				list_add(&l, entry);
				free(data);
				continue;
			}
			SHA256_Update(&ctx, name, i * sizeof(CHAR16));
			SHA256_Update(&ctx, &guid, sizeof(guid));
			SHA256_Update(&ctx, &attrs, sizeof(attrs));
			SHA256_Update(&ctx, data, dsz);
			n++;
			/* <guid's first word>/<name>:<attrs>:<size>:<digest> */
			digest8(data, dsz, d8);
			snprintf(entry, sizeof(entry), "%s:%x:%u:%s", item,
			    (unsigned int)attrs, (unsigned int)dsz, d8);
			list_add(&l, entry);
		}
		free(data);
	}
	free(name);
	list_flush(&l);
	if (n == 0)
		return (m);
	SHA256_Final(m.value.digest, &ctx);
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
