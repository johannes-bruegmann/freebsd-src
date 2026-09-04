/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * nvme.c -- SMART counters via EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL (nvme.h).
 *
 * The protocol is declared here in the shape the UEFI specification gives
 * it (section "NVM Express Pass Through Protocol"); the log page layout is
 * the kernel's own (sys/dev/nvme/nvme.h).
 */

#include <stand.h>
#include <string.h>

#include <efi.h>
#include <efilib.h>

#include <dev/nvme/nvme.h>

#include "nvme.h"

static EFI_GUID nvme_pt_guid = { 0x52c78312, 0x8edc, 0x4233,
    { 0x98, 0xf2, 0x1a, 0x1a, 0xa5, 0xe3, 0x88, 0xa5 } };

typedef struct {
	UINT32	Attributes;
	UINT32	IoAlign;
	UINT32	NvmeVersion;
} EFI_NVM_EXPRESS_PASS_THRU_MODE;

typedef struct {
	UINT32	Cdw0;
	UINT8	Flags;
	UINT32	Nsid;
	UINT32	Cdw2, Cdw3, Cdw10, Cdw11, Cdw12, Cdw13, Cdw14, Cdw15;
} EFI_NVM_EXPRESS_COMMAND;

typedef struct {
	UINT32	DW0, DW1, DW2, DW3;
} EFI_NVM_EXPRESS_COMPLETION;

typedef struct {
	UINT64				CommandTimeout;
	VOID				*TransferBuffer;
	UINT32				TransferLength;
	VOID				*MetadataBuffer;
	UINT32				MetadataLength;
	UINT8				QueueType;
	EFI_NVM_EXPRESS_COMMAND		*NvmeCmd;
	EFI_NVM_EXPRESS_COMPLETION	*NvmeCompletion;
} EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET;

typedef struct _EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_NVME_PASS_THRU_PASSTHRU)(
    EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL *, UINT32 NamespaceId,
    EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET *, EFI_EVENT);

struct _EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL {
	EFI_NVM_EXPRESS_PASS_THRU_MODE	*Mode;
	EFI_NVME_PASS_THRU_PASSTHRU	PassThru;
	VOID				*GetNextNamespace;
	VOID				*BuildDevicePath;
	VOID				*GetNamespace;
};

#define	NVME_PT_FLAG_CDW10	0x04
#define	NVME_PT_QUEUE_ADMIN	0
#define	NVME_OPC_GET_LOG_PAGE	0x02
#define	NVME_NSID_ALL		0xffffffffu

static uint64_t
le128_lo(const uint64_t v[2])
{
	return (v[0]);
}

static bool
smart_of(EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL *pt, struct nvme_smart *out)
{
	EFI_NVM_EXPRESS_COMMAND cmd;
	EFI_NVM_EXPRESS_COMPLETION cpl;
	EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET pkt;
	struct nvme_health_information_page *page;
	uint32_t numd;
	bool ok;

	page = malloc(sizeof(*page) + 4096);
	if (page == NULL)
		return (false);
	{
		/* align to the controller's requirement (IoAlign, a power of 2) */
		uintptr_t a = pt->Mode->IoAlign > 0 ? pt->Mode->IoAlign : 1;
		uintptr_t p = ((uintptr_t)page + a - 1) & ~(a - 1);
		struct nvme_health_information_page *aligned = (void *)p;

		memset(&cmd, 0, sizeof(cmd));
		memset(&cpl, 0, sizeof(cpl));
		memset(&pkt, 0, sizeof(pkt));
		numd = sizeof(*page) / 4 - 1;
		cmd.Cdw0 = NVME_OPC_GET_LOG_PAGE;
		cmd.Nsid = NVME_NSID_ALL;
		cmd.Cdw10 = (numd << 16) | NVME_LOG_HEALTH_INFORMATION;
		cmd.Flags = NVME_PT_FLAG_CDW10;
		pkt.CommandTimeout = 10000000;	/* 1 s, 100 ns units */
		pkt.TransferBuffer = aligned;
		pkt.TransferLength = sizeof(*page);
		pkt.QueueType = NVME_PT_QUEUE_ADMIN;
		pkt.NvmeCmd = &cmd;
		pkt.NvmeCompletion = &cpl;
		ok = !EFI_ERROR(pt->PassThru(pt, NVME_NSID_ALL, &pkt, NULL)) &&
		    ((cpl.DW3 >> 17) & 0x7ff) == 0;
		if (ok) {
			out->power_cycles = le128_lo(aligned->power_cycles);
			out->power_on_hours = le128_lo(aligned->power_on_hours);
			out->unsafe_shutdowns = le128_lo(aligned->unsafe_shutdowns);
			out->data_units_written =
			    le128_lo(aligned->data_units_written);
		}
	}
	free(page);
	return (ok);
}

/*
 * The first controller that answers provides the counters; every answering
 * controller is counted, so a disappeared or added disk shows in the
 * diagnosis.
 */
bool
nvme_smart(struct nvme_smart *out)
{
	static struct nvme_smart cache;
	static bool tried, ok;
	EFI_HANDLE *handles = NULL;
	UINTN n = 0, i;
	EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL *pt;
	struct nvme_smart s;

	if (tried) {
		*out = cache;
		return (ok);
	}
	tried = true;
	memset(&cache, 0, sizeof(cache));
	if (EFI_ERROR(BS->LocateHandleBuffer(ByProtocol, &nvme_pt_guid, NULL,
	    &n, &handles)))
		n = 0;
	for (i = 0; i < n; i++) {
		if (EFI_ERROR(BS->HandleProtocol(handles[i], &nvme_pt_guid,
		    (void **)&pt)))
			continue;
		memset(&s, 0, sizeof(s));
		if (!smart_of(pt, &s))
			continue;
		if (cache.controllers == 0) {
			cache = s;
			ok = true;
		}
		cache.controllers++;
	}
	if (handles != NULL)
		BS->FreePool(handles);
	*out = cache;
	return (ok);
}
