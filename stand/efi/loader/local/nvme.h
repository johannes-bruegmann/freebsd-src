/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * nvme.h -- the SSD's own counters, through the firmware's NVMe pass-through.
 *
 * EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL carries one admin command: Get Log Page
 * 02h (SMART / Health Information). Of it the loader reads Power Cycles,
 * Power On Hours, Unsafe Shutdowns and Data Units Written -- counters the
 * controller maintains and no host command resets. A boot the owner did not
 * make is one power cycle more than the record remembers.
 *
 * Assumes: the boot disks are NVMe and the firmware exposes the pass-through
 * protocol for them (true for the internal nda0/nda2). The first controller
 * that answers is used; the diagnosis names how many answered.
 *
 * Not a catalog: internal to the local layer.
 */

#ifndef _LOCAL_NVME_H_
#define	_LOCAL_NVME_H_

#include <stdint.h>
#include <stdbool.h>

struct nvme_smart {
	uint64_t	power_cycles;
	uint64_t	power_on_hours;
	uint64_t	unsafe_shutdowns;
	uint64_t	data_units_written;
	unsigned int	controllers;	/* how many answered */
};

bool	nvme_smart(struct nvme_smart *);

#endif /* _LOCAL_NVME_H_ */
