/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * The tpm command: what the TPM 2.0 of this machine says (efitpm.h),
 * and a sealed object made a preloaded file -- a GELI key file the TPM
 * releases only under the PCR policy it was sealed with.
 *
 *   tpm clock                        resetCount, restartCount, clock, safe
 *   tpm pcr [list]                   the SHA256 bank of the PCRs (0..7),
 *                                    each in hex, and their sha256
 *   tpm nv read <index>              an 8-byte counter index
 *   tpm nv increment <index>
 *   tpm nv define <index>            define a counter (once)
 *   tpm unseal <handle> <list> <type> [-a]
 *                                    unseal the persistent object under
 *                                    PolicyPCR over the list; with -a the
 *                                    passphrase read hidden from the
 *                                    console (its sha256) is the auth
 *                                    value; the bytes become a preloaded
 *                                    file of <type>, e.g. a GELI key
 *                                    file "nda0p1:geli_keyfile1"
 *
 * tpm pcr sets tpm.pcr.sha256 in the environment; tpm clock sets
 * tpm.clock, tpm.reset, tpm.restart, tpm.safe.
 */

#include <stand.h>
#include <string.h>
#include <bootstrap.h>

#include <efi.h>
#include <efilib.h>
#include <efitpm.h>

#include <crypto/sha2/sha256.h>

#include "loader_efi.h"

void	pwgets(char *, int, int);	/* libsa/geli/pwgets.c */

static void
hex(const uint8_t *d, size_t len, char *out)
{
	static const char hx[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[2 * i] = hx[d[i] >> 4];
		out[2 * i + 1] = hx[d[i] & 0x0f];
	}
	out[2 * len] = '\0';
}

static int
tpm_clock(void)
{
	struct efi_tpm_clock c;
	char buf[32];

	if (!efi_tpm_read_clock(&c)) {
		command_errmsg = efi_tpm_error();
		return (CMD_ERROR);
	}
	printf("reset=%u restart=%u clock=%llu ms safe=%u\n", c.reset_count,
	    c.restart_count, (unsigned long long)c.clock, c.safe ? 1 : 0);
	snprintf(buf, sizeof(buf), "%u", c.reset_count);
	setenv("tpm.reset", buf, 1);
	snprintf(buf, sizeof(buf), "%u", c.restart_count);
	setenv("tpm.restart", buf, 1);
	snprintf(buf, sizeof(buf), "%llu", (unsigned long long)c.clock);
	setenv("tpm.clock", buf, 1);
	setenv("tpm.safe", c.safe ? "1" : "0", 1);
	return (CMD_OK);
}

static int
tpm_pcr(const char *list)
{
	uint8_t bank[8 * 32], d[32];
	char h[65];
	size_t len, off = 0;
	uint32_t mask = 0xff, i;
	SHA256_CTX ctx;

	if (list != NULL && !efi_tpm_parse_pcrs(list, &mask)) {
		command_errmsg = "bad PCR list (0..23, comma-separated)";
		return (CMD_ERROR);
	}
	if (!efi_tpm_pcr_read(mask, bank, sizeof(bank), &len)) {
		command_errmsg = efi_tpm_error();
		return (CMD_ERROR);
	}
	for (i = 0; i < 24 && off + 32 <= len; i++) {
		if ((mask & (1u << i)) == 0)
			continue;
		hex(bank + off, 32, h);
		printf("%2u: %s\n", i, h);
		off += 32;
	}
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, bank, len);
	SHA256_Final(d, &ctx);
	hex(d, sizeof(d), h);
	printf("sha256: %s\n", h);
	setenv("tpm.pcr.sha256", h, 1);
	return (CMD_OK);
}

static int
tpm_nv(int argc, char *argv[])
{
	unsigned long index;
	char *end;
	uint64_t v;

	if (argc < 2) {
		command_errmsg = "tpm nv read|increment|define <index>";
		return (CMD_ERROR);
	}
	index = strtoul(argv[1], &end, 0);
	if (end == argv[1] || *end != '\0' || index > 0xffffffffUL) {
		command_errmsg = "bad NV index";
		return (CMD_ERROR);
	}
	if (strcmp(argv[0], "read") == 0) {
		if (!efi_tpm_nv_counter_read((uint32_t)index, &v)) {
			command_errmsg = efi_tpm_error();
			return (CMD_ERROR);
		}
		printf("%llu\n", (unsigned long long)v);
		return (CMD_OK);
	}
	if (strcmp(argv[0], "increment") == 0) {
		if (!efi_tpm_nv_counter_increment((uint32_t)index)) {
			command_errmsg = efi_tpm_error();
			return (CMD_ERROR);
		}
		return (CMD_OK);
	}
	if (strcmp(argv[0], "define") == 0) {
		if (!efi_tpm_nv_counter_define((uint32_t)index)) {
			command_errmsg = efi_tpm_error();
			return (CMD_ERROR);
		}
		return (CMD_OK);
	}
	command_errmsg = "tpm nv read|increment|define <index>";
	return (CMD_ERROR);
}

static int
tpm_unseal(int argc, char *argv[])
{
	unsigned long handle;
	char *end, pw[128];
	uint32_t mask;
	uint8_t auth[SHA256_DIGEST_LENGTH], secret[128];
	size_t authlen = 0, len;
	bool ask = false;
	SHA256_CTX ctx;

	if (argc == 4 && strcmp(argv[3], "-a") == 0) {
		ask = true;
		argc = 3;
	}
	if (argc != 3) {
		command_errmsg = "tpm unseal <handle> <pcr-list> <type> [-a]";
		return (CMD_ERROR);
	}
	handle = strtoul(argv[0], &end, 0);
	if (end == argv[0] || *end != '\0' || handle > 0xffffffffUL) {
		command_errmsg = "bad handle";
		return (CMD_ERROR);
	}
	if (!efi_tpm_parse_pcrs(argv[1], &mask)) {
		command_errmsg = "bad PCR list (0..23, comma-separated)";
		return (CMD_ERROR);
	}
	if (ask) {
		printf("TPM passphrase for %s: ", argv[0]);
		pwgets(pw, sizeof(pw), 1);
		printf("\n");
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, pw, strlen(pw));
		SHA256_Final(auth, &ctx);
		explicit_bzero(pw, sizeof(pw));
		authlen = sizeof(auth);
	}
	if (!efi_tpm_unseal((uint32_t)handle, mask, auth, authlen, secret,
	    sizeof(secret), &len)) {
		explicit_bzero(auth, sizeof(auth));
		command_errmsg = efi_tpm_error();
		return (CMD_ERROR);
	}
	explicit_bzero(auth, sizeof(auth));
	if (file_addbuf("tpm.unsealed", argv[2], len, secret) != 0) {
		explicit_bzero(secret, sizeof(secret));
		return (CMD_ERROR);	/* command_errmsg set by file_addbuf */
	}
	explicit_bzero(secret, sizeof(secret));
	return (CMD_OK);
}

static int
command_tpm(int argc, char *argv[])
{
	if (argc < 2) {
		command_errmsg = "tpm clock | pcr [list] | nv ... | unseal ...";
		return (CMD_ERROR);
	}
	if (strcmp(argv[1], "clock") == 0)
		return (tpm_clock());
	if (strcmp(argv[1], "pcr") == 0)
		return (tpm_pcr(argc > 2 ? argv[2] : NULL));
	if (strcmp(argv[1], "nv") == 0)
		return (tpm_nv(argc - 2, argv + 2));
	if (strcmp(argv[1], "unseal") == 0)
		return (tpm_unseal(argc - 2, argv + 2));
	command_errmsg = "tpm clock | pcr [list] | nv ... | unseal ...";
	return (CMD_ERROR);
}

COMMAND_SET(tpm, "tpm", "TPM 2.0: clock, PCRs, NV counters, unseal", command_tpm);
