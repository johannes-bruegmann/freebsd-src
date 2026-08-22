/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * action.c -- the const catalog of actions, shared across layers.
 *
 * Every action is UNCONDITIONAL: it always does its thing when run. WHETHER it
 * runs is the policy's decision, via a firing predicate (policy.h). So no
 * handler here inspects the verdict to decide whether to act -- report always
 * warns, halt always halts, publish always exposes. The policy binds report to
 * when_fail, publish to when_always, and so on.
 *
 * publish is where the results reach kenv (loader.trust.<gate>.*); every other
 * action reads what it needs from the appraisal directly, not from kenv.
 */

#include <stand.h>
#include <string.h>

#include <efi.h>
#include <efilib.h>			/* RS (reset) */

#include <crypto/sha2/sha256.h>

#include "measurement.h"
#include "claim.h"
#include "gate.h"
#include "action.h"

#define	LISTLEN	192

/* ------------------------------------------------------------- helpers */

static void
halt_boot(const char *why)
{
	printf("*** boot %s ***\n", why);
	for (;;)
		(void)getchar();
}

/* Read a line without echoing -- getchar does not echo (ngets would). */
static void
readsecret(char *buf, size_t sz)
{
	size_t n = 0;
	int c;

	while ((c = getchar()) != '\r' && c != '\n' && c != -1) {
		if (n + 1 < sz)
			buf[n++] = c;
	}
	buf[n] = '\0';
}

/* Lower-case hex of SHA256(buf); out holds 2*LEN + 1. */
static void
sha256_hex(const void *buf, size_t len, char *out)
{
	static const char hex[] = "0123456789abcdef";
	uint8_t d[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	int i;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, len);
	SHA256_Final(d, &ctx);
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		out[2 * i] = hex[d[i] >> 4];
		out[2 * i + 1] = hex[d[i] & 0x0f];
	}
	out[2 * SHA256_DIGEST_LENGTH] = '\0';
}

/* Read a gate config leaf, "loader.trust.<gate>.<leaf>". */
static const char *
kenv(const struct appraisal *a, const char *leaf)
{
	char name[64];

	gate_var(a->gate, leaf, name, sizeof(name));
	return (getenv(name));
}

/* Set loader.trust.<gate>.<leaf> = value. */
static void
publish(const struct gate *g, const char *leaf, const char *value)
{
	char name[64];

	gate_var(g, leaf, name, sizeof(name));
	setenv(name, value, 1);
}

static void
record(char *list, const char *name, size_t sz)
{
	if (list[0] != '\0')
		(void)strlcat(list, ",", sz);
	(void)strlcat(list, name, sz);
}

/* Comma list of the claim names whose result carries this verdict. */
static void
list_by_verdict(const struct appraisal *a, enum verdict want, char *buf, size_t sz)
{
	const struct claim *c;
	const struct claim_result *r;

	buf[0] = '\0';
	for (c = a->gate->claims, r = a->results; c->measure != NULL; c++, r++)
		if (r->verdict == want)
			record(buf, c->expected.name, sz);
}

/* --- baseline --- */

static void
action_proceed(const struct appraisal *a __unused)
{
	/* Continue execution; at loaderlock this lets the boot proceed. */
}

/* --- exposure --- */

/* Write the appraisal to kenv: each value, each diagnostic, the three lists. */
static void
action_publish(const struct appraisal *a)
{
	char list[LISTLEN], val[2 * SHA256_DIGEST_LENGTH + 1];
	const struct claim *c;
	const struct claim_result *r;

	for (c = a->gate->claims, r = a->results; c->measure != NULL; c++, r++) {
		if (r->actual.present && c->publish != NULL) {
			measurement_render(&r->actual, val, sizeof(val));
			publish(a->gate, c->publish, val);
		}
		if (r->diag.leaf != NULL)
			publish(a->gate, r->diag.leaf, r->diag.text);
	}
	list_by_verdict(a, VERDICT_PASS, list, sizeof(list));
	publish(a->gate, "passed", list);
	list_by_verdict(a, VERDICT_FAIL, list, sizeof(list));
	publish(a->gate, "failed", list);
	list_by_verdict(a, VERDICT_SKIP, list, sizeof(list));
	publish(a->gate, "skipped", list);
}

/* --- evidence --- */

static void
action_report(const struct appraisal *a)
{
	char failed[LISTLEN], passed[LISTLEN];

	list_by_verdict(a, VERDICT_FAIL, failed, sizeof(failed));
	list_by_verdict(a, VERDICT_PASS, passed, sizeof(passed));
	printf("\n*** platform trust: failed=[%s] passed=[%s] ***\n",
	    failed, passed);
	printf("Press any key to continue.\n");
	(void)getchar();
}

static void
action_message(const struct appraisal *a)
{
	const char *msg = kenv(a, "message");

	printf("%s\n", msg != NULL ? msg : "platform trust check failed");
}

/* Pose a plaintext question, read the answer, record it (not verified). */
static void
action_prompt(const struct appraisal *a)
{
	const char *q = kenv(a, "question");
	char ans[128], name[64];

	if (q == NULL)
		return;
	printf("%s ", q);
	ngets(ans, sizeof(ans));
	gate_var(a->gate, "answer", name, sizeof(name));
	setenv(name, ans, 1);
}

/* --- response --- */

static void
action_confirm(const struct appraisal *a)
{
	int c;

	printf("%s: tamper detected -- continue? (y/N) ", a->gate->name);
	c = getchar();
	printf("\n");
	if (c != 'y' && c != 'Y')
		halt_boot("aborted");
}

/* Demand the secret if one is configured. */
static void
action_lock(const struct appraisal *a)
{
	const char *want = kenv(a, "secret");	/* expected SHA256, hex */
	char got[128], hash[2 * SHA256_DIGEST_LENGTH + 1];
	int tries;

	if (want == NULL)
		return;				/* no secret -> nothing to lock */
	for (tries = 0; tries < 3; tries++) {
		printf("%s: secret: ", a->gate->name);
		readsecret(got, sizeof(got));
		printf("\n");
		sha256_hex(got, strlen(got), hash);
		if (strcmp(hash, want) == 0)
			return;			/* unlocked */
		printf("wrong.\n");
	}
	halt_boot("locked");
}

/*
 * Compiled-in recovery lock. Unlike action_lock, the expected hash comes from
 * the gate itself (a->gate->secret, baked into the signed loader) -- not from
 * kenv/loader.conf, which is exactly the object that may be missing or tampered
 * when this fires. Reports which claims failed, then, if a secret is compiled
 * in, demands the passphrase (3 tries) before letting the boot proceed to the
 * loader prompt; a wrong passphrase halts. With no secret compiled in it reports
 * and continues, so an unprovisioned build is report-only and cannot brick.
 */
static void
action_unlock(const struct appraisal *a)
{
	char failed[LISTLEN], got[128], hash[2 * SHA256_DIGEST_LENGTH + 1];
	int tries;

	list_by_verdict(a, VERDICT_FAIL, failed, sizeof(failed));
	printf("\n*** %s: verification failed [%s] ***\n", a->gate->name, failed);
	if (a->gate->secret == NULL) {
		printf("no recovery secret compiled in -- continuing.\n");
		return;
	}
	for (tries = 0; tries < 3; tries++) {
		printf("%s: recovery passphrase: ", a->gate->name);
		readsecret(got, sizeof(got));
		printf("\n");
		sha256_hex(got, strlen(got), hash);
		if (strcmp(hash, a->gate->secret) == 0)
			return;			/* unlocked -> loader prompt */
		printf("wrong.\n");
	}
	halt_boot("locked");
}

static void
action_halt(const struct appraisal *a __unused)
{
	halt_boot("halted");
}

static void
action_panic(const struct appraisal *a)
{
	panic("%s: platform trust FAILED", a->gate->name);
}

static void
action_reboot(const struct appraisal *a __unused)
{
	RS->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
	halt_boot("reboot failed");	/* not reached if reset works */
}

ACTION_DEFINE(proceed, action_proceed);
ACTION_DEFINE(publish, action_publish);
ACTION_DEFINE(report,  action_report);
ACTION_DEFINE(message, action_message);
ACTION_DEFINE(prompt,  action_prompt);
ACTION_DEFINE(confirm, action_confirm);
ACTION_DEFINE(lock,    action_lock);
ACTION_DEFINE(unlock,  action_unlock);
ACTION_DEFINE(halt,    action_halt);
ACTION_DEFINE(panic,   action_panic);
ACTION_DEFINE(reboot,  action_reboot);
