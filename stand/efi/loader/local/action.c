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
 * Interactive actions leave their facts in the ledger (evidence.h): attempts,
 * dwell, cadence, the duress tell. Under silence (silence_act) nothing is
 * published to the console or kenv any more -- the handover word remains
 * the only channel, and it is opaque.
 */

#include <stand.h>
#include <string.h>
#include <bootstrap.h>			/* local_console_lock */

#include <efi.h>
#include <efilib.h>			/* RS (reset), delay */

#include <crypto/sha2/sha256.h>

#include "measurement.h"
#include "claim.h"
#include "gate.h"
#include "action.h"
#include "policy.h"			/* phase_policies: the prompt lock */
#include "evidence.h"
#include "clock.h"
#include "record.h"
#include "nvme.h"

#define	LISTLEN	192

void	delay(int usecs);		/* libefi/delay.c, undeclared upstream */

/* ------------------------------------------------------------- helpers */

static void
halt_boot(const char *why)
{
	printf("*** boot %s ***\n", why);
	for (;;)
		(void)getchar();
}

/*
 * Read a line without echoing -- getchar does not echo (ngets would). The
 * dwell (first key to Enter) and the longest pause between two keys go to
 * the ledger: both are duress tells the coercer cannot forbid.
 */
void
readsecret(char *buf, size_t sz)
{
	struct stamp t0, tk, tprev;
	uint64_t cadence = 0, gap;
	size_t n = 0;
	int c;
	bool first = true;

	clock_now(&t0);
	tprev = t0;
	while ((c = getchar()) != '\r' && c != '\n' && c != -1) {
		clock_now(&tk);
		if (!first) {
			gap = clock_ms_between(&tprev, &tk);
			if (gap > cadence)
				cadence = gap;
		}
		first = false;
		tprev = tk;
		if (n + 1 < sz)
			buf[n++] = c;
	}
	buf[n] = '\0';
	clock_now(&tk);
	evidence_note_prompt(clock_ms_between(&t0, &tk), cadence);
	evidence_note_attempt();
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

static void
hex_of(const uint8_t *d, size_t len, char *out)
{
	static const char hex[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[2 * i] = hex[d[i] >> 4];
		out[2 * i + 1] = hex[d[i] & 0x0f];
	}
	out[2 * len] = '\0';
}

/* Read a gate config leaf, "loader.trust.<gate>.<leaf>". */
static const char *
kenv(const struct appraisal *a, const char *leaf)
{
	char name[64];

	gate_var(a->gate, leaf, name, sizeof(name));
	return (getenv(name));
}

/* Set loader.trust.<gate>.<leaf> = value -- unless the boot is silenced. */
static void
publish(const struct gate *g, const char *leaf, const char *value)
{
	char name[64];

	if (evidence()->silence)
		return;
	gate_var(g, leaf, name, sizeof(name));
	setenv(name, value, 1);
}

/* The handover channel: set even under silence (opaque by construction). */
static void
publish_always(const struct gate *g, const char *leaf, const char *value)
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

/*
 * The passphrase dialogue shared by lock and unlock: up to three tries
 * against the unlock hash and, if one is compiled in, the duress hash. A
 * duress match unlocks EXACTLY like the real one and marks the ledger --
 * nothing on the console tells the two apart.
 */
static bool
passphrase_dialogue(const struct appraisal *a, const char *label,
    const char *want, const char *duress, bool gate)
{
	char got[128], hash[2 * SHA256_DIGEST_LENGTH + 1];
	int tries;

	for (tries = 0; tries < 3; tries++) {
		printf("%s: %s: ", a->gate->name, label);
		readsecret(got, sizeof(got));
		printf("\n");
		sha256_hex(got, strlen(got), hash);
		explicit_bzero(got, sizeof(got));
		if (strcmp(hash, want) == 0) {
			if (gate)
				evidence_note_unlock();
			else
				evidence_note_console();
			return (true);
		}
		if (duress != NULL && strcmp(hash, duress) == 0) {
			evidence_set_duress();
			if (gate)
				evidence_note_unlock();
			else
				evidence_note_console();
			return (true);
		}
		printf("wrong.\n");
	}
	return (false);
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

static void
action_silence(const struct appraisal *a __unused)
{
	evidence_set_silence();
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

/*
 * The context line the owner recognises. The human is the one measurement
 * instrument the platform cannot enumerate: they often know what SHOULD
 * have been (the boot number, when the machine last ran, whether it was
 * switched on without them). loader.trust.<gate>.display names the items,
 * space-separated and shown in that order: bootcount (this boot's number),
 * lastboot (RTC of the previous boot), cycles and unclean (NVMe power
 * cycles and unsafe shutdowns since the previous record; an honest boot
 * shows +1 and +0), gates (appraisals so far, ok/failed), attempts (hidden
 * lines typed this boot). Not interactive: the judgement flows into what
 * the owner does after the kernel starts. Without a valid record the line
 * SAYS which (none, or present but not verified) and shows ? for the record
 * items -- an absence is a fact worth reading too, not a blank. The coercer
 * reads the line as well: only items
 * whose knowledge helps no attacker belong here, and the selection is the
 * owner's conf decision.
 */
static bool
display_item_is(const char *p, size_t n, const char *name)
{
	return (strlen(name) == n && strncmp(p, name, n) == 0);
}

static void
display_line(const struct appraisal *a, const char *items)
{
	const char *p;
	const struct record_state *rs = record_state();
	const struct evidence *e = evidence();
	struct nvme_smart ns;
	struct stamp s;
	char iso[32];
	size_t n;
	bool nvme, first = true;

	nvme = rs->valid && nvme_smart(&ns);
	printf("%s:", a->gate->name);
	if (!rs->valid)
		printf(rs->present ?
		    " record present but it did not verify --" :
		    " no record (first boot of this chain) --");
	for (p = items; *p != '\0'; p += n) {
		while (*p == ' ')
			p++;
		if (*p == '\0')
			break;
		for (n = 0; p[n] != '\0' && p[n] != ' '; n++)
			;
		printf(first ? " " : ", ");
		first = false;
		if (display_item_is(p, n, "bootcount")) {
			if (rs->valid)
				printf("boot %llu",
				    (unsigned long long)rs->prev.counter + 1);
			else
				printf("boot ?");
		} else if (display_item_is(p, n, "lastboot")) {
			if (rs->valid) {
				s.epoch = rs->prev.boot_epoch;
				s.nsec = 0;
				s.tsc = 0;
				clock_calendar(&s, NULL, NULL, iso, sizeof(iso));
				printf("last %s", iso);
			} else
				printf("last ?");
		} else if (display_item_is(p, n, "cycles")) {
			if (nvme)
				printf("cycles %+lld", (long long)
				    (ns.power_cycles - rs->prev.nvme_cycles));
			else
				printf("cycles ?");
		} else if (display_item_is(p, n, "unclean")) {
			if (nvme)
				printf("unclean %+lld", (long long)
				    (ns.unsafe_shutdowns - rs->prev.nvme_unsafe));
			else
				printf("unclean ?");
		} else if (display_item_is(p, n, "gates")) {
			printf("gates %u ok %u failed",
			    e->ngates - e->failed_gates, e->failed_gates);
		} else if (display_item_is(p, n, "attempts")) {
			printf("attempts %u", e->attempts);
		} else
			printf("?%.*s", (int)n, p);
	}
	printf("\n");
}

static void
action_display(const struct appraisal *a)
{
	const char *items = kenv(a, "display");

	if (items == NULL || items[0] == '\0') {
		printf("%s: display: no items configured\n", a->gate->name);
		return;
	}
	display_line(a, items);
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

/*
 * The sentinel: an innocent question whose answer selects the reaction --
 * but the classification lives in earlboot, behind the encrypted root.
 * Here only the salted hash of the answer and of its first character are
 * published (loader.trust.<gate>.answer / .answer.first); no reaction, no
 * visible difference for any input, including none. The context line the
 * owner sees first is display_act's: loader.trust.<gate>.display names the
 * items, and the line stays on screen while the question waits.
 */
static void
action_sentinel(const struct appraisal *a)
{
	const char *q = kenv(a, "question"), *kv = kenv(a, "salt");
	const char *show = kenv(a, "display");
	char ans[128], buf[256], hash[2 * SHA256_DIGEST_LENGTH + 1];
	char salt[128];

	/* Own copy: a getenv() pointer is dead after the setenv() of publish. */
	strlcpy(salt, kv != NULL ? kv : "", sizeof(salt));

	if (q == NULL)
		return;
	if (show != NULL)
		display_line(a, show);
	printf("%s ", q);
	readsecret(ans, sizeof(ans));
	printf("\n");
	snprintf(buf, sizeof(buf), "%s%s", salt, ans);
	sha256_hex(buf, strlen(buf), hash);
	publish_always(a->gate, "answer", hash);
	snprintf(buf, sizeof(buf), "%s%c", salt, ans[0]);
	sha256_hex(buf, strlen(buf), hash);
	publish_always(a->gate, "answer.first", hash);
	explicit_bzero(ans, sizeof(ans));
	explicit_bzero(buf, sizeof(buf));
}

/*
 * Append the appraisal to the medium (/EFI/elvboot/record) and keep the
 * last one in NVRAM (ElvAppraisal): the forensic trace outlives a reboot
 * and a wiped root. Plain text, MAC-sealed by the next boot's chain link.
 */
static void
action_record(const struct appraisal *a)
{
	char failed[LISTLEN], passed[LISTLEN], line[512], iso[32];
	const struct record_state *rs = record_state();
	struct stamp now;

	list_by_verdict(a, VERDICT_FAIL, failed, sizeof(failed));
	list_by_verdict(a, VERDICT_PASS, passed, sizeof(passed));
	clock_now(&now);
	clock_calendar(&now, NULL, NULL, iso, sizeof(iso));
	snprintf(line, sizeof(line), "%s boot=%llu gate=%s verdict=%s "
	    "failed=[%s] passed=[%s]\n", iso,
	    (unsigned long long)(rs->valid ? rs->prev.counter + 1 : 0),
	    a->gate->name, a->verdict == VERDICT_PASS ? "pass" : "fail",
	    failed, passed);
	(void)record_medium_append("record", line, strlen(line));
	(void)record_var_set("ElvAppraisal", line, strlen(line));
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

/* Demand the secret if one is configured (kenv secret, optional duress). */
static void
action_lock(const struct appraisal *a)
{
	const char *want = kenv(a, "secret");	/* expected SHA256, hex */

	if (want == NULL)
		return;				/* no secret -> nothing to lock */
	if (!passphrase_dialogue(a, "secret", want, kenv(a, "duress"), true))
		halt_boot("locked");
}

/*
 * Compiled-in recovery lock. Unlike action_lock, the expected hashes come from
 * the gate itself (a->gate->secret / ->duress, baked into the signed loader)
 * -- not from kenv/loader.conf, which is exactly the object that may be
 * missing or tampered when this fires. Reports which claims failed, then, if
 * a secret is compiled in, demands the passphrase (3 tries) before letting
 * the boot proceed to the loader prompt; a wrong passphrase halts. With no
 * secret compiled in it reports and continues, so an unprovisioned build is
 * report-only and cannot brick.
 */
static void
action_unlock(const struct appraisal *a)
{
	char failed[LISTLEN], name[64];

	list_by_verdict(a, VERDICT_FAIL, failed, sizeof(failed));
	printf("\n*** %s: verification failed [%s] ***\n", a->gate->name, failed);
	if (a->gate->secret == NULL) {
		printf("no recovery secret compiled in -- continuing.\n");
		return;
	}
	if (passphrase_dialogue(a, "recovery passphrase", a->gate->secret,
	    a->gate->duress, true)) {
		/*
		 * Handshake: tell the Lua path this gate is already
		 * satisfied, so it does not ask for the same passphrase
		 * again (see password.lua trustGate).
		 */
		gate_var(a->gate, "unlocked", name, sizeof(name));
		setenv(name, "1", 1);
		return;			/* unlocked -> loader prompt */
	}
	halt_boot("locked");
}

/*
 * The console is a lock. console.c getchar() calls local_console_lock()
 * before it hands out a key, so EVERY interactive path of the loader --
 * the key that interrupts the autoboot, Lua's menu and its password
 * prompts, the OK prompt with or without Lua, the pager, the GELI
 * passphrase of a provider the loader opens -- costs the compiled-in
 * secret of the first LOADER-phase gate that carries one (loaderlock),
 * once per boot, always: a gate's own unlock earlier in this boot lets the
 * boot go on, it does not open the console (11.09.: a recovery unlock had
 * opened the prompt, and a recovery boot is exactly the boot that reaches
 * it). The gates' own dialogs are the trusted readers: local_run() marks
 * the phases trusted, their secrets are asked by the gates themselves.
 * Three wrong answers halt; a build without a compiled-in secret halts at
 * the first key as well -- the console never opens on its own. A boot
 * nobody touches never reads a key and never sees this.
 */
static int console_trusted;	/* > 0 while a trust gate reads */
static int console_unlocked;	/* the secret was typed this boot */

void
local_console_trusted(int on)
{
	console_trusted += on > 0 ? 1 : -1;
}

void
local_console_lock(void)
{
	const struct policy *p;
	struct appraisal a;
	char name[64];

	if (console_unlocked || console_trusted > 0)
		return;
	console_trusted++;		/* the dialog below reads for itself */
	for (p = phase_policies(PHASE_LOADER); p->gate != NULL; p++)
		if (p->gate->secret != NULL)
			break;
	if (p->gate == NULL)
		halt_boot("locked: no console secret compiled in");
	memset(&a, 0, sizeof(a));
	a.gate = p->gate;
	a.results = p->results;
	a.verdict = VERDICT_FAIL;
	printf("\n*** %s: the console ***\n", p->gate->name);
	if (!passphrase_dialogue(&a, "recovery passphrase", p->gate->secret,
	    p->gate->duress, false))
		halt_boot("locked");
	gate_var(p->gate, "console", name, sizeof(name));
	setenv(name, "1", 1);
	console_unlocked = 1;
	console_trusted--;
}

/* Sleep 2^attempts seconds (capped at 64) before whatever comes next. */
static void
action_tarpit(const struct appraisal *a __unused)
{
	unsigned int n = evidence()->attempts, s = 1;

	while (n-- > 0 && s < 64)
		s *= 2;
	delay((int)s * 1000000);
}

/* Halt once the attempts of this boot reach loader.trust.<gate>.attempts (3). */
static void
action_lockout(const struct appraisal *a)
{
	const char *lim = kenv(a, "attempts");
	unsigned int n = 3;

	if (lim != NULL)
		n = (unsigned int)strtoul(lim, NULL, 10);
	if (n > 0 && evidence()->attempts >= n)
		halt_boot("locked out");
}

/*
 * Four words the owner can recognise, derived from the record secret and
 * the ledger: an honest loader with the owner's secret shows the words on
 * the owner's card. Proves the binary, not the medium (see action.h).
 */
static const char *const reveal_words[] = {
	"acre","aged","ahoy","aims","airy","ajar","alps","amid","ants","apex",
	"arch","army","atom","aunt","auto","avid","axis","back","bake","balm",
	"band","bark","barn","bass","bath","bead","beam","bean","bear","beat",
	"bell","belt","bend","bike","bird","blue","boat","bold","bolt","bond",
	"bone","book","boot","born","bowl","brew","bulb","bulk","bump","bush",
	"cafe","cage","cake","calm","camp","cane","cape","card","cart","cash",
	"cast","cave","chef","chin","chip","city","clam","clay","clip","club",
	"coal","coat","code","coin","cold","colt","comb","cone","cook","cool",
	"cord","cork","corn","cost","crab","crew","crop","crow","cube","cure",
	"dart","dawn","deal","deck","deer","dent","desk","dial","dice","dime",
	"dine","dish","dock","dome","door","dose","dove","draw","drum","duck",
	"dune","dusk","dust","earl","east","echo","edge","envy","exam","face",
	"fact","fair","fall","fame","farm","fast","fawn","fern","film","fire",
	"fish","flag","flat","flax","fold","folk","font","food","fork","fort",
	"foxy","frog","fuel","fume","gain","game","gate","gear","germ","gift",
	"glow","glue","goat","gold","golf","gown","grid","grip","gulf","gust",
	"hail","hair","half","hall","hand","harp","hawk","heat","helm","herb",
	"hero","hill","hint","hive","hoof","hook","horn","hose","hour","hull",
	"idea","inch","iris","iron","isle","jade","jazz","jeep","jury","kelp",
	"kilt","kite","knob","lamb","lamp","lane","lark","lava","lawn","leaf",
	"lens","lily","lime","lion","loaf","lock","loft","luck","lung","mail",
	"malt","mane","maze","meal","mesa","milk","mint","mist","moat","mole",
	"moon","moss","moth","mule","nail","nest","newt","node","nose","note",
	"oats","opal","oven","palm","park","path","peak","pear","pier","pine",
	"pint","plum","pond","pump","quay","rain","ramp","reef","rice","ring",
	"road","robe","rock","root","rope","ruby","sail","salt","sand"
};

static void
action_reveal(const struct appraisal *a)
{
	uint8_t d[SHA256_DIGEST_LENGTH], w[SHA256_DIGEST_LENGTH];
	char hex[2 * SHA256_DIGEST_LENGTH + 1];
	unsigned int i;

	if (!word_secret_present()) {
		printf("%s: no word secret compiled in\n", a->gate->name);
		return;
	}
	evidence_digest(d);
	hex_of(d, sizeof(d), hex);
	word_hmac("reveal", hex, strlen(hex), w);
	printf("%s:", a->gate->name);
	for (i = 0; i < 4; i++)
		printf(" %s", reveal_words[w[i] %
		    (sizeof(reveal_words) / sizeof(reveal_words[0]))]);
	printf("\n");
}

static void
action_taint(const struct appraisal *a __unused)
{
	evidence_set_taint();
}

/* Halt when the RTC is past loader.trust.<gate>.deadline (epoch seconds). */
static void
action_expire(const struct appraisal *a)
{
	const char *dl = kenv(a, "deadline");
	struct stamp now;
	uint64_t deadline;

	if (dl == NULL)
		return;
	deadline = strtoull(dl, NULL, 10);
	clock_now(&now);
	if (now.epoch == 0 || deadline == 0)
		return;
	if (now.epoch > deadline)
		halt_boot("expired -- re-provision with elebake");
}

static void
action_single(const struct appraisal *a __unused)
{
	setenv("boot_single", "YES", 1);
}

/*
 * Boot the rescue root instead of the production one: vfs.root.mountfrom
 * from loader.trust.<gate>.rescue (e.g. zfs:zcard/ROOT/rescue). The kernel
 * and modules stay the verified ones already loaded from the boot medium;
 * the production root's GELI is never attached.
 */
static void
action_divert(const struct appraisal *a)
{
	const char *root = kenv(a, "rescue");
	char note[128];

	/* Own copy: a getenv() pointer is dead after setenv()/unsetenv(). */
	if (root != NULL)
		strlcpy(note, root, sizeof(note));
	else if (!record_nextboot_get(note, sizeof(note)))
		return;
	setenv("vfs.root.mountfrom", note, 1);
	unsetenv("vfs.root.mountfrom.options");
	record_nextboot_clear();
	printf("%s: diverting to %s\n", a->gate->name, note);
}

/* Leave the one-shot divert note for the NEXT boot, then reboot. */
static void
action_nextboot(const struct appraisal *a)
{
	const char *root = kenv(a, "rescue");

	if (root == NULL)
		return;
	record_nextboot_set(root);
	RS->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
	halt_boot("reboot failed");
}

/*
 * The handover word: HMAC(HMAC(word secret, "handover"),
 * "<ledger hex>|<counter>|<flags>"). earlboot recomputes it from the
 * same inputs it can see (the published ledger and counter) plus the flags
 * it CANNOT see -- so it learns the flags by trying all eight: bit 1
 * taint, bit 2 duress, bit 4 prompted. Nothing else is derivable from the word. The
 * message is ASCII so a shell reproduces it byte for byte with openssl.
 */
static void
action_handover(const struct appraisal *a)
{
	const struct evidence *e = evidence();
	const struct record_state *rs = record_state();
	uint8_t d[SHA256_DIGEST_LENGTH], w[SHA256_DIGEST_LENGTH];
	uint64_t counter = rs->valid ? rs->prev.counter + 1 : 1;
	unsigned int flags = 0;
	char hex[2 * SHA256_DIGEST_LENGTH + 1], msg[128];

	if (!word_secret_present())
		return;
	if (e->taint)
		flags |= RECORD_F_TAINT;
	if (e->duress)
		flags |= RECORD_F_DURESS;
	if (e->prompted > 0)
		flags |= RECORD_F_PROMPTED;
	evidence_digest(d);
	hex_of(d, sizeof(d), hex);
	snprintf(msg, sizeof(msg), "%s|%llu|%u", hex,
	    (unsigned long long)counter, flags);
	word_hmac("handover", msg, strlen(msg), w);
	publish_always(a->gate, "ledger", hex);
	hex_of(w, sizeof(w), hex);
	publish_always(a->gate, "word", hex);
	snprintf(hex, sizeof(hex), "%llu", (unsigned long long)counter);
	publish_always(a->gate, "counter", hex);
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

static void
action_poweroff(const struct appraisal *a __unused)
{
	RS->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
	halt_boot("poweroff failed");
}

ACTION_DEFINE(proceed,  action_proceed);
ACTION_DEFINE(publish,  action_publish);
ACTION_DEFINE(silence,  action_silence);
ACTION_DEFINE(report,   action_report);
ACTION_DEFINE(message,  action_message);
ACTION_DEFINE(display,  action_display);
ACTION_DEFINE(prompt,   action_prompt);
ACTION_DEFINE(sentinel, action_sentinel);
ACTION_DEFINE(record,   action_record);
ACTION_DEFINE(confirm,  action_confirm);
ACTION_DEFINE(lock,     action_lock);
ACTION_DEFINE(unlock,   action_unlock);
ACTION_DEFINE(tarpit,   action_tarpit);
ACTION_DEFINE(lockout,  action_lockout);
ACTION_DEFINE(reveal,   action_reveal);
ACTION_DEFINE(taint,    action_taint);
ACTION_DEFINE(expire,   action_expire);
ACTION_DEFINE(single,   action_single);
ACTION_DEFINE(divert,   action_divert);
ACTION_DEFINE(nextboot, action_nextboot);
ACTION_DEFINE(handover, action_handover);
ACTION_DEFINE(halt,     action_halt);
ACTION_DEFINE(panic,    action_panic);
ACTION_DEFINE(reboot,   action_reboot);
ACTION_DEFINE(poweroff, action_poweroff);
