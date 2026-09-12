/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 *
 * The user key of the encrypted root, derived in the loader.
 *
 * A machine that boots from a removable medium never has the loader open
 * its encrypted root: libsa's geli tastes nothing, no user key exists, and
 * the record (record.c) has no keying material. Here the loader tastes the
 * GELI partitions of the disks it sees itself, with the passphrase the
 * configuration already asked for (kern.geom.eli.passphrase, set by the
 * Lua prompt of geom_eli_passphrase_prompt) and the key files loader.conf
 * preloaded (<prov>:geli_keyfile<n>) -- exactly the material the kernel
 * would use -- and stops at the first key. The taste is its own
 * (keys_taste): the providers the kernel attaches at boot, not only those
 * the loader may attach. So is the derivation (keys_derive): the kernel
 * feeds a provider its own key files, <prov>:geli_keyfile<n>, and nothing
 * else; the loader cannot tell disk0p1 from nda0p1, so it tries each
 * provider's set in turn, then the passphrase alone, with the PBKDF2 part
 * computed once. Feeding every preloaded key file to every partition, as
 * the first version did, is a wrong key (11.09.: "Bad GELI key" twice per
 * attempt, and the record called the taste on every claim -- now once per
 * boot). No prompt ever comes from here: without a cached passphrase
 * nothing is tasted and the record stays absent, reported. The derived key
 * travels to the kernel in the keybuf like any loader key, so the kernel
 * skips its own PBKDF2: the seconds spent here are not spent twice. Whole
 * disks are opened, never partitions, so devopen's own taste-and-prompt
 * path is not entered.
 */

#include <stand.h>
#include <sys/disk.h>
#include <sys/param.h>
#include <part.h>
#include <string.h>
#include <stdarg.h>
#include <bootstrap.h>

#include <geom/eli/pkcs5v2.h>

#include "geliboot.h"
#include "record.h"

#define	KEYS_DISKS	8		/* disk0 .. disk7 */

struct taste_ctx {
	int		 fd;
	u_int		 secsz;
	uint64_t	 base;		/* partition start, bytes */
	const char	*passphrase;
	int		 unit;
	bool		 found;
	bool		 tasted;	/* a GELI partition was seen */
	bool		 badkey;	/* ... and did not open */
	unsigned int	 parts;		/* partitions seen on this disk */
	unsigned int	 gelis;		/* ... with GELI metadata */
};

/* Why the last geli_keys_prepare() ended as it did (diagnose_record):
 * the verdict, then what was seen -- disk by disk, partitions and GELI
 * partitions among them -- so a silent miss can be read after the boot. */
static char keys_reason[288] = "not tried";
static char keys_seen[200];

const char *
geli_keys_reason(void)
{
	return (keys_reason);
}

static void
keys_note(const char *fmt, ...)
{
	va_list ap;
	size_t n = strlen(keys_seen);

	if (n >= sizeof(keys_seen) - 1)
		return;
	va_start(ap, fmt);
	vsnprintf(keys_seen + n, sizeof(keys_seen) - n, fmt, ap);
	va_end(ap);
}

/* diskread_t for ptable: blocks of secsz from the whole disk */
static int
keys_diskread(void *arg, void *buf, size_t blocks, uint64_t blk)
{
	struct taste_ctx *c = arg;
	size_t bytes = blocks * c->secsz;

	if (lseek(c->fd, blk * c->secsz, SEEK_SET) < 0)
		return (EIO);
	return (read(c->fd, buf, bytes) == (ssize_t)bytes ? 0 : EIO);
}

/* geli_readfunc: bytes relative to the partition start */
static int
keys_partread(void *vdev __unused, void *priv, off_t off, void *buf,
    size_t bytes)
{
	struct taste_ctx *c = priv;

	if (lseek(c->fd, c->base + off, SEEK_SET) < 0)
		return (EIO);
	return (read(c->fd, buf, bytes) == (ssize_t)bytes ? 0 : EIO);
}

/*
 * The partition's GELI metadata, decoded from its last sector, iff it is a
 * provider whose key is worth deriving. libsa's geli_taste() keeps only the
 * providers the loader itself may attach (geli init -g, GELIBOOT): the root
 * the kernel attaches at boot (geli init -b, BOOT) with key files and the
 * passphrase -- on illyria with AUTH, which the loader cannot read -- fell
 * through it and the record stayed absent (11.09.). Nothing is attached or
 * read here. Swap (ONETIME) has no user key and is skipped.
 */
static bool
keys_taste(struct taste_ctx *c, daddr_t lastsector, struct g_eli_metadata *md)
{
	u_char *buf;
	off_t at;
	int error;

	if ((buf = malloc(DEV_GELIBOOT_BSIZE)) == NULL)
		return (false);
	at = rounddown2(lastsector * DEV_BSIZE, DEV_GELIBOOT_BSIZE);
	if (at + DEV_GELIBOOT_BSIZE > (lastsector + 1) * DEV_BSIZE)
		at = (lastsector + 1) * DEV_BSIZE - DEV_GELIBOOT_BSIZE;
	error = keys_partread(NULL, c, at, buf, DEV_GELIBOOT_BSIZE);
	if (error == 0) {
		error = eli_metadata_decode(buf, md);
		if (error != 0)
			error = eli_metadata_decode(buf +
			    (DEV_GELIBOOT_BSIZE - DEV_BSIZE), md);
	}
	explicit_bzero(buf, DEV_GELIBOOT_BSIZE);
	free(buf);
	if (error != 0)
		return (false);
	if ((md->md_flags & G_ELI_FLAG_ONETIME) != 0 ||
	    (md->md_flags & (G_ELI_FLAG_BOOT | G_ELI_FLAG_GELIBOOT)) == 0) {
		explicit_bzero(md, sizeof(*md));
		return (false);
	}
	return (true);
}

/* The providers loader.conf preloaded key files for: the <prov> of <prov>:geli_keyfile<n>. */
#define	KEYS_PROVIDERS	8
#define	KEYS_PROVLEN	32

static unsigned int
keys_providers(char provs[KEYS_PROVIDERS][KEYS_PROVLEN])
{
	struct preloaded_file *fp;
	const char *colon;
	size_t n;
	unsigned int k = 0, i;

	for (fp = preloaded_files; fp != NULL; fp = fp->f_next) {
		if (fp->f_type == NULL ||
		    (colon = strstr(fp->f_type, ":geli_keyfile")) == NULL)
			continue;
		n = colon - fp->f_type;
		if (n == 0 || n >= KEYS_PROVLEN)
			continue;
		for (i = 0; i < k; i++)
			if (strncmp(provs[i], fp->f_type, n) == 0 &&
			    provs[i][n] == '\0')
				break;
		if (i < k)
			continue;
		if (k == KEYS_PROVIDERS)
			break;
		memcpy(provs[k], fp->f_type, n);
		provs[k][n] = '\0';
		k++;
	}
	return (k);
}

/* One provider's key files into the HMAC, in the kernel's order and naming
 * (<prov>:geli_keyfile<i>, a lone file also <prov>:geli_keyfile); their count. */
static int
keys_hmac_keyfiles(struct hmac_ctx *ctx, const char *prov)
{
	struct preloaded_file *fp;
	char type[KEYS_PROVLEN + 24];
	void *buf;
	unsigned int i;

	for (i = 0; ; i++) {
		snprintf(type, sizeof(type), "%s:geli_keyfile%u", prov, i);
		fp = file_findfile(NULL, type);
		if (fp == NULL && i == 0) {
			snprintf(type, sizeof(type), "%s:geli_keyfile", prov);
			fp = file_findfile(NULL, type);
		}
		if (fp == NULL)
			return (i);
		if (fp->f_size == 0 || (buf = malloc(fp->f_size)) == NULL)
			return (-1);
		archsw.arch_copyout(fp->f_addr, buf, fp->f_size);
		g_eli_crypto_hmac_update(ctx, buf, fp->f_size);
		explicit_bzero(buf, fp->f_size);
		free(buf);
	}
}

/*
 * The user key of one provider, the kernel's way (g_eli_taste): HMAC over
 * that provider's key files, then the passphrase part -- PBKDF2 with the
 * metadata's iterations, computed once here and reused for every key file
 * set tried -- and the master key must decrypt with it. The sets are tried
 * in turn, the passphrase alone last. true iff the key is in the keychain.
 */
static bool
keys_derive(const struct g_eli_metadata *md, const char *passphrase,
    const char *name, daddr_t lastsector)
{
	char provs[KEYS_PROVIDERS][KEYS_PROVLEN];
	u_char dkey[G_ELI_USERKEYLEN], key[G_ELI_USERKEYLEN];
	u_char mkey[G_ELI_DATAIVKEYLEN];
	struct hmac_ctx ctx;
	u_int keynum;
	unsigned int np, g;
	int nfiles[KEYS_PROVIDERS];
	bool ok = false;

	np = keys_providers(provs);
	for (g = 0; g < np; g++)
		nfiles[g] = 0;
	if (md->md_iterations > 0) {
		printf("platform trust: deriving the key of %s (%d iterations)...\n",
		    name, md->md_iterations);
		pkcs5v2_genkey(dkey, sizeof(dkey), md->md_salt,
		    sizeof(md->md_salt), passphrase, md->md_iterations);
	}
	for (g = 0; g <= np && !ok; g++) {
		g_eli_crypto_hmac_init(&ctx, NULL, 0);
		if (g < np) {
			nfiles[g] = keys_hmac_keyfiles(&ctx, provs[g]);
			if (nfiles[g] <= 0)
				continue;
		} else if (md->md_iterations < 0)
			break;		/* key files only, and no set fit */
		if (md->md_iterations == 0) {
			g_eli_crypto_hmac_update(&ctx, md->md_salt,
			    sizeof(md->md_salt));
			g_eli_crypto_hmac_update(&ctx,
			    (const uint8_t *)passphrase, strlen(passphrase));
		} else if (md->md_iterations > 0)
			g_eli_crypto_hmac_update(&ctx, dkey, sizeof(dkey));
		g_eli_crypto_hmac_final(&ctx, key, 0);
		if (g_eli_mkey_decrypt_any(md, key, mkey, &keynum) == 0) {
			geli_add_key(key);
			ok = true;
		}
	}
	explicit_bzero(dkey, sizeof(dkey));
	explicit_bzero(key, sizeof(key));
	explicit_bzero(mkey, sizeof(mkey));
	explicit_bzero(&ctx, sizeof(ctx));
	/* What was tried, for diagnose_record: <name>(it=N,v=V,prov=ok|SIZE,sets=P:files..) */
	keys_note("%s%s(it=%d,v=%u,prov=%s,sets=%u", keys_seen[0] ? ";" : "",
	    name, md->md_iterations,
	    md->md_version,
	    md->md_provsize == (uint64_t)(lastsector + 1) * DEV_BSIZE ? "ok" :
	    "off", np);
	for (g = 0; g < np; g++)
		keys_note("%c%s:%d", g ? ',' : ':', provs[g], nfiles[g]);
	keys_note(",%s)", ok ? "key" : "nokey");
	return (ok);
}

static int
keys_partition(void *arg, const char *partname __unused,
    const struct ptable_entry *part)
{
	struct taste_ctx *c = arg, pc;
	struct g_eli_metadata md;
	daddr_t lastsector;
	char name[16];

	if (c->found)
		return (1);
	c->parts++;
	pc = *c;
	pc.base = part->start * c->secsz;
	lastsector = ((part->end - part->start + 1) * c->secsz) / DEV_BSIZE - 1;
	if (!keys_taste(&pc, lastsector, &md))
		return (0);
	c->tasted = true;
	c->gelis++;
	snprintf(name, sizeof(name), "disk%dp%d", c->unit, part->index);
	if (keys_derive(&md, c->passphrase, name, lastsector))
		c->found = true;
	else
		c->badkey = true;
	explicit_bzero(&md, sizeof(md));
	return (c->found ? 1 : 0);
}

/*
 * Derive and save the user key of the first GELI partition the cached
 * passphrase and the preloaded key files open. 1 iff a key is saved now.
 * One attempt per boot once a passphrase is there: every record claim
 * asks, the disks and the PBKDF2 cost are paid once (11.09.).
 */
int
geli_keys_prepare(void)
{
	static bool tried;
	struct taste_ctx c;
	struct ptable *table;
	uint64_t mediasz;
	char devname[16];
	int unit;

	if (tried)
		return (0);
	memset(&c, 0, sizeof(c));
	keys_seen[0] = '\0';
	c.passphrase = getenv("kern.geom.eli.passphrase");
	if (c.passphrase == NULL) {
		snprintf(keys_reason, sizeof(keys_reason),
		    "no cached GELI passphrase (kern.geom.eli.passphrase)");
		return (0);
	}
	tried = true;
	for (unit = 0; unit < KEYS_DISKS && !c.found; unit++) {
		snprintf(devname, sizeof(devname), "disk%d:", unit);
		c.fd = open(devname, O_RDONLY);
		if (c.fd < 0)
			continue;
		c.unit = unit;
		c.parts = c.gelis = 0;
		if (ioctl(c.fd, DIOCGSECTORSIZE, &c.secsz) == 0 &&
		    ioctl(c.fd, DIOCGMEDIASIZE, &mediasz) == 0 &&
		    c.secsz > 0) {
			table = ptable_open(&c, mediasz / c.secsz, c.secsz,
			    keys_diskread);
			if (table != NULL) {
				ptable_iterate(table, &c, keys_partition);
				ptable_close(table);
				keys_note("%sdisk%d:%u/%u", keys_seen[0] ? ";" : "",
				    unit, c.gelis, c.parts);
			} else
				keys_note("%sdisk%d:notable",
				    keys_seen[0] ? ";" : "", unit);
		} else
			keys_note("%sdisk%d:noioctl", keys_seen[0] ? ";" : "",
			    unit);
		close(c.fd);
	}
	snprintf(keys_reason, sizeof(keys_reason), "%s [%s]",
	    c.found ? "GELI user key derived" :
	    c.badkey ? "GELI partition seen, passphrase and key files did not open it" :
	    c.tasted ? "GELI partition seen, no key" :
	    "no GELI partition seen",
	    keys_seen[0] != '\0' ? keys_seen : "no disk opened");
	return (c.found ? 1 : 0);
}
