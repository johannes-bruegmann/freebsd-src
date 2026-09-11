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
 * would use -- and stops at the first key. No prompt ever comes from here:
 * without a cached passphrase nothing is tasted and the record stays
 * absent, reported. The derived key travels to the kernel in the keybuf
 * like any loader key, so the kernel skips its own PBKDF2: the seconds
 * spent here are not spent twice. Whole disks are opened, never
 * partitions, so devopen's own taste-and-prompt path is not entered.
 */

#include <stand.h>
#include <sys/disk.h>
#include <sys/param.h>
#include <part.h>
#include <string.h>
#include <stdarg.h>
#include <bootstrap.h>

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
static char keys_reason[160] = "not tried";
static char keys_seen[96];

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

static int
keys_partition(void *arg, const char *partname __unused,
    const struct ptable_entry *part)
{
	struct taste_ctx *c = arg, pc;
	struct geli_dev *gdev;
	daddr_t lastsector;

	if (c->found)
		return (1);
	c->parts++;
	pc = *c;
	pc.base = part->start * c->secsz;
	lastsector = ((part->end - part->start + 1) * c->secsz) / DEV_BSIZE - 1;
	gdev = geli_taste(keys_partread, &pc, lastsector, "disk%dp%d",
	    c->unit, part->index);
	if (gdev == NULL)
		return (0);
	c->tasted = true;
	c->gelis++;
	if (geli_probe(gdev, c->passphrase, NULL) == 0) {
		c->found = true;
		return (1);
	}
	c->badkey = true;
	return (0);
}

/* The preloaded key files, <prov>:geli_keyfile<n>, into libsa's registry. */
static void
keys_register_keyfiles(void)
{
	struct preloaded_file *fp;
	void *buf;

	for (fp = preloaded_files; fp != NULL; fp = fp->f_next) {
		if (fp->f_type == NULL ||
		    strstr(fp->f_type, ":geli_keyfile") == NULL)
			continue;
		if (fp->f_size == 0 || fp->f_size > GELI_KEYFILE_MAX)
			continue;
		if ((buf = malloc(fp->f_size)) == NULL)
			continue;
		archsw.arch_copyout(fp->f_addr, buf, fp->f_size);
		geli_keyfile_add(buf, fp->f_size);
		explicit_bzero(buf, fp->f_size);
		free(buf);
	}
}

/*
 * Derive and save the user key of the first GELI partition the cached
 * passphrase and the preloaded key files open. 1 iff a key is saved now.
 */
int
geli_keys_prepare(void)
{
	struct taste_ctx c;
	struct ptable *table;
	uint64_t mediasz;
	char devname[16];
	int unit;

	memset(&c, 0, sizeof(c));
	keys_seen[0] = '\0';
	c.passphrase = getenv("kern.geom.eli.passphrase");
	if (c.passphrase == NULL) {
		snprintf(keys_reason, sizeof(keys_reason),
		    "no cached GELI passphrase (kern.geom.eli.passphrase)");
		return (0);
	}
	keys_register_keyfiles();
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
				keys_note("%sdisk%d:%u/%u", unit ? "," : "",
				    unit, c.gelis, c.parts);
			} else
				keys_note("%sdisk%d:notable", unit ? "," : "",
				    unit);
		} else
			keys_note("%sdisk%d:noioctl", unit ? "," : "", unit);
		close(c.fd);
	}
	geli_keyfile_clear();
	snprintf(keys_reason, sizeof(keys_reason), "%s [%s]",
	    c.found ? "GELI user key derived" :
	    c.badkey ? "GELI partition seen, passphrase and key files did not open it" :
	    c.tasted ? "GELI partition seen, no key" :
	    "no GELI partition seen",
	    keys_seen[0] != '\0' ? keys_seen : "no disk opened");
	return (c.found ? 1 : 0);
}
