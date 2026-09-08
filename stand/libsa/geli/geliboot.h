/*-
 * Copyright (c) 2015 Allan Jude <allanjude@FreeBSD.org>
 * Copyright (c) 2005-2011 Pawel Jakub Dawidek <pawel@dawidek.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <crypto/intake.h>

#ifndef _GELIBOOT_H_
#define _GELIBOOT_H_

#include <geom/eli/g_eli.h>

#ifndef DEV_BSIZE
#define DEV_BSIZE 			512
#endif
#ifndef DEV_GELIBOOT_BSIZE
#define DEV_GELIBOOT_BSIZE		4096
#endif

#ifndef MIN
#define    MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

#define	GELI_MAX_KEYS			64
#define	GELI_PW_MAXLEN			256
#define	GELI_KEYBUF_SIZE		(sizeof(struct keybuf) + \
    (GELI_MAX_KEYS * sizeof(struct keybuf_ent)))

typedef enum geli_op {
	GELI_DECRYPT,
	GELI_ENCRYPT
} geli_op_t;

extern void pwgets(char *buf, int n, int hide);

typedef u_char geli_ukey[G_ELI_USERKEYLEN];

/*
 * An opaque struct used internally by geliboot functions. Returned by
 * geli_taste(), a pointer to one of these is essentially a device handle. There
 * is no need to release or free or "give back" the pointer.
 */
struct geli_dev;

/* Forward decls. */
struct open_file;
struct preloaded_file;

/*
 * Low-level interface, used by early-stage bootloaders...
 */

/* Read callback function type for geli_taste(). */
typedef int (*geli_readfunc)(void *vdev, void *readpriv, off_t offbytes,
    void *buf, size_t sizebytes);

struct geli_dev *geli_taste(geli_readfunc readfunc, void *readpriv,
    daddr_t lastsector, const char *namefmt, ...);
int geli_io(struct geli_dev *gdev, geli_op_t, off_t offset, u_char *buf,
    size_t bytes);
int geli_havekey(struct geli_dev *gdev);
int geli_passphrase(struct geli_dev *gdev, char *pw);

/*
 * Libsa device-and-file-level interface.
 */
void geli_probe_and_attach(struct open_file *f);

/*
 * Manage key data.
 */
void geli_add_key(geli_ukey key);
void geli_import_key_buffer(struct keybuf *keybuf);
void geli_export_key_buffer(struct keybuf *keybuf);
/*
 * SHA256 of the first user key geliboot derived this boot -- the PBKDF2
 * output over passphrase and keyfiles, i.e. key material that already
 * carries GELI's full per-guess cost. Available until bi_load() exports and
 * wipes the keys; 0 when no provider was unlocked. Used by the loader's
 * local layer as the input keying material of its record keys (record.c):
 * a record then costs an attacker exactly what GELI costs, never less.
 */
int geli_ikm_digest(u_char out[32]);
/*
 * Key files for geli_probe(): registered by the caller (the loader reads
 * them from the preloaded <prov>:geli_keyfile<n> files), fed into the user
 * key HMAC before the passphrase part -- the kernel's order. Cleared by the
 * caller once the key is found. Was a TODO in geli_probe().
 */
#define	GELI_KEYFILES_MAX	4
#define	GELI_KEYFILE_MAX	(64 * 1024)
void geli_keyfile_add(const void *data, size_t len);
void geli_keyfile_clear(void);
int geli_probe(struct geli_dev *gdev, const char *passphrase, u_char *mkeyp);
void geli_export_key_metadata(struct preloaded_file *kfp);

#endif /* _GELIBOOT_H_ */
