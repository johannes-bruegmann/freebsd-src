/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Johannes Brügmann
 */

/*
 * mac_bootlock -- the loader's evidence is immutable in the kernel.
 *
 * The EFI loader's platform-trust gates publish what they measured to kenv
 * under loader.trust.<gate>.<leaf> (and the handover word for earlboot).
 * KENV_SET/KENV_UNSET need PRIV_KENV_SET/UNSET, i.e. root -- so root could
 * scrub the evidence before earlboot reads it. This policy refuses every
 * set and unset of a name under the protected prefixes for every
 * credential, root included, and counts the attempts (a refused scrub is
 * itself a finding: security.mac.bootlock.denied).
 *
 * Reading stays free: the evidence is meant to be read.
 *
 * Assumes: the module is loaded by the LOADER (loader.conf
 * mac_bootlock_load="YES", covered by the veriexec manifest) so it is in
 * place before init runs, and mac_veriexec/securelevel keep root from
 * unloading modules later. It is not unloadable by design
 * (no MPC_LOADTIME_FLAG_UNLOADOK). What it does not do: it protects the
 * NAMES, not the truth -- a loader that never ran leaves nothing to
 * protect, which earlboot detects as the empty namespace.
 *
 * Precedent: mac_veriexec, mac_ntpd (the small policies).
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

SYSCTL_DECL(_security_mac);

static SYSCTL_NODE(_security_mac, OID_AUTO, bootlock,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "elvboot: loader evidence immutability");

static int bootlock_enabled = 1;
SYSCTL_INT(_security_mac_bootlock, OID_AUTO, enabled, CTLFLAG_RD,
    &bootlock_enabled, 0, "protection of loader.trust.* and elvboot.* is on");

static unsigned long bootlock_denied = 0;
SYSCTL_ULONG(_security_mac_bootlock, OID_AUTO, denied, CTLFLAG_RD,
    &bootlock_denied, 0, "refused kenv set/unset attempts under the prefixes");

/* The protected prefixes: the loader's publications and elvboot's own. */
static const char *const bootlock_prefixes[] = {
	"loader.trust.",
	"elvboot.",
	NULL
};

static int
bootlock_protected(const char *name)
{
	const char *const *p;

	if (name == NULL)
		return (0);
	for (p = bootlock_prefixes; *p != NULL; p++)
		if (strncmp(name, *p, strlen(*p)) == 0)
			return (1);
	return (0);
}

static int
bootlock_kenv_check_set(struct ucred *cred __unused, char *name,
    char *value __unused)
{
	if (!bootlock_protected(name))
		return (0);
	atomic_add_long(&bootlock_denied, 1);
	return (EPERM);
}

static int
bootlock_kenv_check_unset(struct ucred *cred __unused, char *name)
{
	if (!bootlock_protected(name))
		return (0);
	atomic_add_long(&bootlock_denied, 1);
	return (EPERM);
}

static struct mac_policy_ops bootlock_ops = {
	.mpo_kenv_check_set = bootlock_kenv_check_set,
	.mpo_kenv_check_unset = bootlock_kenv_check_unset,
};

MAC_POLICY_SET(&bootlock_ops, mac_bootlock, "elvboot/bootlock", 0, NULL);
