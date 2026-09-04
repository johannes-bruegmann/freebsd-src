#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Johannes Brügmann
#
# elvbootd -- the runtime action catalog (contract: earlboot/policy.sh).
# The generated hooks carry earlboot's palette as well (log, console, spool,
# mark, freeze, persist, courier, beacon, attest, reauth, quarantine,
# shutdown, poweroff, lock, disarm, degrade); these are the runtime-only
# ones. Every action states what it assumes.

# heartbeat_act -- the watch ran: touch the heartbeat earlboot claims at the
# next boot, and remember the chain link the loader published this boot
heartbeat_act() {
	/bin/mkdir -p "$ELV_STATE"
	/usr/bin/touch "$ELV_STATE/heartbeat"
}

# verified_act <gate> -- the positive booking of a tested medium (JB 26.08.):
# replace the untested note of the medium with a verified file naming the
# exact stand (loader sha256 + manifest sha256). Assumes the ESP is mounted
# read-only for the read and the medium is THE anchor (a MEDIA claim passed).
verified_act() {
	local mnt l m
	[ -n "$ELV_ESP" ] && [ -c "/dev/$ELV_ESP" ] || return 0
	mnt=$(/usr/bin/mktemp -d) || return 0
	if /sbin/mount -t msdosfs -o ro "/dev/$ELV_ESP" "$mnt" 2>/dev/null; then
		l=$(/sbin/sha256 -q "$mnt/EFI/BOOT/BOOTX64.EFI" 2>/dev/null)
		/sbin/umount "$mnt" 2>/dev/null
	fi
	/bin/rmdir "$mnt" 2>/dev/null
	m=$(/sbin/sha256 -q /boot/manifest 2>/dev/null)
	/bin/mkdir -p "$ELV_STATE"
	printf 'loader=%s manifest=%s %s\n' "$l" "$m" "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ELV_STATE/verified"
	/bin/rm -f "$ELV_STATE/untested"
}

# compare_media_act <gate> -- log the loader on the medium against the
# digest elebake deployed ($ELV_LOADER_DIGEST); a mismatch is spooled
compare_media_act() {
	local have
	have=$(measure_esp_digest EFI/BOOT/BOOTX64.EFI)
	if [ -n "$have" ] && [ "$have" != "$ELV_LOADER_DIGEST" ]; then
		GATE_VERDICT=fail; FAILED="$FAILED media-loader"
		spool_act "$1"
	fi
}

# sentinel_act <gate> -- the runtime watchdog: no persisted appraisal of
# this boot means earlboot never ran (or was removed) -- itself a finding
sentinel_act() {
	[ -f "$ELV_STATE/appraisal-$ELV_GATE_LOADER" ] && return 0
	GATE_VERDICT=fail; FAILED="$FAILED earlboot-missing"
	spool_act "$1"
	mark_act "$1"
}

# fascist_log_act <gate> -- the forensic full record: kenv, dmesg, mounts,
# processes, sockets, signed, into $ELV_STATE/forensic. Off-host delivery
# by courier/attest. Assumes disk space and gpg.
fascist_log_act() {
	local d
	d="$ELV_STATE/forensic/$(/bin/date -u +%Y%m%dT%H%M%SZ)-$1"
	/bin/mkdir -p "$d"
	/bin/kenv > "$d/kenv" 2>/dev/null
	/sbin/dmesg > "$d/dmesg" 2>/dev/null
	/sbin/mount > "$d/mount" 2>/dev/null
	/bin/ps auxww > "$d/ps" 2>/dev/null
	/usr/bin/sockstat > "$d/sockstat" 2>/dev/null
	/sbin/gpart show > "$d/gpart" 2>/dev/null
	/usr/sbin/efivar -l > "$d/efivars" 2>/dev/null
	(cd "$d" && /usr/bin/find . -type f | LC_ALL=C /usr/bin/sort | /usr/bin/xargs /sbin/sha256 -r) > "$d.sha256" 2>/dev/null
	/usr/local/bin/gpg --batch --yes --clearsign "$d.sha256" > /dev/null 2>&1
	/bin/chflags -R sappnd "$d" 2>/dev/null
}

# reprovision_act <gate> -- after a deliberate change: leave the note that
# tells the owner (and elebake stage status) that the baselines are stale
reprovision_act() {
	/bin/mkdir -p "$ELV_STATE"
	elv_finding "$1" > "$ELV_STATE/reprovision"
}
