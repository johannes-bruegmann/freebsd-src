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
	$MKDIR -p "$ELV_STATE"
	$TOUCH "$ELV_STATE/heartbeat"
}

# verified_act <gate> -- the positive booking of a tested medium (JB 26.08.):
# replace the untested note of the medium with a verified file naming the
# exact stand (loader sha256 + manifest sha256). Assumes the ESP is mounted
# read-only for the read and the medium is THE anchor (a MEDIA claim passed).
verified_act() {
	local mnt l m
	[ -n "$ELV_ESP" ] && [ -c "/dev/$ELV_ESP" ] || return 0
	mnt=$($MKTEMP -d) || return 0
	if $MOUNT -t msdosfs -o ro "/dev/$ELV_ESP" "$mnt" 2>/dev/null; then
		l=$($SHA256 -q "$mnt/EFI/BOOT/BOOTX64.EFI" 2>/dev/null)
		$UMOUNT "$mnt" 2>/dev/null
	fi
	$RMDIR "$mnt" 2>/dev/null
	m=$($SHA256 -q /boot/manifest 2>/dev/null)
	$MKDIR -p "$ELV_STATE"
	printf 'loader=%s manifest=%s %s\n' "$l" "$m" "$($DATE -u +%Y-%m-%dT%H:%M:%SZ)" > "$ELV_STATE/verified"
	$RM -f "$ELV_STATE/untested"
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
	d="$ELV_STATE/forensic/$($DATE -u +%Y%m%dT%H%M%SZ)-$1"
	$MKDIR -p "$d"
	$KENV > "$d/kenv" 2>/dev/null
	$DMESG > "$d/dmesg" 2>/dev/null
	$MOUNT > "$d/mount" 2>/dev/null
	$PS auxww > "$d/ps" 2>/dev/null
	$SOCKSTAT > "$d/sockstat" 2>/dev/null
	$GPART show > "$d/gpart" 2>/dev/null
	$EFIVAR -l > "$d/efivars" 2>/dev/null
	(cd "$d" && $FIND . -type f | LC_ALL=C $SORT | $XARGS $SHA256 -r) > "$d.sha256" 2>/dev/null
	$GPG --batch --yes --clearsign "$d.sha256" > /dev/null 2>&1
	$CHFLAGS -R sappnd "$d" 2>/dev/null
}

# marker_heal_act <gate> -- put the boot marker back into the load option
# before the next boot: the value from $ELV_MARKER_FILE (0400 root, placed
# by elebake stage marker install; never inside a hook), the same byte
# surgery as elebake stage marker write (header, description and device
# path kept, "RC <token>" NUL appended), the finding spooled. Bound in
# SHUTDOWN behind a failed marker claim: the firmware shortens the entry
# after a boot from another medium, the loader's BootMarker claim would
# fall at the next boot -- the heal keeps the boot silent and the finding
# visible; a tamper is still measured at boot, before any heal (JB 10.09.).
# Assumes efivar(8) can write the variable (root, /dev/efi).
marker_heal_act() {
	local g v m t new size fplen desclen off
	[ -n "$ELV_MARKER_VAR" ] && [ -r "$ELV_MARKER_FILE" ] || return 0
	g=8be4df61-93ca-11d2-aa0d-00e098032b8c; v=$ELV_MARKER_VAR
	m=$($HEAD -n1 "$ELV_MARKER_FILE")
	[ -n "$m" ] || return 0
	t=$($MKTEMP) || return 0
	if ! $EFIVAR --no-name --name "$g-$v" --binary > "$t" 2>/dev/null; then
		$RM -f "$t"; return 0
	fi
	size=$($WC -c < "$t" | $TR -d ' ')
	fplen=$($OD -An -tu1 -j4 -N2 "$t" | $AWK '{print $1 + $2*256}')
	desclen=$($OD -An -tu1 -j6 "$t" | $AWK '{for (i = 1; i <= NF; i++) v[n++] = $i} END {for (k = 0; k + 1 < n; k += 2) if (v[k] == 0 && v[k+1] == 0) {print k + 2; exit}}')
	off=$((6 + ${desclen:-0} + ${fplen:-0}))
	if [ -z "$fplen" ] || [ -z "$desclen" ] || [ "$off" -le 6 ] || [ "$off" -gt "$size" ]; then
		$RM -f "$t"; return 0
	fi
	new=$($MKTEMP) || { $RM -f "$t"; return 0; }
	$DD if="$t" of="$new" bs=1 count="$off" 2>/dev/null
	printf 'RC %s' "$m" >> "$new"
	$DD if=/dev/zero bs=1 count=1 2>/dev/null >> "$new"
	if $EFIVAR --write --name "$g-$v" < "$new" 2>/dev/null; then
		FAILED="$FAILED marker-healed"
	else
		FAILED="$FAILED marker-heal-failed"
	fi
	$RM -f "$t" "$new"
	spool_act "$1"
}

# reprovision_act <gate> -- after a deliberate change: leave the note that
# tells the owner (and elebake stage status) that the baselines are stale
reprovision_act() {
	$MKDIR -p "$ELV_STATE"
	elv_finding "$1" > "$ELV_STATE/reprovision"
}
