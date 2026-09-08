#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Johannes Brügmann
#
# elvbootd -- the runtime measurement catalog (contract: earlboot/policy.sh).
# The generated hooks also carry earlboot's providers (measure_efivar,
# measure_file_sha256, measure_manifest, measure_esp_digest, measure_smart,
# measure_smart_step, measure_heartbeat); these are the runtime-only ones.
# Every provider states what it assumes.

# measure_geom <disk> -- sha256 of the disk's partition table as gpart
# reports it (gpart backup), the runtime twin of the loader's GPT digest.
# Assumes gpart(8) can read the disk.
measure_geom() {
	$GPART backup "$1" 2>/dev/null | $SHA256 -q 2>/dev/null
}

# measure_rtc_gap <max-seconds> -- 1 iff the wall clock moved at most
# <max-seconds> since the last heartbeat (RESUME: an implausible sleep
# window, or a clock set back below the heartbeat, fails); absent when
# no heartbeat exists yet
measure_rtc_gap() {
	local now stamp gap
	[ -f "$ELV_STATE/heartbeat" ] || return 0
	now=$($DATE +%s)
	stamp=$($STAT -f %m "$ELV_STATE/heartbeat" 2>/dev/null) || return 0
	gap=$((now - stamp))
	if [ "$gap" -ge 0 ] && [ "$gap" -le "$1" ]; then printf '1\n'; else printf '0\n'; fi
}

# measure_media_serial <daN> -- the medium's serial as camcontrol reports it
# (MEDIA phase: $1 is the cdev devd announced; a claim expects THE anchor).
# Assumes a USB/SD reader visible to CAM.
measure_media_serial() {
	$CAMCONTROL inquiry "$1" -S 2>/dev/null | $TR -d ' \n'
}

# measure_media_partitions <daN> -- sha256 of the medium's partition table
measure_media_partitions() {
	$GPART backup "$1" 2>/dev/null | $SHA256 -q 2>/dev/null
}

# measure_media_bootcode <daN> -- sha256 of EFI/BOOT/BOOTX64.EFI on the
# medium's first partition (the ESP), mounted read-only for the read
measure_media_bootcode() {
	local mnt out
	[ -c "/dev/$1p1" ] || return 0
	mnt=$($MKTEMP -d) || return 0
	if $MOUNT -t msdosfs -o ro "/dev/$1p1" "$mnt" 2>/dev/null; then
		out=$($SHA256 -q "$mnt/EFI/BOOT/BOOTX64.EFI" 2>/dev/null)
		$UMOUNT "$mnt" 2>/dev/null
	fi
	$RMDIR "$mnt" 2>/dev/null
	[ -n "$out" ] && printf '%s\n' "$out"
}

# measure_media_chain <daN> -- 1 iff the last chain link on the medium
# (EFI/elvboot/chain, written by the loader at every boot) equals the
# link earlboot persisted for this boot; the runtime twin of the loader's
# ChainOnMedium claim. Absent without a persisted link.
measure_media_chain() {
	local mnt have want
	[ -f "$ELV_STATE/chain" ] || return 0
	want=$($CAT "$ELV_STATE/chain")
	[ -c "/dev/$1p1" ] || return 0
	mnt=$($MKTEMP -d) || return 0
	if $MOUNT -t msdosfs -o ro "/dev/$1p1" "$mnt" 2>/dev/null; then
		have=$($TAIL -c 32 "$mnt/EFI/elvboot/chain" 2>/dev/null | $OD -An -tx1 | $TR -d ' \n')
		$UMOUNT "$mnt" 2>/dev/null
	fi
	$RMDIR "$mnt" 2>/dev/null
	[ -n "$have" ] || return 0
	if [ "$have" = "$want" ]; then printf '1\n'; else printf '0\n'; fi
}

# measure_degraded -- 1 iff this boot runs in quarantine (disarm/degrade)
measure_degraded() {
	if [ -f "$ELV_STATE/degraded" ]; then printf '1\n'; else printf '0\n'; fi
}

# measure_freeze -- 1 iff an unacknowledged finding freezes trust operations
measure_freeze() {
	if [ -s "$ELV_STATE/freeze" ]; then printf '1\n'; else printf '0\n'; fi
}

# diagnose_media_serial <daN> -- the medium's full inquiry line (vendor,
# product, revision)
diagnose_media_serial() { $CAMCONTROL inquiry "$1" 2>/dev/null | $HEAD -1; }
# diagnose_rtc_gap -- heartbeat and now as epochs
diagnose_rtc_gap() { [ -f "$ELV_STATE/heartbeat" ] && printf 'heartbeat=%s now=%s\n' "$($STAT -f %m "$ELV_STATE/heartbeat")" "$($DATE +%s)"; }
