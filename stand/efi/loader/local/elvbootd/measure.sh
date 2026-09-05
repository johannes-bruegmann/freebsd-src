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
	/sbin/gpart backup "$1" 2>/dev/null | /sbin/sha256 -q 2>/dev/null
}

# measure_rtc_gap <max-seconds> -- 1 iff the wall clock moved at most
# <max-seconds> since the last heartbeat (RESUME: an implausible sleep
# window, or a clock set back below the heartbeat, fails); absent when
# no heartbeat exists yet
measure_rtc_gap() {
	local now stamp gap
	[ -f "$ELV_STATE/heartbeat" ] || return 0
	now=$(/bin/date +%s)
	stamp=$(/usr/bin/stat -f %m "$ELV_STATE/heartbeat" 2>/dev/null) || return 0
	gap=$((now - stamp))
	if [ "$gap" -ge 0 ] && [ "$gap" -le "$1" ]; then printf '1\n'; else printf '0\n'; fi
}

# measure_media_serial <daN> -- the medium's serial as camcontrol reports it
# (MEDIA phase: $1 is the cdev devd announced; a claim expects THE anchor).
# Assumes a USB/SD reader visible to CAM.
measure_media_serial() {
	/sbin/camcontrol inquiry "$1" -S 2>/dev/null | /usr/bin/tr -d ' \n'
}

# measure_media_partitions <daN> -- sha256 of the medium's partition table
measure_media_partitions() {
	/sbin/gpart backup "$1" 2>/dev/null | /sbin/sha256 -q 2>/dev/null
}

# measure_media_bootcode <daN> -- sha256 of EFI/BOOT/BOOTX64.EFI on the
# medium's first partition (the ESP), mounted read-only for the read
measure_media_bootcode() {
	local mnt out
	[ -c "/dev/$1p1" ] || return 0
	mnt=$(/usr/bin/mktemp -d) || return 0
	if /sbin/mount -t msdosfs -o ro "/dev/$1p1" "$mnt" 2>/dev/null; then
		out=$(/sbin/sha256 -q "$mnt/EFI/BOOT/BOOTX64.EFI" 2>/dev/null)
		/sbin/umount "$mnt" 2>/dev/null
	fi
	/bin/rmdir "$mnt" 2>/dev/null
	[ -n "$out" ] && printf '%s\n' "$out"
}

# measure_media_chain <daN> -- 1 iff the last chain link on the medium
# (EFI/elvboot/chain, written by the loader at every boot) equals the
# link earlboot persisted for this boot; the runtime twin of the loader's
# ChainOnMedium claim. Absent without a persisted link.
measure_media_chain() {
	local mnt have want
	[ -f "$ELV_STATE/chain" ] || return 0
	want=$(/bin/cat "$ELV_STATE/chain")
	[ -c "/dev/$1p1" ] || return 0
	mnt=$(/usr/bin/mktemp -d) || return 0
	if /sbin/mount -t msdosfs -o ro "/dev/$1p1" "$mnt" 2>/dev/null; then
		have=$(/usr/bin/tail -c 32 "$mnt/EFI/elvboot/chain" 2>/dev/null | /usr/bin/od -An -tx1 | /usr/bin/tr -d ' \n')
		/sbin/umount "$mnt" 2>/dev/null
	fi
	/bin/rmdir "$mnt" 2>/dev/null
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
diagnose_media_serial() { /sbin/camcontrol inquiry "$1" 2>/dev/null | /usr/bin/head -1; }
# diagnose_rtc_gap -- heartbeat and now as epochs
diagnose_rtc_gap() { [ -f "$ELV_STATE/heartbeat" ] && printf 'heartbeat=%s now=%s\n' "$(/usr/bin/stat -f %m "$ELV_STATE/heartbeat")" "$(/bin/date +%s)"; }
