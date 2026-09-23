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

# measure_marker_digest <BootXXXX> -- sha256 of the marker token in the
# load option's optional data ("RC <token>": what elebake stage marker
# write put there and the loader's BootMarker claim recognises by the same
# digest); absent when the entry carries no token -- the firmware shortens
# the entry after a boot from another medium. Assumes efivar(8) can read
# the variable (root).
measure_marker_digest() {
	local t
	t=$($EFIVAR --no-name --name "8be4df61-93ca-11d2-aa0d-00e098032b8c-$1" --binary 2>/dev/null | LC_ALL=C $TR -d '\000' | LC_ALL=C $GREP -o 'RC [0-9a-f]\{32\}' | $HEAD -n1 | $CUT -c4-)
	[ -n "$t" ] || return 0
	printf '%s' "$t" | $SHA256 -q 2>/dev/null
}

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

# measure_efivar_unique <guid8/name> -- 1 iff the digest this boot's loader
# published for the variable (kenv loader.trust.list.efivars.*, the
# <id>:<attrs>:<size>:<digest> entries) appears in NO earlier inventory
# record ($ELV_STATE/inventory/*, one file per boot). A variable that
# moves every boot must never repeat: a repeat is a dump written back
# blindly. Absent without the entry or without earlier records.
measure_efivar_unique() {
	local cur f
	cur=$($KENV | $SED -n 's/^loader\.trust\.list\.efivars\.[0-9]*="\(.*\)"$/\1/p' | $TR ',' '\n' | $GREP "^$1:" | $HEAD -n1 | $AWK -F: '{print $NF}')
	[ -n "$cur" ] || return 0
	[ -d "$ELV_STATE/inventory" ] || return 0
	f=$(ls "$ELV_STATE/inventory" 2>/dev/null | $SORT | $SED '$d')
	[ -n "$f" ] || return 0
	for f in $f; do
		if $TR ',' '\n' < "$ELV_STATE/inventory/$f" | $GREP -q "^\(loader\.trust\.list\.efivars\.[0-9]*=\"\)\{0,1\}$1:.*:$cur\$"; then
			printf '0\n'; return 0
		fi
	done
	printf '1\n'
}
# diagnose_efivar_unique <guid8/name> -- this boot's digest and the number of earlier records
diagnose_efivar_unique() {
	local cur n
	cur=$($KENV | $SED -n 's/^loader\.trust\.list\.efivars\.[0-9]*="\(.*\)"$/\1/p' | $TR ',' '\n' | $GREP "^$1:" | $HEAD -n1 | $AWK -F: '{print $NF}')
	n=$(ls "$ELV_STATE/inventory" 2>/dev/null | $WC -l | $TR -d ' ')
	printf 'digest=%s,records=%s\n' "${cur:-none}" "$((n > 0 ? n - 1 : 0))"
}

# measure_ntp_gap <max-seconds> -- 1 iff the RTC the boot ran on agrees
# with the network time within <max-seconds>: earlboot left the RTC epoch
# and the monotonic uptime (clock-at-boot); now, with ntpd synchronised
# (ntpq: stratum below 16), the expected RTC is that epoch plus the
# uptime since -- the difference to the real now is what ntpd corrected,
# i.e. how far the RTC was off at boot. A silent boot on a set-back RTC
# shows here, after the login, where the attacker cannot prevent it
# Absent without the note or
# without synchronisation. Assumes ntpd and the tunnel are up (STARTUP
# late, PERIODIC daily).
measure_ntp_gap() {
	local rtc up now bt upnow expect gap st
	[ -f "$ELV_STATE/clock-at-boot" ] || return 0
	read -r rtc up < "$ELV_STATE/clock-at-boot" || return 0
	st=$($NTPQ -c 'rv 0 stratum' 2>/dev/null | $SED -n 's/.*stratum=\([0-9]*\).*/\1/p')
	[ -n "$st" ] && [ "$st" -lt 16 ] || return 0
	now=$($DATE +%s)
	bt=$($SYSCTL -n kern.boottime 2>/dev/null | $SED -n 's/.*sec = \([0-9]*\).*/\1/p')
	[ -n "$bt" ] || return 0
	upnow=$((now - bt))
	expect=$((rtc + upnow - up))
	gap=$((now - expect))
	[ "$gap" -lt 0 ] && gap=$((-gap))
	if [ "$gap" -le "$1" ]; then printf '1\n'; else printf '0\n'; fi
}
# diagnose_ntp_gap -- the gap in seconds (signed: now minus expected RTC), or unknown
diagnose_ntp_gap() {
	local rtc up now bt
	[ -f "$ELV_STATE/clock-at-boot" ] || { printf 'unknown\n'; return 0; }
	read -r rtc up < "$ELV_STATE/clock-at-boot" || { printf 'unknown\n'; return 0; }
	now=$($DATE +%s)
	bt=$($SYSCTL -n kern.boottime 2>/dev/null | $SED -n 's/.*sec = \([0-9]*\).*/\1/p')
	[ -n "$bt" ] || { printf 'unknown\n'; return 0; }
	printf 'gap.s=%s\n' "$((now - (rtc + (now - bt) - up)))"
}
