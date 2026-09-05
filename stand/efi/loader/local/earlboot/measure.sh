#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Johannes Brügmann
#
# earlboot -- the measurement catalog (see policy.sh for the contract).
# Each provider prints ONE line, the measured value, or nothing when the
# source is absent. The <label> is the expectation's label (the kenv name,
# the path, the device) -- one provider serves many claims. Every provider
# states what it assumes.

# measure_kenv <variable> -- the loader's publication. Assumes mac_bootlock
# keeps loader.trust.* immutable; an EMPTY namespace is the finding "loader
# bypassed" (the claim fails because nothing was measured).
measure_kenv() {
	/bin/kenv -q "$1" 2>/dev/null
}

# measure_word <gate> -- 1 iff the handover word of <gate> verifies against
# the WORD secret (elv_word_check ran in the prologue). Assumes Secure Boot
# with the owner db only: only the owner's loader can have produced it.
measure_word() {
	[ "$1" = "$ELV_GATE_LOADER" ] || return 0
	/bin/kenv -q "loader.trust.$1.word" > /dev/null 2>&1 || return 0
	printf '%s\n' "$ELV_WORD_OK"
}

# measure_flag_taint <gate> -- the taint bit the handover word carried (0/1),
# only meaningful when the word verified
measure_flag_taint() {
	[ "$ELV_WORD_OK" = 1 ] || return 0
	printf '%s\n' "$ELV_TAINT"
}
# measure_flag_duress <gate> -- the duress bit the handover word carried
# (0/1), only meaningful when the word verified
measure_flag_duress() {
	[ "$ELV_WORD_OK" = 1 ] || return 0
	printf '%s\n' "$ELV_DURESS"
}
# measure_flag_prompted <gate> -- the prompted bit the handover word carried
# (0/1), only meaningful when the word verified
measure_flag_prompted() {
	[ "$ELV_WORD_OK" = 1 ] || return 0
	printf '%s\n' "$ELV_PROMPTED"
}

# measure_securelevel -- kern.securelevel as the kernel reports it
measure_securelevel() {
	/sbin/sysctl -n kern.securelevel 2>/dev/null
}

# measure_veriexec -- mac_veriexec state (loaded, active, enforce) as the
# kernel reports it; absent when the module is not loaded. Assumes the
# kernel carries mac_veriexec (Entscheid 3, 04.09.).
measure_veriexec() {
	/sbin/sysctl -n security.mac.veriexec.state 2>/dev/null
}

# measure_bootlock -- 1 iff mac_bootlock is loaded (loader.trust.* immutable)
measure_bootlock() {
	if /sbin/kldstat -q -m mac_bootlock 2>/dev/null; then printf '1\n'; else printf '0\n'; fi
}

# measure_rootdev -- the mounted root as the kernel reports it
measure_rootdev() {
	/sbin/sysctl -n vfs.root.mountfrom 2>/dev/null || /bin/kenv -q vfs.root.mountfrom 2>/dev/null
}

# measure_kernel_ident -- kernel identity (osrelease + ident), one line
measure_kernel_ident() {
	printf '%s %s\n' "$(/sbin/sysctl -n kern.osrelease 2>/dev/null)" "$(/sbin/sysctl -n kern.ident 2>/dev/null)"
}

# measure_book <gate> -- 1 iff the counter the loader published is exactly
# the book's last counter + 1 (the book is what book_act keeps under
# $ELV_STATE/book); 1 as well on the very first run (no book yet)
measure_book() {
	local c last
	c=$(/bin/kenv -q "loader.trust.$1.counter" 2>/dev/null) || return 0
	[ -n "$c" ] || return 0
	if [ -f "$ELV_STATE/book" ]; then
		last=$(/usr/bin/tail -1 "$ELV_STATE/book" | /usr/bin/cut -d' ' -f1)
		if [ "$c" = $((last + 1)) ]; then printf '1\n'; else printf '0\n'; fi
	else
		printf '1\n'
	fi
}

# measure_heartbeat <max-age-seconds> -- 1 iff elvbootd's runtime watch left
# a heartbeat younger than <max-age>; 0 when older; absent when none ever
measure_heartbeat() {
	local now stamp
	[ -f "$ELV_STATE/heartbeat" ] || return 0
	now=$(/bin/date +%s)
	stamp=$(/usr/bin/stat -f %m "$ELV_STATE/heartbeat" 2>/dev/null) || return 0
	if [ $((now - stamp)) -le "$1" ]; then printf '1\n'; else printf '0\n'; fi
}

# measure_efivar <GUID-NAME> -- sha256 of an EFI variable's binary value
# (BootOrder, BootNext, the owner's marker). Assumes efivar(8) and a
# firmware that exposes the variable at runtime.
measure_efivar() {
	/usr/sbin/efivar --no-name --name "$1" --binary 2>/dev/null | /sbin/sha256 -q 2>/dev/null
}

# measure_file_sha256 <path> -- sha256 of a file; absent when unreadable
measure_file_sha256() {
	[ -r "$1" ] || return 0
	/sbin/sha256 -q "$1" 2>/dev/null
}

# measure_manifest <manifest> -- 1 iff every file the manifest lists matches
# its sha256 (lines "<path> sha256=<hex> ..." as libsecureboot writes them,
# paths resolved from the manifest's directory); 0 on any mismatch or
# missing file; absent when the manifest is unreadable
measure_manifest() {
	local dir line path want have bad=0 n=0
	[ -r "$1" ] || return 0
	dir=$(/usr/bin/dirname "$1")
	while IFS= read -r line; do
		case "$line" in ""|\#*) continue ;; esac
		path=${line%% *}
		want=$(printf '%s\n' "$line" | /usr/bin/sed -n 's/.*sha256=\([0-9a-f]*\).*/\1/p')
		[ -n "$want" ] || continue
		n=$((n + 1))
		case "$path" in /*) ;; *) path="$dir/$path" ;; esac
		have=$(/sbin/sha256 -q "$path" 2>/dev/null) || { bad=1; continue; }
		[ "$have" = "$want" ] || bad=1
	done < "$1"
	[ "$n" -gt 0 ] || return 0
	if [ "$bad" -eq 0 ]; then printf '1\n'; else printf '0\n'; fi
}

# measure_esp_digest <file> -- sha256 of <file> (e.g. EFI/BOOT/BOOTX64.EFI)
# on the boot medium's ESP ($ELV_ESP), mounted read-only for the read.
# Assumes the medium is attached and the ESP is FAT.
measure_esp_digest() {
	local mnt out
	[ -n "$ELV_ESP" ] && [ -c "/dev/$ELV_ESP" ] || return 0
	mnt=$(/usr/bin/mktemp -d) || return 0
	if /sbin/mount -t msdosfs -o ro "/dev/$ELV_ESP" "$mnt" 2>/dev/null; then
		out=$(/sbin/sha256 -q "$mnt/$1" 2>/dev/null)
		/sbin/umount "$mnt" 2>/dev/null
	fi
	/bin/rmdir "$mnt" 2>/dev/null
	[ -n "$out" ] && printf '%s\n' "$out"
}

# measure_smart <nvmeN> -- the controller's power-cycle count (SMART log
# page 2), a counter no host command resets. Assumes an NVMe controller.
measure_smart() {
	/sbin/nvmecontrol logpage -p 2 "$1" 2>/dev/null | /usr/bin/awk -F: '/Power Cycles/ { gsub(/[ \t]/, "", $2); print $2; exit }'
}

# measure_smart_step <nvmeN> -- 1 iff the power-cycle count is exactly the
# book's last value + 1 (the anti-rollback anchor of the NVRAM record);
# 1 on the first run
measure_smart_step() {
	local c last
	c=$(measure_smart "$1")
	[ -n "$c" ] || return 0
	if [ -f "$ELV_STATE/smart-$1" ]; then
		last=$(/bin/cat "$ELV_STATE/smart-$1")
		if [ "$c" = $((last + 1)) ]; then printf '1\n'; else printf '0\n'; fi
	else
		printf '1\n'
	fi
}

# measure_answer <gate> -- the sentinel's salted answer hash (classification
# is the expectation's value: one claim per answer class)
measure_answer() {
	/bin/kenv -q "loader.trust.$1.answer" 2>/dev/null
}

# measure_answer_first <gate> -- the salted hash of the answer's first character
measure_answer_first() {
	/bin/kenv -q "loader.trust.$1.answer.first" 2>/dev/null
}

# --- diagnostics ---

# diagnose_kenv -- the loader.trust.* publications as one line
diagnose_kenv() { /bin/kenv 2>/dev/null | /usr/bin/grep "^loader\.trust\." | /usr/bin/tr '\n' ' '; }
# diagnose_word -- ok/taint/duress/prompted as the word check learned them
diagnose_word() { printf 'ok=%s taint=%s duress=%s prompted=%s\n' "$ELV_WORD_OK" "$ELV_TAINT" "$ELV_DURESS" "$ELV_PROMPTED"; }
# diagnose_book -- the book's last line (counter and stamp)
diagnose_book() { [ -f "$ELV_STATE/book" ] && /usr/bin/tail -1 "$ELV_STATE/book"; }
# diagnose_smart <nvmeN> -- power cycles, power-on hours, unsafe shutdowns
diagnose_smart() { /sbin/nvmecontrol logpage -p 2 "$1" 2>/dev/null | /usr/bin/grep -E 'Power Cycles|Power On Hours|Unsafe Shutdowns' | /usr/bin/tr -s ' \t' ' ' | /usr/bin/tr '\n' ';'; }
