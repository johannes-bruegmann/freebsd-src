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
	$KENV -q "$1" 2>/dev/null
}

# measure_word <gate> -- 1 iff the handover word of <gate> verifies against
# the WORD secret (elv_word_check ran in the prologue). Assumes Secure Boot
# with the owner db only: only the owner's loader can have produced it.
measure_word() {
	[ "$1" = "$ELV_GATE_LOADER" ] || return 0
	$KENV -q "loader.trust.$1.word" > /dev/null 2>&1 || return 0
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
	$SYSCTL -n kern.securelevel 2>/dev/null
}

# measure_veriexec -- mac_veriexec state (loaded, active, enforce) as the
# kernel reports it; absent when the module is not loaded. Assumes the
# kernel carries mac_veriexec (Entscheid 3, 04.09.).
measure_veriexec() {
	$SYSCTL -n security.mac.veriexec.state 2>/dev/null
}

# measure_bootlock -- 1 iff mac_bootlock is loaded (loader.trust.* immutable)
measure_bootlock() {
	if $KLDSTAT -q -m mac_bootlock 2>/dev/null; then printf '1\n'; else printf '0\n'; fi
}

# measure_rootdev -- the mounted root as the kernel reports it
measure_rootdev() {
	$SYSCTL -n vfs.root.mountfrom 2>/dev/null || $KENV -q vfs.root.mountfrom 2>/dev/null
}

# measure_kernel_ident -- kernel identity (osrelease + ident), one line
measure_kernel_ident() {
	printf '%s %s\n' "$($SYSCTL -n kern.osrelease 2>/dev/null)" "$($SYSCTL -n kern.ident 2>/dev/null)"
}

# measure_book <gate> -- 1 iff the counter the loader published is exactly
# the book's last counter + 1 (the book is what book_act keeps under
# $ELV_STATE/book); 1 as well on the very first run (no book yet)
measure_book() {
	local c last
	c=$($KENV -q "loader.trust.$1.counter" 2>/dev/null) || return 0
	[ -n "$c" ] || return 0
	if [ -f "$ELV_STATE/book" ]; then
		last=$($TAIL -1 "$ELV_STATE/book" | $CUT -d' ' -f1)
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
	now=$($DATE +%s)
	stamp=$($STAT -f %m "$ELV_STATE/heartbeat" 2>/dev/null) || return 0
	if [ $((now - stamp)) -le "$1" ]; then printf '1\n'; else printf '0\n'; fi
}

# measure_pcr_agree -- 1 iff the sha256 over PCR 0..7 of the SHA256 bank,
# read from the TPM here, equals what the loader published as its PcrBank
# (loader.trust.kernellock.pcr.sha256): the TPM itself against the loader's
# word, a witness the loader cannot forge. 0 on disagreement; absent when
# the loader published nothing or the TPM cannot be read. Assumes
# tpm2-tools (tpm2_pcrread) and /dev/tpm0 -- the tpm driver loaded.
measure_pcr_agree() {
	local said mine t
	said=$($KENV -q loader.trust.kernellock.pcr.sha256 2>/dev/null)
	[ -n "$said" ] || return 0
	t=$($MKTEMP) || return 0
	if $TPM2_PCRREAD -Q -o "$t" sha256:0,1,2,3,4,5,6,7 2>/dev/null; then
		mine=$($SHA256 -q "$t" 2>/dev/null)
	fi
	$RM -f "$t"
	[ -n "$mine" ] || return 0
	[ "$mine" = "$said" ] && printf '1\n' || printf '0\n'
}

# measure_images_expected -- 1 iff the LoadedImages digest the loader
# published (loader.trust.inventory.images.sha256) equals ELV_IMAGES_EXPECTED,
# the stage's value at generation time: the second witness of a claim whose
# expectation the loader reads from its conf. 0 on disagreement; absent
# when either side is missing. Assumes the constant rendered by
# stage earlboot mk from the record.
measure_images_expected() {
	local said
	said=$($KENV -q loader.trust.inventory.images.sha256 2>/dev/null)
	[ -n "$said" ] && [ -n "$ELV_IMAGES_EXPECTED" ] || return 0
	[ "$said" = "$ELV_IMAGES_EXPECTED" ] && printf '1\n' || printf '0\n'
}

# measure_efivar <GUID-NAME> -- sha256 of an EFI variable's binary value
# (BootOrder, BootNext, the owner's marker). Assumes efivar(8) and a
# firmware that exposes the variable at runtime.
measure_efivar() {
	$EFIVAR --no-name --name "$1" --binary 2>/dev/null | $SHA256 -q 2>/dev/null
}

# measure_file_sha256 <path> -- sha256 of a file; absent when unreadable
measure_file_sha256() {
	[ -r "$1" ] || return 0
	$SHA256 -q "$1" 2>/dev/null
}

# measure_manifest <manifest> -- 1 iff every file the manifest lists matches
# its sha256 (lines "<path> sha256=<hex> ..." as libsecureboot writes them,
# paths resolved from the manifest's directory); 0 on any mismatch or
# missing file; absent when the manifest is unreadable
measure_manifest() {
	local dir line path want have bad=0 n=0
	[ -r "$1" ] || return 0
	dir=$($DIRNAME "$1")
	while IFS= read -r line; do
		case "$line" in ""|\#*) continue ;; esac
		path=${line%% *}
		want=$(printf '%s\n' "$line" | $SED -n 's/.*sha256=\([0-9a-f]*\).*/\1/p')
		[ -n "$want" ] || continue
		n=$((n + 1))
		case "$path" in /*) ;; *) path="$dir/$path" ;; esac
		have=$($SHA256 -q "$path" 2>/dev/null) || { bad=1; continue; }
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
	mnt=$($MKTEMP -d) || return 0
	if $MOUNT -t msdosfs -o ro "/dev/$ELV_ESP" "$mnt" 2>/dev/null; then
		out=$($SHA256 -q "$mnt/$1" 2>/dev/null)
		$UMOUNT "$mnt" 2>/dev/null
	fi
	$RMDIR "$mnt" 2>/dev/null
	[ -n "$out" ] && printf '%s\n' "$out"
}

# measure_smart <nvmeN> -- the controller's power-cycle count (SMART log
# page 2), a counter no host command resets. Assumes an NVMe controller.
measure_smart() {
	$NVMECONTROL logpage -p 2 "$1" 2>/dev/null | $AWK -F: '/^Power cycles:/ { gsub(/[ \t]/, "", $2); print $2; exit }'
}

# measure_smart_step <nvmeN> -- 1 iff the power-cycle count is exactly the
# book's last value + 1 (the anti-rollback anchor of the NVRAM record);
# 1 on the first run
measure_smart_step() {
	local c last
	c=$(measure_smart "$1")
	[ -n "$c" ] || return 0
	if [ -f "$ELV_STATE/smart-$1" ]; then
		last=$($CAT "$ELV_STATE/smart-$1")
		if [ "$c" = $((last + 1)) ]; then printf '1\n'; else printf '0\n'; fi
	else
		printf '1\n'
	fi
}

# measure_answer <gate> -- the sentinel's salted answer hash (classification
# is the expectation's value: one claim per answer class)
measure_answer() {
	$KENV -q "loader.trust.$1.answer" 2>/dev/null
}

# measure_answer_first <gate> -- the salted hash of the answer's first character
measure_answer_first() {
	$KENV -q "loader.trust.$1.answer.first" 2>/dev/null
}

# measure_answer_matched <gate> -- 1 iff an answer class of this run matched
# (answer_matched_act fired), else 0. The catch-all class: bound AFTER the
# word classes, its when_fail is "an answer was given, or none, and no word
# we know" -- leer and wrong alike. Assumes the templates all carry
# answer_matched_act.
measure_answer_matched() {
	printf '%s\n' "${ELV_ANSWER_MATCHED:-0}"
}

# --- diagnostics ---

# diagnose_kenv -- the loader.trust.* publications as one line
diagnose_kenv() { $KENV 2>/dev/null | $GREP "^loader\.trust\." | $TR '\n' ' '; }
# diagnose_word -- ok/taint/duress/prompted as the word check learned them
diagnose_word() { printf 'ok=%s taint=%s duress=%s prompted=%s\n' "$ELV_WORD_OK" "$ELV_TAINT" "$ELV_DURESS" "$ELV_PROMPTED"; }
# diagnose_book -- the book's last line (counter and stamp)
diagnose_book() { [ -f "$ELV_STATE/book" ] && $TAIL -1 "$ELV_STATE/book"; }
# diagnose_smart <nvmeN> -- power cycles, power-on hours, unsafe shutdowns
diagnose_smart() { $NVMECONTROL logpage -p 2 "$1" 2>/dev/null | $GREP -E '^Power cycles:|^Power on hours:|^Unsafe shutdowns:' | $TR -s ' \t' ' ' | $TR '\n' ';'; }
