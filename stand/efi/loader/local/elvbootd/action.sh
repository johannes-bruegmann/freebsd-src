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

# replay_act <gate> -- re-log the lines earlboot kept while syslogd was not
# up ($ELV_STATE/pending-log, one finding per line), then drop the file.
# Bound in the runtime gate of STARTUP, after syslogd (rc.d: REQUIRE
# NETWORKING). The lines carry their own timestamps.
replay_act() {
	local f="$ELV_STATE/pending-log" line
	[ -f "$f" ] || return 0
	while IFS= read -r line; do
		[ -n "$line" ] && $LOGGER -t elvboot -p security.notice "$line"
	done < "$f"
	$RM -f "$f"
}

# notice_act <gate> -- what earlboot wanted the owner to see on the console
# ($ELV_STATE/pending-console) goes into /var/run/motd, which every login
# prints; then the file is dropped. motd(8) regenerates /var/run/motd at
# every boot from /etc/motd.template, so the notice lives one boot.
notice_act() {
	local f="$ELV_STATE/pending-console"
	[ -f "$f" ] || return 0
	{ printf '\nelvboot -- findings of this boot:\n'; $SED 's/^/  /' "$f"; printf '\n'; } >> /var/run/motd 2>/dev/null
	$RM -f "$f"
}

# summary_act <gate> -- one readable syslog line per boot: the loader's
# gates (passed/failed), the record (counter, chain), the TPM key file, the
# prompts, earlboot's custody verdict. Reads kenv and the appraisal; says
# nothing of duress (the word carries that, the counter is the trace).
summary_act() {
	local gates="" failed="" g f rec tpm att custody
	for g in bootlock loaderlock inventory strictwatch kernellock recordlock tellwatch kernelpost; do
		f=$($KENV -q "loader.trust.$g.failed" 2>/dev/null) || continue
		if [ -z "$f" ]; then gates="$gates $g:pass"; else gates="$gates $g:fail($f)"; failed="$failed $g"; fi
	done
	rec=$($KENV -q loader.trust.recordlock.record 2>/dev/null)
	tpm=$($KENV -q loader.trust.recordlock.tpm.keyfile 2>/dev/null | $SED 's/,unsealed.*//; s/.*key=//')
	att=$($KENV -q loader.trust.kernelpost.attempts 2>/dev/null)
	custody=$($SED -n 's/^gate=custody verdict=//p' "$ELV_STATE/appraisal-custody" 2>/dev/null)
	$LOGGER -t elvboot -p security.notice "boot summary: gates=[${gates# }] record=[${rec:-none}] tpm.key=${tpm:-none} attempts=${att:-?} custody=${custody:-none}"
}

# smart_anchor_act <gate> -- SHUTDOWN (B1): what the next boot must find
# in the shutdown index -- the NVMe's power-on hours, data units read and
# written, the medium's letter -- written under the cap PCR's CAPPED state
# (the loader capped it after its own anchor write; only the runtime can
# write here), then the PCR is extended once more so nothing after this
# hook can rewrite it. The loader's SmartStep compares at the next boot:
# a boot's worth of difference passes, a clone of the disks does not.
# Layout = struct record_anchor (record.h): three u64 little endian, the
# letter, seven zero bytes, sha256 over those 32 bytes. Reads the leafs
# from kenv; without them, or without the tools, nothing is written
# (SmartStep stays absent). Assumes an NVMe controller nvme0 and tpm2-tools.
smart_anchor_act() {
	local idx cap hours rd wr medium body tag f s
	idx=$($KENV -q loader.trust.tpm.shutdown.nv 2>/dev/null) || return 0
	cap=$($KENV -q loader.trust.tpm.cap.pcr 2>/dev/null) || return 0
	[ -n "$idx" ] && [ -n "$cap" ] || return 0
	[ -c /dev/nvme0 ] || return 0
	hours=$($NVMECONTROL logpage -p 2 nvme0 2>/dev/null | $AWK -F: '/^Power on hours:/ { gsub(/[ \t]/, "", $2); print $2; exit }')
	rd=$($NVMECONTROL logpage -p 2 nvme0 2>/dev/null | $AWK -F: '/^Data units \(512,000 byte\) read:/ { gsub(/[ \t]/, "", $2); print $2; exit }')
	wr=$($NVMECONTROL logpage -p 2 nvme0 2>/dev/null | $AWK -F: '/^Data units written:/ { gsub(/[ \t]/, "", $2); print $2; exit }')
	[ -n "$hours" ] && [ -n "$rd" ] && [ -n "$wr" ] || return 0
	medium=$($KENV -q loader.trust.tellwatch.medium 2>/dev/null | $SED -n 's/.*now=\(.\).*/\1/p')
	[ "$medium" = - ] && medium=""
	$MKDIR -p "$ELV_STATE"
	f="$ELV_STATE/shutdown-anchor.bin"; s="$ELV_STATE/shutdown-anchor.session"
	body=$($AWK -v a="$hours" -v b="$rd" -v c="$wr" -v m="$medium" 'BEGIN {
		n = a; for (i = 0; i < 8; i++) { printf "\\%03o", n % 256; n = int(n / 256) }
		n = b; for (i = 0; i < 8; i++) { printf "\\%03o", n % 256; n = int(n / 256) }
		n = c; for (i = 0; i < 8; i++) { printf "\\%03o", n % 256; n = int(n / 256) }
		if (m == "") printf "\\000"; else printf "%s", m
		for (i = 0; i < 7; i++) printf "\\000" }')
	# shellcheck disable=SC2059
	printf "$body" > "$f"
	printf "$body" | $OPENSSL dgst -sha256 -binary >> "$f"
	TPM2TOOLS_TCTI=device:/dev/tpm0; export TPM2TOOLS_TCTI
	if $TPM2_STARTAUTHSESSION --policy-session --session="$s" 2>/dev/null &&
	    $TPM2_POLICYPCR --session="$s" --pcr-list="sha256:$cap" 2>/dev/null &&
	    $TPM2_NVWRITE "$idx" --auth="session:$s" --input="$f" 2>/dev/null; then
		$TPM2_FLUSHCONTEXT "$s" 2>/dev/null
		$TPM2_PCREXTEND "$cap:sha256=e77d35bc1f1b86c4267bfba0d4b874afad6ebc964b8367b05b817ee557a70e8f" 2>/dev/null
		$LOGGER -t elvboot -p security.notice "shutdown anchor written: hours=$hours read=$rd written=$wr medium=${medium:--}"
	else
		$TPM2_FLUSHCONTEXT "$s" 2>/dev/null
		$LOGGER -t elvboot -p security.notice "shutdown anchor NOT written (index $idx, pcr $cap): the next boot's SmartStep will fall"
	fi
	$RM -f "$f" "$s"
}

# sentinel_act <gate> -- the runtime watchdog: no persisted appraisal of
# THIS boot means earlboot never ran (or was removed) -- itself a finding.
# earlboot persists under the name of ITS gate (appraisal-custody), which
# elvbootd does not know; so the question is whether any appraisal is
# younger than the kernel's boot time (kern.boottime). Illyria 16.09.: the
# old test looked for appraisal-<loader gate> and failed every boot.
sentinel_act() {
	local boot="" f
	boot=$($SYSCTL -n kern.boottime 2>/dev/null | $SED 's/^{ sec = \([0-9]*\),.*/\1/')
	case "$boot" in ''|*[!0-9]*) boot=0 ;; esac
	# no glob: the generated script runs under set -f
	for f in $($FIND "$ELV_STATE" -maxdepth 1 -type f -name 'appraisal-*' 2>/dev/null); do
		[ "$($STAT -f %m "$f" 2>/dev/null || echo 0)" -ge "$boot" ] && return 0
	done
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

# inventory_record_act <gate> -- the loader's inventory lists (kenv
# loader.trust.list.*: one entry per ACPI table and per non-volatile EFI
# variable, each with its own digest) into $ELV_STATE/inventory/<boot time>,
# so boots can be compared and the entries the firmware rewrites can be
# named before a claim's scope is decided (JB 11.09.: record first, decide
# after). Assumes a loader of this fork published the lists.
inventory_record_act() {
	local t
	t=$($KENV -q loader.trust.kernellock.time.now 2>/dev/null | $SED 's/,.*//; s/[-:]//g')
	[ -n "$t" ] || t=$($DATE +%Y%m%dT%H%M%S)
	$MKDIR -p "$ELV_STATE/inventory"
	$KENV | $GREP '^loader\.trust\.list\.' > "$ELV_STATE/inventory/$t"
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
