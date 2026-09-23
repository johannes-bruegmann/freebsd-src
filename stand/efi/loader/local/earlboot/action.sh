#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Johannes Brügmann
#
# earlboot -- the action catalog (see policy.sh for the contract). Every
# action is UNCONDITIONAL and takes the gate name; the policy decides when
# it fires. The air-gap palette: everything works with the console, the
# disks, the EFI variables and the removable medium. Every action states
# what it assumes.

# elv_finding -- one line "stamp gate verdict failed=[..] passed=[..]"
elv_finding() {
	printf '%s %s %s failed=[%s] passed=[%s] skipped=[%s]\n' \
	    "$($DATE -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$GATE_VERDICT" \
	    "$(printf '%s' "${FAILED# }" | $TR ' ' ',')" \
	    "$(printf '%s' "${PASSED# }" | $TR ' ' ',')" \
	    "$(printf '%s' "${SKIPPED# }" | $TR ' ' ',')"
}

# log_act -- syslog, the baseline record
log_act() {
	$LOGGER -t elvboot -p security.notice "$(elv_finding "$1")"
	# earlboot runs before syslogd: the line above reaches nobody. It is
	# kept for elvbootd's replay_act (STARTUP, syslogd up), which re-logs
	# every kept line and removes the file (illyria 18.09.: no fish line
	# in any log although the gate had passed).
	$MKDIR -p "$ELV_STATE"
	elv_finding "$1" >> "$ELV_STATE/pending-log"
}

# console_act -- immediate human visibility: console line + wall. Never for
# duress (the coercer reads the console too).
console_act() {
	elv_finding "$1" | $TEE /dev/console 2>/dev/null | $WALL 2>/dev/null
	# before the login nobody reads the console: kept for elvbootd's
	# notice_act, which puts the lines into /var/run/motd for the next login
	$MKDIR -p "$ELV_STATE"
	elv_finding "$1" >> "$ELV_STATE/pending-console"
}

# spool_act -- append the finding to the append-only spool. Assumes
# kern.securelevel >= 1 at runtime so the sappnd flag binds root too.
spool_act() {
	$MKDIR -p "$ELV_STATE"
	[ -f "$ELV_STATE/spool" ] || { : > "$ELV_STATE/spool"; $CHFLAGS sappnd "$ELV_STATE/spool"; }
	elv_finding "$1" >> "$ELV_STATE/spool"
}

# mark_act -- a marker that SURVIVES reboot and the next run claims
mark_act() {
	$MKDIR -p "$ELV_STATE"
	elv_finding "$1" > "$ELV_STATE/mark-$1"
}

# answer_matched_act -- note that an answer class matched this run; the
# catch-all class (measure_answer_matched) reads it. Bind it, with the
# class's own reaction, in EVERY class template
answer_matched_act() {
	ELV_ANSWER_MATCHED=1
}

# freeze_act -- the mark elebake honours: trust operations refuse until the
# owner acknowledges (elebake stage ... refuses while $ELV_STATE/freeze exists)
freeze_act() {
	$MKDIR -p "$ELV_STATE"
	elv_finding "$1" >> "$ELV_STATE/freeze"
}

# persist_act -- the appraisal for the runtime hooks (elvbootd) and the next boot
persist_act() {
	$MKDIR -p "$ELV_STATE"
	{
		printf 'gate=%s verdict=%s\n' "$1" "$GATE_VERDICT"
		printf 'passed=%s\nfailed=%s\nskipped=%s\n' "$PASSED" "$FAILED" "$SKIPPED"
		printf 'word=%s taint=%s duress=%s prompted=%s\n' "$ELV_WORD_OK" "$ELV_TAINT" "$ELV_DURESS" "$ELV_PROMPTED"
		printf 'diag=%s\n' "$DIAG"
	} > "$ELV_STATE/appraisal-$1"
}

# book_act -- keep the counter book (loader counter, NVMe power cycles) so
# the next boot can claim "exactly one step". Assumes the loader published
# loader.trust.<gate>.counter (handover_act bound in the KERNEL phase).
book_act() {
	local c dev
	$MKDIR -p "$ELV_STATE"
	c=$($KENV -q "loader.trust.$ELV_GATE_LOADER.counter" 2>/dev/null)
	[ -n "$c" ] && printf '%s %s\n' "$c" "$($DATE -u +%Y-%m-%dT%H:%M:%SZ)" >> "$ELV_STATE/book"
	# no glob: the generated script runs under set -f
	for dev in nvme0 nvme1 nvme2 nvme3 nvme4 nvme5 nvme6 nvme7; do
		[ -c "/dev/$dev" ] || continue
		c=$($NVMECONTROL logpage -p 2 "$dev" 2>/dev/null | $AWK -F: '/^Power cycles:/ { gsub(/[ \t]/, "", $2); print $2; exit }')
		[ -n "$c" ] && printf '%s\n' "$c" > "$ELV_STATE/smart-$dev"
	done
}

# arm_act -- install the configuration set (network, VPN, pf, ssh-agent)
# only now: the machine gets its full configuration because the boot
# passed. Assumes $ELV_ARM_DIR mirrors / (e.g. etc/rc.conf.d/network).
arm_act() {
	[ -d "$ELV_ARM_DIR" ] || return 0
	(cd "$ELV_ARM_DIR" && $FIND . -type f | while IFS= read -r f; do
		$MKDIR -p "/$($DIRNAME "$f")"
		$CP -p "$f" "/$f"
	done)
	$RM -f "$ELV_STATE/degraded"
}

# disarm_act -- remove the configuration set: the quarantine boot. What
# arm_act would install stays absent (no network, no VPN, no key release).
disarm_act() {
	[ -d "$ELV_ARM_DIR" ] || return 0
	(cd "$ELV_ARM_DIR" && $FIND . -type f | while IFS= read -r f; do
		$RM -f "/$f"
	done)
	$MKDIR -p "$ELV_STATE"
	elv_finding "$1" > "$ELV_STATE/degraded"
}

# degrade_act -- disarm + mark: the quarantine boot, recorded
degrade_act() {
	disarm_act "$1"
	mark_act "$1"
}

# lock_act -- keep the data pool sealed: nothing is imported that a later
# step would otherwise unlock (zdata stays detached). Assumes the pool
# import is a later rc step reading $ELV_STATE/locked.
lock_act() {
	$MKDIR -p "$ELV_STATE"
	elv_finding "$1" > "$ELV_STATE/locked"
}

# courier_act -- the air-gap alert: spool the finding onto the removable
# medium so it surfaces on the administration machine at the next contact.
# Assumes the ESP is writable.
courier_act() {
	local mnt
	[ -n "$ELV_ESP" ] && [ -c "/dev/$ELV_ESP" ] || return 0
	mnt=$($MKTEMP -d) || return 0
	if $MOUNT -t msdosfs "/dev/$ELV_ESP" "$mnt" 2>/dev/null; then
		$MKDIR -p "$mnt/EFI/elvboot"
		elv_finding "$1" >> "$mnt/EFI/elvboot/courier"
		$UMOUNT "$mnt" 2>/dev/null
	fi
	$RMDIR "$mnt" 2>/dev/null
}

# beacon_act -- the silent alarm: ONE UDP datagram to $ELV_BEACON, no
# visible change. Assumes a network path exists at this point (it usually
# does not in SYSINIT -- bind it in elvbootd's STARTUP instead).
beacon_act() {
	[ -n "$ELV_BEACON" ] || return 0
	printf 'elvboot %s %s\n' "$($HOSTNAME)" "$1" | $NC -u -w 1 "${ELV_BEACON%:*}" "${ELV_BEACON#*:}" 2>/dev/null
}

# attest_act -- sign the finding (OpenPGP, the host's manifest key) into
# $ELV_STATE/attest for off-host delivery by courier or elvbootd
attest_act() {
	$MKDIR -p "$ELV_STATE/attest"
	elv_finding "$1" | $GPG --batch --yes --clearsign 2>/dev/null > "$ELV_STATE/attest/$($DATE -u +%Y%m%dT%H%M%SZ)-$1.asc"
}

# reauth_act -- demand the owner's token before the boot proceeds: waits
# until an OpenPGP card answers (Nitrokey inserted). Assumes pcscd/gpg.
reauth_act() {
	local n=0
	printf 'elvboot: %s -- insert the owner token to continue\n' "$1" > /dev/console
	while ! $GPG --batch --card-status > /dev/null 2>&1; do
		n=$((n + 1)); [ "$n" -ge 120 ] && break
		$SLEEP 5
	done
}

# quarantine_act -- leave the suspect medium unmounted (MEDIA phase, elvbootd)
quarantine_act() {
	[ -n "$ELV_ESP" ] || return 0
	$UMOUNT "/dev/$ELV_ESP" 2>/dev/null
	mark_act "$1"
}

# shutdown_act -- the hard stop: continuing to run is worse than stopping.
# Console and broadcast say only that a policy stopped the boot; which
# gate (an answer class, a claim) stays in the spool, root-only (JB
# 18.09.: the line before the halt must not name the class).
shutdown_act() {
	printf 'elvboot: shutdown by policy\n' > /dev/console
	halt_count_act "$1"
	$SHUTDOWN -p now "elvboot: shutdown by policy"
}

# halt_count_act <gate> -- raise the increment-only NV index
# loader.trust.halt.nv before the halt: the trace of a halt nobody
# lowers, which the loader's HaltQuiet claim reads on the next boot (its
# expectation is learned, so the boot after a halt fails it until the
# owner relearns). The index authorizes by PolicyCommandCode(NV_Increment),
# so anyone may raise it, nobody may write a value. Without the leaf, or
# without the tools, nothing happens (a probe must leave a mark).
halt_count_act() {
	local nv s i err
	nv=$($KENV -q loader.trust.halt.nv 2>/dev/null) || return 0
	[ -n "$nv" ] || return 0
	s="$ELV_STATE/halt.session"
	TPM2TOOLS_TCTI=device:/dev/tpm0; export TPM2TOOLS_TCTI
	i=1
	while [ "$i" -le 5 ]; do
		if err=$(halt_count_once "$nv" "$s" 2>&1); then
			halt_count_note "pass attempt=$i"
			return 0
		fi
		$SLEEP 1
		i=$((i + 1))
	done
	halt_count_note "fail attempts=5 error=$(printf '%s' "$err" | $TR '\n' ' ' | $HEAD -c 300)"
}

# halt_count_once <index> <session file> -- one attempt: policy session,
# PolicyCommandCode(NV_Increment), the increment, flush; the tools' output
# is the caller's evidence (illyria 18.09.: two probes raised nothing and
# earlboot had swallowed the reason)
halt_count_once() {
	$TPM2_STARTAUTHSESSION --policy-session --session="$2" || return 1
	if ! $TPM2_POLICYCOMMANDCODE --session="$2" TPM2_CC_NV_Increment; then
		$TPM2_FLUSHCONTEXT "$2"; $RM -f "$2"; return 1
	fi
	if ! $TPM2_NVINCREMENT "$1" --auth="session:$2"; then
		$TPM2_FLUSHCONTEXT "$2"; $RM -f "$2"; return 1
	fi
	$TPM2_FLUSHCONTEXT "$2"
	$RM -f "$2"
}

# warn_shutdown_act <gate> -- the owner's login warning after an unclean
# shutdown: one plain line per finding into pending-console,
# which elvbootd's notice_act puts into /var/run/motd -- "unsafe power
# loss, NVMe counter +N since the last boot" when UnsafeStep fell, "last
# shutdown was not clean (no marker)" when BootMarker fell; both when
# both. Reads the loader's kenv, assumes the loader gate tellwatch carries UnsafeStep.
warn_shutdown_act() {
	local v now rec f
	$MKDIR -p "$ELV_STATE"
	v=$($KENV -q loader.trust.tellwatch.unsafe 2>/dev/null)
	case "$v" in
	*/*)	now=${v%%/*}; rec=${v##*/}
		[ "$now" != "$rec" ] && printf 'WARNUNG: unsauberer Stromverlust -- NVMe-Zaehler unsafe shutdowns %s (Record %s), +%s seit dem letzten Boot\n' "$now" "$rec" "$((now - rec))" >> "$ELV_STATE/pending-console"
		;;
	esac
	f=$($KENV -q loader.trust.bootlock.failed 2>/dev/null)
	case ",$f," in
	*,BootMarker,*) printf 'WARNUNG: letzter Shutdown nicht ordentlich (kein Marker im NVRAM)\n' >> "$ELV_STATE/pending-console" ;;
	esac
}

# clock_note_act <gate> -- the RTC as earlboot sees it (no ntpd yet) beside
# the monotonic uptime, for elvbootd's measure_ntp_gap after the tunnel:
# $ELV_STATE/clock-at-boot = "<epoch> <uptime-seconds>". Assumes: the
# kernel took its clock from the RTC (no network before earlboot).
clock_note_act() {
	local now bt
	$MKDIR -p "$ELV_STATE"
	now=$($DATE +%s)
	bt=$($SYSCTL -n kern.boottime 2>/dev/null | $SED -n 's/.*sec = \([0-9]*\).*/\1/p')
	[ -n "$bt" ] || return 0
	printf '%s %s\n' "$now" "$((now - bt))" > "$ELV_STATE/clock-at-boot"
}

# spool_note <what> <text> -- one dated line into the append-only spool
spool_note() {
	$MKDIR -p "$ELV_STATE"
	[ -f "$ELV_STATE/spool" ] || { : > "$ELV_STATE/spool"; $CHFLAGS sappnd "$ELV_STATE/spool"; }
	printf '%s %s %s\n' "$($DATE -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" >> "$ELV_STATE/spool"
}

# halt_count_note <text> -- the outcome into the append-only spool
halt_count_note() {
	spool_note halt-count "$1"
}

# unlock_note_act <gate> -- the owner overrode a fallen gate with the unlock
# passphrase: not a custody failure, but the append-only witness that this
# boot ran on a gate the loader had reported (the loader
# reports, earlboot judges). Bound with when_unlocked.
unlock_note_act() {
	spool_note unlock-ack "taint=$ELV_TAINT gates=[$($KENV -q loader.trust.kernellock.failed 2>/dev/null),$($KENV -q loader.trust.recordlock.failed 2>/dev/null)]"
}

# poweroff_act -- immediate power off, no grace
poweroff_act() {
	$HALT -p
}
