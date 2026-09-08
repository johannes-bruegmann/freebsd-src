#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Johannes Brügmann
#
# earlboot/elvbootd -- the tools table: every external command the catalogs
# run, one variable each, absolute. The catalogs say $KENV, $SYSCTL, ...;
# the emitter (elebake stage earlboot|elvbootd mk) turns this table into
# readonly constants at the top of the generated script -- the hardening of
# absolute paths in one block instead of on every line -- and a test run
# (stage earlboot test) renders the same script with mocks in their place:
# KENV reading a captured kenv dump, SHUTDOWN writing a note, the state dir
# on a tmpfs. Nothing here runs by itself.
#
# JB 08.09.: refactor so the generated scripts can be tested without root
# and without side effects.
#
AWK=/usr/bin/awk
CAMCONTROL=/sbin/camcontrol
CAT=/bin/cat
CHFLAGS=/bin/chflags
CP=/bin/cp
CUT=/usr/bin/cut
DATE=/bin/date
DIRNAME=/usr/bin/dirname
DMESG=/sbin/dmesg
EFIVAR=/usr/sbin/efivar
FIND=/usr/bin/find
GPART=/sbin/gpart
GPG=/usr/local/bin/gpg
GREP=/usr/bin/grep
HALT=/sbin/halt
HEAD=/usr/bin/head
HOSTNAME=/bin/hostname
KENV=/bin/kenv
KLDSTAT=/sbin/kldstat
LOGGER=/usr/bin/logger
MKDIR=/bin/mkdir
MKTEMP=/usr/bin/mktemp
MOUNT=/sbin/mount
NC=/usr/bin/nc
NVMECONTROL=/sbin/nvmecontrol
OD=/usr/bin/od
OPENSSL=/usr/bin/openssl
PS=/bin/ps
RM=/bin/rm
RMDIR=/bin/rmdir
SED=/usr/bin/sed
SHA256=/sbin/sha256
SHUTDOWN=/sbin/shutdown
SLEEP=/bin/sleep
SOCKSTAT=/usr/bin/sockstat
SORT=/usr/bin/sort
STAT=/usr/bin/stat
SYSCTL=/sbin/sysctl
TAIL=/usr/bin/tail
TEE=/usr/bin/tee
TOUCH=/usr/bin/touch
TR=/usr/bin/tr
UMOUNT=/sbin/umount
WALL=/usr/bin/wall
XARGS=/usr/bin/xargs
