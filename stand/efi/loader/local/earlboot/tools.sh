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
# The "# test:" mark says what the test run puts in a tool's place:
#   kenv     a function answering from the captured dump (key="value" lines)
#   sysctl   from the dump too, keys "sysctl.<oid>"
#   kldstat  present iff the dump has "kldstat.<module>=1"
#   silent   returns nothing, exit 1 (the source is absent in the test)
#   note     prints "mock: <args>" on stderr, exit 0 (side effects reported)
#   tee      passes stdin through (console_act's tee | wall)
#   (none)   pure text tools stay real
#
AWK=/usr/bin/awk
CAMCONTROL=/sbin/camcontrol # test:silent
CAT=/bin/cat
CHFLAGS=/bin/chflags # test:note
CP=/bin/cp
CUT=/usr/bin/cut
DATE=/bin/date
DD=/bin/dd
DIRNAME=/usr/bin/dirname
DMESG=/sbin/dmesg # test:silent
EFIVAR=/usr/sbin/efivar # test:silent
FIND=/usr/bin/find
GPART=/sbin/gpart # test:silent
GPG=/usr/local/bin/gpg # test:silent
GREP=/usr/bin/grep
HALT=/sbin/halt # test:note
HEAD=/usr/bin/head
HOSTNAME=/bin/hostname
KENV=/bin/kenv # test:kenv
KLDSTAT=/sbin/kldstat # test:kldstat
LOGGER=/usr/bin/logger # test:note
MKDIR=/bin/mkdir
MKTEMP=/usr/bin/mktemp
MOUNT=/sbin/mount # test:silent
NC=/usr/bin/nc # test:silent
NVMECONTROL=/sbin/nvmecontrol # test:silent
OD=/usr/bin/od
OPENSSL=/usr/bin/openssl
PS=/bin/ps # test:silent
RM=/bin/rm
RMDIR=/bin/rmdir
SED=/usr/bin/sed
SHA256=/sbin/sha256
SHUTDOWN=/sbin/shutdown # test:note
SLEEP=/bin/sleep
SOCKSTAT=/usr/bin/sockstat # test:silent
SORT=/usr/bin/sort
STAT=/usr/bin/stat
SYSCTL=/sbin/sysctl # test:sysctl
TAIL=/usr/bin/tail
TEE=/usr/bin/tee # test:tee
TOUCH=/usr/bin/touch
TR=/usr/bin/tr
UMOUNT=/sbin/umount # test:silent
WALL=/usr/bin/wall # test:note
WC=/usr/bin/wc
XARGS=/usr/bin/xargs
