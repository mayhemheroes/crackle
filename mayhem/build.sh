#!/usr/bin/env bash
#
# mayhem/build.sh — build crackle's fuzz harness (sanitized + instrumented), a
# standalone reproducer, and the project's own test binary (normal flags) for
# the functional oracle. Runs inside the commit image as `mayhem` in /mayhem.
# Air-gapped: libpcap-dev is installed by the Dockerfile, so this re-runs offline.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

# crackle's BTLE parser does unaligned integer loads THROUGHOUT (e.g. read_32 at crackle.c:110
# casts arbitrary packet offsets to uint32_t*). These are technically UB but harmless on x86_64;
# under -fno-sanitize-recover they otherwise abort on the very first packet and starve the fuzzer.
# Drop ONLY the `alignment` UBSan check so real memory-safety bugs (ASan OOB/UAF + the rest of
# UBSan) still halt. Applied only when sanitizers are enabled (a caller-forced empty SANITIZER_FLAGS
# leaves this a harmless no-op).
HARNESS_SAN="$SANITIZER_FLAGS"
[ -n "$SANITIZER_FLAGS" ] && HARNESS_SAN="$SANITIZER_FLAGS -fno-sanitize=alignment"

cd "$SRC"

# crackle's sources (excluding its own main via the harness's #include of crackle.c).
SUPPORT_SRCS="aes.c aes-ccm.c aes-enc.c test.c"

# 1+2) Fuzz harness — the project code (crackle.c is #included by the harness, plus the
#      AES/support TUs) is compiled WITH $SANITIZER_FLAGS so the fuzzed code is instrumented,
#      and $DEBUG_FLAGS keeps DWARF < 4. libpcap parses the container; crackle parses the
#      attacker-controlled BTLE payloads (the surface we instrument).
# shellcheck disable=SC2086
$CC $HARNESS_SAN $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$SRC/mayhem/fuzz_crackle.c" $SUPPORT_SRCS -I"$SRC" \
    -lpcap -o /mayhem/crackle_fuzz

# Standalone (non-fuzzer) reproducer: same harness linked against LLVM's run-once driver.
# shellcheck disable=SC2086
$CC $HARNESS_SAN $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" \
    "$SRC/mayhem/fuzz_crackle.c" $SUPPORT_SRCS -I"$SRC" \
    -lpcap -o /mayhem/crackle_fuzz-standalone

# 3) Project's OWN build for the functional oracle — the upstream Makefile with normal flags
#    (drop -Werror: the suite is compiled with clang here and upstream's warnings-as-errors is
#    tuned for gcc). Produces the `crackle` CLI (incl. its built-in -t crypto self-tests, from
#    test.c) that mayhem/test.sh runs against the upstream tests/ pcap suite. Independent of the
#    sanitized build above so the oracle can't false-fail on benign UB.
# shellcheck disable=SC2086
make -j"$MAYHEM_JOBS" CC="$CC" CFLAGS="-O2 -Wall -g $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" crackle
cp -f crackle /mayhem/crackle-oracle

echo "build.sh: done — /mayhem/crackle_fuzz, /mayhem/crackle_fuzz-standalone, /mayhem/crackle-oracle"
