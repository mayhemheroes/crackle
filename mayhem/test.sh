#!/usr/bin/env bash
#
# mayhem/test.sh — RUN crackle's OWN functional test suite (built by mayhem/build.sh).
# This is the upstream suite, unchanged:
#   1. tests/run_tests.pl  — the `make test` integration suite: runs crackle on each capture in
#      tests/NN_*/ and asserts BOTH the textual report (diff vs out/expected_output.txt) AND the
#      decrypted-PCAP bytes (sha256 vs out/expected_output.pcap). 5 cases.
#   2. crackle -t           — the built-in AES-CCM / STK / session-key known-answer self-tests
#      (test.c), asserting fixed crypto vectors.
# A no-op / exit(0) patch produces neither the expected report nor "All tests passed", so it FAILS
# here (anti-reward-hacking). Emits a CTRF summary. Does NOT compile — build.sh already did.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

CRACKLE=/mayhem/crackle-oracle
if [ ! -x "$CRACKLE" ]; then
  echo "test.sh: $CRACKLE missing — build.sh did not produce the oracle binary" >&2
  exit 2
fi

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

passed=0
failed=0

# 1) Integration suite (tests/run_tests.pl). Prints "Ran N tests, M passed".
echo "== crackle integration suite (tests/run_tests.pl) =="
suite_out="$(cd tests && perl run_tests.pl "$CRACKLE" 2>&1)"
echo "$suite_out"
ran="$(printf '%s\n' "$suite_out"   | sed -n 's/^Ran \([0-9]\+\) tests, .*/\1/p'    | tail -1)"
sp="$(printf '%s\n'  "$suite_out"   | sed -n 's/^Ran [0-9]\+ tests, \([0-9]\+\) passed/\1/p' | tail -1)"
if [ -z "${ran:-}" ] || [ -z "${sp:-}" ]; then
  echo "test.sh: could not parse run_tests.pl summary" >&2
  emit_ctrf "crackle-suite" 0 1
  exit 1
fi
passed=$(( passed + sp ))
failed=$(( failed + ran - sp ))

# 2) Built-in crypto known-answer self-tests (crackle -t → "All tests passed").
echo "== crackle -t crypto self-tests =="
if selftest_out="$("$CRACKLE" -t 2>&1)" && printf '%s\n' "$selftest_out" | grep -q "All tests passed"; then
  echo "$selftest_out"
  passed=$(( passed + 1 ))
else
  echo "crackle -t FAILED:"; printf '%s\n' "$selftest_out"
  failed=$(( failed + 1 ))
fi

emit_ctrf "crackle-run_tests" "$passed" "$failed"
