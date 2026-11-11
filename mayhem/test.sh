#!/usr/bin/env bash
# Runs the known-answer probe build.sh produced (mayhem/kat_probe.c, linked against upstream's own
# libibmad/libibnetdisc/util built with its normal flags) and maps its PASS/FAIL lines to CTRF.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

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

EXPECTED=27
PROBE="$SRC/kat_probe"
[ -x "$PROBE" ] || { echo "missing $PROBE: mayhem/build.sh did not produce it" >&2; emit_ctrf kat-probe 0 1; exit $?; }

out="$("$PROBE" 2>&1)"; rc=$?
printf '%s\n' "$out"
passed=$(printf '%s\n' "$out" | grep -c '^PASS: ')
failed=$(printf '%s\n' "$out" | grep -c '^FAIL: ')
# a probe that was neutered (no output) or crashed must not pass: demand every assertion reported
if [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ]; then failed=1; fi
if [ "$passed" -lt "$EXPECTED" ]; then failed=$(( failed + EXPECTED - passed )); fi
emit_ctrf kat-probe "$passed" "$failed"
