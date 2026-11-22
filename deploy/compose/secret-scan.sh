#!/bin/sh
# End to end secret scan (pitfall 9, ADR 0053 and 0058): fails when any secret that a run handled
# appears in the spans or the container logs it produced.
#
# Usage: deploy/compose/secret-scan.sh SECRETS_FILE PATH...
#   SECRETS_FILE has one "kind=value" line per secret the run handled (written by cli-e2e.sh into a
#   temp directory, never into the job log). Each PATH is a file or a directory, scanned recursively.
#
# Output: only the kind of secret and the file that matched, never a value. Values reach grep
# through a file, not through a command line.
set -eu

secrets="$1"
shift
[ -s "${secrets}" ] || { echo "secret-scan: no secrets file, or it is empty"; exit 2; }
[ "$#" -gt 0 ] || { echo "secret-scan: no path to scan"; exit 2; }
for p in "$@"; do
  [ -e "${p}" ] || { echo "secret-scan: nothing to scan at ${p}"; exit 2; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
hits=0
checked=0

# check KIND PATTERN_FILE PATH...: report every file under the paths that contains a pattern.
check() {
  kind="$1" patfile="$2"
  shift 2
  checked=$((checked + 1))
  found="$(grep -rlF -f "${patfile}" -- "$@" 2>/dev/null || true)"
  [ -n "${found}" ] || return 0
  printf '%s\n' "${found}" | while IFS= read -r f; do echo "LEAK: ${kind} found in ${f}"; done
  hits=$((hits + 1))
}

# The parameters of a signed URL must never appear, whatever their value.
printf '%s\n' X-Amz-Signature X-Amz-Credential X-Amz-Security-Token > "${tmp}/names"
check signed-url-parameter "${tmp}/names" "$@"

while IFS= read -r line || [ -n "${line}" ]; do
  [ -n "${line}" ] || continue
  kind="${line%%=*}"
  value="${line#*=}"
  if [ "${#value}" -lt 8 ]; then
    echo "secret-scan: the value of ${kind} is too short to scan for"
    exit 2
  fi
  printf '%s\n' "${value}" > "${tmp}/pat"
  check "${kind}" "${tmp}/pat" "$@"
done < "${secrets}"

if [ "${hits}" -gt 0 ]; then
  echo "secret-scan: ${hits} kind(s) of secret found"
  exit 1
fi
echo "secret-scan: ${checked} pattern(s) checked in $# path(s), no secret found"
