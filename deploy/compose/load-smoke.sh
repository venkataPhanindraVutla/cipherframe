#!/bin/sh
# Smoke test of cipherframe-load (ADR 0061) against the running development stack: two viewers play
# for about 20 seconds in each delivery mode, then one clip is transcoded. It checks that the tool
# works and that nothing it prints or writes holds a secret; it measures nothing.
#
# Usage: deploy/compose/load-smoke.sh CIPHERFRAME_BINARY CIPHERFRAME_LOAD_BINARY VIDEO_FILE MEDIA_SECONDS
# Needs: the stack and the worker running (docker compose --profile worker) and curl.
set -eu

cf="$1"
load="$2"
video="$3"
secs="$4"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

key="$(docker compose run --rm -T --no-deps server admin bootstrap --tenant-name load-smoke --client-name load-smoke)"
echo "::add-mask::${key}"
printf '%s' "${key}" > "${tmp}/key"
export CIPHERFRAME_SERVER=http://127.0.0.1:8080

id="$("${cf}" upload "${video}" --wait --wait-timeout 10m --api-key-file "${tmp}/key")"
case "${id}" in ast_*) ;; *) echo "upload did not print an asset ID"; exit 1 ;; esac

for mode in proxy presigned; do
  "${load}" play --asset "${id}" --delivery "${mode}" --api-key-file "${tmp}/key" --start 2 --step 2 --max 2 \
    --step-duration 20s --settle 2s --speed 3 --raw "${tmp}/raw-${mode}.csv" --summary "${tmp}/sum-${mode}.csv" > "${tmp}/out-${mode}.txt"
  grep -q 'highest passing step: 2 viewers' "${tmp}/out-${mode}.txt"
  grep -q ',segment,' "${tmp}/sum-${mode}.csv"
done

"${load}" transcode --file "${video}" --media-seconds "${secs}" --jobs 1 --api-key-file "${tmp}/key" \
  --raw "${tmp}/raw-transcode.csv" --summary "${tmp}/sum-transcode.csv" > "${tmp}/out-transcode.txt"
grep -q ',transcode,' "${tmp}/sum-transcode.csv"

# No token, session ID or key in anything the tool wrote or printed.
if grep -rIlE 'ses_[a-z0-9]{20}|cf_[A-Za-z0-9]+_|v1\.[A-Za-z0-9_-]{20}|X-Amz-Signature' "${tmp}"/out-* "${tmp}"/raw-* "${tmp}"/sum-*; then
  echo "a secret-looking value is in the load tool's output"; exit 1
fi
if grep -rIlF "${key}" "${tmp}"/out-* "${tmp}"/raw-* "${tmp}"/sum-*; then
  echo "the API key is in the load tool's output"; exit 1
fi
"${cf}" delete "${id}" --wait --api-key-file "${tmp}/key" >/dev/null
echo "load smoke OK"
