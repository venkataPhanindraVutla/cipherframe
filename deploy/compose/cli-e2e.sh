#!/bin/sh
# End to end check of the cipherframe command line tool against the running development stack
# (ADR 0051): upload a small video, wait for it to be ready, list it, delete it with --wait and
# verify the printed deletion record against the server's published keys. Before the delete it also
# runs the M8-1b commands: a playback session, an inclusion proof and verify-file on one fetched
# segment, a subtitle import and the session revoke.
#
# Usage: deploy/compose/cli-e2e.sh CIPHERFRAME_BINARY VIDEO_FILE
# Needs: the stack and the worker running (docker compose --profile worker), curl and jq.
#
# With CIPHERFRAME_SCAN_SECRETS_FILE set to a path (in a private temp directory, not the job log) it
# also writes one "kind=value" line for every secret the run handled, for secret-scan.sh (ADR 0058).
set -eu

cf="$1"
video="$2"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

# record KIND VALUE: hand a secret to the end to end scan. Nothing is printed.
record() {
  [ -z "${CIPHERFRAME_SCAN_SECRETS_FILE:-}" ] || (umask 077; printf '%s=%s\n' "$1" "$2" >> "${CIPHERFRAME_SCAN_SECRETS_FILE}")
}

CIPHERFRAME_API_KEY="$(docker compose run --rm -T --no-deps server admin bootstrap --tenant-name cli-e2e --client-name cli-e2e)"
echo "::add-mask::${CIPHERFRAME_API_KEY}"
case "${CIPHERFRAME_API_KEY}" in cf_*_*) ;; *) echo "bootstrap did not print a key"; exit 1 ;; esac
export CIPHERFRAME_API_KEY
export CIPHERFRAME_SERVER=http://127.0.0.1:8080
record api-key "${CIPHERFRAME_API_KEY}"
record api-key-secret-part "${CIPHERFRAME_API_KEY##*_}"
record metrics-scrape-token "$(cat "$(dirname "$0")/../observability/dev/metrics-token")"

id="$("${cf}" upload "${video}" --wait --wait-timeout 10m)"
case "${id}" in ast_*) ;; *) echo "upload did not print an asset ID: ${id}"; exit 1 ;; esac
echo "uploaded ${id}"

# The source object key and the multipart upload ID never leave the server: none may reach a span or
# a log. They exist until the asset is deleted, so read them now.
if [ -n "${CIPHERFRAME_SCAN_SECRETS_FILE:-}" ]; then
  docker compose exec -T postgres psql -U cipherframe -d cipherframe -At -F ' ' \
    -c "SELECT source_key, coalesce(s3_upload_id, '') FROM assets WHERE source_key IS NOT NULL" |
    while read -r skey uid; do
      echo "::add-mask::${skey}"
      record source-object-key "${skey}"
      [ -z "${uid}" ] || { echo "::add-mask::${uid}"; record upload-id "${uid}"; }
    done
fi

test "$("${cf}" status "${id}" --json | jq -r .state)" = ready
"${cf}" inspect "${id}" | jq -e --arg id "${id}" '.id == $id and .state == "ready"' >/dev/null
"${cf}" list --json | jq -e --arg id "${id}" '[.items[].id] | index($id) != null' >/dev/null
echo "listed ${id}"

# M8-1b: a session, one segment fetched through it, its proof and a verify-file of it.
sess="$("${cf}" session create "${id}" --show-token --json)"
sid="$(printf '%s' "${sess}" | jq -r .session_id)"
token="$(printf '%s' "${sess}" | jq -r .token)"
murl="$(printf '%s' "${sess}" | jq -r .manifest_url)"
echo "::add-mask::${token}"
echo "::add-mask::${sid}"
record playback-token "${token}"
record session-id "${sid}"
printf '%s' "${sess}" | jq -e '.heartbeat_interval_seconds > 0' >/dev/null
"${cf}" session show "${sid}" --json | jq -e '.state == "active"' >/dev/null
rend="$(curl -fsS -H "Authorization: Bearer ${token}" "${murl}" | grep -v '^#' | head -n 1 | cut -d/ -f1)"
seg="${rend}/seg-0.m4s"
curl -fsS -H "Authorization: Bearer ${token}" "${murl%/master.m3u8}/${seg}" -o "${tmp}/seg.m4s"
curl -fsS -H "Authorization: Bearer ${CIPHERFRAME_API_KEY}" "${CIPHERFRAME_SERVER}/v1/assets/${id}/manifest" > "${tmp}/manifest.json"
"${cf}" proof "${id}" "${seg}" > "${tmp}/proof.json"
"${cf}" verify --manifest "${tmp}/manifest.json" --proof "${tmp}/proof.json" \
  --keys-url "${CIPHERFRAME_SERVER}/.well-known/cipherframe-keys.json" "${tmp}/seg.m4s" >/dev/null
"${cf}" verify-file "${id}" "${tmp}/seg.m4s" --path "${seg}" --json | jq -e '.outcome == "ours"' >/dev/null
cp "${tmp}/seg.m4s" "${tmp}/bad.m4s"
printf x >> "${tmp}/bad.m4s"
code=0
"${cf}" verify-file "${id}" "${tmp}/bad.m4s" --path "${seg}" >/dev/null || code=$?
test "${code}" = 1
echo "session, proof and verify-file of ${seg} OK"

printf 'WEBVTT\n\n00:00.000 --> 00:01.500\nhello\n' > "${tmp}/en.vtt"
"${cf}" subtitles import "${id}" "${tmp}/en.vtt" --language en --label English --default --json |
  jq -e '.language == "en" and .default == true' >/dev/null
test "$("${cf}" subtitles list "${id}" --json | jq '.items | length')" = 1
echo "subtitle imported"

"${cf}" session revoke "${sid}" --reason cli-e2e --json | jq -e '.state == "revoked"' >/dev/null
test "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${token}" "${murl}")" = 401
echo "session revoked"

"${cf}" delete "${id}" --wait > "${tmp}/record.json"
"${cf}" verify --deletion-record "${tmp}/record.json" --json \
  --keys-url http://127.0.0.1:8080/.well-known/cipherframe-keys.json |
  jq -e --arg id "${id}" '.outcome == "ours" and .record.asset_id == $id' >/dev/null
echo "deletion record of ${id} verified"

# The same record again, by its own command, and a missing asset's exit code (5, not found).
"${cf}" deletion-record "${id}" | cmp - "${tmp}/record.json"
code=0
"${cf}" deletion-record ast_00000000000000000000000000 >/dev/null 2>&1 || code=$?
test "${code}" = 5
echo "cli e2e OK"
