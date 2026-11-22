#!/bin/sh
# End to end check of the cipherframe command line tool against the running development stack
# (ADR 0051): upload a small video, wait for it to be ready, list it, delete it with --wait and
# verify the printed deletion record against the server's published keys.
#
# Usage: deploy/compose/cli-e2e.sh CIPHERFRAME_BINARY VIDEO_FILE
# Needs: the stack and the worker running (docker compose --profile worker), curl and jq.
set -eu

cf="$1"
video="$2"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

CIPHERFRAME_API_KEY="$(docker compose run --rm -T --no-deps server admin bootstrap --tenant-name cli-e2e --client-name cli-e2e)"
echo "::add-mask::${CIPHERFRAME_API_KEY}"
case "${CIPHERFRAME_API_KEY}" in cf_*_*) ;; *) echo "bootstrap did not print a key"; exit 1 ;; esac
export CIPHERFRAME_API_KEY
export CIPHERFRAME_SERVER=http://127.0.0.1:8080

id="$("${cf}" upload "${video}" --wait --wait-timeout 10m)"
case "${id}" in ast_*) ;; *) echo "upload did not print an asset ID: ${id}"; exit 1 ;; esac
echo "uploaded ${id}"

test "$("${cf}" status "${id}" --json | jq -r .state)" = ready
"${cf}" inspect "${id}" | jq -e --arg id "${id}" '.id == $id and .state == "ready"' >/dev/null
"${cf}" list --json | jq -e --arg id "${id}" '[.items[].id] | index($id) != null' >/dev/null
echo "listed ${id}"

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
