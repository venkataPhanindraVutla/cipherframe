#!/bin/sh
# Self-test of secret-scan.sh: it passes clean input, fails on a planted secret and on a signed URL
# parameter, and never prints a secret value.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
mkdir "${tmp}/out"
printf 'api-key=test-fixture-secret-value-1\nsession-id=test-fixture-session-value-2\n' > "${tmp}/secrets"
printf '{"name":"GET /v1/whoami"}\nlevel=info msg=started\n' > "${tmp}/out/clean.log"

"${here}/secret-scan.sh" "${tmp}/secrets" "${tmp}/out" >/dev/null

printf 'level=info something test-fixture-session-value-2 more\n' > "${tmp}/out/leaky.log"
code=0
"${here}/secret-scan.sh" "${tmp}/secrets" "${tmp}/out" > "${tmp}/report" 2>&1 || code=$?
test "${code}" = 1
grep -q 'LEAK: session-id found in .*leaky.log' "${tmp}/report"
if grep -q 'test-fixture' "${tmp}/report"; then echo "the report shows a secret value"; exit 1; fi

rm "${tmp}/out/leaky.log"
printf 'GET /x?X-Amz-Signature=abc\n' > "${tmp}/out/url.log"
code=0
"${here}/secret-scan.sh" "${tmp}/secrets" "${tmp}/out" > "${tmp}/report" 2>&1 || code=$?
test "${code}" = 1
grep -q 'LEAK: signed-url-parameter found in .*url.log' "${tmp}/report"
echo "secret-scan self-test OK"
