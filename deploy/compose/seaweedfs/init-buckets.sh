#!/bin/sh
# Creates the Cipherframe buckets and proves they are private. Safe to run on every `up`
# (ADR 0014): creating an existing bucket is skipped, and the anonymous check runs every time.
set -eu

MASTER="${SEAWEED_MASTER:-seaweedfs:9333}"
S3_URL="${SEAWEED_S3_URL:-http://seaweedfs:8333}"
BUCKETS="${BUCKETS:-cipherframe-source cipherframe-delivery}"

list_buckets() { printf 's3.bucket.list\n' | weed shell -master="$MASTER" 2>&1; }

for b in $BUCKETS; do
  if list_buckets | grep -q "^[[:space:]]*$b\([[:space:]]\|\$\)"; then
    echo "bucket $b exists"
  else
    echo "creating bucket $b"
    printf 's3.bucket.create -name %s\n' "$b" | weed shell -master="$MASTER"
  fi
done

# Verify: every bucket exists and an anonymous GET is refused with 403.
listing="$(list_buckets)"
for b in $BUCKETS; do
  printf '%s\n' "$listing" | grep -q "^[[:space:]]*$b\([[:space:]]\|\$\)" || {
    echo "FAIL: bucket $b missing" >&2
    exit 1
  }
  status="$(wget -S -O /dev/null "$S3_URL/$b/" 2>&1 | awk '/^ *HTTP\// {print $2}' | tail -n1)"
  if [ "$status" != "403" ]; then
    echo "FAIL: anonymous GET of $b returned '${status:-no response}', expected 403" >&2
    exit 1
  fi
  echo "bucket $b is private (anonymous GET: 403)"
done
