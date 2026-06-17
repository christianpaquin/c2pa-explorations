#!/usr/bin/env bash
# End-to-end demo for the Aggregated Revocation Artifact (ARA) proof of concept.
#
# Drives the full pipeline:
#   1. Build the aggregator and validator.
#   2. Aggregate revocation data from the C2PA Trust Lists.
#   3. Validate a signed asset against the resulting artifact (clean run).
#   4. Re-aggregate with synthetic injected entries pinned to that asset's
#      claim-signing and TSA certs, exercising the temporal logic both ways.
#
# Asset under test: c2pa-rs's CA.jpg fixture. Override via $C2PA_ASSET.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSET="${C2PA_ASSET:-/home/cpaquin/dev/c2pa/c2pa-rs/sdk/tests/fixtures/CA.jpg}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

AGG="$REPO_ROOT/aggregator/target/release/ara-aggregator"
VAL="$REPO_ROOT/validator/target/release/ara-validator"

hdr() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }

hdr "Building aggregator and validator (release)"
( cd "$REPO_ROOT/aggregator" && cargo build --release --quiet )
( cd "$REPO_ROOT/validator"  && cargo build --release --quiet )

hdr "Step 1: aggregate from the live C2PA trust lists (clean)"
"$AGG" \
  --anchors https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TRUST-LIST.pem \
  --anchors https://contentcredentials.org/trust/anchors.pem \
  --tsa     https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TSA-TRUST-LIST.pem \
  --out     "$OUT/clean" \
  --trust-list-id "C2PA-demo-clean" 2>&1 | tail -3
echo

hdr "Step 2: validate $ASSET against the CLEAN artifact (expect both PASS — issuers not covered, --uncovered-policy=warn)"
set +e
"$VAL" \
  --artifact "$OUT/clean/artifact.cose" \
  --pubkey "$OUT/clean/publisher.jwk" \
  --trust-list-id "C2PA-demo-clean" \
  "$ASSET"
clean_exit=$?
set -e
printf '\nClean exit: %d\n' "$clean_exit"

hdr "Step 3: re-aggregate with synthetic injected revocations for that asset's certs"
"$AGG" \
  --anchors https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TRUST-LIST.pem \
  --tsa     https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TSA-TRUST-LIST.pem \
  --inject-entries "$REPO_ROOT/sample/inject-demo.json" \
  --out     "$OUT/injected" \
  --trust-list-id "C2PA-demo-injected" 2>&1 | tail -8
echo

hdr "Step 4: validate $ASSET against the INJECTED artifact (expect claim FAIL, TSA PASS — injected issuers are now covered)"
set +e
"$VAL" \
  --artifact "$OUT/injected/artifact.cose" \
  --pubkey "$OUT/injected/publisher.jwk" \
  --trust-list-id "C2PA-demo-injected" \
  "$ASSET"
injected_exit=$?
set -e
printf '\nInjected exit: %d\n' "$injected_exit"

hdr "Summary"
printf 'Clean artifact run:    exit %d (0 = both PASS, as expected)\n' "$clean_exit"
printf 'Injected artifact run: exit %d (1 = claim cert revoked, as expected)\n' "$injected_exit"
if [ "$clean_exit" -eq 0 ] && [ "$injected_exit" -eq 1 ]; then
  printf '\n\033[1;32mDemo passed.\033[0m\n'
  exit 0
else
  printf '\n\033[1;31mDemo did NOT match expected outcomes.\033[0m\n'
  exit 1
fi
