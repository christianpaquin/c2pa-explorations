# ara-validator

Proof-of-concept C2PA validator wrapper for the [Aggregated Revocation Artifact (ARA) for C2PA proposal](../ara-for-c2pa.md). It uses [`c2pa-rs`](https://github.com/contentauth/c2pa-rs) to read a signed asset, then post-processes the claim-signing and TSA certificates' revocation status against a signed revocation artifact produced by [`../aggregator`](../aggregator/).

## Build

```
cargo build --release
```

## Run

```
cargo run --release -- \
  --artifact ../sample/artifact.cose \
  --pubkey   ../sample/publisher.jwk \
  --trust-list-id C2PA-sample \
  --rollback-state ~/.cache/ara-validator/state.json \
  --grace-days 30 \
  --uncovered-policy warn \
  path/to/signed-asset.jpg
```

To perform the optional TSA check, also pass `--tsa-artifact`, `--tsa-pubkey`, and `--tsa-trust-list-id` for an artifact bound to the TSA trust list. All three options must be supplied together.

Exit status: `0` if the claim-signing revocation check passed, `1` if it failed (cert revoked at/before signing time, coverage stale, or not-covered under `--uncovered-policy refuse`). TSA revocation is informational and never directly makes the claim fail.

## What it does

1. Loads `artifact.cose`, verifies its ES256 (ECDSA P-256) COSE_Sign1 signature against `publisher.jwk`, CBOR-decodes the payload, and enforces the required `--trust-list-id` binding.
2. Enforces freshness and rejects rollback using the greatest `generatedAt` previously recorded for each trust list in `--rollback-state`.
3. Opens the asset with `c2pa::Reader::with_file`, takes the active manifest's `SignatureInfo`.
4. Parses the PEM cert chain, extracts the claim-signing (leaf) certificate's AKI (= the issuer SKI) and serial number.
5. Determines `T_sig` from the manifest's `time` field (set by `c2pa-rs` from the trusted timestamp). Falls back to `now` with a warning if no trusted timestamp is present.
6. Applies the v0.3 **coverage-set decision logic** for `(issuerSKI, serialNumber)`:
  * **Issuer covered and fresh** → authoritative: revoked iff an entry exists and `T_sig >= revocationDate`; otherwise good standing.
   * **Issuer covered but stale** → fail the revocation step (cannot assert non-revocation).
   * **Issuer not covered** → if the COSE_Sign1 carries an OCSP staple (`rVals`), report the legacy path (staple consultation is out of scope for the PoC); otherwise apply `--uncovered-policy` (`warn` → pass with a warning, `refuse` → fail).
7. When the optional TSA artifact is supplied, extracts the TSA signing cert from the COSE_Sign1's `sigTst` (v1) or `sigTst2` (v2) unprotected header and checks it against that artifact using the time attested by the timestamp. A revoked TSA cert records `timeStamp.ara.revoked` and causes the timestamp to be ignored rather than failing the claim.

## Limitations

The validator does *not* perform broader C2PA validity checks beyond what `c2pa::Reader::with_file` does at load time — its sole job is to plug the new revocation step into the existing C2PA validation pipeline. For not-covered issuers it only *detects* an OCSP staple's presence; it does not consult or verify it.

See [the design doc's Future work and known gaps](../ara-for-c2pa.md#future-work-and-known-gaps) for the canonical list of PoC gaps (test certificates, production policy choices, etc.).
