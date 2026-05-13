# crlite-validator

Proof-of-concept C2PA validator wrapper for the [CRLite for C2PA proposal](../crlite.md). It uses [`c2pa-rs`](https://github.com/contentauth/c2pa-rs) to read a signed asset, then post-processes the claim-signing certificate's revocation status against a signed revocation artifact produced by [`../aggregator`](../aggregator/).

## Build

```
cargo build --release
```

## Run

```
cargo run --release -- \
  --artifact ../sample/artifact.jws \
  --pubkey   ../sample/publisher.jwk \
  --grace-days 30 \
  path/to/signed-asset.jpg
```

Exit status: `0` if the revocation check passed (cert not in the artifact, or revoked strictly after signing time), `1` if the cert was revoked at or before the signing time.

## What it does

1. Loads `artifact.jws` and verifies its ES256 (ECDSA P-256) signature against `publisher.jwk`.
2. Enforces freshness: rejects the artifact if `now > next_update + grace_days`.
3. Opens the asset with `c2pa::Reader::from_file`, takes the active manifest's `SignatureInfo`.
4. Parses the PEM cert chain, extracts the claim-signing (leaf) certificate's AKI (= the issuer SKI) and serial number.
5. Determines `T_sig` from the manifest's `time` field (set by `c2pa-rs` from the trusted timestamp). Falls back to `now` with a warning if no trusted timestamp is present.
6. Looks up `(scope=anchors, issuer_ski, serial)` in the artifact. If a match exists and `T_sig ≥ revocation_date`, reports the cert as revoked at signing time and exits non-zero.
7. Extracts the TSA's signing cert from the COSE_Sign1's `sigTst` (v1) or `sigTst2` (v2) unprotected header — pulls JUMBF directly via `c2pa::jumbf_io::load_jumbf_from_file`, finds the `c2pa.signature` data box, parses the COSE_Sign1 with `coset`, walks into the TimeStampToken (CMS `ContentInfo`/`SignedData` via the `cms` crate), and extracts the first cert in `SignedData.certificates`. Looks it up with `scope=tsa`.

## Limitations

The validator does *not* perform broader C2PA validity checks beyond what `c2pa::Reader::with_file` does at load time — its sole job is to plug the new revocation step into the existing C2PA validation pipeline.

See [the design doc's Future work and known gaps](../crlite.md#future-work-and-known-gaps) for the canonical list of PoC gaps (TSA cert handling, test certificates, etc.).
