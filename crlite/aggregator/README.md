# crlite-aggregator

Proof-of-concept aggregator for the [CRLite for C2PA proposal](../crlite.md). Given one or more anchor PEM bundles and (optionally) one or more TSA PEM bundles, it:

1. Loads each certificate in each bundle.
2. Extracts CRL Distribution Point (CDP) URIs from each cert and downloads the referenced CRLs.
3. Parses each CRL into a deduplicated table of `(scope, issuer SKI, serial, revocation date)` entries.
4. Generates a fresh Ed25519 key pair (unless one is supplied), produces a signed JSON revocation artifact, and writes the artifact, its JWS, and the publisher's public key to an output directory.

The artifact format is documented in [`../crlite.md`](../crlite.md).

## Build

```
cargo build --release
```

## Run

Each `--anchors` / `--tsa` flag accepts either a local PEM file path or an `http(s)://` URL, and may be repeated.

```
cargo run --release -- \
  --anchors https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TRUST-LIST.pem \
  --anchors https://contentcredentials.org/trust/anchors.pem \
  --tsa     https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TSA-TRUST-LIST.pem \
  --out     ../sample \
  --trust-list-version "C2PA-2026-05"
```

Add `--inject-entries <file>` to merge synthetic entries (e.g. for demo or test scenarios) into the artifact. The file is a JSON array of Entry objects (`scope`, `issuer_ski`, `serial`, `revocation_date`); see `../sample/inject-demo.json`.

Outputs in `--out`:

* `artifact.json` — pretty-printed revocation artifact (for inspection).
* `artifact.jws` — compact EdDSA JWS over the canonical JSON encoding of the artifact (this is the signed truth).
* `publisher.jwk` — Ed25519 public key in JWK form, to be embedded in or distributed alongside a validator.
* `publisher.key.jwk` — the matching private key. **Do not redistribute.** Only emitted when a fresh key was generated.

## Caveats

* Many C2PA trust anchors are self-signed root CAs that carry no CDP extension — there is simply no CRL URL to fetch from a root. To gather meaningful revocation data, the input PEMs should include intermediate CAs in each chain (whose CDPs point to the CRLs the root publishes about them) and ideally the EE certs whose issuers' CRLs we want to consume. The PoC just iterates whatever certs are in the input and logs which ones lacked a CDP. Where to source intermediates is an open question — see [the design doc's "Sourcing intermediate certs" section](../crlite.md#sourcing-intermediate-certs).
* CDP entries pointing to non-HTTP(S) URIs (e.g., LDAP) are skipped with a warning.
* CRLs that fail to fetch or parse are skipped with a warning; the artifact is still emitted from the CRLs that did succeed, with `partial: true` set in the artifact metadata.
