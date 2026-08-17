# ara-aggregator

Proof-of-concept aggregator for the [Aggregated Revocation Artifact (ARA) for C2PA proposal](../ara-for-c2pa.md). Given one or more PEM bundles for a single trust list, it:

1. Loads each certificate in each bundle.
2. Extracts CRL Distribution Point (CDP) URIs from each cert and downloads the referenced CRLs.
3. Parses each CRL into a deduplicated table of `(issuer SKI, serial number, revocation date)` entries.
4. Records every issuer whose CRL was successfully processed in the `coveredIssuers` set, with the source's `thisUpdate` as `lastUpdate`; issuers whose data could not be fetched or parsed are marked `stale`.
5. Generates an ECDSA P-256 key pair (unless one is supplied), CBOR-encodes the artifact and signs it as a **COSE_Sign1**, and writes the signed artifact, a JSON debug projection, and the publisher's keys to an output directory.

The artifact format (CDDL) is documented in [`../ara-for-c2pa.md`](../ara-for-c2pa.md#artifact-format).

## Build

```
cargo build --release
```

## Run

Each `--certs` flag accepts either a local PEM file path or an `http(s)://` URL, and may be repeated. Run the aggregator separately for each trust list; v0.3 artifacts contain no cross-list `scope` field.

```
cargo run --release -- \
  --certs https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TRUST-LIST.pem \
  --certs https://contentcredentials.org/trust/anchors.pem \
  --out     ../sample \
  --trust-list-id "C2PA-2026-05"
```

Add `--inject-entries <file>` to merge synthetic entries (e.g. for demo or test scenarios) into the artifact. The file is a JSON array of objects (`issuer_ski` hex, `serial_number` hex, `revocation_date` RFC 3339); see `../sample/inject-demo.json`. Each injected issuer is also added to the coverage set, since an injected revocation is only authoritative for a covered issuer.

Outputs in `--out`:

* `artifact.cose` — CBOR artifact signed as a COSE_Sign1 (ES256). **This is the signed truth** the validator consumes.
* `artifact.json` — pretty-printed JSON debug projection (the proposal's Appendix A form: hex SKI/serial, ISO dates), for inspection only.
* `publisher.jwk` — P-256 public key in JWK form (`kty: "EC"`, `crv: "P-256"`), to be embedded in or distributed alongside a validator.
* `publisher.key.jwk` — the matching private key. **Do not redistribute.** Only emitted when a fresh key was generated.

## Caveats

* Many C2PA trust anchors are self-signed root CAs that carry no CDP extension — there is simply no CRL URL to fetch from a root. To gather meaningful revocation data, the input PEMs should include intermediate CAs in each chain (whose CDPs point to the CRLs the root publishes about them) and ideally the EE certs whose issuers' CRLs we want to consume. The PoC just iterates whatever certs are in the input and logs which ones lacked a CDP. Where to source intermediates is an open question — see [the design doc's "Sourcing intermediate certs" section](../ara-for-c2pa.md#sourcing-intermediate-certs).
* CDP entries pointing to non-HTTP(S) URIs (e.g., LDAP) are skipped with a warning.
* CRLs that fail to fetch or parse are skipped with a warning; the affected issuer is marked `stale` in the coverage set, the artifact is still emitted from the CRLs that did succeed, and `partial: true` is set in the artifact metadata.
