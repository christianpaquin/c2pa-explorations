# CRLite for C2PA proposal

_draft 0.1_

This document proposes a [CRLite](https://github.com/mozilla/crlite)-inspired mechanism for proving non-revocation of C2PA signing certificates. The goal is to replace per-signature OCSP stapling with a single, periodically-refreshed, signed revocation artifact published alongside the [C2PA Trust List](https://c2pa.org/conformance/). Validators consult the local artifact at validation time and need no network call to a CA.

This is exploratory work intended to demonstrate feasibility through a proof-of-concept; any actual spec change would be a separate, later effort.

## Justification

The current [C2PA core specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html) requires a claim signer to embed a stapled OCSP response in the COSE signature as the means of proving non-revocation, and disallows CRLs. This has several costs:

* **Signer-side network dependency** — every signing operation must reach an OCSP responder to obtain a fresh response. This complicates offline or batch signing and ties the signer to the issuing CA's OCSP availability.
* **Per-manifest overhead** — each OCSP response (~1–2 KB) is carried in every manifest. For platforms generating many small assets this adds up.
* **Validator-side privacy leak in the OCSP-fallback case** — if validators ever need to refresh, they leak validation activity to the issuing CA.
* **No global revocation view** — there is no single artifact a verifier can audit to see "what is currently revoked across the C2PA ecosystem?"

[CRLite](https://blog.mozilla.org/security/2020/01/09/crlite-part-1-all-web-pki-revocations-compressed/) was designed to solve a comparable set of problems for the WebPKI by centrally aggregating all CA-published CRLs into a compact filter that browsers ship and consult offline. C2PA is a far friendlier environment for this approach because the certificate universe is bounded by the C2PA Trust List — orders of magnitude smaller than the WebPKI — and because there is already a natural publishing authority (the C2PA conformance program) governing the trust list.

## Description

### Overview

A trusted aggregator — naturally the same entity that publishes the [C2PA Trust List](https://github.com/c2pa-org/conformance-public/) — periodically:

1. Reads the current trust list (anchors).
2. For each anchor, dereferences its CRL Distribution Point (CDP) extension and downloads the issuer's CRL.
3. Merges all CRL entries into a single deduplicated table keyed by `(issuer SKI, certificate serial)`.
4. Wraps the table in a signed artifact and publishes it at a well-known URL alongside the trust list.

Validators fetch the artifact on their normal trust-list refresh schedule, verify its signature, and consult it locally during manifest validation. No per-signature OCSP staple is needed if a fresh artifact is available.

A single artifact covers both the claim-signing anchors and the TSA trust list, with each entry tagged by scope. Splitting into two files was considered (cleaner scope boundaries, potentially independent governance) but rejected in favor of a single file for simpler validator fetch logic.

### Naming

We call this "CRLite-inspired" rather than "CRLite." At C2PA's expected scale (anchors counted in tens, end-entity certs plausibly in the low thousands) the cascading-Bloom-filter / Clubcard compression that makes CRLite a notable engineering result is not strictly necessary: a flat deduplicated list fits comfortably in a few tens of KB. We borrow the *concept* — central aggregation, signed push to clients, offline lookup — and leave the filter-compression machinery as a future option for if/when the universe grows.

### Temporal model

This is the central design choice and the place where the C2PA setting genuinely differs from WebPKI CRLite.

WebPKI CRLite answers: "Is this certificate revoked **now**?" A revoked TLS cert simply fails the handshake; there is no historical authenticity to preserve.

C2PA needs to answer: "Was this certificate valid **at signing time `T_sig`**, as attested by a trusted [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp?" A claim signed in 2024 by a cert revoked in 2026 must still validate, provided the revocation was not for `keyCompromise` (which by [RFC 5280 §5.3.2](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.2) implicates earlier signatures as well).

This proposal adopts a **revocation-date-aware** model: rather than a pure set-membership filter answering yes/no, the artifact stores the revocation date for each revoked certificate. A validator with signing time `T_sig` treats a certificate as revoked if and only if an entry exists for it AND `T_sig ≥ revocation_date`.

#### Alternatives considered

A **reason-aware** variant would additionally store the [RFC 5280 §5.3.1](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1) reason code and apply different rules per reason — for example, `keyCompromise` would invalidate all earlier signatures unconditionally, while `affiliationChanged` or `cessationOfOperation` would only invalidate signatures after `revocation_date`. This more faithfully captures the intent of [RFC 5280 §5.3.2](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.2). It is deferred to future work — conservative treatment of all revocations (the option chosen) is safer for a first draft, and reason codes in real-world CRLs are widely known to be inconsistently populated.

A second alternative — pure **snapshot lookup** with rolling dated filters — was also considered but rejected: it pushes complexity onto the publisher (history retention) and the validator (selecting the right snapshot) without materially improving the answer compared to the date-aware approach.

### Artifact format

For the proof of concept the artifact is a JSON object — easy to inspect, easy to diff, easy to debug. A production version would more naturally use signed CBOR (smaller, matches C2PA's existing COSE/CBOR conventions); the schema below is given in JSON form but maps directly.

```json
{
  "version": 1,
  "trust_list_version": "<identifier of the trust list this corresponds to>",
  "generated_at": "<ISO 8601 UTC>",
  "next_update": "<ISO 8601 UTC, after which validators should consider it stale>",
  "entries": [
    {
      "scope": "anchors" | "tsa",
      "issuer_ski": "<hex-encoded SKI of issuing CA>",
      "serial": "<hex-encoded big-endian serial>",
      "revocation_date": "<ISO 8601 UTC>"
    }
  ]
}
```

The artifact is signed by the publisher. For the PoC this is a freshly minted demo key; in production the publisher would be the C2PA conformance program, using a key whose certificate is well-known to validators (analogous to the trust list signing key). The signing format for the PoC is an ES256 (ECDSA P-256) JWS over the canonical JSON encoding of the artifact; the production CBOR version would use COSE_Sign1.

`issuer_ski` is chosen over the issuer's distinguished name because it is short, unambiguous, and directly matches the AKI extension on end-entity certificates, which is what the validator already has in hand.

The `scope` field on each entry distinguishes claim-signing revocations (`anchors`) from TSA revocations (`tsa`), since both are carried in the same artifact.

### Validation procedure

A validator that supports this mechanism, when checking a C2PA claim signature:

1. Load the current revocation artifact, verify its signature against the known publisher key, and check that `now ≤ next_update + grace_window`. If stale, fail the revocation step.
2. Extract the claim-signing certificate from the COSE signature and identify its issuer via the AKI extension.
3. Determine `T_sig` from the embedded `sigTst2` timestamp (per the C2PA spec, signatures should be timestamped by a TSA on the C2PA TSA Trust List).
4. Look up `(issuer_ski, serial)` among entries with `scope == "anchors"` in the artifact. If found and `T_sig ≥ revocation_date`, the certificate is considered revoked at signing time; the signature fails revocation validation.
5. Repeat steps 2–4 for the TSA's signing certificate, looking up against entries with `scope == "tsa"`.

If `T_sig` cannot be determined (no trusted timestamp), the validator falls back to treating `T_sig = now`, with the consequence that any later revocation invalidates the signature. This is consistent with current C2PA practice for untimestamped signatures.

### Freshness

* The aggregator runs **daily**, producing a new artifact each run.
* Each artifact carries `next_update = generated_at + 7 days`, matching typical CA CRL semantics.
* Validators accept the artifact for an additional `grace_window` past `next_update` before treating it as stale. For the PoC, `grace_window = 30 days`, giving a total freshness tolerance of ~37 days from generation. These are tunable and would warrant a C2PA WG conversation in any future spec discussion.

### Relation to OCSP stapling

In the long run the intent is for this mechanism to *replace* per-signature OCSP stapling, not supplement it: clients sign without contacting any OCSP responder, and validators rely on the artifact. The PoC reflects this — it does not consult any stapled OCSP response that may be present in a manifest. The only fallback path is for certificates that do not chain to a known trust list anchor; revocation cannot be checked for those by this mechanism, and a real deployment would need to decide whether to refuse them or fall back to OCSP — out of scope for this PoC.

### Spec changes that would be needed

These are not part of this proof of concept; they are noted here only to indicate the scope of a future spec change that would make this mechanism normative.

* **§13/§14** (signing) — permit signers to omit the stapled OCSP response when an alternative non-revocation artifact is in use.
* **§15.9** (validate credential revocation information) — define the artifact-based validation procedure described above as a permitted means of satisfying the revocation check.
* **New §14.x** (revocation artifact) — define the artifact format, signing requirements, publication URL convention, and freshness semantics.
* **Trust list metadata** — note that each trust list may publish a companion revocation artifact at a sibling URL with a fixed naming convention (e.g., `<trust-list>-revocation.cbor`).

## Security and privacy considerations

* **Centralization** — the artifact's authority equals the trust list publisher's authority. A malicious or compromised publisher could either omit a real revocation (failing open) or fabricate one (denial of service against a specific signer). This is the same trust assumption already made for the trust list itself, so it does not enlarge the attack surface.
* **Stale artifact / replay** — a network attacker could serve an old artifact to mask a recent revocation. Mitigated by the validator-enforced freshness window (`next-update + grace`) and the signed `generated-at` field. Validators that have ever seen a newer artifact MUST NOT accept an older one.
* **CDP unavailability at aggregation time** — if a CA's CRL cannot be fetched, the aggregator must decide between publishing a partial artifact (and marking the affected issuer as stale in metadata) or skipping the update. Default for the PoC: emit a warning, retain the last successfully fetched CRL for that issuer, and surface the staleness in the artifact metadata.
* **Validator privacy** — validators no longer call OCSP responders at validation time, eliminating the corresponding leak of viewing/validation patterns to issuing CAs. This is a meaningful improvement over the OCSP-fallback path.
* **Out-of-scope-revocation** — certificates not chaining to a trust list anchor cannot be checked by this mechanism. For those, the existing OCSP path remains the answer; the proposal does not remove that capability.

## Proof of concept

Planned in this subdirectory:

1. **`aggregator/`** — a small Rust binary that takes one or more anchor PEM files as input, parses each anchor cert (using `x509-parser`), follows each CDP, downloads and parses the CRL, deduplicates entries, and emits a signed CBOR artifact.
2. **`sample/`** — an example output artifact built from the current [official C2PA anchors trust list](https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TRUST-LIST.pem) augmented (for prototyping density only) with the [interim anchors list](https://contentcredentials.org/trust/anchors.pem). The [interim end-entity list](https://verify.contentauthenticity.org/trust/allowed.pem) is deliberately not used: it enumerates leaf certs rather than CAs, and revocation there is already handled by removal from the allowlist.
3. **`validator/`** — a small wrapper around [`c2pa-rs`](https://github.com/contentauth/c2pa-rs) that performs normal C2PA validation, extracts the claim-signing certificate and `sigTst2` time, then post-processes the revocation check against the local artifact.
4. **`demo/`** — sign a sample asset with `c2patool` and run the wrapper validator both on the unmodified asset and on a synthetic scenario with a revoked cert, demonstrating both pass and fail paths.

The PoC is intentionally scoped to the flat-list artifact form. The Clubcard / cascading Bloom variant from upstream CRLite is left as future work; it is only interesting once the universe of C2PA certs is large enough for raw-list size to matter.

## Future work and known gaps

This is the canonical list. The `aggregator/` and `validator/` READMEs link here rather than maintaining their own lists.

### PoC gaps (would be addressed before this is more than a demo)

* **Intermediate cert coverage in the aggregator.** Most certs in the C2PA anchors trust lists are self-signed roots that carry no CDP — the smoke-test run found only ~7 of 47 anchors had a fetchable CRL URL. Meaningful revocation data lives on *intermediate* certs (whose CDPs point to CRLs the root publishes about them) and on *end-entity* certs (whose CDPs point to CRLs the intermediate publishes). Where to source intermediates is the open question, see [Sourcing intermediate certs](#sourcing-intermediate-certs) below.
* **Test certificate minting.** The aggregator now has an `--inject-entries` flag that takes a JSON list of synthetic entries and merges them into the artifact (see `sample/inject-demo.json` and `demo/run.sh`). What's still outstanding is a dedicated test-cert minter — a small helper that produces a fresh test CA + EE cert + matching CRL so the demo doesn't have to pin its synthetic entries to existing fixture certs. Useful once we want regression tests independent of `c2pa-rs` fixtures.
* **TSA cert resolution refinement.** The validator now extracts the TSA cert from the COSE_Sign1's `sigTst`/`sigTst2` header (CMS SignedData inside the TimeStampToken). It currently uses a "first cert in `SignedData.certificates`" heuristic; production should resolve via `SignerInfo.sid` (issuer+serial or SKI) to handle multi-cert chains correctly.
* **Filtering broad-CA noise from the aggregated artifact.** Feeding `allowed.pem` to the aggregator inflates the artifact from ~36 entries to ~101,840 — but the bulk are non-C2PA revocations (e.g., ~36.9k Sectigo email/code-signing entries) pulled in because the C2PA leaves chain through broad-purpose public CAs that publish a single shared CRL across many use cases. A production CRLite-for-C2PA should filter to entries that intersect the C2PA universe — for example, only retain a revoked serial if at least one cert with that `(issuer SKI, serial)` exists under a C2PA-trusted chain. Without this, the artifact balloons in size and most of its entries are irrelevant to C2PA verifiers.

### Design-level extensions (would warrant a C2PA WG conversation)

* **Reason-aware variant.** Extend each entry with the RFC 5280 reason code and differentiate `keyCompromise` (invalidates earlier signatures) from softer reasons. Worth doing once we have evidence that issuers in the C2PA ecosystem populate reason codes reliably.
* **CBOR / COSE_Sign1 artifact.** Replace the PoC's signed-JSON form with the more compact production format.
* **Clubcard / cascade compression.** Only interesting if the C2PA cert universe grows by orders of magnitude beyond the current trust-list scope.
* **Delta artifacts.** Incremental updates rather than full re-publication; same observation as above, only matters at scale.

### Sourcing intermediate certs

Several plausible sources, in roughly increasing order of effort:

1. **Already in the bundles we have.** A few of the "anchors" PEMs really do contain intermediates (the ones whose CDPs the aggregator successfully followed — e.g., the Adobe intermediate at `pki-cdn.adobe.net`). This gives us a *partial* set already.
2. **Embedded in signed C2PA assets.** Every signed C2PA manifest's COSE_Sign1 carries the full `x5chain`. Harvesting intermediates from a corpus of public C2PA-signed media is straightforward (and is how Mozilla CRLite uses Certificate Transparency).
3. **The interim end-entity list (`allowed.pem`).** Despite the design-level rationale for excluding it (its revocation semantics are "remove from the allowlist"), it does enumerate real-world C2PA EE certs whose CDPs point at the right intermediates' CRLs. Feeding `allowed.pem` to the aggregator would yield denser revocation data for demo purposes, with a clear note that this is not the production trust model.
4. **AIA chasing.** Each cert's Authority Information Access extension typically has a `caIssuers` URL pointing to the parent cert. The aggregator could walk this chain upward from any starting point.
5. **CA cert repositories / C2PA conformance program.** Some CAs publish their full intermediate inventory; the conformance program may eventually formalize this.
