# Aggregated Revocation Artifact (ARA) for C2PA

_draft 0.2.1_

This document proposes an **Aggregated Revocation Artifact (ARA)** — a [CRLite](https://github.com/mozilla/crlite)-inspired mechanism for proving non-revocation of C2PA signing certificates. The goal is to replace per-signature OCSP stapling with a single, periodically-refreshed, signed revocation artifact published alongside a [trust list](https://c2pa.org/conformance/) (the C2PA Trust List being the motivating case). Validators consult the local artifact at validation time and need no network call to a CA.

Although C2PA is the motivating deployment, the design is deliberately **trust-list-neutral**: an ARA is bound to a particular trust list, covers that trust list's issuers, and is signed by that trust list's authority. A validator may consult several ARAs — one per trust list it honors — so the mechanism generalizes to any ecosystem that maintains a curated trust list.

This is exploratory work intended to demonstrate feasibility through a proof-of-concept; any actual spec change would be a separate, later effort.

> **Naming note (v0.2).** Earlier drafts called this "CRLite for C2PA." We have renamed it to **Aggregated Revocation Artifact (ARA)** because the design is not CRLite: it carries no cascading-Bloom/Ribbon filter, it is revocation-date-aware rather than a pure set-membership test, and it is bound to a bounded trust list rather than the whole WebPKI. We borrow CRLite's *concept* — central aggregation of CRLs, a signed push to clients, and offline lookup — not its compression machinery. The file is still named `crlite.md` to preserve existing links from the PoC READMEs.

## Justification

The current [C2PA core specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html) requires a claim signer to embed a stapled OCSP response in the COSE signature as the means of proving non-revocation, and disallows CRLs. This has several costs:

* **Signer-side network dependency** — every signing operation must reach an OCSP responder to obtain a fresh response. This complicates offline or batch signing and ties the signer to the issuing CA's OCSP availability.
* **Per-manifest overhead** — each OCSP response (~1–2 KB) is carried in every manifest. For platforms generating many small assets this adds up.
* **Validator-side privacy leak in the OCSP-fallback case** — if validators ever need to refresh, they leak validation activity to the issuing CA.
* **No global revocation view** — there is no single artifact a verifier can audit to see "what is currently revoked across the C2PA ecosystem?"

### OCSP is being deprecated in the WebPKI

Beyond the standing costs above, C2PA's reliance on mandatory OCSP stapling runs **against the direction of the wider WebPKI**, which is actively retiring OCSP in favor of CRLs:

* The CA/Browser Forum's [Ballot SC-063v4](https://cabforum.org/2023/07/14/ballot-sc063v4-make-ocsp-optional-require-crls-and-incentivize-automation/) (passed August 2023) made OCSP **optional** for publicly-trusted CAs and made **CRLs mandatory** — the formal pivot away from OCSP, citing privacy, performance, and operational concerns.
* Let's Encrypt put this into practice: it [announced the end of OCSP in December 2024](https://letsencrypt.org/2024/12/05/ending-ocsp), removed OCSP URLs from newly issued certificates on **7 May 2025**, and [shut down its OCSP responders entirely on **6 August 2025**](https://letsencrypt.org/2025/08/06/ocsp-service-has-reached-end-of-life), citing the privacy leak (the responder learns what a relying party is validating) and the operational cost of running the service. Browsers are following suit — Firefox disabled OCSP querying in version 142 (see [Background](#background-on-crlite) below).

The risk for C2PA is structural: the spec **mandates** the one mechanism the ecosystem is abandoning and **disallows** the one it is standardizing on. As public CAs retire OCSP responders, signers chaining to those CAs may be unable to obtain a staple at all, and C2PA risks being stranded on a legacy mechanism with declining CA support and tooling. (The pressure is currently sharpest for TLS/DV CAs; the code- and document-signing CAs closer to C2PA's usage may retain OCSP somewhat longer — but the direction of travel is unambiguous, and C2PA should not stake its only non-revocation path on it.) An aggregated, CRL-derived artifact aligns C2PA with where the WebPKI is heading.

## Background on CRLite

[CRLite](https://blog.mozilla.org/security/2020/01/09/crlite-part-1-all-web-pki-revocations-compressed/) was introduced by Mozilla (originally a [2017 IEEE S&P paper by Larisch et al.](https://obj.umiacs.umd.edu/papers_for_stories/crlite_oakland17.pdf)) to solve revocation for the WebPKI: aggregate **all** CA-published CRLs — discovered via Certificate Transparency logs — into a single compact filter that browsers download and consult entirely offline, with no per-handshake network call and no privacy leak to the CA.

Its scale and performance, per Mozilla's [August 2025 write-up](https://hacks.mozilla.org/2025/08/crlite-fast-private-and-comprehensive-certificate-revocation-checking-in-firefox/):

* **Coverage:** roughly **4 million** revoked certificates — effectively every revocation in the WebPKI.
* **Size / bandwidth:** about a **4 MB** snapshot every **45 days**, plus delta updates, averaging **~300 kB/day**. Firefox refreshes every **12 hours**.
* **Compression:** the original design used a multi-level cascade of Bloom filters. The 2025 [**Clubcard**](https://eprint.iacr.org/2025/610.pdf) redesign (presented at IEEE S&P 2025 / RWC 2025) replaced this with a *partitioned two-level cascade of Ribbon filters*, achieving roughly **1000×** the bandwidth efficiency of downloading CRLs directly, and about **half** the size of Chrome's CRLSets *while covering all revocations*.
* **Deployment:** shipped to **all Firefox desktop** users in **Firefox 137** (early 2025); OCSP querying was disabled in **Firefox 142** (August 2025). Mozilla has open-sourced the building blocks (`clubcard`, `clubcard-crlite`, and the CRLite backend), but to date CRLite is **essentially Firefox-only** — there is no other production deployment.
* **Closest analog elsewhere:** Chrome's [CRLSets](https://www.chromium.org/Home/chromium-security/crlsets/) push revocation data to browsers offline as well, but they ship a **curated subset** of revocations chosen by Google rather than the comprehensive set CRLite covers — a useful contrast for C2PA's design choices below.

**Why C2PA is a friendlier environment.** CRLite's filter-compression machinery exists because the WebPKI universe is enormous (millions of live certs, ~4M revocations). The relevant comparison for an ARA, though, is not the *total* number of end-entity certificates but the number of *revocations* it must carry. C2PA's trust anchors are counted in the *tens*, and that bound is fixed by the trust list. The end-entity population is harder to bound and may grow large: edge-device deployments can mint a unique, short-lived certificate per signed asset, so EE certs could eventually outnumber today's WebPKI hosts.

That growth does not translate into a proportionally large ARA. Per-asset certificates of this kind are short-lived and could even be single-use, and are therefore unlikely to be individually revoked; the revocations an ARA must enumerate come predominantly from the longer-lived, reused signing certificates and intermediates, a much smaller set. So while the total certificate universe could become large, the *revocation* set it produces is expected to stay modest — at that scale a flat, deduplicated list fits in tens of KB with no filter at all, and there is already a natural publishing authority (the conformance program governing the trust list). The interesting design problems for C2PA are therefore not compression but **temporal validity**, **backward compatibility**, and **long-term persistence**, addressed below. Should the revocation set ever grow enough to make size a real constraint, CRLite-style filter compression remains available as a later option.

## Description

### Overview

A trusted aggregator — naturally the same entity that publishes the relevant trust list (for C2PA, the [conformance program](https://github.com/c2pa-org/conformance-public/)) — periodically:

1. Reads the current trust list (anchors), plus any intermediates it can source (see [Sourcing intermediate certs](#sourcing-intermediate-certs)).
2. For each issuer, dereferences its CRL Distribution Point (CDP) extension and downloads the issuer's CRL.
3. Merges all CRL entries into a single deduplicated table keyed by `(issuer SKI, certificate serial)`.
4. Records, for every issuer it successfully processed, an entry in a **coverage set** (see [Backward compatibility](#backward-compatibility-and-coexistence)).
5. Wraps the table and coverage set in a signed artifact and publishes it at a well-known URL alongside the trust list.

Validators fetch the artifact on their normal trust-list refresh schedule, verify its signature, and consult it locally during manifest validation. No per-signature OCSP staple is needed for any certificate whose issuer is in the artifact's coverage set.

A single artifact covers both the claim-signing anchors and the TSA trust list, with each entry tagged by scope. Splitting into two files was considered (cleaner scope boundaries, potentially independent governance) but rejected in favor of a single file for simpler validator fetch logic.

### Temporal model

This is the central design choice and the place where the C2PA setting genuinely differs from WebPKI CRLite.

WebPKI CRLite answers: "Is this certificate revoked **now**?" A revoked TLS cert simply fails the handshake; there is no historical authenticity to preserve.

C2PA needs to answer: "Was this certificate valid **at signing time `T_sig`**, as attested by a trusted [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp?" A claim signed in 2024 by a cert revoked in 2026 must still validate, provided the revocation was not for `keyCompromise` (which by [RFC 5280 §5.3.2](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.2) implicates earlier signatures as well).

This proposal adopts a **revocation-date-aware** model: rather than a pure set-membership filter answering yes/no, the artifact stores the revocation date for each revoked certificate. A validator with signing time `T_sig` treats a certificate as revoked if and only if an entry exists for it AND `T_sig ≥ revocation_date`.

This date-awareness is also why a naive Bloom/Clubcard filter is not a drop-in for C2PA even at scale: a set-membership filter answers "is it revoked?" but not "as of when?" — see [Persistence and retention](#persistence-and-retention).

#### Alternatives considered

A **reason-aware** variant would additionally store the [RFC 5280 §5.3.1](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1) reason code and apply different rules per reason — for example, `keyCompromise` would invalidate all earlier signatures unconditionally, while `affiliationChanged` or `cessationOfOperation` would only invalidate signatures after `revocation_date`. This more faithfully captures the intent of [RFC 5280 §5.3.2](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.2). It is deferred to future work — conservative treatment of all revocations (the option chosen) is safer for a first draft, and reason codes in real-world CRLs are widely known to be inconsistently populated. The artifact format reserves an optional `reason` field so this can be added without a format break.

A second alternative — pure **snapshot lookup** with rolling dated filters — was also considered but rejected: it pushes complexity onto the publisher (history retention) and the validator (selecting the right snapshot) without materially improving the answer compared to the date-aware approach.

### Backward compatibility and coexistence

ARA will not be adopted everywhere at once. Legacy signers, and signers whose issuers are not (yet) covered by any ARA, will keep stapling OCSP responses; some manifests will carry a staple, some will not. A validator therefore needs a **deterministic rule for which mechanism is authoritative** for a given signature — and, critically, a way to know that an *absent* entry means "good standing" rather than "this issuer simply isn't covered."

#### The coverage set

The key addition in v0.2 is that an ARA enumerates not only the *revoked* certificates but also the **issuers it authoritatively covers**, with per-issuer freshness metadata (the timestamp of the last successfully fetched CRL for that issuer). This mirrors CRLite's notion of "enrolled" issuers: a revocation filter is only trustworthy for issuers whose CRLs were actually incorporated.

The rule follows directly: **absence of an entry means "not revoked" only if the issuer is in the coverage set and that coverage is fresh.** If the issuer is not covered, the ARA is silent about it and the validator must fall back.

#### Validator decision logic

For each certificate to be checked (claim signer, then TSA), the validator resolves the issuer via the AKI extension and applies:

| Issuer in a fresh coverage set? | Manifest carries a staple? | Action |
| --- | --- | --- |
| Yes | — | **Authoritative.** Revoked iff an entry exists and `T_sig ≥ revocation_date`; otherwise good standing. |
| In coverage set but **stale** | — | Fail the revocation step (or apply local policy fallback to OCSP). |
| **No** (not covered) | Yes | Use the stapled OCSP response — the legacy path. |
| **No** (not covered) | No | Policy decision: refuse, or accept with a warning. |

This answers the two questions directly: a manifest with no staple is fine *if its issuer is covered* (the ARA is authoritative), and the validator knows to consult the ARA because the issuer appears in a coverage set.

#### Generalizing across trust lists

Because the coverage set is keyed by issuer SKI and an ARA is bound to a specific trust list, the same logic generalizes when multiple trust lists adopt ARAs. A validator honoring several trust lists holds several ARAs; for a given signing certificate it selects the ARA whose coverage set contains the issuer. If more than one covers it, local policy decides precedence (e.g., prefer the trust list that anchors the chain being validated). The coverage-set lookup is thus the single primitive that makes ARA portable beyond C2PA.

### Persistence and retention

WebPKI CRLite can **drop** a revocation entry once the certificate **expires** — an expired TLS cert fails the handshake regardless, so there is no history to preserve. C2PA cannot: it validates against `T_sig`, potentially years or decades after the certificate expired, so a revocation record must be retained as long as we want signatures from that era to remain verifiable. **The list is append-mostly and grows monotonically.**

The growth is real but the scale is modest and bounded:

* Only *revoked* certificates are stored — a small fraction of those issued — not the whole universe.
* The universe is trust-list-bounded. Each entry is roughly SKI (~20 B) + serial (~20 B) + date (~4 B) ≈ **~50 bytes**. Even **10,000 lifetime revocations is ≈ 0.5 MB** — three orders of magnitude below the WebPKI's ~4M.

So for the foreseeable C2PA future the all-time list stays small. To keep it from being a concern at larger scale, the proposed model **segments by certificate expiry**:

* **Active segment** — revocations for certificates that have **not yet expired**. Only these can gain *new* revocations, so this segment is small and changes between aggregation runs. Validators fetch it frequently.
* **Immutable historical archive** — once a certificate expires, its revocation record is frozen (the `revocation_date` never changes and no new revocation can appear for it). Such records move into an append-only archive, partitioned for convenience (e.g., by year of expiry), published once and **cached indefinitely** by validators. This bounds the recurring fetch/bandwidth cost even as the all-time record grows without limit.

**When would compression (Bloom/Clubcard) be needed?** Only if the *active* segment becomes large enough that its raw size matters on the wire — i.e., orders of magnitude beyond the current trust-list scope. Two caveats temper that: (1) the historical archive is cached, not re-fetched, so it does not drive recurring bandwidth; and (2) the date-aware model means a plain set-membership filter cannot answer the query alone — a real deployment would need the filter **plus** a side table of revocation dates, or filters **partitioned by revocation epoch**. Compression for ARA is therefore both *not needed yet* and *more involved than in CRLite*; it stays firmly in future work.

### Artifact format

The normative form is **CBOR**, signed as a **COSE_Sign1** — compact and aligned with C2PA's existing COSE/CBOR conventions. A JSON projection is given in [Appendix A](#appendix-a-json-projection) for human inspection and debugging only; the CBOR/COSE form is the signed truth.

Structure, in [CDDL](https://www.rfc-editor.org/rfc/rfc8610):

```cddl
ara = {
  version:        uint,            ; format version, currently 1
  trust-list-id:  tstr,            ; identifier of the trust list this artifact is bound to
  generated-at:   ~time,           ; epoch seconds (CBOR tag 1)
  next-update:    ~time,           ; after which validators should consider it stale
  ? partial:      bool,            ; true if some issuers' CRLs could not be refreshed this run
  covered-issuers: [* coverage],   ; the authoritative coverage set
  entries:        [* revocation],  ; revoked certificates
}

coverage = {
  scope:          scope,
  issuer-ski:     bstr,            ; SKI of the issuing CA
  last-crl-update: ~time,          ; last successful CRL fetch for this issuer
  ? status:       tstr,            ; "ok" (default) | "stale"
}

revocation = {
  scope:          scope,
  issuer-ski:     bstr,            ; SKI of the issuing CA (matches the AKI of the revoked cert)
  serial:         bstr,            ; big-endian certificate serial
  revocation-date: ~time,
  ? reason:       uint,            ; RFC 5280 reason code, reserved for the future reason-aware variant
}

scope = &(anchors: 0, tsa: 1)
```

The artifact is signed by the publisher as a `COSE_Sign1` over the CBOR encoding of `ara`. For the PoC the publisher is a freshly minted demo key; in production it would be the trust list's authority (for C2PA, the conformance program), using a key whose certificate is well-known to validators — analogous to the trust-list signing key.

Notes on the encoding choices:

* `issuer-ski` is chosen over the issuer's distinguished name because it is short, unambiguous, and directly matches the AKI extension on end-entity certificates, which is what the validator already has in hand. As byte strings (`bstr`) rather than hex text, SKI and serial are roughly half the size of the JSON form.
* `scope` distinguishes claim-signing revocations (`anchors`) from TSA revocations (`tsa`), since both are carried in the same artifact, and applies to both the coverage set and the entry list.
* Dates are CBOR epoch-seconds (tag 1) integers rather than ISO-8601 strings — smaller, and unambiguous.

### Validation procedure

A validator that supports this mechanism, when checking a C2PA claim signature:

1. Load the current ARA(s), verify each signature against the known publisher key(s), and check that `now ≤ next_update + grace_window`. Treat a stale artifact per the [decision logic](#validator-decision-logic) (fail the revocation step, or local-policy fallback).
2. Extract the claim-signing certificate from the COSE signature and identify its issuer via the AKI extension.
3. Select the ARA whose `covered-issuers` set contains that issuer (per [Generalizing across trust lists](#generalizing-across-trust-lists)). If no ARA covers it, apply the not-covered branch of the decision logic (legacy OCSP staple if present, else policy).
4. Determine `T_sig` from the embedded `sigTst2` timestamp (per the C2PA spec, signatures should be timestamped by a TSA on the C2PA TSA Trust List).
5. Look up `(issuer_ski, serial)` among `scope == anchors` entries. If found and `T_sig ≥ revocation_date`, the certificate is revoked at signing time; the signature fails revocation validation.
6. Repeat steps 2–5 for the TSA's signing certificate, against the coverage set and entries with `scope == tsa`.

If `T_sig` cannot be determined (no trusted timestamp), the validator falls back to treating `T_sig = now`, with the consequence that any later revocation invalidates the signature. This is consistent with current C2PA practice for untimestamped signatures.

### Freshness

* The aggregator runs **daily**, producing a new artifact each run.
* Each artifact carries `next_update = generated_at + 7 days`, matching typical CA CRL semantics.
* Validators accept the artifact for an additional `grace_window` past `next_update` before treating it as stale. For the PoC, `grace_window = 30 days`, giving a total freshness tolerance of ~37 days from generation. These are tunable and would warrant a C2PA WG conversation in any future spec discussion.

### Relation to OCSP stapling

In the long run the intent is for ARA to *replace* per-signature OCSP stapling for any certificate whose issuer is covered: clients sign without contacting an OCSP responder, and validators rely on the artifact. During the transition the two coexist, governed by the coverage set as described in [Backward compatibility](#backward-compatibility-and-coexistence): the ARA is authoritative for covered issuers, and the stapled OCSP response remains the fallback for certificates whose issuer is not covered. The PoC reflects the end state for covered issuers — it does not consult a stapled OCSP response when the issuer is covered — while preserving the legacy path for everything else.

### Spec changes that would be needed

These are not part of this proof of concept; they are noted here only to indicate the scope of a future spec change that would make this mechanism normative.

* **§13/§14** (signing) — permit signers to omit the stapled OCSP response when their issuer is covered by an ARA.
* **§15.9** (validate credential revocation information) — define the ARA-based validation procedure, including the coverage-set / staple fallback logic, as a permitted means of satisfying the revocation check.
* **New §14.x** (revocation artifact) — define the ARA format, signing requirements, publication URL convention, coverage-set semantics, and freshness semantics.
* **Trust list metadata** — note that each trust list may publish a companion ARA at a sibling URL with a fixed naming convention (e.g., `<trust-list>-revocation.cbor`).

## Security and privacy considerations

* **Centralization** — the artifact's authority equals the trust list publisher's authority. A malicious or compromised publisher could either omit a real revocation (failing open) or fabricate one (denial of service against a specific signer). This is the same trust assumption already made for the trust list itself, so it does not enlarge the attack surface.
* **Stale artifact / replay** — a network attacker could serve an old artifact to mask a recent revocation. Mitigated by the validator-enforced freshness window (`next_update + grace`) and the signed `generated_at` field. Validators that have ever seen a newer artifact MUST NOT accept an older one.
* **Coverage-set downgrade** — because absence-of-entry is only trustworthy for covered issuers, an attacker who could strip or shrink the coverage set could push a covered issuer into the "fall back to staple / policy" branch. The coverage set is inside the signed artifact, so this requires breaking the signature; it is called out here because the coverage set is now load-bearing for the fail-open/closed decision.
* **CDP unavailability at aggregation time** — if a CA's CRL cannot be fetched, the aggregator must decide between publishing a partial artifact (marking the affected issuer `stale` in the coverage set and setting `partial: true`) or skipping the update. Default for the PoC: emit a warning, retain the last successfully fetched CRL for that issuer, and surface the staleness in the coverage metadata.
* **Validator privacy** — validators no longer call OCSP responders at validation time, eliminating the corresponding leak of viewing/validation patterns to issuing CAs. This is the same privacy win that motivated the WebPKI's move off OCSP.
* **Out-of-scope revocation** — certificates whose issuer is not in any coverage set cannot be checked by this mechanism. For those, the existing OCSP path remains the answer; the proposal does not remove that capability.

## Proof of concept

Implemented in this subdirectory. As of v0.2 the PoC emits the normative **CBOR + COSE_Sign1** artifact and populates the **coverage set**; a JSON debug projection (Appendix A) is written alongside for inspection.

1. **`aggregator/`** — a small Rust binary that takes one or more anchor PEM files as input, parses each cert (using `x509-parser`), follows each CDP, downloads and parses the CRL, deduplicates entries, records the coverage set, and emits a CBOR artifact signed as COSE_Sign1.
2. **`sample/`** — an example output artifact built from the current [official C2PA anchors trust list](https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TRUST-LIST.pem) augmented (for prototyping density only) with the [interim anchors list](https://contentcredentials.org/trust/anchors.pem). The [interim end-entity list](https://verify.contentauthenticity.org/trust/allowed.pem) is deliberately not used: it enumerates leaf certs rather than CAs, and revocation there is already handled by removal from the allowlist.
3. **`validator/`** — a small wrapper around [`c2pa-rs`](https://github.com/contentauth/c2pa-rs) that performs normal C2PA validation, extracts the claim-signing certificate and `sigTst2` time, then post-processes the revocation check against the local artifact, applying the coverage-set decision logic (with an `--uncovered-policy` fallback).
4. **`demo/`** — sign a sample asset with `c2patool` and run the wrapper validator both on the unmodified asset and on a synthetic scenario with a revoked cert, demonstrating both pass and fail paths.

The PoC is intentionally scoped to the flat-list artifact form. The Clubcard / cascading-filter variant from upstream CRLite is left as future work; it is only interesting once the universe of C2PA certs is large enough for raw-list size to matter.

## Future work and known gaps

This is the canonical list. The `aggregator/` and `validator/` READMEs link here rather than maintaining their own lists.

### Implemented in v0.2

* **CBOR / COSE_Sign1 artifact and coverage set.** The aggregator now emits the normative CBOR artifact signed as COSE_Sign1 and populates `covered-issuers`; the validator verifies the COSE_Sign1, CBOR-decodes the payload, and applies the coverage-set decision logic with an `--uncovered-policy` (`warn`/`refuse`) fallback for not-covered issuers. The `--uncovered-policy` default (`warn`) is provisional and worth revisiting.

### PoC gaps (would be addressed before this is more than a demo)

* **OCSP staple consultation.** For a not-covered issuer the validator only *detects* a stapled OCSP response (`rVals`); it does not parse or verify it. A real deployment would consult the staple on the legacy path.
* **Intermediate cert coverage in the aggregator.** Most certs in the C2PA anchors trust lists are self-signed roots that carry no CDP — the smoke-test run found only ~7 of 47 anchors had a fetchable CRL URL. Meaningful revocation data lives on *intermediate* certs (whose CDPs point to CRLs the root publishes about them) and on *end-entity* certs (whose CDPs point to CRLs the intermediate publishes). Where to source intermediates is the open question, see [Sourcing intermediate certs](#sourcing-intermediate-certs) below.
* **Test certificate minting.** The aggregator now has an `--inject-entries` flag that takes a JSON list of synthetic entries and merges them into the artifact (see `sample/inject-demo.json` and `demo/run.sh`). What's still outstanding is a dedicated test-cert minter — a small helper that produces a fresh test CA + EE cert + matching CRL so the demo doesn't have to pin its synthetic entries to existing fixture certs. Useful once we want regression tests independent of `c2pa-rs` fixtures.
* **TSA cert resolution refinement.** The validator now extracts the TSA cert from the COSE_Sign1's `sigTst`/`sigTst2` header (CMS SignedData inside the TimeStampToken). It currently uses a "first cert in `SignedData.certificates`" heuristic; production should resolve via `SignerInfo.sid` (issuer+serial or SKI) to handle multi-cert chains correctly.
* **Filtering broad-CA noise from the aggregated artifact.** Feeding `allowed.pem` to the aggregator inflates the artifact from ~36 entries to ~101,840 — but the bulk are non-C2PA revocations (e.g., ~36.9k Sectigo email/code-signing entries) pulled in because the C2PA leaves chain through broad-purpose public CAs that publish a single shared CRL across many use cases. A production ARA should filter to entries that intersect the C2PA universe — for example, only retain a revoked serial if at least one cert with that `(issuer SKI, serial)` exists under a C2PA-trusted chain. Without this, the artifact balloons in size and most of its entries are irrelevant to C2PA verifiers.

### Design-level extensions (would warrant a C2PA WG conversation)

* **Reason-aware variant.** Populate the reserved `reason` field with the RFC 5280 reason code and differentiate `keyCompromise` (invalidates earlier signatures) from softer reasons. Worth doing once we have evidence that issuers in the C2PA ecosystem populate reason codes reliably.
* **Active/archive segmentation.** Implement the expiry-based split from [Persistence and retention](#persistence-and-retention) — a frequently-fetched active segment plus an immutable, indefinitely-cached historical archive. Only needed once the all-time list is large enough for retention to matter.
* **Clubcard / cascade compression.** Only interesting if the C2PA cert universe grows by orders of magnitude beyond the current trust-list scope, and even then it must be combined with a date side-table or epoch-partitioned filters to preserve the temporal model.
* **Delta artifacts.** Incremental updates rather than full re-publication; same observation as above, only matters at scale.

### Sourcing intermediate certs

Several plausible sources, in roughly increasing order of effort:

1. **Already in the bundles we have.** A few of the "anchors" PEMs really do contain intermediates (the ones whose CDPs the aggregator successfully followed — e.g., the Adobe intermediate at `pki-cdn.adobe.net`). This gives us a *partial* set already.
2. **Embedded in signed C2PA assets.** Every signed C2PA manifest's COSE_Sign1 carries the full `x5chain`. Harvesting intermediates from a corpus of public C2PA-signed media is straightforward (and is how Mozilla CRLite uses Certificate Transparency).
3. **The interim end-entity list (`allowed.pem`).** Despite the design-level rationale for excluding it (its revocation semantics are "remove from the allowlist"), it does enumerate real-world C2PA EE certs whose CDPs point at the right intermediates' CRLs. Feeding `allowed.pem` to the aggregator would yield denser revocation data for demo purposes, with a clear note that this is not the production trust model.
4. **AIA chasing.** Each cert's Authority Information Access extension typically has a `caIssuers` URL pointing to the parent cert. The aggregator could walk this chain upward from any starting point.
5. **CA cert repositories / C2PA conformance program.** Some CAs publish their full intermediate inventory; the conformance program may eventually formalize this.

## Appendix A: JSON projection

For inspection and debugging only — the normative artifact is the CBOR/COSE_Sign1 form in [Artifact format](#artifact-format). This projection maps field-for-field, with byte strings shown hex-encoded and dates as ISO-8601 UTC:

```json
{
  "version": 1,
  "trust_list_id": "<identifier of the trust list this corresponds to>",
  "generated_at": "<ISO 8601 UTC>",
  "next_update": "<ISO 8601 UTC, after which validators should consider it stale>",
  "partial": false,
  "covered_issuers": [
    {
      "scope": "anchors",
      "issuer_ski": "<hex-encoded SKI of issuing CA>",
      "last_crl_update": "<ISO 8601 UTC>",
      "status": "ok"
    }
  ],
  "entries": [
    {
      "scope": "anchors",
      "issuer_ski": "<hex-encoded SKI of issuing CA>",
      "serial": "<hex-encoded big-endian serial>",
      "revocation_date": "<ISO 8601 UTC>"
    }
  ]
}
```

## Change history

### v0.2.1 (2026-06-22)

* **Scale framing corrected.** Replaced the "low thousands" end-entity estimate in *Background on CRLite*, which understated edge-device deployments that mint a unique cert per signed asset. Clarified that an ARA carries *revocations*, not the total EE population, and that short-lived single-use certs are unlikely to be revoked — keeping the revocation set modest.

### v0.2 (2026-06-09)

* **Renamed** the mechanism from "CRLite for C2PA" to **Aggregated Revocation Artifact (ARA)**, and added a naming note explaining why it is not CRLite. The file remains `crlite.md` for link stability.
* **OCSP deprecation.** Added an "OCSP is being deprecated in the WebPKI" subsection to *Justification*, framing C2PA's mandatory-OCSP requirement as a structural risk (CA/B Forum SC-063v4; Let's Encrypt's 2025 OCSP shutdown).
* **CRLite background.** Added a *Background on CRLite* section with concrete scale, size, deployment, and Clubcard details, and the rationale for why C2PA does not need CRLite's compression.
* **Backward compatibility.** Added a *Backward compatibility and coexistence* section introducing the **coverage set** (`covered-issuers`), a validator decision matrix for the OCSP-staple fallback, and generalization across multiple trust lists.
* **Persistence.** Added a *Persistence and retention* section: the list is append-mostly (records cannot be dropped at cert expiry as in CRLite), with an active-segment / immutable-archive model and scale estimates.
* **CBOR format.** Made **CBOR + COSE_Sign1** the normative artifact form (CDDL definition), tightened field encodings (`bstr` SKI/serial, epoch-second dates), and moved the JSON form to *Appendix A* as a debug-only projection.
* **Validation procedure** updated to select an ARA by coverage set and apply the staple-fallback logic.
* **Trust-list-neutral framing** throughout, so the design generalizes beyond the C2PA Trust List.
* Doc-only release: the PoC code still emits signed JSON; the CBOR/COSE + coverage-set migration is tracked in *Future work*.

### v0.1 (initial draft)

* Initial CRLite-inspired proposal: daily aggregator over trust-list CRLs, revocation-date-aware temporal model, signed-JSON (ES256 JWS) artifact, validation procedure, freshness window, and the PoC (`aggregator/`, `validator/`, `sample/`, `demo/`).
