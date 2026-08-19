# Aggregated Revocation Artifact (ARA) for C2PA

_draft 0.3.1_

This document proposes an **Aggregated Revocation Artifact (ARA)** — a [CRLite](https://github.com/mozilla/crlite)-inspired mechanism for proving non-revocation of C2PA signing certificates. For more details on CRLite and how the C2PA environment differs, see [Appendix A](#appendix-a-background-on-crlite). The goal is to replace per-signature OCSP stapling with a single, periodically-refreshed, signed revocation artifact published alongside a [trust list](https://c2pa.org/conformance/) (the C2PA Trust List being the motivating case). Validators consult the local artifact at validation time and need no network call to a CA.

Although C2PA is the motivating deployment, the design is deliberately **trust-list-neutral**: an ARA is bound to a particular trust list, covers that trust list's issuers, and is signed by that trust list's authority. A validator may consult several ARAs — one per trust list it honors — so the mechanism generalizes to any ecosystem that maintains a curated trust list.

This began as exploratory work intended to demonstrate feasibility through a proof-of-concept. As of v0.3 a [draft spec change](https://github.com/christianpaquin/specs-core/tree/cpaquin/aggregated-revocation-artifact) implementing this mechanism has been prepared against the C2PA core specification, and this document has been revised to match what that draft actually specifies — see [Spec changes](#spec-changes).

## Justification

The current [C2PA core specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html) requires a claim signer to embed a stapled OCSP response in the COSE signature as the means of proving non-revocation, and disallows CRLs. This has several costs:

* **Signer-side network dependency** — every signing operation must reach an OCSP responder to obtain a fresh response. This complicates offline or batch signing and ties the signer to the issuing CA's OCSP availability.
* **Per-manifest overhead** — each OCSP response (~1–2 KB) is carried in every manifest. For platforms generating many small assets this adds up.
* **Validator-side privacy leak in the OCSP-fallback case** — if validators ever need to refresh, they leak validation activity to the issuing CA.
* **No global revocation view** — there is no single artifact a verifier can audit to see "what is currently revoked across the C2PA ecosystem?"

### OCSP is being deprecated in the WebPKI

Beyond the standing costs above, C2PA's reliance on mandatory OCSP stapling runs **against the direction of the wider WebPKI**, which is actively retiring OCSP in favor of CRLs:

* The CA/Browser Forum's [Ballot SC-063v4](https://cabforum.org/2023/07/14/ballot-sc063v4-make-ocsp-optional-require-crls-and-incentivize-automation/) (passed August 2023) made OCSP **optional** for publicly-trusted CAs and made **CRLs mandatory** — the formal pivot away from OCSP, citing privacy, performance, and operational concerns.
* Let's Encrypt put this into practice: it [announced the end of OCSP in December 2024](https://letsencrypt.org/2024/12/05/ending-ocsp), removed OCSP URLs from newly issued certificates on **7 May 2025**, and [shut down its OCSP responders entirely on **6 August 2025**](https://letsencrypt.org/2025/08/06/ocsp-service-has-reached-end-of-life), citing the privacy leak (the responder learns what a relying party is validating) and the operational cost of running the service. Browsers are following suit — Firefox disabled OCSP querying in version 142 (see [Appendix A](#appendix-a-background-on-crlite)).

The risk for C2PA is structural: the spec **mandates** the one mechanism the ecosystem is abandoning and **disallows** the one it is standardizing on. As public CAs retire OCSP responders, signers chaining to those CAs may be unable to obtain a staple at all, and C2PA risks being stranded on a legacy mechanism with declining CA support and tooling. (The pressure is currently sharpest for TLS/DV CAs; the code- and document-signing CAs closer to C2PA's usage may retain OCSP somewhat longer — but the direction of travel is unambiguous, and C2PA should not stake its only non-revocation path on it.) An aggregated, CRL-derived artifact aligns C2PA with where the WebPKI is heading.

## Description

### Overview

A trusted aggregator — naturally the same entity that publishes the relevant trust list (for C2PA, the [conformance program](https://github.com/c2pa-org/conformance-public/)) — periodically:

1. Reads the current trust list (anchors), plus any intermediates it can source (see [Sourcing intermediate certs](#sourcing-intermediate-certs)).
2. For each issuer, dereferences its CRL Distribution Point (CDP) extension and downloads the issuer's CRL.
3. Merges all CRL entries into a single deduplicated table keyed by `(issuer SKI, certificate serial)`.
4. Records, for every issuer it successfully processed, an entry in a **coverage set** (see [Backward compatibility](#backward-compatibility-and-coexistence)).
5. Wraps the table and coverage set in a signed artifact and publishes it alongside the trust list.

Validators fetch the artifact on their normal trust-list refresh schedule, verify its signature, and consult it locally during manifest validation. No per-signature OCSP staple is needed for any certificate whose issuer is in the artifact's coverage set.

**One artifact per trust list.** An ARA is bound to exactly one trust list, and carries no `scope` field distinguishing claim-signing from time-stamping issuers. Tagging entries by purpose would contradict this document's trust-list-neutral framing (an ARA "is bound to a particular trust list"), and it is redundant, because the C2PA specification already requires the TSA trust anchor list to be kept separate from the list used for claim signers. The purpose an issuer's certificates serve is therefore determined by *which* trust list the artifact is bound to, and does not need recording inside the artifact.

In practice this means the C2PA conformance program publishes **two** artifacts: one for the C2PA Trust List and one for the C2PA TSA Trust List. The cost is a second fetch; the benefit is that a validator can never apply claim-signing coverage to a time-stamping certificate.

Binding each artifact to a single trust list is safe even where one CA issues both claim-signing and time-stamping certificates. Such a CA appears in both artifacts, and — since a CRL is not partitioned by purpose — both may carry the same entries. That produces no false positives: serial numbers are unique per issuer, so `(issuer SKI, serial)` identifies exactly one certificate regardless of the purpose it was issued for.

### Temporal model

This is the central design choice and the place where the C2PA setting genuinely differs from WebPKI CRLite.

WebPKI CRLite answers: "Is this certificate revoked **now**?" A revoked TLS cert simply fails the handshake; there is no historical authenticity to preserve.

C2PA needs to answer: "Was this certificate valid **at signing time `T_sig`**, as attested by a trusted [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp?" A claim signed in 2024 by a cert revoked in 2026 must still validate, provided the revocation was not for `keyCompromise` (which by [RFC 5280 §5.3.2](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.2) implicates earlier signatures as well).

This proposal adopts a **revocation-date-aware** model: rather than a pure set-membership filter answering yes/no, the artifact stores the revocation date for each revoked certificate. A validator with signing time `T_sig` treats a certificate as revoked if and only if an entry exists for it AND `T_sig ≥ revocationDate`.

This date-awareness is also why a naive Bloom/Clubcard filter is not a drop-in for C2PA even at scale: a set-membership filter answers "is it revoked?" but not "as of when?" — see [Persistence and retention](#persistence-and-retention).

#### Alternatives considered

A **reason-aware** variant would additionally store the [RFC 5280 §5.3.1](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1) reason code and apply different rules per reason — for example, `keyCompromise` would invalidate all earlier signatures unconditionally, while `affiliationChanged` or `cessationOfOperation` would only invalidate signatures after `revocationDate`. This more faithfully captures the intent of [RFC 5280 §5.3.2](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.2). It is deferred to future work — conservative treatment of all revocations (the option chosen) is safer for a first draft, and reason codes in real-world CRLs are widely known to be inconsistently populated. The artifact format reserves an optional `reason` field so this can be added without a format break.

A second alternative — pure **snapshot lookup** with rolling dated filters — was also considered but rejected: it pushes complexity onto the publisher (history retention) and the validator (selecting the right snapshot) without materially improving the answer compared to the date-aware approach.

### Backward compatibility and coexistence

ARA will not be adopted everywhere at once. Legacy signers, and signers whose issuers are not (yet) covered by any ARA, will keep stapling OCSP responses; some manifests will carry a staple, some will not. A validator therefore needs a **deterministic rule for which mechanism is authoritative** for a given signature — and, critically, a way to know that an *absent* entry means "good standing" rather than "this issuer simply isn't covered."

#### The coverage set

An ARA enumerates not only the *revoked* certificates but also the **issuers it authoritatively covers**, with per-issuer freshness metadata (the timestamp of the last successfully fetched CRL for that issuer). This mirrors CRLite's notion of "enrolled" issuers: a revocation filter is only trustworthy for issuers whose CRLs were actually incorporated.

The rule follows directly: **absence of an entry means "not revoked" only if the issuer is in the coverage set and that coverage is fresh.** If the issuer is not covered, the ARA is silent about it and the validator must fall back.

#### Validator decision logic

For each certificate to be checked (claim signer, then TSA), the validator resolves the issuer via the AKI extension and applies:

| Artifact fresh? | Issuer covered? | Manifest carries a staple? | Action |
| --- | --- | --- | --- |
| Yes | Yes, `status: ok` | — | **Authoritative.** Revoked iff an entry exists and `T_sig ≥ revocationDate`; otherwise good standing. |
| **No** (past `nextUpdate` + grace) | — | — | Not authoritative. Record `signingCredential.ara.stale` and fall through to the OCSP path. |
| Yes | Covered but `status: stale` | — | Not authoritative. Fall through to the OCSP path. |
| Yes | **No** (not covered) | Yes | Record `signingCredential.ara.notCovered`; use the stapled OCSP response — the legacy path. |
| Yes | **No** (not covered) | No | Record `signingCredential.ara.notCovered`; fall through to online OCSP or local policy. |

This answers the two questions directly: a manifest with no staple is fine *if its issuer is covered* (the ARA is authoritative), and the validator knows to consult the ARA because the issuer appears in a coverage set.

Note that an ARA being authoritative does **not** suppress a staple that is also present. Where more than one mechanism is applied to the same certificate, any one of them establishing revocation rejects the claim. The ARA removes the *need* to staple; it does not override a staple that says "revoked".

#### Generalizing across trust lists

Because the coverage set is keyed by issuer SKI and an ARA is bound to a specific trust list, the same logic generalizes when multiple trust lists adopt ARAs. A validator honoring several trust lists holds several ARAs; for a given signing certificate it selects the ARA whose coverage set contains the issuer. If more than one covers it, local policy decides precedence (e.g., prefer the trust list that anchors the chain being validated). The coverage-set lookup is thus the single primitive that makes ARA portable beyond C2PA.

### Persistence and retention

WebPKI CRLite can **drop** a revocation entry once the certificate **expires** — an expired TLS cert fails the handshake regardless, so there is no history to preserve. C2PA cannot: it validates against `T_sig`, potentially years or decades after the certificate expired, so a revocation record must be retained as long as we want signatures from that era to remain verifiable. **The list is append-mostly and grows monotonically.**

The growth is real but the scale is modest and bounded:

* Only *revoked* certificates are stored — a small fraction of those issued — not the whole universe.
* The universe is trust-list-bounded. Each entry is roughly SKI (~20 B) + serial (~20 B) + date (~4 B) ≈ **~50 bytes**. Even **10,000 lifetime revocations is ≈ 0.5 MB** — three orders of magnitude below the WebPKI's ~4M.

So for the foreseeable C2PA future the all-time list stays small.

#### Completeness is what makes absence meaningful

Retention is one half of a pair. The other is **completeness**: an artifact that names an issuer in its coverage set must enumerate *every* revocation the publisher knows of for that issuer. This is the property that licenses the central inference — absence of an entry means "not revoked". An artifact carrying only part of an issuer's revocations, while still claiming to cover it, would report genuinely revoked certificates as being in good standing, silently.

Retention and completeness are the same requirement viewed over time: dropping an entry at certificate expiry is just a particular way of becoming incomplete, and it fails for exactly the claims whose signing credential is oldest.

Both are normative in the spec draft: an issuer appears in the coverage set only if the artifact carries all of its known revocations, and a publisher cannot drop an entry because the certificate expired.

#### Segmentation, and why it is not free

One way to keep the all-time list manageable would be to **segment by certificate expiry**:

* **Active segment** — revocations for certificates that have **not yet expired**. Only these can gain *new* revocations, so this segment is small and changes between aggregation runs. Validators fetch it frequently.
* **Immutable historical archive** — once a certificate expires, its revocation record is frozen (the `revocationDate` never changes and no new revocation can appear for it). Such records move into an append-only archive, partitioned for convenience (e.g., by year of expiry), published once and **cached indefinitely** by validators.

Attractive, but it **collides with completeness**, and the collision is easy to miss. An active segment that omits expired-certificate revocations while still listing those issuers in its coverage set is authoritative-but-incomplete. A validator checking an old claim finds the issuer covered, finds no entry, and concludes "not revoked" — precisely for the long-tail claims the archive exists to serve. The failure is silent and hits the oldest content.

Segmentation is therefore a **format change**, not a publishing convention. Doing it safely requires the artifact to state the extent of what it covers, so a validator knows when it is obliged to go and fetch the archive. Options, roughly in order of intrusiveness:

* a completeness bound per artifact or per covered issuer (e.g. "complete for certificates expiring after *X*"), so a validator can tell when a query falls outside what it holds;
* explicit references from the active artifact to the companion archive artifacts that together form the complete set;
* coverage entries partitioned by expiry epoch, with the validator required to hold a contiguous run of them.

The spec draft deliberately does not define any of these. It instead requires an artifact to be **self-contained** — a validator is never obliged to consult a companion artifact to interpret the one in hand — which keeps the v1 semantics simple and leaves the door open. Given the size arithmetic above (~0.5 MB at 10,000 lifetime revocations), segmentation buys nothing yet.

**When would compression (Bloom/Clubcard) be needed?** Only if the *active* segment becomes large enough that its raw size matters on the wire — i.e., orders of magnitude beyond the current trust-list scope. Two caveats temper that: (1) the historical archive is cached, not re-fetched, so it does not drive recurring bandwidth; and (2) the date-aware model means a plain set-membership filter cannot answer the query alone — a real deployment would need the filter **plus** a side table of revocation dates, or filters **partitioned by revocation epoch**. Compression for ARA is therefore both *not needed yet* and *more involved than in CRLite*; it stays firmly in future work.

### Artifact format

The normative form is **CBOR**, signed as a **COSE_Sign1** — compact and aligned with C2PA's existing COSE/CBOR conventions. A JSON projection is given in [Appendix B](#appendix-b-json-projection) for human inspection and debugging only; the CBOR/COSE form is the signed truth.

Structure, in [CDDL](https://www.rfc-editor.org/rfc/rfc8610):

```cddl
aggregated-revocation-artifact-map = {
  "version":       uint,     ; format version, currently 1
  "trustListId":   tstr,     ; identifier of the trust list this artifact is bound to
  "generatedAt":   time,     ; epoch seconds, CBOR tag 1
  "nextUpdate":    time,     ; after which validators consider it stale
  ? "partial":     bool,     ; true if some issuers could not be refreshed this run
  "coveredIssuers": [* revocation-coverage-map],  ; the authoritative coverage set
  "entries":       [* revocation-entry-map],      ; revoked certificates
}

revocation-coverage-map = {
  "issuerSKI":     bstr,     ; SKI of the issuing CA
  "lastUpdate":    time,     ; last successful refresh for this issuer
  ? "status":      "ok" / "stale",   ; defaults to "ok" when omitted
}

revocation-entry-map = {
  "issuerSKI":     bstr,     ; SKI of the issuing CA (matches the AKI of the revoked cert)
  "serialNumber":  bstr,     ; big-endian certificate serial
  "revocationDate": time,
  ? "reason":      uint,     ; RFC 5280 reason code, reserved for the future reason-aware variant
}
```

The naming follows the conventions of the C2PA schema repository: rule names are kebab-case with a `-map` suffix, field names are camelCase, and map keys are quoted text strings.

The artifact is signed by the publisher as a `COSE_Sign1` over the CBOR encoding of `ara`. For the PoC the publisher is a freshly minted demo key; in production it would be the trust list's authority (for C2PA, the conformance program), using a key whose certificate is well-known to validators — analogous to the trust-list signing key.

Notes on the encoding choices:

* `issuerSKI` is chosen over the issuer's distinguished name because it is short, unambiguous, and directly matches the AKI extension on end-entity certificates, which is what the validator already has in hand. As byte strings (`bstr`) rather than hex text, SKI and serial are roughly half the size of the JSON form.
* Dates use the CDDL `time` type — CBOR epoch seconds under tag 1 — rather than ISO-8601 strings: smaller, and unambiguous. This is the tagged `time`, consistent with the C2PA schemas' existing use of the tagged `tdate`.
* `lastUpdate` is named generically because nothing requires a publisher to source its revocation data from a CRL specifically.

### Validation procedure

A validator that supports this mechanism, when checking a C2PA claim signature:

1. Load the current ARA(s), verify each signature against the known publisher key(s), and check that `now ≤ nextUpdate + grace_window`. Treat a stale artifact per the [decision logic](#validator-decision-logic).
2. Extract the claim-signing certificate from the COSE signature and identify its issuer via the AKI extension.
3. Select an ARA that is bound to a trust list the validator uses **for claim signing**, and whose `coveredIssuers` set contains that issuer with `status` absent or `ok` (per [Generalizing across trust lists](#generalizing-across-trust-lists)). If no ARA covers it, apply the not-covered branch of the decision logic (legacy OCSP staple if present, else policy).
4. Determine `T_sig` from the embedded `sigTst2` timestamp (per the C2PA spec, signatures should be timestamped by a TSA on the C2PA TSA Trust List).
5. Look up `(issuerSKI, serialNumber)` among the artifact's entries. If found and `T_sig ≥ revocationDate`, the certificate is revoked at signing time; the signature fails revocation validation.

If `T_sig` cannot be determined (no trusted timestamp), the validator falls back to treating `T_sig = now`, with the consequence that any later revocation invalidates the signature. This is consistent with current C2PA practice for untimestamped signatures.

#### Time Stamping Authority certificates

A validator **may** additionally check the TSA's own signing certificate, using an ARA bound to a trust list of Time Stamping Authorities. Two things differ from the claim-signing case:

* **The time used is the time attested by that time-stamp**, not the claim's `T_sig` and not `now`. This matches how the C2PA specification already checks the TSA certificate's *validity period*. Using `now` would mean that revoking a TSA certificate retroactively invalidates every time-stamp it ever issued, which contradicts the specification's position that time-stamps stay valid even after the TSA's credential expires.
* **A revoked TSA certificate is not fatal to the claim.** The C2PA specification treats a failing time-stamp as *ignored* — recorded with an informational code, with validation continuing as though no time-stamp were present — never as grounds for rejecting the claim. A revoked TSA certificate is therefore reported informationally and the time-stamp discarded.

This check is optional because the C2PA specification explicitly does not require TSA revocation status to be captured at signing time or validated at validation time. An ARA makes the check *possible* offline; it does not make it mandatory.

### Freshness

* The aggregator runs **daily**, producing a new artifact each run.
* Each artifact carries `nextUpdate = generatedAt + 7 days`, matching typical CA CRL semantics. The spec draft states this as a recommendation: `nextUpdate` shall be later than `generatedAt`, and should be no more than seven days after it.
* Validators accept the artifact for an additional `grace_window` past `nextUpdate` before treating it as stale. The spec draft leaves this window to **local policy** rather than fixing a number, since the right tolerance depends on how often a given validator can reach the network. The PoC uses `grace_window = 30 days`, giving a total freshness tolerance of ~37 days from generation.
* A validator **shall not** accept an artifact whose `generatedAt` is earlier than one it has already used for the same trust list. The spec draft makes this a normative requirement, since it is what stops an attacker from rolling a validator back to a pre-revocation artifact.

### Relation to OCSP stapling

In the long run the intent is for ARA to *replace* per-signature OCSP stapling for any certificate whose issuer is covered: clients sign without contacting an OCSP responder, and validators rely on the artifact. During the transition the two coexist, governed by the coverage set as described in [Backward compatibility](#backward-compatibility-and-coexistence): the ARA is authoritative for covered issuers, and the stapled OCSP response remains the fallback for certificates whose issuer is not covered.

The spec draft is deliberately **additive** here. All existing OCSP requirements stay exactly as they are; the ARA is added as a permitted means of satisfying the revocation check, and signers gain explicit permission to omit the staple when they know their issuer is covered. Crucially, coverage does not *suppress* a staple that is present: if both mechanisms run and either reports revocation, the claim is rejected. The PoC's behavior — skipping the staple entirely once the issuer is covered — is therefore an optimization a validator may choose, not something the spec mandates.

One consequence worth recording: the C2PA prohibition on CRLs (`the claim generator shall not use Certificate Revocation Lists`) **stays in place**, and is not an obstacle: it binds the *claim generator*, which cannot reasonably download a CRL per signing operation, and it says nothing about a trust list authority that consults those same CRLs once per publication cycle on behalf of every validator. The spec draft keeps the prohibition and adds a note clarifying its scope.

### Spec changes

A draft change against the C2PA core specification has been prepared. It makes the following edits:

* **Trust Model → X.509 Certificates → Certificate Revocation** — permit a claim generator to omit the stapled OCSP response for a certificate whose issuer is covered by an ARA. The existing OCSP recommendations and the CRL prohibition are unchanged.
* **Trust Model → X.509 Certificates → new "Aggregated Revocation Artifact" clause** — define the format (CDDL plus a worked CBOR-diagnostic example), the coverage-set semantics, the retention rule that entries are never dropped at certificate expiry, and the signing and publication requirements.
* **Trust Model → Trust Lists** — note that the authority maintaining a trust list may publish a companion ARA, and that the signer and TSA trust lists take separate artifacts.
* **Validation → Validate the Credential Revocation Information** — add the ARA-based procedure: signature verification, freshness, the rollback rule, the authoritative-coverage test, the `T_sig` comparison, and the fallback to the OCSP path when no artifact is authoritative.
* **Validation → Validate the Time-Stamp** — permit checking the TSA certificate against a covering ARA, using the attested time, and note that a revoked TSA credential causes the time-stamp to be ignored rather than the claim rejected.
* **New status codes** — `signingCredential.ara.notRevoked` (success), `signingCredential.ara.revoked` (failure), `signingCredential.ara.notCovered` and `signingCredential.ara.stale` (informational), and `timeStamp.ara.revoked` (informational, for the optional TSA check).

Two things that were expected to need spec text turned out not to:

* **Publication URL convention.** The draft says an artifact is obtained by the same means as the trust list it is bound to, and leaves those means out of scope — matching how the specification already declines to say how trust lists themselves are distributed. The naming convention is a conformance-program matter, not a spec matter.
* **Trust list identifiers.** Likewise, how identifiers are assigned to trust lists is left out of scope, so `trustListId` is specified as an opaque string.

## Security and privacy considerations

* **Centralization** — the artifact's authority equals the trust list publisher's authority. A malicious or compromised publisher could either omit a real revocation (failing open) or fabricate one (denial of service against a specific signer). This is the same trust assumption already made for the trust list itself, so it does not enlarge the attack surface.
* **Stale artifact / replay** — a network attacker could serve an old artifact to mask a recent revocation. Mitigated by the validator-enforced freshness window (`nextUpdate + grace`) and the signed `generatedAt` field. Validators that have ever seen a newer artifact MUST NOT accept an older one; the spec draft states this as a normative requirement rather than advice.
* **Coverage-set downgrade** — because absence-of-entry is only trustworthy for covered issuers, an attacker who could strip or shrink the coverage set could push a covered issuer into the "fall back to staple / policy" branch. The coverage set is inside the signed artifact, so this requires breaking the signature; it is called out here because the coverage set is now load-bearing for the fail-open/closed decision.
* **CDP unavailability at aggregation time** — if a CA's CRL cannot be fetched, the aggregator must decide between publishing a partial artifact (marking the affected issuer `stale` in the coverage set and setting `partial: true`) or skipping the update. Default for the PoC: emit a warning, retain the last successfully fetched CRL for that issuer, and surface the staleness in the coverage metadata.
* **Validator privacy** — validators no longer call OCSP responders at validation time, eliminating the corresponding leak of viewing/validation patterns to issuing CAs. This is the same privacy win that motivated the WebPKI's move off OCSP.
* **Out-of-scope revocation** — certificates whose issuer is not in any coverage set cannot be checked by this mechanism. For those, the existing OCSP path remains the answer; the proposal does not remove that capability.

## What C2PA would need to do

The spec change defines the artifact and how a validator interprets it. It deliberately says nothing about who publishes, how often, from where, or what goes in — because those are operational matters for the conformance program, not interoperability matters. This section collects them. Everything here is a decision to be made or work to be done outside the specification.

### Governance and signing

* **Who publishes.** The natural answer is the conformance program, since the artifact's authority is exactly the trust list's authority and this adds no new trust root. Needs confirming, along with who operates the aggregator in practice.
* **Signing key.** Decide whether the ARA is signed with the trust list signing key or a dedicated key. A dedicated key limits blast radius and allows different operational handling, at the cost of one more thing for validators to learn. Either way: HSM custody, rotation policy, and a documented compromise procedure.
* **Bootstrapping.** Validators need the publisher's credential before they can use an artifact. The spec says this arrives by the same means as the trust list; the program needs to say concretely what that means, including how a rotation reaches deployed validators.
* **Two artifacts.** Since the design is one artifact per trust list, the program publishes one for the C2PA Trust List and one for the C2PA TSA Trust List. Confirm both are in scope — the TSA one is only useful to validators that opt into the optional TSA check.

### Publication

* **Identifiers.** Assign `trustListId` values for the two trust lists. The spec treats these as opaque, so any stable convention works; a URL is the obvious choice.
* **Location and discovery.** Pick a URL convention alongside the trust list. This was dropped from the spec on purpose, so it needs to live in program documentation.
* **Cadence and freshness.** Confirm daily generation and `nextUpdate = generatedAt + 7 days`. The spec leaves the validator's grace window to local policy; publishing a recommended value gives implementers a default and makes behavior more predictable across the ecosystem.
* **Hosting.** Availability target, CDN, and the fact that artifact fetches are now on the validation path for anyone who has stopped stapling. An outage degrades to the OCSP fallback, which is precisely the path that may no longer exist for some CAs.

### Aggregation inputs — the hard part

This is the largest open problem and the one most likely to determine whether the mechanism is useful.

* **CA obligations.** For an ARA to cover an issuer, that issuer's revocation data has to be reachable. The program would likely need to require, as a condition of trust list inclusion, that CAs publish CRLs and keep their CDP endpoints reachable and current. This is a new conformance requirement on CAs and is the single biggest ask in the whole proposal.
* **Sourcing intermediates.** The smoke test found only ~7 of 47 anchors had a fetchable CRL URL, because most anchors are self-signed roots with no CDP. The meaningful revocation data lives on intermediates. Options are listed under [Sourcing intermediate certs](#sourcing-intermediate-certs); the most robust is to have the program collect intermediate inventories from participating CAs directly, rather than discovering them.
* **Coverage honesty.** Because an issuer in the coverage set is a claim of completeness, the aggregator must only enroll issuers whose data it genuinely has in full. Enrolling optimistically is the one failure mode that silently produces wrong answers.

### Data quality

* **Filtering broad-CA noise.** Feeding the interim end-entity list to the aggregator inflated the artifact from ~36 entries to ~101,840, most of them unrelated to C2PA, because C2PA leaves chain through general-purpose CAs publishing one shared CRL across many products. A production ARA needs a rule for which entries intersect the C2PA universe — for example, retaining a serial only if some certificate with that `(issuer SKI, serial)` exists under a C2PA-trusted chain. Without it the artifact is mostly irrelevant data.
* **Failure handling.** Decide what the aggregator does when a CDP is unreachable: retain last-good data and mark that issuer `stale`, or hold back publication entirely. The spec supports the former via `status` and `partial`; the program should say when each is appropriate and how long an issuer may stay stale before it is dropped from coverage.
* **Monitoring.** Staleness, fetch failures, and unexpected swings in entry count all want alerting. An artifact that quietly stops updating fails open.

### Lifecycle

* **Retention horizon.** How long should C2PA claims remain verifiable? The answer sets how far the append-only list grows and whether segmentation ever becomes necessary. "Indefinitely" is the honest default for provenance and is what the current size arithmetic assumes.
* **Retired CAs.** This one is easy to miss. When a CA leaves the trust list, its issuers presumably drop out of the coverage set — at which point historical claims signed under it fall back to the OCSP path, which for a departed CA may no longer exist at all. The program should decide explicitly whether to keep covering retired issuers so that old content stays verifiable. Continuing to cover them costs almost nothing, as their entry set is frozen.
* **Format versioning.** Have a story for shipping a `version: 2` — most plausibly to add the completeness bounds that segmentation needs — including how validators behave when handed a version they do not understand.

### Transition

* **When signers may stop stapling.** Signers can only safely drop the staple once enough validators consult ARAs. The program should say when that threshold is considered met, and ideally publish coverage statistics so signers can judge.
* **Validator policy for uncovered issuers.** When no artifact covers an issuer and no staple is present, the spec leaves the outcome to policy. The PoC defaults to warn rather than refuse. A recommended default worth agreeing on, since it determines whether the transition is safe or merely permissive.

### Conformance and testing

* **Test vectors.** Publish a reference artifact plus assets exercising each branch: covered-and-good, covered-and-revoked, revoked-after-signing (which must still validate), stale artifact, uncovered issuer, and rolled-back artifact.
* **Validator conformance.** Define what an implementation claiming ARA support has to demonstrate, including the negative cases — particularly that it rejects a rolled-back artifact and does not treat a stale one as authoritative.
* **A revocation drill.** Stand up a test CA in the program's environment and actually revoke something, end to end. Revocation paths that are never exercised are usually broken.

## Proof of concept

Implemented in this subdirectory. As of v0.3 the PoC emits the normative **CBOR + COSE_Sign1** artifact and populates the **coverage set**; a JSON debug projection (Appendix B) is written alongside for inspection.

1. **`aggregator/`** — a small Rust binary that takes one or more certificate PEM files for a single trust list, parses each cert (using `x509-parser`), follows each CDP, downloads and parses the CRL, deduplicates entries, records the coverage set, and emits a CBOR artifact signed as COSE_Sign1. It is run separately for the claim-signing and TSA trust lists.
2. **`sample/`** — an example output artifact built from the current [official C2PA anchors trust list](https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TRUST-LIST.pem) augmented (for prototyping density only) with the [interim anchors list](https://contentcredentials.org/trust/anchors.pem). The [interim end-entity list](https://verify.contentauthenticity.org/trust/allowed.pem) is deliberately not used: it enumerates leaf certs rather than CAs, and revocation there is already handled by removal from the allowlist.
3. **`validator/`** — a small wrapper around [`c2pa-rs`](https://github.com/contentauth/c2pa-rs) that performs normal C2PA validation, extracts the claim-signing certificate and trusted time, then post-processes the revocation check against the claim-signing artifact. It can optionally check the TSA certificate against a separate TSA artifact and persists a per-trust-list rollback watermark.
4. **`demo/`** — run the aggregator and wrapper validator against a signed `c2pa-rs` fixture, first with artifacts built from the live trust lists and then with synthetic claim-signing and TSA revocations, demonstrating failure and informational paths.

The PoC is intentionally scoped to the flat-list artifact form. The Clubcard / cascading-filter variant from upstream CRLite is left as future work; it is only interesting once the universe of C2PA certs is large enough for raw-list size to matter.

## Future work and known gaps

This is the canonical list. The `aggregator/` and `validator/` READMEs link here rather than maintaining their own lists.

### Implemented in v0.3

* **CBOR / COSE_Sign1 artifact and coverage set.** The aggregator emits the normative CBOR artifact signed as COSE_Sign1 and populates `coveredIssuers`; the validator verifies the COSE_Sign1, CBOR-decodes the payload, and applies the coverage-set decision logic with an `--uncovered-policy` (`warn`/`refuse`) fallback for not-covered issuers. The `--uncovered-policy` default (`warn`) is provisional and worth revisiting.
* **One artifact per trust list.** The aggregator accepts certificates for one trust list per invocation and emits scope-free coverage and entry maps. The demo builds separate claim-signing and TSA artifacts.
* **v0.3 wire format.** Field names use the camelCase forms above, and all artifact dates are emitted and required as tagged `time` values (CBOR tag 1).
* **Partial coverage.** Fetch or processing failures mark the affected issuer `stale` when its identifier is available and set the artifact-level `partial` flag.
* **TSA handling.** The optional TSA check uses a separate TSA artifact and the time attested by the time-stamp. A revoked TSA certificate records `timeStamp.ara.revoked`, causes the time-stamp to be ignored, and does not directly fail the claim.
* **Rollback protection.** The validator persists the greatest `generatedAt` used for each `trustListId` and rejects an older artifact.

One incidental finding from the spec work, relevant if the artifact ever grows an enumerated field: the `cddl` npm package used by the C2PA schema repository (0.21.1) cannot parse CDDL group-to-choice syntax (`&(name: 0, ...)`) at all, so named enums of that form are not usable there.

### PoC gaps (would be addressed before this is more than a demo)

* **OCSP staple consultation.** For a not-covered issuer the validator only *detects* a stapled OCSP response (`rVals`); it does not parse or verify it. A real deployment would consult the staple on the legacy path.
* **Intermediate cert coverage in the aggregator.** Most certs in the C2PA anchors trust lists are self-signed roots that carry no CDP — the smoke-test run found only ~7 of 47 anchors had a fetchable CRL URL. Meaningful revocation data lives on *intermediate* certs (whose CDPs point to CRLs the root publishes about them) and on *end-entity* certs (whose CDPs point to CRLs the intermediate publishes). Where to source intermediates is the open question, see [Sourcing intermediate certs](#sourcing-intermediate-certs) below.
* **Test certificate minting.** The aggregator now has an `--inject-entries` flag that takes a JSON list of synthetic entries and merges them into the artifact (see `sample/inject-demo.json` and `demo/run.sh`). What's still outstanding is a dedicated test-cert minter — a small helper that produces a fresh test CA + EE cert + matching CRL so the demo doesn't have to pin its synthetic entries to existing fixture certs. Useful once we want regression tests independent of `c2pa-rs` fixtures.
* **Filtering broad-CA noise from the aggregated artifact.** Feeding `allowed.pem` to the aggregator inflates the artifact from ~36 entries to ~101,840 — but the bulk are non-C2PA revocations (e.g., ~36.9k Sectigo email/code-signing entries) pulled in because the C2PA leaves chain through broad-purpose public CAs that publish a single shared CRL across many use cases. A production ARA should filter to entries that intersect the C2PA universe — for example, only retain a revoked serial if at least one cert with that `(issuer SKI, serial)` exists under a C2PA-trusted chain. Without this, the artifact balloons in size and most of its entries are irrelevant to C2PA verifiers.

### Design-level extensions (would warrant a C2PA WG conversation)

* **Reason-aware variant.** Populate the reserved `reason` field with the RFC 5280 reason code and differentiate `keyCompromise` (invalidates earlier signatures) from softer reasons. Worth doing once we have evidence that issuers in the C2PA ecosystem populate reason codes reliably.
* **Active/archive segmentation.** The expiry-based split from [Persistence and retention](#persistence-and-retention) — a frequently-fetched active segment plus an immutable, indefinitely-cached historical archive. Note that this is a **format change, not a publishing convention**: it requires adding a completeness bound so a validator can tell when a query falls outside the segment it holds, since otherwise an incomplete-but-authoritative artifact silently reports revoked certificates as good. Only needed once the all-time list is large enough for retention to matter, which the size arithmetic says is not soon.
* **Clubcard / cascade compression.** Only interesting if the C2PA cert universe grows by orders of magnitude beyond the current trust-list scope, and even then it must be combined with a date side-table or epoch-partitioned filters to preserve the temporal model.
* **Delta artifacts.** Incremental updates rather than full re-publication; same observation as above, only matters at scale.

### Sourcing intermediate certs

Several plausible sources, in roughly increasing order of effort:

1. **Already in the bundles we have.** A few of the "anchors" PEMs really do contain intermediates (the ones whose CDPs the aggregator successfully followed — e.g., the Adobe intermediate at `pki-cdn.adobe.net`). This gives us a *partial* set already.
2. **Embedded in signed C2PA assets.** Every signed C2PA manifest's COSE_Sign1 carries the full `x5chain`. Harvesting intermediates from a corpus of public C2PA-signed media is straightforward (and is how Mozilla CRLite uses Certificate Transparency).
3. **The interim end-entity list (`allowed.pem`).** Despite the design-level rationale for excluding it (its revocation semantics are "remove from the allowlist"), it does enumerate real-world C2PA EE certs whose CDPs point at the right intermediates' CRLs. Feeding `allowed.pem` to the aggregator would yield denser revocation data for demo purposes, with a clear note that this is not the production trust model.
4. **AIA chasing.** Each cert's Authority Information Access extension typically has a `caIssuers` URL pointing to the parent cert. The aggregator could walk this chain upward from any starting point.
5. **CA cert repositories / C2PA conformance program.** Some CAs publish their full intermediate inventory; the conformance program may eventually formalize this.

## Appendix A: Background on CRLite

[CRLite](https://blog.mozilla.org/security/2020/01/09/crlite-part-1-all-web-pki-revocations-compressed/) was introduced by Mozilla (originally a [2017 IEEE S&P paper by Larisch et al.](https://obj.umiacs.umd.edu/papers_for_stories/crlite_oakland17.pdf)) to solve revocation for the WebPKI: aggregate **all** CA-published CRLs — discovered via Certificate Transparency logs — into a single compact filter that browsers download and consult entirely offline, with no per-handshake network call and no privacy leak to the CA.

Its scale and performance, per Mozilla's [August 2025 write-up](https://hacks.mozilla.org/2025/08/crlite-fast-private-and-comprehensive-certificate-revocation-checking-in-firefox/):

* **Coverage:** roughly **4 million** revoked certificates — effectively every revocation in the WebPKI.
* **Size / bandwidth:** about a **4 MB** snapshot every **45 days**, plus delta updates, averaging **~300 kB/day**. Firefox refreshes every **12 hours**.
* **Compression:** the original design used a multi-level cascade of Bloom filters. The 2025 [**Clubcard**](https://eprint.iacr.org/2025/610.pdf) redesign (presented at IEEE S&P 2025 / RWC 2025) replaced this with a *partitioned two-level cascade of Ribbon filters*, achieving roughly **1000×** the bandwidth efficiency of downloading CRLs directly, and about **half** the size of Chrome's CRLSets *while covering all revocations*.
* **Deployment:** shipped to **all Firefox desktop** users in **Firefox 137** (early 2025); OCSP querying was disabled in **Firefox 142** (August 2025). Mozilla has open-sourced the building blocks (`clubcard`, `clubcard-crlite`, and the CRLite backend), but to date CRLite is **essentially Firefox-only** — there is no other production deployment.
* **Closest analog elsewhere:** Chrome's [CRLSets](https://www.chromium.org/Home/chromium-security/crlsets/) push revocation data to browsers offline as well, but they ship a **curated subset** of revocations chosen by Google rather than the comprehensive set CRLite covers — a useful contrast for C2PA's design choices above.

**Why C2PA is a friendlier environment.** CRLite's filter-compression machinery exists because the WebPKI universe is enormous (millions of live certs, ~4M revocations). The relevant comparison for an ARA, though, is not the *total* number of end-entity certificates but the number of *revocations* it must carry. C2PA's trust anchors are counted in the *tens*, and that bound is fixed by the trust list. The end-entity population is harder to bound and may grow large: edge-device deployments can mint a unique, short-lived certificate per signed asset, so EE certs could eventually outnumber today's WebPKI hosts.

That growth does not translate into a proportionally large ARA. Per-asset certificates of this kind are short-lived and could even be single-use, and are therefore unlikely to be individually revoked; the revocations an ARA must enumerate come predominantly from the longer-lived, reused signing certificates and intermediates, a much smaller set. So while the total certificate universe could become large, the *revocation* set it produces is expected to stay modest — at that scale a flat, deduplicated list fits in tens of KB with no filter at all, and there is already a natural publishing authority (the conformance program governing the trust list). The interesting design problems for C2PA are therefore not compression but **temporal validity**, **backward compatibility**, and **long-term persistence**, addressed above. Should the revocation set ever grow enough to make size a real constraint, CRLite-style filter compression remains available as a later option.

## Appendix B: JSON projection

For inspection and debugging only — the normative artifact is the CBOR/COSE_Sign1 form in [Artifact format](#artifact-format). This projection maps field-for-field, with byte strings shown hex-encoded and dates as ISO-8601 UTC:

```json
{
  "version": 1,
  "trustListId": "<identifier of the trust list this corresponds to>",
  "generatedAt": "<ISO 8601 UTC>",
  "nextUpdate": "<ISO 8601 UTC, after which validators should consider it stale>",
  "partial": false,
  "coveredIssuers": [
    {
      "issuerSKI": "<hex-encoded SKI of issuing CA>",
      "lastUpdate": "<ISO 8601 UTC>",
      "status": "ok"
    }
  ],
  "entries": [
    {
      "issuerSKI": "<hex-encoded SKI of issuing CA>",
      "serialNumber": "<hex-encoded big-endian serial>",
      "revocationDate": "<ISO 8601 UTC>"
    }
  ]
}
```

Note that `partial` and the per-issuer `status` are linked: `partial` is `true` exactly when at least one covered issuer carries `"status": "stale"`.

## Change history

### v0.3.1 (2026-08-19)

Editorial pass; no normative or format changes.

* **Background on CRLite moved to an appendix.** The section is now [Appendix A](#appendix-a-background-on-crlite), with a pointer to it at the document's first mention of CRLite; the JSON projection became Appendix B.
* **Trimmed inline version history.** Removed the running "a previous draft did X" asides from the body (the naming note, and the various `v0.2`/`v0.2.1` references), since they only distract a first-time reader. The rename rationale was folded into the v0.2 entry below, and this Change history remains the record of what changed between drafts.
* **Reworded the single-artifact rationale** so it states the current design directly rather than describing the removal of the old `scope` field.

### v0.3 (2026-08-17)

Revised to match the draft spec change prepared against the C2PA core specification. The substantive changes all came out of reconciling this proposal with what the specification already says.

* **Dropped `scope`; one artifact per trust list.** The single-artifact-with-scope design contradicted this document's own trust-list-neutral framing, and was redundant given that the specification already keeps the TSA trust anchor list separate from the claim-signing lists. The conformance program now publishes two artifacts. See [Overview](#overview).
* **TSA handling corrected.** "Repeat steps 2–5 for the TSA's signing certificate" was wrong in two ways: it used the claim's `T_sig` rather than the time attested by the time-stamp, and it implied a revoked TSA certificate fails the claim, when the specification treats a failing time-stamp as ignored rather than fatal. The check is also explicitly optional. See [Validation procedure](#validation-procedure).
* **ARA does not suppress a staple.** Made explicit that where both mechanisms are applied, either one reporting revocation rejects the claim. The PoC's skip-the-staple behavior is an optimization, not a spec requirement.
* **CRL prohibition retained.** Established that the prohibition binds the claim generator, not the artifact publisher, so it never needed removing.
* **Completeness made explicit.** Added the requirement that an artifact enumerate *every* known revocation for each issuer it claims to cover. This was implicit before, and its absence was a soundness hole: the "absence means not revoked" inference is only valid against a complete artifact. Also established that this makes segmentation a format change rather than a publishing convention. See [Persistence and retention](#persistence-and-retention).
* **New [What C2PA would need to do](#what-c2pa-would-need-to-do) section** collecting the operational decisions and work the conformance program would have to take on — governance and signing, publication, aggregation inputs, data quality, lifecycle, transition, and conformance testing. These were previously scattered or unstated.
* **Format tightened to C2PA schema conventions** — camelCase fields, `-map` rule names, and tagged `time` (CBOR tag 1) in place of `~time`, which was the untagged form and contradicted its own comment. `last-crl-update` became `lastUpdate`.
* **Rollback protection promoted** from a security consideration to a normative requirement.
* **Freshness** — the grace window is left to local policy rather than fixed at 30 days; the 7-day `nextUpdate` interval becomes a recommendation.
* **Publication URL convention and trust list identifiers dropped** from the spec scope; both are conformance-program concerns.
* **Status codes named** for the first time.
* Noted that `partial` and per-issuer `status` are linked, and corrected the Appendix B example, which had shown an invalid combination.

### v0.2.1 (2026-06-22)

* **Scale framing corrected.** Replaced the "low thousands" end-entity estimate in *Background on CRLite*, which understated edge-device deployments that mint a unique cert per signed asset. Clarified that an ARA carries *revocations*, not the total EE population, and that short-lived single-use certs are unlikely to be revoked — keeping the revocation set modest.

### v0.2 (2026-06-09)

* **Renamed** the mechanism from "CRLite for C2PA" to **Aggregated Revocation Artifact (ARA)**, because the design is not CRLite: it carries no cascading-Bloom/Ribbon filter, it is revocation-date-aware rather than a pure set-membership test, and it is bound to a bounded trust list rather than the whole WebPKI. It borrows CRLite's *concept* — central aggregation of CRLs, a signed push to clients, and offline lookup — not its compression machinery.
* **OCSP deprecation.** Added an "OCSP is being deprecated in the WebPKI" subsection to *Justification*, framing C2PA's mandatory-OCSP requirement as a structural risk (CA/B Forum SC-063v4; Let's Encrypt's 2025 OCSP shutdown).
* **CRLite background.** Added a *Background on CRLite* section with concrete scale, size, deployment, and Clubcard details, and the rationale for why C2PA does not need CRLite's compression.
* **Backward compatibility.** Added a *Backward compatibility and coexistence* section introducing the **coverage set** (`covered-issuers`), a validator decision matrix for the OCSP-staple fallback, and generalization across multiple trust lists.
* **Persistence.** Added a *Persistence and retention* section: the list is append-mostly (records cannot be dropped at cert expiry as in CRLite), with an active-segment / immutable-archive model and scale estimates.
* **CBOR format.** Made **CBOR + COSE_Sign1** the normative artifact form (CDDL definition), tightened field encodings (`bstr` SKI/serial, epoch-second dates), and moved the JSON form to *Appendix B* as a debug-only projection.
* **Validation procedure** updated to select an ARA by coverage set and apply the staple-fallback logic.
* **Trust-list-neutral framing** throughout, so the design generalizes beyond the C2PA Trust List.
* Doc-only release: the PoC code still emits signed JSON; the CBOR/COSE + coverage-set migration is tracked in *Future work*.

### v0.1 (initial draft)

* Initial CRLite-inspired proposal: daily aggregator over trust-list CRLs, revocation-date-aware temporal model, signed-JSON (ES256 JWS) artifact, validation procedure, freshness window, and the PoC (`aggregator/`, `validator/`, `sample/`, `demo/`).
