# C2PA Signer Privacy

_draft 0.1_

A C2PA creator or editor might want to hide their identity while signing a digital asset. This page explores some scenarios and techniques to achieve various levels of privacy, ranging from pseudonymity to full anonymity.

Note that we only consider the signer’s (a person or organization) privacy here, not the ability to redact or modify the asset itself.

## Example scenarios
1. A reporter documenting human right abuses wants to remain anonymous to avoid retribution from a hostile government but would like to disclose her affiliation (to a news organization or press association). The news organizations publishing the images and videos doesn’t want the ability to identify the journalist to avoid the risk of being compelled to disclose her identity.
2. A news organization receives a signed video from a confidential source for a story, and wants to share it without disclosing the source's identity (or leaking identifiable attributes) while preserving the authenticity guarantees of the video. 
3. A whistle blower records some incriminating conversations using his phone and releases the audio files signed by his corporate identity. He wants to remain anonymous without anyone (including the employer who issued the identity credential) being able to trace his identity.
4. A Banksy-style artist creates authenticated pictures and posts them at various online locations. They want to remain pseudonymous reusing the same signing credential, but without linking it to their real life identity.

## Techniques

The current C2PA [core 2.0 specification](https://c2pa.org/specifications/specifications/2.0/specs/C2PA_Specification.html) only supports X.509 certificates to generate (claim) signatures. The [Creator Assertion Working Group](https://creator-assertions.github.io/) is specifying [identity assertions](https://creator-assertions.github.io/identity/1.0-draft/) where additional identity information can be attached to a C2PA asset. Identity assertions could support various credential types; initially, Verifiable Credentials (see [PR 90](https://github.com/creator-assertions/identity-assertion/pull/90)). Additional credential types, such as mDL and SD-JWT could also be added in the future.

### Pseudonymous certificates

The simplest technique compatible with the current specification is to generate a self-signed X.509 certificate and use it to sign digital assets (i.e., use it as the claim generator certificate). The certificate would then need to be obtained out-of-band by verifiers. This technique doesn't allow signers to prove things about themselves (memberships, entitlements, etc.), it only demonstrates ownership of a public key; it is only useful for scenario #4.

### One-use certificates

Re-using a X.509 certificate creates linkable signatures: even if a certificate doesn't identify its owner, all the resulting signatures can be associated to the same entity. 

To achieve unlinkability, a signer could obtain a new certificate for each signature. A signer could prove an entitlement or membership in an organization by using certificates issued by the organization's CA. This would however be hard to deploy in practice, complicating key management for signing clients. 

### Zero-knowledge proofs over X.509 certificates

A Zero-Knowledge Proof (ZKP) is a cryptographic mechanism allowing someone to prove properties about some data without disclosing the data itself. Given some data signed by a X.509 certificate, a user could prove that the signature and certificate are valid without disclosing the identifiable parts of the certificate (serial number, public key, issuer signature, validity period). A C2PA manifest could be redacted using a ZKP allowing anyone to verify that:
1. the digital asset hasn't been modified
2. the signer's cert was valid at signing
3. the signer cert's CA is trusted (the CA cert would be visible, allowing validators to infer memberships)

This technique is very promising as it is compatible with the current C2PA specification and doesn't require changes to the key management infrastructure. Early prototyping efforts show that the approach would be practical for this use case, but more experiments must be conducted to work out the details.  

### Privacy-preserving Verifiable Credentials

Using [CAWG identity assertions](https://creator-assertions.github.io/identity/1.0-draft/) with a privacy-preserving credential type would provide rich disclosure capabilities to users. For example, a credential encoding various user attributes (e.g., name, affiliation, role, location, etc.) that could be selectively disclosed would offer flexible privacy control for signers. Example of such credential types include:
* [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) using unlinkable signatures (e.g., [BBS signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/))
* [anoncreds](https://wiki.hyperledger.org/display/anoncreds)
* [SD-JWT](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
* [mDL](https://www.iso.org/standard/69084.html)

It would however be hard to achieve anonymity using this technique alone. The current C2PA specification mandates the use of a X.509 claim generator signature on all assertions in the manifest (including the identity one); this signature is inescapably linkable and could negate the privacy properties of the identity assertion. The X.509-based techniques above could be used by the C2PA claim generator to work-around this issue.
