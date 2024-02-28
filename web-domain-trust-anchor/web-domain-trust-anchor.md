# Web Domain Trust Anchor proposal

_draft 0.1_

The [Creator Assertion WG](https://creator-assertions.github.io/) is developing a specification describing how identity assertions can be attached to a C2PA manifest to identity the entity associated with a digital asset or its transformations. Currently, the main mechanism described in the  [draft specification](https://creator-assertions.github.io/identity/0.1-draft/) is based on X.509 certificates (just like in the core C2PA specification). The trust model defining how these identity credentials can be trusted by a validator is currently undefined.

This document proposes a simple trust model which would allow the owner of a origin URL to sign C2PA identity assertions in a indepedant manner, allower verifiers to display a signature as originating from a web domain, allowing the human user to make its own trust decision. Trust of the C2PA asset would then be as if it had be found on the origin URL's web page.

## Justification

In order to scale adoption of C2PA to a larger set of users beyond acreditated creators (e.g., hardware and software vendors, members of recognized organizations, etc.), we need to provide the ability set up easily discoverable identities. There is a long tail of independant, unafiliated creators that would benefit from a simple self-sufficient mechanism, allowing anyone with a web presence to create identified content and anyone with web access to verify it. Example creators include companies, indy artists, politicians, athletes, etc.

Issuing 3rd-party-verified PKI-based identities at in internet scale is difficult. Similarly, Verifiable Credentials is an emergent framework that also requires a PKI-like infrastructure (for non self-asserted identities) which isn't widely available today.

Anchoring an identity to an origin URL (a web domain or a URL path) is a simple and scalable solution. It is very easy for anyone to setup a TLS certificate for their website, proving to connecting users that they control content on the origin URL. Most public figures and organizations already have a web presence; anything present on such a website is implicitely trusted by visitors.

## Description

### Definitions

* Actor: asset creator or editor, as defined in the Identity assertion specification.
* Origin URL: path to the actor's identity web presence, a web domain (e.g., "exampleuser.com") or a URL (e.g., "exampleplatform/exampleuser"). 

### Identity lifecycle

#### Creation

To anchor trust to its web domain, an actor (asset creator/editor):

1. Creates a self-signed certificate and a corresponding private key, following the guidelines in [C2PA 2.0 core specfication](https://c2pa.org/specifications/specifications/2.0/specs/C2PA_Specification.html#x509_certificates), and
2. Creates a JSON Web Key (JWK) set containing the certificate (in a `x5c` property, as defined in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)), and makes it available at `<origin URL>/.well-known/c2pa.jwks`

It can then sign the identity assertions with its certificate, as it would using a CA-issued one. TODO: the assertion should link back to the origin URL, either throug an extension in the certificate, or a field in the assertion itself.

### Revocation

To revoke a certificate, the actor removes it from its JWK set.

#### Expiration

When a certificate expires, the actor deletes the corresponding private key, generates a new one and adds it to its JWK set. The expired certificate remains in the JWK set to allow validation of C2PA assets signed with the expired certificate (which was valid at the time of signature).

### Identity assertion creation

Works as defined in [section 6](https://creator-assertions.github.io/identity/0.1-draft/#_creating_the_identity_assertion) of the Identity Assertion specification.

### Identity assertion validation

Works as defined in [section 7](https://creator-assertions.github.io/identity/0.1-draft/#_validating_the_identity_assertion) of the Identity Assertion specification, but with the following post-processing step:

The validator
1. looks up the actor's origin URL,
2. retrieves the JWK set `<origin URL>/.well-known/c2pa.jwks`, and
3. checks if the certificate contained in the C2PA manifest is also contained in the JWK set.

## Security/privacy considerations

### Domain takeover

Control of a web domain or URL can change over time. Someone forcefully getting control of an origin URL could mount a denial of service attack by preventing validators to verify assets (by removing the required certificate). An attacker couldn't however create signed assets on behalf of the real owner. 

### Call home validation

Asset verification requires validators to fetch the JWK set from the origin URL well-known path. This has privacy impact which can be mitigated by various strategies, e.g.:
* Building intermediary trust list repositories of known url/certificate maps
* Allowing users to explicitely request validation of an asset (akin to a mail agent not loading an email's HTML images until authorized by the user)

