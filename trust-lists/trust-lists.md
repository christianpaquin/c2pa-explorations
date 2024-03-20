# Trust list proposal

_draft 0.2_

One of the urgent issues to resolve in C2PA is defining trust lists for signers of [identity assertions](https://creator-assertions.github.io/identity/1.0-draft/). The C2PA trust list task force is defining the trust mechanisms for the [C2PA Trust List](https://c2pa.org/specifications/specifications/2.0/specs/C2PA_Specification.html#_trust_lists), but defining how to create domain-specific lists (e.g., for [project Origin](https://www.originproject.info/)) is out of scope for C2PA.

This page explores some design options to define trust lists. In each case, it is the [validator](https://c2pa.org/specifications/specifications/2.0/specs/C2PA_Specification.html#_validator)'s responsibility to trust a specific list (in this note, the validator could be a validation tool deployer or a human user with the ability to select specific trust lists in its implementation).

## List of X.509 certificates

The simplest option (and the one closest to what is described in [section 14.4](https://c2pa.org/specifications/specifications/2.0/specs/C2PA_Specification.html#_trust_lists) of the C2PA 2.0 specification) is to list the trusted X.509 certificates. The core specification mentions listing the core anchors, but for more generality, a trust list could also include end-entity certificates.

The list would be encoded in a JSON file containing the following data:
* `name`: the name of the trust list (e.g., the entity who created the list)
* `download_url`: the URL where the list can be downloaded/updated from 
* `description`": the description of the list
* `website`: a URL to a page to get more information about the trust list
* `last_updated`: the last update timestamp, represented in the ISO 8601 date-time format (YYYY-MM-DDTHH:MM:SSZ) in UTC
* `entities`: an array of trusted entities (signers or anchors) objects with the following data:
  * `name`: the full name of the entity (person or organization)
  * `display_name`: a display name (e.g., a simpler name to show in validators)
  * `contact`: some contact information (URL, human contact info)
  * `type`: "leaf" for end-entity certificates, "CA" for CAs, "root" for root CAs (TODO: do we need to distinguish CAs and root CAs?)
  * `jwks`: a JSON Web Key set, as defined in [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), containing the list of current _and_ expired (for anchors) certificates (to allow validation of old signatures). The 
    * TODO: decide which JWK properties to require; for non-root CAs, we'd at least need the rest of the cert chain in, e.g., an `x5c` property. All values should adhere to the [C2PA cert profile](https://c2pa.org/specifications/specifications/2.0/specs/C2PA_Specification.html#_certificate_profile).

## List of JWKS pointers

Another simple option similar to the previous one is to create a list that contains _pointers_ to external key stores (e.g., a key set as [prototyped here](../web-domain-trust-anchor/web-domain-trust-anchor.md)) vs. listing the certificates directly. This would allow the trust list to stay fairly stable without requiring an update when a signer/anchor update their certificates.

The trust list JSON file would contain the same information as before, but replacing the `jwks` property with a `jwks_url` pointing to the location of an entity's JWK set.

NOTE: this approach has been successfully adopted by the [VCI](https://vci.org) to list the 600+ trusted international signers of covid-19 vaccination credentials for the [SMART Health Cards](https://smarthealth.cards/) framework. Their [trust directory](https://github.com/the-commons-project/vci-directory/) is managed on github and accessible as a JSON file that is openly audited, with scripts fetching and validating issuer keys on a daily basis.

An example trust list file might look like this
```JSON
{
    "name": "Sample Trust List",
    "url": "https://raw.githubusercontent.com/christianpaquin/void/main/c2pa/sample-trust-list.json", 
    "description": "A trust list for sample issuers",
    "website": "https://github.com/christianpaquin/c2pa-explorations/blob/main/trust-lists/sample/about.md",
    "last_updated": "2024-03-16T03:47:34Z",
    "signers": [
        {
            "id": "Christian Paquin",
            "display_name": "Christian Paquin",
            "contact": "christianpaquin.github.io/contact",
            "jwks_url": "christianpaquin.github.io"
        },
        {
            "id": "Example issuer",
            "display_name": "Example",
            "contact": "example.com/contact",
            "jwks_url": "example.com"
        }
    ]
}
```

Some validators might want to frequently obtain a fresh list of the signer's certificates to enable offline validation. This can be done by fetching each entry in the trust list; the trust list provider could create this downloadable file containing each signer's JWK.

### Proof of concept

The example trust list above has been deployed [here](./sample/sample.json). The [proof-of-concept validator](../web-domain-trust-anchor/web-domain-trust-anchor.md#proof-of-concept) for the web domain trust anchor proposal has been modified to handle this type of trust lists. The [instructions]((../web-domain-trust-anchor/web-domain-trust-anchor.md#proof-of-concept)) are the same to create a key pair and a signed asset, but call the validator with the `trustlist` parameter:
```
./verify.sh <file> <trust_list_url>
```

Running (from ../web-domain-trust-anchor/)
```
./verify.sh media/cards_created.jpg https://raw.githubusercontent.com/christianpaquin/void/main/c2pa/sample-trust-list.json
```

results in the following output:
```
Fetching trust list from https://raw.githubusercontent.com/christianpaquin/void/main/c2pa/sample-trust-list.json
Trust list fetched:
         - name: Sample Trust List
         - url: https://raw.githubusercontent.com/christianpaquin/void/main/c2pa/sample-trust-list.json
         - description: A trust list for sample issuers
         - website: https://github.com/christianpaquin/void
         - last updated: 2024-03-16T03:47:34Z
         - number of signers: 2
         
Origin URL: https://christianpaquin.github.io
Fetching JWKS from: https://christianpaquin.github.io/c2pa.json
Valid asset signed by trusted issuer: Christian Paquin
```

## Trust Registries

Another option is to use trust registries/directories, for example the one defined in [ToIP](https://trustoverip.github.io/tswg-trust-registry-protocol/).

TODO: more details