# Trust list proposal

_draft 0.1_

One of the urgent issues to resolve in C2PA is defining trust lists for signers of [identity assertions](https://creator-assertions.github.io/identity/1.0-draft/). The C2PA trust list task force is defining the trust mechanisms for a [claim generator](https://c2pa.org/specifications/specifications/2.0/specs/C2PA_Specification.html#claim-generator-definition), but defining how to create domain-specific lists (e.g., for [project Origin](https://www.originproject.info/)) is out of scope for C2PA.

This page explores some design options to define trust lists. In each case, it is the [validator](https://c2pa.org/specifications/specifications/2.0/specs/C2PA_Specification.html#_validator)'s responsibility to trust a specific list.

## Simple JSON trust list

The simplest option is to create a JSON file containing the list of trusted signers. The file would contain the following data:
* `name`: the name of the trust list (e.g., the entity who created the list)
* `download_url`: the URL where the list can be downloaded/updated from 
* `description`": the description of the list
* `website`: a URL to a page to get more information about the trust list
* `last_updated`: the last update timestamp, represented in the ISO 8601 date-time format (YYYY-MM-DDTHH:MM:SSZ) in UTC
* `signers`: an array of trusted signer objets with the following data:
  * `id`: the signer identifier (e.g., person/organization's name)
  * `display_name`: a display name (e.g., to show in validators)
  * `contact`: some contact information (URL, human contact info)
  * `jwks_url`: a pointer to the signer's certificates (e.g., a key set as [prototyped here](../web-domain-trust-anchor/web-domain-trust-anchor.md)). We wouldn't want the trust list to change every time a signer updates their certificates, so the list itself should only contain a pointer to some signer information vs. the certs themselves.

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


## ToIP Trust Registries

Another option is to use [trust registries](https://trustoverip.github.io/tswg-trust-registry-protocol/) as defined by Trust over IP foundation.

TODO: more details