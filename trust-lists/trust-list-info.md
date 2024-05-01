# Trust List Information

_draft 0.1_

 It would be helpful to include a trust list indicator in a C2PA manifest for signers (claim generators) not part of the C2PA trust list, this could be used by validators to convey more information to users when encountering unknown signers. The simplest would be to include a URL pointing to a website describing the list, such as project Origin’s [IPTC trust list page](https://iptc.org/origin-trust-list/). The mechanism should ideally be reusable for CAWG identity assertions.

Some options where this could be located:
1. In the COSE signature (e.g., in the protected header); this is where the cert (chain) is stored already. This works both for claim signatures and identity assertions, but requires lower-level integration into the COSE layer.
2. In the Claim Generator Info. Easy to integrate into existing element, but doesn't work for identity assertions.
3. In an assertion (or its metadata). This would need to be defined, and could work both for claim signatures and identity assertions.
