# crlite-for-c2pa end-to-end demo

A single shell script that drives the full proof of concept:

1. Builds `aggregator` and `validator` in release mode.
2. Aggregates revocation data from the live C2PA Trust Lists into a signed COSE artifact plus a JSON debug projection.
3. Validates `c2pa-rs`'s `CA.jpg` test fixture against the clean artifact → both the claim-signing cert and the TSA cert pass.
4. Re-aggregates with synthetic injected entries (`../sample/inject-demo.json`) targeting that asset's exact `(issuer SKI, serial)` pairs, with carefully chosen revocation dates that exercise both temporal cases.
5. Validates again — the claim-signing cert fails (revoked before signing time) while the TSA cert passes (revoked *after* signing time, the design doc's whole point).

## Run

```
./run.sh
```

Override the asset by setting `C2PA_ASSET=/path/to/some-signed-image.jpg`. The default is the `CA.jpg` fixture from a sibling `c2pa-rs` checkout at `~/dev/c2pa/c2pa-rs`. If you point it at a different asset, you'll need to regenerate `../sample/inject-demo.json` with that asset's actual issuer-SKI and serial values.

Exit `0` if the clean run passes and the injected run fails as expected, `1` otherwise.

## Sample output

```
=== Step 2: validate CA.jpg against the CLEAN artifact (expect both PASS) ===
Claim-signing cert revocation check: PASS (not in revocation artifact)
TSA cert revocation check:           PASS (not in revocation artifact)

=== Step 4: validate CA.jpg against the INJECTED artifact (expect claim FAIL, TSA PASS) ===
Claim-signing cert revocation check: FAIL (revoked at 2020-01-01T00:00:00Z, before/at signing time)
TSA cert revocation check:           PASS (revoked at 2025-06-01T00:00:00Z, after signing time — signature was made while the cert was still valid)

Demo passed.
```
