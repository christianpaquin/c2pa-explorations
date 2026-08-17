# crlite-for-c2pa end-to-end demo

A single shell script that drives the full proof of concept:

1. Builds `aggregator` and `validator` in release mode.
2. Aggregates separate signed COSE artifacts for the claim-signing and TSA trust lists.
3. Validates `c2pa-rs`'s `CA.jpg` test fixture against the clean artifacts.
4. Re-aggregates with separate synthetic claim and TSA entries targeting that asset's exact `(issuer SKI, serialNumber)` pairs.
5. Validates again: the claim-signing cert fails, while TSA revocation is reported informationally and the timestamp is ignored.

## Run

```
./run.sh
```

Override the asset by setting `C2PA_ASSET=/path/to/some-signed-image.jpg`. The default is the `CA.jpg` fixture from a sibling `c2pa-rs` checkout at `~/dev/c2pa/c2pa-rs`. For a different asset, regenerate both injection files with its claim-signing and TSA certificate identifiers.

Exit `0` if the clean run passes and the injected run fails as expected, `1` otherwise.

## Sample output

```
=== Step 2: validate CA.jpg against the CLEAN artifact (expect both PASS) ===
Claim-signing cert revocation check: PASS (not in revocation artifact)
TSA cert revocation check:           PASS (not in revocation artifact)

=== Step 4: validate CA.jpg against the INJECTED artifacts (expect claim FAIL, TSA revocation informational) ===
Claim-signing cert revocation check: FAIL (revoked at 2020-01-01T00:00:00Z, before/at signing time)
TSA cert revocation check: INFORMATIONAL [timeStamp.ara.revoked] (revoked at 2020-01-01T00:00:00Z, timestamp ignored)

Demo passed.
```
