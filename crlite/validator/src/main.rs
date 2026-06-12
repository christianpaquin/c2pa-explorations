use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use clap::{Parser, ValueEnum};
use coset::{CborSerializable, TaggedCborSerializable};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::EncodedPoint;
use serde::Deserialize;
use serde_repr::Deserialize_repr;
use std::fs;
use std::path::PathBuf;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::Pem;

#[derive(Deserialize)]
struct TstContainer {
    #[serde(rename = "tstTokens")]
    tst_tokens: Vec<TstToken>,
}

#[derive(Deserialize)]
struct TstToken {
    #[serde(with = "serde_bytes")]
    val: Vec<u8>,
}

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum UncoveredPolicy {
    /// Accept (exit 0) with a warning when the issuer is not covered and no staple is present.
    Warn,
    /// Refuse (exit 1) when the issuer is not covered and no staple is present.
    Refuse,
}

#[derive(Parser, Debug)]
#[command(version, about = "Verify a C2PA asset's certs against an Aggregated Revocation Artifact (ARA)")]
struct Args {
    /// Signed revocation artifact (COSE_Sign1, CBOR).
    #[arg(long)]
    artifact: PathBuf,

    /// Publisher's public key (P-256 EC JWK).
    #[arg(long)]
    pubkey: PathBuf,

    /// Days past `next_update` to still accept the artifact.
    #[arg(long, default_value_t = 30i64)]
    grace_days: i64,

    /// What to do when the issuer is not in the coverage set and no OCSP staple is present.
    #[arg(long, value_enum, default_value_t = UncoveredPolicy::Warn)]
    uncovered_policy: UncoveredPolicy,

    /// Asset to validate.
    asset: PathBuf,
}

// ---- artifact (CBOR / COSE_Sign1 payload, kebab-case per the CDDL) ----------

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Artifact {
    version: u32,
    trust_list_id: String,
    generated_at: i64,
    next_update: i64,
    #[serde(default)]
    partial: Option<bool>,
    #[serde(default)]
    covered_issuers: Vec<Coverage>,
    entries: Vec<Entry>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
struct Coverage {
    scope: Scope,
    #[serde(with = "serde_bytes")]
    issuer_ski: Vec<u8>,
    #[allow(dead_code)]
    last_crl_update: i64,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
struct Entry {
    scope: Scope,
    #[serde(with = "serde_bytes")]
    issuer_ski: Vec<u8>,
    #[serde(with = "serde_bytes")]
    serial: Vec<u8>,
    revocation_date: i64,
}

#[derive(Deserialize_repr, Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Scope {
    Anchors = 0,
    Tsa = 1,
}

#[derive(Deserialize)]
struct PublicJwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

/// Whether the issuer is authoritatively covered by the artifact.
enum CoverageStatus {
    Fresh,
    Stale,
    NotCovered,
}

enum Outcome {
    GoodStanding,
    Revoked { date: OffsetDateTime },
    RevokedAfterSig { date: OffsetDateTime },
    CoverageStale,
    NotCoveredStaple,
    NotCoveredWarn,
    NotCoveredRefuse,
}

impl Outcome {
    /// True if this outcome means the revocation check failed (process should exit non-zero).
    fn is_failure(&self) -> bool {
        matches!(
            self,
            Outcome::Revoked { .. } | Outcome::CoverageStale | Outcome::NotCoveredRefuse
        )
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let artifact = load_and_verify_artifact(&args.artifact, &args.pubkey, args.grace_days)?;
    println!("Artifact:");
    println!("  trust_list_id:   {}", artifact.trust_list_id);
    println!("  generated_at:    {}", iso(artifact.generated_at));
    println!("  next_update:     {}", iso(artifact.next_update));
    println!("  covered issuers: {}", artifact.covered_issuers.len());
    println!(
        "  entries:         {} ({})",
        artifact.entries.len(),
        if artifact.partial.unwrap_or(false) {
            "partial"
        } else {
            "complete"
        }
    );
    println!();

    println!("Reading C2PA manifest: {}", args.asset.display());
    let reader = c2pa::Reader::default()
        .with_file(&args.asset)
        .with_context(|| format!("c2pa::Reader::with_file({})", args.asset.display()))?;
    let manifest = reader
        .active_manifest()
        .ok_or_else(|| anyhow!("no active manifest in asset"))?;
    let sig_info = manifest
        .signature_info()
        .ok_or_else(|| anyhow!("manifest has no signature info"))?;

    let t_sig = match sig_info.time.as_ref() {
        Some(t) => {
            let dt = OffsetDateTime::parse(t, &Rfc3339)
                .with_context(|| format!("parsing signing time '{}'", t))?;
            println!("Signing time (T_sig, from trusted timestamp): {}", t);
            dt
        }
        None => {
            let now = OffsetDateTime::now_utc();
            println!(
                "WARNING: no trusted timestamp; falling back to T_sig = now ({})",
                now.format(&Rfc3339)?
            );
            now
        }
    };

    let cose_sign1_bytes = load_cose_sign1_bytes(&args.asset).ok().flatten();
    let staple_present = cose_sign1_bytes
        .as_deref()
        .map(has_ocsp_staple)
        .unwrap_or(false);

    let chain = parse_pem_chain(sig_info.cert_chain().as_bytes())?;
    let ee_der = chain
        .first()
        .ok_or_else(|| anyhow!("empty cert chain in manifest"))?;
    let (_, ee) = parse_x509_certificate(ee_der)?;
    let issuer_ski = extract_aki(&ee).ok_or_else(|| {
        anyhow!("claim-signing cert lacks AKI extension; cannot determine issuer SKI")
    })?;
    let serial = ee.tbs_certificate.serial.to_bytes_be();

    println!("Claim-signing cert:");
    println!("  subject:    {}", ee.subject());
    println!("  issuer SKI: {}", hex::encode(&issuer_ski));
    println!("  serial:     {}", hex::encode(&serial));
    println!();

    let outcome = evaluate(
        &artifact,
        Scope::Anchors,
        &issuer_ski,
        &serial,
        t_sig,
        staple_present,
        args.uncovered_policy,
    );
    print_outcome("Claim-signing cert", &outcome);

    println!();
    let tsa_outcome = match extract_tsa_cert_der(cose_sign1_bytes.as_deref()) {
        Ok(Some(tsa_der)) => {
            let (_, tsa_cert) = parse_x509_certificate(&tsa_der)?;
            let tsa_issuer_ski = extract_aki(&tsa_cert).ok_or_else(|| {
                anyhow!("TSA cert lacks AKI extension; cannot determine issuer SKI")
            })?;
            let tsa_serial = tsa_cert.tbs_certificate.serial.to_bytes_be();
            println!("TSA cert:");
            println!("  subject:    {}", tsa_cert.subject());
            println!("  issuer SKI: {}", hex::encode(&tsa_issuer_ski));
            println!("  serial:     {}", hex::encode(&tsa_serial));
            println!();
            Some(evaluate(
                &artifact,
                Scope::Tsa,
                &tsa_issuer_ski,
                &tsa_serial,
                t_sig,
                staple_present,
                args.uncovered_policy,
            ))
        }
        Ok(None) => {
            println!("TSA cert revocation check: skipped (no sigTst2 in COSE signature)");
            None
        }
        Err(e) => {
            println!("TSA cert revocation check: skipped (extract failed: {:#})", e);
            None
        }
    };
    if let Some(o) = &tsa_outcome {
        print_outcome("TSA cert", o);
    }

    let failed = outcome.is_failure() || tsa_outcome.map(|o| o.is_failure()).unwrap_or(false);
    if failed {
        std::process::exit(1);
    }
    Ok(())
}

/// Apply the v0.2 coverage-set decision logic for one certificate.
fn evaluate(
    artifact: &Artifact,
    scope: Scope,
    issuer_ski: &[u8],
    serial: &[u8],
    t_sig: OffsetDateTime,
    staple_present: bool,
    policy: UncoveredPolicy,
) -> Outcome {
    match coverage_status(artifact, scope, issuer_ski) {
        CoverageStatus::NotCovered => {
            if staple_present {
                Outcome::NotCoveredStaple
            } else {
                match policy {
                    UncoveredPolicy::Warn => Outcome::NotCoveredWarn,
                    UncoveredPolicy::Refuse => Outcome::NotCoveredRefuse,
                }
            }
        }
        CoverageStatus::Stale => Outcome::CoverageStale,
        CoverageStatus::Fresh => {
            for e in &artifact.entries {
                if e.scope == scope && e.issuer_ski == issuer_ski && e.serial == serial {
                    let rev = OffsetDateTime::from_unix_timestamp(e.revocation_date)
                        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
                    return if t_sig >= rev {
                        Outcome::Revoked { date: rev }
                    } else {
                        Outcome::RevokedAfterSig { date: rev }
                    };
                }
            }
            Outcome::GoodStanding
        }
    }
}

fn coverage_status(artifact: &Artifact, scope: Scope, issuer_ski: &[u8]) -> CoverageStatus {
    for c in &artifact.covered_issuers {
        if c.scope == scope && c.issuer_ski == issuer_ski {
            return if c.status.as_deref() == Some("stale") {
                CoverageStatus::Stale
            } else {
                CoverageStatus::Fresh
            };
        }
    }
    CoverageStatus::NotCovered
}

fn print_outcome(label: &str, o: &Outcome) {
    match o {
        Outcome::GoodStanding => println!(
            "{} revocation check: PASS (issuer covered, not revoked)",
            label
        ),
        Outcome::Revoked { date } => println!(
            "{} revocation check: FAIL (revoked at {}, before/at signing time)",
            label,
            iso_dt(date)
        ),
        Outcome::RevokedAfterSig { date } => println!(
            "{} revocation check: PASS (revoked at {}, after signing time — signature was made while the cert was still valid)",
            label,
            iso_dt(date)
        ),
        Outcome::CoverageStale => println!(
            "{} revocation check: FAIL (issuer covered but its CRL data is stale — cannot assert non-revocation)",
            label
        ),
        Outcome::NotCoveredStaple => println!(
            "{} revocation check: PASS (issuer not covered; an OCSP staple is present — legacy path; staple consultation is out of scope for this PoC)",
            label
        ),
        Outcome::NotCoveredWarn => println!(
            "{} revocation check: PASS with WARNING (issuer not covered and no staple — cannot assert non-revocation; --uncovered-policy=warn)",
            label
        ),
        Outcome::NotCoveredRefuse => println!(
            "{} revocation check: FAIL (issuer not covered and no staple; --uncovered-policy=refuse)",
            label
        ),
    }
}

/// Locate the active manifest's `c2pa.signature` JUMBF data box and return the
/// raw COSE_Sign1_Tagged bytes it contains.
fn load_cose_sign1_bytes(asset: &PathBuf) -> Result<Option<Vec<u8>>> {
    use jumbf::parser::SuperBox;

    let jumbf = c2pa::jumbf_io::load_jumbf_from_file(asset)
        .with_context(|| format!("loading JUMBF from {}", asset.display()))?;
    let (outer, _) = SuperBox::from_slice(&jumbf)
        .map_err(|e| anyhow!("parsing outer JUMBF SuperBox: {:?}", e))?;
    find_signature_in_super(&outer)
        .map(Some)
        .ok_or_else(|| anyhow!("no c2pa.signature box found in JUMBF"))
}

fn find_signature_in_super(sb: &jumbf::parser::SuperBox) -> Option<Vec<u8>> {
    use jumbf::parser::ChildBox;
    let label = sb.desc.label.as_deref();
    if label == Some("c2pa.signature") {
        if let Some(db) = sb.data_box() {
            return Some(db.data.to_vec());
        }
    }
    for child in &sb.child_boxes {
        if let ChildBox::SuperBox(inner) = child {
            if let Some(found) = find_signature_in_super(inner) {
                return Some(found);
            }
        }
    }
    None
}

/// Detect whether the COSE_Sign1 carries a stapled OCSP response. C2PA carries
/// these in the unprotected header under the `rVals` label. We only check for
/// presence (the legacy-path signal); consulting the staple is out of scope.
fn has_ocsp_staple(cose_bytes: &[u8]) -> bool {
    let Ok(sign1) = coset::CoseSign1::from_tagged_slice(cose_bytes)
        .or_else(|_| coset::CoseSign1::from_slice(cose_bytes))
    else {
        return false;
    };
    sign1
        .unprotected
        .rest
        .iter()
        .any(|(label, _)| matches!(label, coset::Label::Text(t) if t == "rVals"))
}

/// Extract the TSA signing cert DER from a COSE_Sign1's `sigTst2` unprotected header.
///
/// Layout: sigTst2 value is CBOR `{ "tstTokens": [ { "val": <DER bytes> } ] }`. The
/// DER bytes are an RFC 3161 TimeStampToken — a CMS ContentInfo wrapping SignedData.
/// We extract the first certificate carried in SignedData.certificates as the TSA cert
/// (heuristic; production would resolve via SignerInfo.sid).
fn extract_tsa_cert_der(cose_sig: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
    use cms::cert::CertificateChoices;
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::{Decode, Encode};

    let Some(cose_bytes) = cose_sig else {
        return Ok(None);
    };
    // C2PA stores the signature as a COSE_Sign1_Tagged structure; try tagged first,
    // fall back to untagged.
    let sign1 = coset::CoseSign1::from_tagged_slice(cose_bytes)
        .or_else(|_| coset::CoseSign1::from_slice(cose_bytes))
        .map_err(|e| anyhow!("coset parse: {:?}", e))?;

    let mut is_v2 = false;
    let sigtst_value = sign1
        .unprotected
        .rest
        .iter()
        .find_map(|(label, value)| match label {
            coset::Label::Text(t) if t == "sigTst2" => {
                is_v2 = true;
                Some(value)
            }
            coset::Label::Text(t) if t == "sigTst" => {
                is_v2 = false;
                Some(value)
            }
            _ => None,
        });
    let Some(sigtst_value) = sigtst_value else {
        return Ok(None);
    };

    let mut buf = Vec::new();
    ciborium::into_writer(sigtst_value, &mut buf).context("re-serializing sigTst value")?;
    let container: TstContainer =
        ciborium::from_reader(&buf[..]).context("parsing sigTst as TstContainer")?;
    let token = container
        .tst_tokens
        .first()
        .ok_or_else(|| anyhow!("sigTst contained no tst_tokens"))?;

    // sigTst2 carries a TimeStampToken (ContentInfo); sigTst carries a TimeStampResp
    // which wraps a TimeStampToken — peel one ASN.1 SEQUENCE layer in that case.
    let ci_der: Vec<u8> = if is_v2 {
        token.val.clone()
    } else {
        unwrap_tst_resp_to_token(&token.val)?
    };

    let ci = ContentInfo::from_der(&ci_der).context("parsing TimeStampToken ContentInfo")?;
    let sd_der = ci.content.to_der().context("re-encoding SignedData")?;
    let sd = SignedData::from_der(&sd_der).context("decoding SignedData")?;
    let certs = sd
        .certificates
        .ok_or_else(|| anyhow!("SignedData has no certificates"))?;
    let cert_choice = certs
        .0
        .iter()
        .next()
        .ok_or_else(|| anyhow!("SignedData.certificates is empty"))?;
    let cert = match cert_choice {
        CertificateChoices::Certificate(c) => c,
        other => bail!("unsupported CertificateChoices variant: {:?}", other),
    };
    let cert_der = cert.to_der().context("re-encoding TSA cert to DER")?;
    Ok(Some(cert_der))
}

fn load_and_verify_artifact(
    artifact_path: &PathBuf,
    pubkey_path: &PathBuf,
    grace_days: i64,
) -> Result<Artifact> {
    let cose_bytes = fs::read(artifact_path)
        .with_context(|| format!("reading artifact {}", artifact_path.display()))?;

    let sign1 = coset::CoseSign1::from_tagged_slice(&cose_bytes)
        .or_else(|_| coset::CoseSign1::from_slice(&cose_bytes))
        .map_err(|e| anyhow!("parsing artifact COSE_Sign1: {:?}", e))?;

    let alg = sign1.protected.header.alg.clone();
    if alg != Some(coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES256)) {
        bail!("unsupported COSE alg: {:?} (expected ES256)", alg);
    }

    let verifying_key = load_pubkey(pubkey_path)?;
    sign1
        .verify_signature(b"", |sig, data| {
            let signature = Signature::from_slice(sig)
                .map_err(|e| anyhow!("invalid ES256 signature: {}", e))?;
            verifying_key
                .verify(data, &signature)
                .map_err(|e| anyhow!("COSE signature verification failed: {}", e))
        })
        .context("verifying artifact signature")?;

    let payload = sign1
        .payload
        .as_ref()
        .ok_or_else(|| anyhow!("artifact COSE_Sign1 has no payload"))?;
    let artifact: Artifact =
        ciborium::from_reader(payload.as_slice()).context("CBOR-decoding artifact payload")?;
    if artifact.version != 1 {
        bail!("unsupported artifact version: {}", artifact.version);
    }

    let now = OffsetDateTime::now_utc();
    let next_update = OffsetDateTime::from_unix_timestamp(artifact.next_update)
        .context("artifact next_update out of range")?;
    let deadline = next_update + time::Duration::days(grace_days);
    if now > deadline {
        bail!(
            "artifact is stale: now={}, next_update + {}-day grace = {}",
            now.format(&Rfc3339)?,
            grace_days,
            deadline.format(&Rfc3339)?
        );
    }

    Ok(artifact)
}

fn load_pubkey(pubkey_path: &PathBuf) -> Result<VerifyingKey> {
    let pubkey_json = fs::read_to_string(pubkey_path)
        .with_context(|| format!("reading pubkey {}", pubkey_path.display()))?;
    let pubjwk: PublicJwk = serde_json::from_str(&pubkey_json)?;
    if pubjwk.kty != "EC" || pubjwk.crv != "P-256" {
        bail!("unsupported public key: kty={}, crv={}", pubjwk.kty, pubjwk.crv);
    }
    let x_bytes = B64URL.decode(&pubjwk.x)?;
    let y_bytes = B64URL.decode(&pubjwk.y)?;
    let x_arr: [u8; 32] = x_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("P-256 x coordinate not 32 bytes"))?;
    let y_arr: [u8; 32] = y_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("P-256 y coordinate not 32 bytes"))?;
    let encoded_point = EncodedPoint::from_affine_coordinates(&x_arr.into(), &y_arr.into(), false);
    VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|e| anyhow!("invalid P-256 public key: {}", e))
}

fn iso(ts: i64) -> String {
    OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| ts.to_string())
}

fn iso_dt(dt: &OffsetDateTime) -> String {
    dt.format(&Rfc3339).unwrap_or_default()
}

fn parse_pem_chain(buf: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for pem in Pem::iter_from_buffer(buf) {
        let pem = pem.map_err(|e| anyhow!("PEM parse: {}", e))?;
        out.push(pem.contents);
    }
    Ok(out)
}

/// For the v1 `sigTst` form, the value is a DER-encoded TimeStampResp:
///   TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
/// Skip past PKIStatusInfo to return the TimeStampToken (ContentInfo) DER bytes.
fn unwrap_tst_resp_to_token(resp: &[u8]) -> Result<Vec<u8>> {
    if resp.is_empty() || resp[0] != 0x30 {
        bail!("TimeStampResp: expected outer SEQUENCE");
    }
    let (outer_len, outer_hdr) = parse_der_length(&resp[1..])?;
    let outer_content = &resp[1 + outer_hdr..1 + outer_hdr + outer_len];
    if outer_content.is_empty() || outer_content[0] != 0x30 {
        bail!("TimeStampResp: expected PKIStatusInfo SEQUENCE");
    }
    let (pki_len, pki_hdr) = parse_der_length(&outer_content[1..])?;
    let after_pki = &outer_content[1 + pki_hdr + pki_len..];
    if after_pki.is_empty() || after_pki[0] != 0x30 {
        bail!("TimeStampResp: expected TimeStampToken SEQUENCE after PKIStatusInfo");
    }
    let (ct_len, ct_hdr) = parse_der_length(&after_pki[1..])?;
    Ok(after_pki[..1 + ct_hdr + ct_len].to_vec())
}

fn parse_der_length(input: &[u8]) -> Result<(usize, usize)> {
    if input.is_empty() {
        bail!("DER: empty length field");
    }
    let first = input[0];
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 4 || input.len() < 1 + count {
        bail!("DER: bad length encoding");
    }
    let mut len = 0usize;
    for i in 0..count {
        len = (len << 8) | input[1 + i] as usize;
    }
    Ok((len, 1 + count))
}

fn extract_aki(cert: &X509Certificate) -> Option<Vec<u8>> {
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() {
            if let Some(ki) = aki.key_identifier.as_ref() {
                return Some(ki.0.to_vec());
            }
        }
    }
    None
}
