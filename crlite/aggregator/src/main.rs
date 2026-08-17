use anyhow::{anyhow, Context, Result};
use ciborium::tag::Required;
use clap::Parser;
use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::pem::Pem;
use x509_parser::revocation_list::CertificateRevocationList;
use x509_parser::{parse_x509_certificate, parse_x509_crl};

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Aggregated Revocation Artifact (ARA) aggregator for C2PA"
)]
struct Args {
    /// Certificate PEM bundle for this trust list (file path or http(s) URL). May be repeated.
    #[arg(long = "certs", required = true)]
    certs: Vec<String>,

    /// Output directory.
    #[arg(long, default_value = ".")]
    out: PathBuf,

    /// Identifier of the trust list this artifact is bound to, recorded in the artifact.
    #[arg(long, default_value = "unspecified")]
    trust_list_id: String,

    /// next_update offset, in days from generation time.
    #[arg(long, default_value_t = 7i64)]
    next_update_days: i64,

    /// Optional JSON file containing extra entries to merge into the artifact.
    /// Each element: {issuer_ski (hex), serial_number (hex), revocation_date (RFC 3339)}.
    /// Each injected issuer is also added to the coverage set so the entry is authoritative.
    /// Useful for demonstrating revocation scenarios against synthetic or fixture certs.
    #[arg(long)]
    inject_entries: Option<PathBuf>,
}

// ---- wire structs (CBOR / COSE_Sign1 payload) -----------------------------

type CborTime = Required<i64, 1>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Artifact {
    version: u32,
    trust_list_id: String,
    generated_at: CborTime,
    next_update: CborTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    partial: Option<bool>,
    covered_issuers: Vec<Coverage>,
    entries: Vec<Entry>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Coverage {
    #[serde(rename = "issuerSKI")]
    #[serde(with = "serde_bytes")]
    issuer_ski: Vec<u8>,
    last_update: CborTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Entry {
    #[serde(rename = "issuerSKI")]
    #[serde(with = "serde_bytes")]
    issuer_ski: Vec<u8>,
    #[serde(with = "serde_bytes")]
    serial_number: Vec<u8>,
    revocation_date: CborTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<u8>,
}

// ---- inject file (human-authored JSON: hex SKI/serial, RFC 3339 date) -------

#[derive(Deserialize)]
struct InjectEntry {
    issuer_ski: String,
    serial_number: String,
    revocation_date: String,
}

// ---- publisher key (JWK; key representation is orthogonal to the artifact) --

#[derive(Serialize)]
struct PublicJwk<'a> {
    kty: &'a str,
    crv: &'a str,
    x: String,
    y: String,
}

#[derive(Serialize)]
struct PrivateJwk<'a> {
    kty: &'a str,
    crv: &'a str,
    x: String,
    y: String,
    d: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out)?;

    let bundles = load_sources(&args.certs)?;
    let ders = collect_ders(&bundles)?;
    eprintln!("Parsed {} cert(s)", ders.len());

    let client = reqwest::blocking::Client::builder()
        .user_agent("ara-aggregator/0.2 (C2PA PoC)")
        .timeout(Duration::from_secs(30))
        .build()?;

    let mut subject_to_ski: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    populate_subject_index(&ders, &mut subject_to_ski)?;

    let now = OffsetDateTime::now_utc();
    let now_ts = now.unix_timestamp();

    let mut crl_cache: HashMap<String, Vec<u8>> = HashMap::new();
    let mut entries_map: BTreeMap<(Vec<u8>, Vec<u8>), OffsetDateTime> = BTreeMap::new();
    let mut coverage_map: BTreeMap<Vec<u8>, (i64, Option<String>)> = BTreeMap::new();
    let mut partial = false;

    for der in &ders {
        let (_, cert) = parse_x509_certificate(der).context("parse cert")?;
        let subject_str = cert.subject().to_string();
        let cert_aki = extract_aki(&cert);
        let urls = extract_cdp_http_urls(&cert);
        if urls.is_empty() {
            eprintln!("  no HTTP CDP: {}", short_dn(&subject_str));
            continue;
        }
        for url in urls {
            if !crl_cache.contains_key(&url) {
                eprintln!("  fetching CRL {}", url);
                match fetch(&client, &url) {
                    Ok(bytes) => {
                        crl_cache.insert(url.clone(), bytes);
                    }
                    Err(e) => {
                        eprintln!("    fetch failed: {}", e);
                        partial = true;
                        mark_stale(&mut coverage_map, cert_aki.as_ref(), now_ts);
                        continue;
                    }
                }
            }
            let raw = crl_cache.get(&url).unwrap().clone();
            match process_crl(&raw, &subject_to_ski, &mut entries_map) {
                Ok((issuer_ski, last_update, n)) => {
                    eprintln!("    {} revoked entries from {}", n, url);
                    // mark this issuer covered (do not downgrade an ok to stale)
                    coverage_map.insert(issuer_ski, (last_update, None));
                }
                Err(e) => {
                    eprintln!("    parse/process failed for {}: {}", url, e);
                    partial = true;
                    mark_stale(&mut coverage_map, cert_aki.as_ref(), now_ts);
                }
            }
        }
    }

    let mut entries: Vec<Entry> = entries_map
        .into_iter()
        .map(|((ski, serial_number), dt)| Entry {
            issuer_ski: ski,
            serial_number,
            revocation_date: Required(dt.unix_timestamp()),
            reason: None,
        })
        .collect();

    if let Some(inject_path) = &args.inject_entries {
        let raw = fs::read_to_string(inject_path)
            .with_context(|| format!("reading inject file {}", inject_path.display()))?;
        let injected: Vec<InjectEntry> = serde_json::from_str(&raw)
            .with_context(|| format!("parsing inject file {}", inject_path.display()))?;
        eprintln!(
            "Injecting {} synthetic entr{}",
            injected.len(),
            if injected.len() == 1 { "y" } else { "ies" }
        );
        for e in &injected {
            let ski = hex::decode(&e.issuer_ski)
                .with_context(|| format!("decoding injected issuer_ski {}", e.issuer_ski))?;
            let serial_number = hex::decode(&e.serial_number)
                .with_context(|| format!("decoding injected serial_number {}", e.serial_number))?;
            let rev = OffsetDateTime::parse(&e.revocation_date, &Rfc3339)
                .with_context(|| format!("parsing injected revocation_date {}", e.revocation_date))?
                .unix_timestamp();
            eprintln!(
                "  + issuer_ski={} serial_number={} rev={}",
                e.issuer_ski, e.serial_number, e.revocation_date
            );
            // an injected revocation is only authoritative if its issuer is covered
            coverage_map.entry(ski.clone()).or_insert((now_ts, None));
            entries.push(Entry {
                issuer_ski: ski,
                serial_number,
                revocation_date: Required(rev),
                reason: None,
            });
        }
        entries.sort_by(|a, b| {
            (&a.issuer_ski, &a.serial_number).cmp(&(&b.issuer_ski, &b.serial_number))
        });
    }

    let covered_issuers: Vec<Coverage> = coverage_map
        .into_iter()
        .map(|(ski, (last_update, status))| Coverage {
            issuer_ski: ski,
            last_update: Required(last_update),
            status,
        })
        .collect();

    let next_update = now + time::Duration::days(args.next_update_days);
    let artifact = Artifact {
        version: 1,
        trust_list_id: args.trust_list_id.clone(),
        generated_at: Required(now_ts),
        next_update: Required(next_update.unix_timestamp()),
        partial: if partial { Some(true) } else { None },
        covered_issuers,
        entries,
    };

    // CBOR payload, signed as COSE_Sign1 (the normative artifact)
    let mut payload = Vec::new();
    ciborium::into_writer(&artifact, &mut payload).context("CBOR-encoding artifact")?;

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let x_bytes = encoded_point
        .x()
        .ok_or_else(|| anyhow!("P-256 verifying key missing x coordinate"))?;
    let y_bytes = encoded_point
        .y()
        .ok_or_else(|| anyhow!("P-256 verifying key missing y coordinate"))?;
    let x_b64 = b64url(x_bytes);
    let y_b64 = b64url(y_bytes);
    let d_b64 = b64url(&signing_key.to_bytes());
    let kid = format!("{}.{}", x_b64, y_b64);

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(kid.into_bytes())
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(b"", |pt| {
            let sig: Signature = signing_key.sign(pt);
            sig.to_bytes().to_vec()
        })
        .build();
    let cose_bytes = sign1
        .to_tagged_vec()
        .map_err(|e| anyhow!("COSE_Sign1 encode: {:?}", e))?;

    let cose_path = args.out.join("artifact.cose");
    let json_path = args.out.join("artifact.json");
    let pubjwk_path = args.out.join("publisher.jwk");
    let privjwk_path = args.out.join("publisher.key.jwk");

    fs::write(&cose_path, &cose_bytes)?;
    fs::write(
        &json_path,
        serde_json::to_string_pretty(&debug_json(&artifact))?,
    )?;
    fs::write(
        &pubjwk_path,
        serde_json::to_string_pretty(&PublicJwk {
            kty: "EC",
            crv: "P-256",
            x: x_b64.clone(),
            y: y_b64.clone(),
        })?,
    )?;
    fs::write(
        &privjwk_path,
        serde_json::to_string_pretty(&PrivateJwk {
            kty: "EC",
            crv: "P-256",
            x: x_b64,
            y: y_b64,
            d: d_b64,
        })?,
    )?;

    eprintln!();
    eprintln!("Wrote:");
    eprintln!(
        "  {}  (signed COSE_Sign1 — the artifact)",
        cose_path.display()
    );
    eprintln!("  {}  (debug JSON projection)", json_path.display());
    eprintln!("  {}", pubjwk_path.display());
    eprintln!("  {} (KEEP PRIVATE)", privjwk_path.display());
    eprintln!();
    eprintln!(
        "Artifact: {} covered issuer(s), {} entr{}, partial={}",
        artifact.covered_issuers.len(),
        artifact.entries.len(),
        if artifact.entries.len() == 1 {
            "y"
        } else {
            "ies"
        },
        partial
    );

    Ok(())
}

/// JSON debug projection matching the proposal's Appendix A (hex SKI/serial, ISO dates).
fn debug_json(a: &Artifact) -> serde_json::Value {
    json!({
        "version": a.version,
        "trustListId": a.trust_list_id,
        "generatedAt": iso(a.generated_at.0),
        "nextUpdate": iso(a.next_update.0),
        "partial": a.partial.unwrap_or(false),
        "coveredIssuers": a.covered_issuers.iter().map(|c| json!({
            "issuerSKI": hex::encode(&c.issuer_ski),
            "lastUpdate": iso(c.last_update.0),
            "status": c.status.clone().unwrap_or_else(|| "ok".to_string()),
        })).collect::<Vec<_>>(),
        "entries": a.entries.iter().map(|e| json!({
            "issuerSKI": hex::encode(&e.issuer_ski),
            "serialNumber": hex::encode(&e.serial_number),
            "revocationDate": iso(e.revocation_date.0),
        })).collect::<Vec<_>>(),
    })
}

fn iso(ts: i64) -> String {
    OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| ts.to_string())
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn mark_stale(
    coverage_map: &mut BTreeMap<Vec<u8>, (i64, Option<String>)>,
    cert_ski: Option<&Vec<u8>>,
    now_ts: i64,
) {
    if let Some(ski) = cert_ski {
        coverage_map
            .entry(ski.clone())
            .or_insert((now_ts, Some("stale".to_string())));
    }
}

fn load_sources(sources: &[String]) -> Result<Vec<Vec<u8>>> {
    sources
        .iter()
        .map(|s| {
            let bytes = if s.starts_with("http://") || s.starts_with("https://") {
                let resp = reqwest::blocking::get(s)?.error_for_status()?;
                resp.bytes()?.to_vec()
            } else {
                fs::read(s).with_context(|| format!("reading {}", s))?
            };
            eprintln!("Loaded source {} ({} bytes)", s, bytes.len());
            Ok(bytes)
        })
        .collect()
}

fn collect_ders(bundles: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for buf in bundles {
        for pem in Pem::iter_from_buffer(buf) {
            let pem = pem.map_err(|e| anyhow!("PEM parse: {}", e))?;
            out.push(pem.contents);
        }
    }
    Ok(out)
}

fn populate_subject_index(ders: &[Vec<u8>], map: &mut HashMap<Vec<u8>, Vec<u8>>) -> Result<()> {
    for der in ders {
        let (_, cert) = parse_x509_certificate(der).context("parse cert for index")?;
        let subj = cert.subject().as_raw().to_vec();
        if let Some(ski) = extract_ski(&cert) {
            map.entry(subj).or_insert(ski);
        }
    }
    Ok(())
}

fn extract_ski(cert: &X509Certificate) -> Option<Vec<u8>> {
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectKeyIdentifier(ski) = ext.parsed_extension() {
            return Some(ski.0.to_vec());
        }
    }
    None
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

fn extract_cdp_http_urls(cert: &X509Certificate) -> Vec<String> {
    let mut urls = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::CRLDistributionPoints(cdps) = ext.parsed_extension() {
            for dp in cdps.points.iter() {
                if let Some(dpn) = dp.distribution_point.as_ref() {
                    if let DistributionPointName::FullName(names) = dpn {
                        for n in names {
                            if let GeneralName::URI(uri) = n {
                                if uri.starts_with("http://") || uri.starts_with("https://") {
                                    urls.push((*uri).to_string());
                                } else {
                                    eprintln!("    skipping non-HTTP CDP: {}", uri);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    urls
}

fn fetch(client: &reqwest::blocking::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client.get(url).send()?.error_for_status()?;
    Ok(resp.bytes()?.to_vec())
}

/// Parse a CRL and merge its revocations into `entries_map`. Returns
/// `(issuer SKI, thisUpdate as epoch seconds, entry count)`.
fn process_crl(
    raw: &[u8],
    subject_to_ski: &HashMap<Vec<u8>, Vec<u8>>,
    entries_map: &mut BTreeMap<(Vec<u8>, Vec<u8>), OffsetDateTime>,
) -> Result<(Vec<u8>, i64, usize)> {
    // Accept either DER or PEM-encoded CRLs.
    let der_owned: Vec<u8> = if parse_x509_crl(raw).is_ok() {
        raw.to_vec()
    } else {
        let first = Pem::iter_from_buffer(raw)
            .next()
            .ok_or_else(|| anyhow!("not DER and not PEM"))?
            .map_err(|e| anyhow!("PEM parse: {}", e))?;
        first.contents
    };
    let (_, crl) = parse_x509_crl(&der_owned).map_err(|e| anyhow!("parse_x509_crl: {}", e))?;

    let issuer_ski = resolve_crl_issuer_ski(&crl, subject_to_ski)
        .ok_or_else(|| anyhow!("cannot resolve CRL issuer SKI"))?;
    let last_update = crl.last_update().timestamp();

    let mut count = 0usize;
    for revoked in crl.iter_revoked_certificates() {
        let serial = revoked.user_certificate.to_bytes_be();
        let rev_dt = OffsetDateTime::from_unix_timestamp(revoked.revocation_date.timestamp())
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let key = (issuer_ski.clone(), serial);
        entries_map
            .entry(key)
            .and_modify(|d| {
                if rev_dt < *d {
                    *d = rev_dt;
                }
            })
            .or_insert(rev_dt);
        count += 1;
    }
    Ok((issuer_ski, last_update, count))
}

fn resolve_crl_issuer_ski(
    crl: &CertificateRevocationList,
    subject_to_ski: &HashMap<Vec<u8>, Vec<u8>>,
) -> Option<Vec<u8>> {
    for ext in crl.extensions() {
        if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() {
            if let Some(ki) = aki.key_identifier.as_ref() {
                return Some(ki.0.to_vec());
            }
        }
    }
    let issuer_raw = crl.issuer().as_raw();
    subject_to_ski.get(issuer_raw).cloned()
}

fn short_dn(dn: &str) -> &str {
    if dn.len() > 80 {
        &dn[..80]
    } else {
        dn
    }
}
