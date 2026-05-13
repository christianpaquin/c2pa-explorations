use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use clap::Parser;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
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

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Parser, Debug)]
#[command(version, about = "CRLite-inspired revocation artifact aggregator for C2PA")]
struct Args {
    /// Anchor PEM bundle (file path or http(s) URL). May be repeated.
    #[arg(long = "anchors", required = true)]
    anchors: Vec<String>,

    /// TSA PEM bundle (file path or http(s) URL). May be repeated.
    #[arg(long = "tsa")]
    tsa: Vec<String>,

    /// Output directory.
    #[arg(long, default_value = ".")]
    out: PathBuf,

    /// Identifier of the trust list version, recorded in the artifact.
    #[arg(long, default_value = "unspecified")]
    trust_list_version: String,

    /// next_update offset, in days from generation time.
    #[arg(long, default_value_t = 7i64)]
    next_update_days: i64,

    /// Optional JSON file containing extra entries to merge into the artifact.
    /// Each element must be an Entry: {scope, issuer_ski (hex), serial (hex), revocation_date (RFC 3339)}.
    /// Useful for demonstrating revocation scenarios against synthetic or fixture certs.
    #[arg(long)]
    inject_entries: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
struct Artifact {
    version: u32,
    trust_list_version: String,
    generated_at: String,
    next_update: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    partial: Option<bool>,
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    scope: Scope,
    issuer_ski: String,
    serial: String,
    revocation_date: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
enum Scope {
    Anchors,
    Tsa,
}

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

#[derive(Serialize)]
struct JwsHeader<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out)?;

    let anchor_bundles = load_sources(&args.anchors)?;
    let tsa_bundles = load_sources(&args.tsa)?;
    let anchor_ders = collect_ders(&anchor_bundles)?;
    let tsa_ders = collect_ders(&tsa_bundles)?;
    eprintln!(
        "Parsed {} anchor cert(s), {} TSA cert(s)",
        anchor_ders.len(),
        tsa_ders.len()
    );

    let client = reqwest::blocking::Client::builder()
        .user_agent("crlite-aggregator/0.1 (C2PA PoC)")
        .timeout(Duration::from_secs(30))
        .build()?;

    let mut subject_to_ski: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    populate_subject_index(&anchor_ders, &mut subject_to_ski)?;
    populate_subject_index(&tsa_ders, &mut subject_to_ski)?;

    let mut crl_cache: HashMap<String, Vec<u8>> = HashMap::new();
    let mut entries_map: BTreeMap<(Scope, Vec<u8>, Vec<u8>), OffsetDateTime> = BTreeMap::new();
    let mut partial = false;

    for (scope, ders) in [(Scope::Anchors, &anchor_ders), (Scope::Tsa, &tsa_ders)] {
        for der in ders {
            let (_, cert) = parse_x509_certificate(der).context("parse cert")?;
            let subject_str = cert.subject().to_string();
            let urls = extract_cdp_http_urls(&cert);
            if urls.is_empty() {
                eprintln!("  [{:?}] no HTTP CDP: {}", scope, short_dn(&subject_str));
                continue;
            }
            for url in urls {
                if !crl_cache.contains_key(&url) {
                    eprintln!("  [{:?}] fetching CRL {}", scope, url);
                    match fetch(&client, &url) {
                        Ok(bytes) => {
                            crl_cache.insert(url.clone(), bytes);
                        }
                        Err(e) => {
                            eprintln!("    fetch failed: {}", e);
                            partial = true;
                            continue;
                        }
                    }
                }
                let raw = crl_cache.get(&url).unwrap().clone();
                match process_crl(&raw, scope, &subject_to_ski, &mut entries_map) {
                    Ok(n) => eprintln!("    {} revoked entries from {}", n, url),
                    Err(e) => {
                        eprintln!("    parse/process failed for {}: {}", url, e);
                        partial = true;
                    }
                }
            }
        }
    }

    let mut entries: Vec<Entry> = entries_map
        .into_iter()
        .map(|((scope, ski, serial), dt)| Entry {
            scope,
            issuer_ski: hex::encode(ski),
            serial: hex::encode(serial),
            revocation_date: dt.format(&Rfc3339).unwrap_or_default(),
        })
        .collect();

    if let Some(inject_path) = &args.inject_entries {
        let raw = fs::read_to_string(inject_path)
            .with_context(|| format!("reading inject file {}", inject_path.display()))?;
        let injected: Vec<Entry> = serde_json::from_str(&raw)
            .with_context(|| format!("parsing inject file {}", inject_path.display()))?;
        eprintln!("Injecting {} synthetic entr{}", injected.len(),
            if injected.len() == 1 { "y" } else { "ies" });
        for e in &injected {
            eprintln!("  + [{:?}] issuer_ski={} serial={} rev={}",
                e.scope, e.issuer_ski, e.serial, e.revocation_date);
        }
        entries.extend(injected);
        entries.sort_by(|a, b| (a.scope, &a.issuer_ski, &a.serial)
            .cmp(&(b.scope, &b.issuer_ski, &b.serial)));
    }

    let now = OffsetDateTime::now_utc();
    let next_update = now + time::Duration::days(args.next_update_days);
    let artifact = Artifact {
        version: 1,
        trust_list_version: args.trust_list_version.clone(),
        generated_at: now.format(&Rfc3339)?,
        next_update: next_update.format(&Rfc3339)?,
        partial: if partial { Some(true) } else { None },
        entries,
    };

    let pretty = serde_json::to_string_pretty(&artifact)?;
    let compact = serde_json::to_vec(&artifact)?;

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let x_bytes = encoded_point
        .x()
        .ok_or_else(|| anyhow!("P-256 verifying key missing x coordinate"))?;
    let y_bytes = encoded_point
        .y()
        .ok_or_else(|| anyhow!("P-256 verifying key missing y coordinate"))?;
    let x_b64 = B64URL.encode(x_bytes);
    let y_b64 = B64URL.encode(y_bytes);
    let d_b64 = B64URL.encode(signing_key.to_bytes());
    let kid = format!("{}.{}", x_b64, y_b64);

    let header = JwsHeader {
        alg: "ES256",
        typ: "JWS",
        kid: &kid,
    };
    let header_bytes = serde_json::to_vec(&header)?;
    let header_b64 = B64URL.encode(&header_bytes);
    let payload_b64 = B64URL.encode(&compact);
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = B64URL.encode(signature.to_bytes());
    let jws = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let artifact_path = args.out.join("artifact.json");
    let jws_path = args.out.join("artifact.jws");
    let pubjwk_path = args.out.join("publisher.jwk");
    let privjwk_path = args.out.join("publisher.key.jwk");

    fs::write(&artifact_path, &pretty)?;
    fs::write(&jws_path, &jws)?;
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
    eprintln!("  {}", artifact_path.display());
    eprintln!("  {}", jws_path.display());
    eprintln!("  {}", pubjwk_path.display());
    eprintln!("  {} (KEEP PRIVATE)", privjwk_path.display());
    eprintln!();
    eprintln!(
        "Artifact: {} entries, partial={}",
        artifact.entries.len(),
        partial
    );

    Ok(())
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

fn populate_subject_index(
    ders: &[Vec<u8>],
    map: &mut HashMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
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

fn process_crl(
    raw: &[u8],
    scope: Scope,
    subject_to_ski: &HashMap<Vec<u8>, Vec<u8>>,
    entries_map: &mut BTreeMap<(Scope, Vec<u8>, Vec<u8>), OffsetDateTime>,
) -> Result<usize> {
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

    let mut count = 0usize;
    for revoked in crl.iter_revoked_certificates() {
        let serial = revoked.user_certificate.to_bytes_be();
        let rev_dt = OffsetDateTime::from_unix_timestamp(revoked.revocation_date.timestamp())
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let key = (scope, issuer_ski.clone(), serial);
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
    Ok(count)
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
