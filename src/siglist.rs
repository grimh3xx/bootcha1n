//! EFI_SIGNATURE_LIST parsing (UEFI spec §32.4.1) and X.509 summarisation for
//! the PK / KEK / db / dbx / MokList databases.

use anyhow::{bail, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::guid::{self, Guid};

#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub common_name: String,
    pub not_before: String,
    pub not_after: String,
    pub not_after_unix: i64,
    pub serial: String,
    pub sha256: String,
    pub self_signed: bool,
    pub key: String,
    pub rsa_bits: Option<usize>,
}

impl CertInfo {
    pub fn expired_at(&self, now: i64) -> bool {
        self.not_after_unix < now
    }

    /// Placeholder keys shipped from reference firmware (CVE-2024-8105, "PKfail").
    pub fn is_untrusted_test_key(&self) -> bool {
        let s = format!("{} {}", self.subject, self.issuer).to_ascii_uppercase();
        s.contains("DO NOT TRUST") || s.contains("DO NOT SHIP")
    }

    pub fn looks_like_test_key(&self) -> bool {
        let s = self.subject.to_ascii_lowercase();
        self.is_untrusted_test_key()
            || s.contains("test key")
            || s.contains("testkey")
            || s.contains("test cert")
            || s.contains("sample")
            || s.contains("example")
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    X509 {
        cert: Option<CertInfo>,
        der_len: usize,
    },
    Hash {
        alg: &'static str,
        hex: String,
    },
    /// Revocation of a certificate by the hash of its TBSCertificate.
    CertHash {
        alg: &'static str,
        hex: String,
    },
    Other {
        sig_type: Guid,
        len: usize,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct SigEntry {
    pub owner: Guid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_name: Option<&'static str>,
    #[serde(flatten)]
    pub payload: Payload,
}

impl SigEntry {
    pub fn cert(&self) -> Option<&CertInfo> {
        match &self.payload {
            Payload::X509 { cert, .. } => cert.as_ref(),
            _ => None,
        }
    }
}

const LIST_HEADER: usize = 28;

pub fn parse(buf: &[u8]) -> Result<Vec<SigEntry>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < buf.len() {
        let rest = &buf[off..];
        if rest.len() < LIST_HEADER {
            bail!("truncated EFI_SIGNATURE_LIST header at offset {off}");
        }
        let sig_type = Guid::from_slice(rest).expect("16 bytes checked");
        let list_size = u32le(rest, 16) as usize;
        let header_size = u32le(rest, 20) as usize;
        let sig_size = u32le(rest, 24) as usize;
        if list_size < LIST_HEADER || list_size > rest.len() {
            bail!("EFI_SIGNATURE_LIST at {off}: SignatureListSize {list_size} out of bounds");
        }
        if sig_size < 16 {
            bail!("EFI_SIGNATURE_LIST at {off}: SignatureSize {sig_size} < owner GUID");
        }
        let body_start = LIST_HEADER
            .checked_add(header_size)
            .filter(|s| *s <= list_size)
            .ok_or_else(|| anyhow::anyhow!("SignatureHeaderSize {header_size} out of bounds"))?;
        let body = &rest[body_start..list_size];
        if body.len() % sig_size != 0 {
            bail!(
                "EFI_SIGNATURE_LIST at {off}: {} bytes not a multiple of {sig_size}",
                body.len()
            );
        }
        for sig in body.chunks_exact(sig_size) {
            let owner = Guid::from_slice(sig).expect("sig_size >= 16");
            let data = &sig[16..];
            out.push(SigEntry {
                owner,
                owner_name: owner.well_known(),
                payload: payload(&sig_type, data),
            });
        }
        off += list_size;
    }
    Ok(out)
}

fn payload(t: &Guid, data: &[u8]) -> Payload {
    let hash = |alg| Payload::Hash {
        alg,
        hex: hex::encode(data),
    };
    let cert_hash = |alg| Payload::CertHash {
        alg,
        // EFI_CERT_X509_SHAxxx carries the digest followed by an EFI_TIME
        // revocation timestamp; only the digest identifies the certificate.
        hex: hex::encode(
            &data[..data.len().min(match alg {
                "sha256" => 32,
                "sha384" => 48,
                _ => 64,
            })],
        ),
    };
    match *t {
        guid::CERT_X509 => Payload::X509 {
            cert: summarize(data),
            der_len: data.len(),
        },
        guid::CERT_SHA256 => hash("sha256"),
        guid::CERT_SHA1 => hash("sha1"),
        guid::CERT_SHA224 => hash("sha224"),
        guid::CERT_SHA384 => hash("sha384"),
        guid::CERT_SHA512 => hash("sha512"),
        guid::CERT_X509_SHA256 => cert_hash("sha256"),
        guid::CERT_X509_SHA384 => cert_hash("sha384"),
        guid::CERT_X509_SHA512 => cert_hash("sha512"),
        other => Payload::Other {
            sig_type: other,
            len: data.len(),
        },
    }
}

pub fn summarize(der: &[u8]) -> Option<CertInfo> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("")
        .to_string();
    let (key, rsa_bits) = match cert.public_key().parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => {
            let bits = rsa.key_size();
            (format!("RSA-{bits}"), Some(bits))
        }
        Ok(x509_parser::public_key::PublicKey::EC(ec)) => (format!("EC-{}", ec.key_size()), None),
        Ok(_) => ("other".into(), None),
        Err(_) => ("unparsed".into(), None),
    };
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    Some(CertInfo {
        self_signed: subject == issuer,
        subject,
        issuer,
        common_name,
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        not_after_unix: cert.validity().not_after.timestamp(),
        serial: cert.raw_serial_as_string(),
        sha256: hex::encode(Sha256::digest(der)),
        key,
        rsa_bits,
    })
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("bounds checked"))
}

/// Serialise entries back into a signature list (used by tests / fixtures).
#[cfg(test)]
pub fn build_list(sig_type: &Guid, owner: &Guid, items: &[&[u8]]) -> Vec<u8> {
    let sig_size = 16 + items.first().map_or(0, |i| i.len());
    let list_size = LIST_HEADER + sig_size * items.len();
    let mut v = Vec::with_capacity(list_size);
    v.extend_from_slice(&sig_type.0);
    v.extend_from_slice(&(list_size as u32).to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&(sig_size as u32).to_le_bytes());
    for i in items {
        v.extend_from_slice(&owner.0);
        v.extend_from_slice(i);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hash_lists_back_to_back() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let mut buf = build_list(&guid::CERT_SHA256, &guid::MICROSOFT_OWNER, &[&a, &b]);
        buf.extend(build_list(
            &guid::CERT_SHA1,
            &guid::MICROSOFT_OWNER,
            &[&[0x33u8; 20]],
        ));
        let e = parse(&buf).unwrap();
        assert_eq!(e.len(), 3);
        assert_eq!(e[0].owner_name, Some("Microsoft"));
        assert!(
            matches!(&e[1].payload, Payload::Hash { alg: "sha256", hex } if hex.starts_with("2222"))
        );
        assert!(matches!(&e[2].payload, Payload::Hash { alg: "sha1", .. }));
    }

    #[test]
    fn rejects_overlong_list() {
        let mut buf = build_list(&guid::CERT_SHA256, &guid::MICROSOFT_OWNER, &[&[0u8; 32]]);
        buf[16] = 0xff; // SignatureListSize past the end
        assert!(parse(&buf).is_err());
    }

    #[test]
    fn rejects_ragged_body() {
        let mut buf = build_list(&guid::CERT_SHA256, &guid::MICROSOFT_OWNER, &[&[0u8; 32]]);
        buf[24] = 40; // SignatureSize no longer divides the body
        assert!(parse(&buf).is_err());
    }

    #[test]
    fn empty_is_ok() {
        assert!(parse(&[]).unwrap().is_empty());
    }
}
