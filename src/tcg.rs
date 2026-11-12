//! TCG PC Client firmware event log: parsing (SHA-1 legacy and crypto-agile
//! formats), PCR replay per hash bank, and extraction of the events that matter
//! for boot-chain trust (Secure Boot config, boot authorities, loaded images).

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::guid::Guid;
use crate::siglist;

pub const NUM_PCRS: usize = 24;

pub const EV_NO_ACTION: u32 = 0x3;
pub const EV_SEPARATOR: u32 = 0x4;
pub const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001;
pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;
pub const EV_EFI_ACTION: u32 = 0x8000_0007;
pub const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x8000_00E0;

pub const ALG_SHA1: u16 = 0x0004;
pub const ALG_SHA256: u16 = 0x000B;
pub const ALG_SHA384: u16 = 0x000C;
pub const ALG_SHA512: u16 = 0x000D;
pub const ALG_SM3_256: u16 = 0x0012;

pub fn alg_name(alg: u16) -> &'static str {
    match alg {
        ALG_SHA1 => "sha1",
        ALG_SHA256 => "sha256",
        ALG_SHA384 => "sha384",
        ALG_SHA512 => "sha512",
        ALG_SM3_256 => "sm3_256",
        _ => "unknown",
    }
}

fn alg_size(alg: u16) -> Option<usize> {
    match alg {
        ALG_SHA1 => Some(20),
        ALG_SHA256 | ALG_SM3_256 => Some(32),
        ALG_SHA384 => Some(48),
        ALG_SHA512 => Some(64),
        _ => None,
    }
}

pub fn hash(alg: u16, parts: &[&[u8]]) -> Option<Vec<u8>> {
    fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
        let mut h = D::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().to_vec()
    }
    Some(match alg {
        ALG_SHA1 => run::<Sha1>(parts),
        ALG_SHA256 => run::<Sha256>(parts),
        ALG_SHA384 => run::<Sha384>(parts),
        ALG_SHA512 => run::<Sha512>(parts),
        _ => return None,
    })
}

pub fn event_name(t: u32) -> &'static str {
    match t {
        0x0 => "EV_PREBOOT_CERT",
        0x1 => "EV_POST_CODE",
        0x3 => "EV_NO_ACTION",
        0x4 => "EV_SEPARATOR",
        0x5 => "EV_ACTION",
        0x6 => "EV_EVENT_TAG",
        0x7 => "EV_S_CRTM_CONTENTS",
        0x8 => "EV_S_CRTM_VERSION",
        0x9 => "EV_CPU_MICROCODE",
        0xA => "EV_PLATFORM_CONFIG_FLAGS",
        0xB => "EV_TABLE_OF_DEVICES",
        0xC => "EV_COMPACT_HASH",
        0xD => "EV_IPL",
        0xE => "EV_IPL_PARTITION_DATA",
        0xF => "EV_NONHOST_CODE",
        0x10 => "EV_NONHOST_CONFIG",
        0x11 => "EV_NONHOST_INFO",
        0x12 => "EV_OMIT_BOOT_DEVICE_EVENTS",
        0x8000_0001 => "EV_EFI_VARIABLE_DRIVER_CONFIG",
        0x8000_0002 => "EV_EFI_VARIABLE_BOOT",
        0x8000_0003 => "EV_EFI_BOOT_SERVICES_APPLICATION",
        0x8000_0004 => "EV_EFI_BOOT_SERVICES_DRIVER",
        0x8000_0005 => "EV_EFI_RUNTIME_SERVICES_DRIVER",
        0x8000_0006 => "EV_EFI_GPT_EVENT",
        0x8000_0007 => "EV_EFI_ACTION",
        0x8000_0008 => "EV_EFI_PLATFORM_FIRMWARE_BLOB",
        0x8000_0009 => "EV_EFI_HANDOFF_TABLES",
        0x8000_000A => "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
        0x8000_000B => "EV_EFI_HANDOFF_TABLES2",
        0x8000_000C => "EV_EFI_VARIABLE_BOOT2",
        0x8000_0010 => "EV_EFI_HCRTM_EVENT",
        0x8000_00E0 => "EV_EFI_VARIABLE_AUTHORITY",
        0x8000_00E1 => "EV_EFI_SPDM_FIRMWARE_BLOB",
        0x8000_00E2 => "EV_EFI_SPDM_FIRMWARE_CONFIG",
        _ => "EV_UNKNOWN",
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub index: usize,
    pub pcr: u32,
    pub etype: u32,
    pub digests: Vec<(u16, Vec<u8>)>,
    pub data: Vec<u8>,
}

impl Event {
    pub fn digest(&self, alg: u16) -> Option<&[u8]> {
        self.digests
            .iter()
            .find(|(a, _)| *a == alg)
            .map(|(_, d)| d.as_slice())
    }
}

#[derive(Debug)]
pub struct EventLog {
    pub crypto_agile: bool,
    pub spec: Option<String>,
    pub banks: Vec<u16>,
    pub events: Vec<Event>,
    /// Bytes left over that did not form a complete event.
    pub trailing: usize,
    pub startup_locality: u8,
}

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.p..self.p.checked_add(n)?)?;
        self.p += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
    }
}

const SPEC_ID_03: &[u8] = b"Spec ID Event03\0";
const STARTUP_LOCALITY: &[u8] = b"StartupLocality\0";
/// An event larger than this is treated as corruption, not data.
const MAX_EVENT: usize = 16 * 1024 * 1024;

pub fn parse(buf: &[u8]) -> Result<EventLog> {
    let mut r = Rd { b: buf, p: 0 };

    // The first event is always in the legacy TCG_PCR_EVENT (SHA-1) format.
    let (pcr, etype) = match (r.u32(), r.u32()) {
        (Some(p), Some(t)) => (p, t),
        _ => bail!("event log shorter than one header"),
    };
    let sha1 = r.take(20).map(<[u8]>::to_vec);
    let size = r.u32().map(|s| s as usize);
    let (Some(sha1), Some(size)) = (sha1, size) else {
        bail!("truncated first event")
    };
    if size > MAX_EVENT {
        bail!("first event claims {size} bytes — not a TCG log");
    }
    let Some(data) = r.take(size).map(<[u8]>::to_vec) else {
        bail!("truncated first event data")
    };

    let mut log = EventLog {
        crypto_agile: false,
        spec: None,
        banks: vec![ALG_SHA1],
        events: Vec::new(),
        trailing: 0,
        startup_locality: 0,
    };

    let mut sizes: BTreeMap<u16, usize> = BTreeMap::new();
    if etype == EV_NO_ACTION && pcr == 0 && data.starts_with(SPEC_ID_03) {
        let mut s = Rd { b: &data, p: 16 };
        let _platform_class = s.u32();
        let (minor, major, errata) = (s.u8(), s.u8(), s.u8());
        let _uintn = s.u8();
        let n = s.u32().unwrap_or(0);
        if n == 0 || n > 16 {
            bail!("Spec ID event declares {n} algorithms");
        }
        log.banks.clear();
        for _ in 0..n {
            let (Some(alg), Some(sz)) = (s.u16(), s.u16()) else {
                bail!("truncated Spec ID algorithm table")
            };
            sizes.insert(alg, sz as usize);
            log.banks.push(alg);
        }
        log.crypto_agile = true;
        log.spec = Some(format!(
            "TCG2 {}.{} errata {}",
            major.unwrap_or(0),
            minor.unwrap_or(0),
            errata.unwrap_or(0)
        ));
    } else {
        log.spec = Some("TCG 1.2 (SHA-1 only)".into());
    }

    // Spec ID header is informational; a legacy first event is a real one.
    if !log.crypto_agile {
        log.events.push(Event {
            index: 0,
            pcr,
            etype,
            digests: vec![(ALG_SHA1, sha1)],
            data,
        });
    }

    loop {
        let start = r.p;
        if start >= buf.len() {
            break;
        }
        let ev = if log.crypto_agile {
            next_agile(&mut r, &sizes)
        } else {
            next_legacy(&mut r)
        };
        match ev {
            Some((pcr, etype, digests, data)) => {
                // Zero-filled tail (Windows pre-allocates the log buffer).
                if pcr == 0
                    && etype == 0
                    && digests.iter().all(|(_, d)| d.iter().all(|b| *b == 0))
                    && data.is_empty()
                {
                    log.trailing = buf.len() - start;
                    break;
                }
                if pcr as usize >= NUM_PCRS && pcr != 0xFFFF_FFFF {
                    log.trailing = buf.len() - start;
                    break;
                }
                if etype == EV_NO_ACTION && data.starts_with(STARTUP_LOCALITY) {
                    log.startup_locality = data.get(STARTUP_LOCALITY.len()).copied().unwrap_or(0);
                }
                let index = log.events.len();
                log.events.push(Event {
                    index,
                    pcr,
                    etype,
                    digests,
                    data,
                });
            }
            None => {
                log.trailing = buf.len() - start;
                break;
            }
        }
    }
    Ok(log)
}

type Raw = (u32, u32, Vec<(u16, Vec<u8>)>, Vec<u8>);

fn next_legacy(r: &mut Rd) -> Option<Raw> {
    let pcr = r.u32()?;
    let etype = r.u32()?;
    let d = r.take(20)?.to_vec();
    let n = r.u32()? as usize;
    if n > MAX_EVENT {
        return None;
    }
    Some((pcr, etype, vec![(ALG_SHA1, d)], r.take(n)?.to_vec()))
}

fn next_agile(r: &mut Rd, sizes: &BTreeMap<u16, usize>) -> Option<Raw> {
    let pcr = r.u32()?;
    let etype = r.u32()?;
    let count = r.u32()?;
    if count as usize > sizes.len().max(1) * 2 {
        return None;
    }
    let mut digests = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let alg = r.u16()?;
        let sz = sizes.get(&alg).copied().or_else(|| alg_size(alg))?;
        digests.push((alg, r.take(sz)?.to_vec()));
    }
    let n = r.u32()? as usize;
    if n > MAX_EVENT {
        return None;
    }
    Some((pcr, etype, digests, r.take(n)?.to_vec()))
}

/// Replay every bank we can hash. Returns alg -> 24 PCR values.
pub fn replay(log: &EventLog) -> BTreeMap<u16, Vec<Vec<u8>>> {
    let mut out = BTreeMap::new();
    for &alg in &log.banks {
        let Some(size) = alg_size(alg) else { continue };
        if hash(alg, &[]).is_none() {
            continue;
        }
        let mut pcrs = vec![vec![0u8; size]; NUM_PCRS];
        // PCR0 starts at the locality the S-CRTM ran from (TCG PFP §10.4.5.3).
        pcrs[0][size - 1] = log.startup_locality;
        for ev in &log.events {
            if ev.etype == EV_NO_ACTION || ev.pcr as usize >= NUM_PCRS {
                continue;
            }
            if let Some(d) = ev.digest(alg) {
                let p = ev.pcr as usize;
                pcrs[p] = hash(alg, &[&pcrs[p], d]).expect("supported alg");
            }
        }
        out.insert(alg, pcrs);
    }
    out
}

/// Events whose digest is defined as the hash of their own event data. A
/// mismatch means the log entry does not describe what was extended.
pub fn self_describing(ev: &Event) -> bool {
    matches!(
        ev.etype,
        EV_SEPARATOR | EV_EFI_ACTION | EV_EFI_VARIABLE_DRIVER_CONFIG
    )
}

#[derive(Debug, Clone, Serialize)]
pub struct DigestMismatch {
    pub index: usize,
    pub pcr: u32,
    pub event: &'static str,
    pub alg: &'static str,
}

pub fn verify_self_describing(log: &EventLog) -> Vec<DigestMismatch> {
    let mut bad = Vec::new();
    for ev in log.events.iter().filter(|e| self_describing(e)) {
        for (alg, d) in &ev.digests {
            if let Some(h) = hash(*alg, &[&ev.data]) {
                if &h != d {
                    bad.push(DigestMismatch {
                        index: ev.index,
                        pcr: ev.pcr,
                        event: event_name(ev.etype),
                        alg: alg_name(*alg),
                    });
                }
            }
        }
    }
    bad
}

/// UEFI_VARIABLE_DATA as carried by EV_EFI_VARIABLE_* events.
#[derive(Debug, Clone)]
pub struct VarEvent {
    pub guid: Guid,
    pub name: String,
    pub data: Vec<u8>,
}

pub fn parse_var_event(data: &[u8]) -> Option<VarEvent> {
    let mut r = Rd { b: data, p: 0 };
    let guid = Guid::from_slice(r.take(16)?)?;
    let name_len = u64::from_le_bytes(r.take(8)?.try_into().ok()?) as usize;
    let data_len = u64::from_le_bytes(r.take(8)?.try_into().ok()?) as usize;
    let name_raw = r.take(name_len.checked_mul(2)?)?;
    let name = String::from_utf16_lossy(
        &name_raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
    );
    let data = r.take(data_len)?.to_vec();
    Some(VarEvent {
        guid,
        name: name.trim_end_matches('\0').to_string(),
        data,
    })
}

/// File path out of UEFI_IMAGE_LOAD_EVENT's device path, when present.
pub fn image_path(data: &[u8]) -> Option<String> {
    let mut r = Rd { b: data, p: 0 };
    r.take(24)?; // location, length, link-time address
    let dp_len = u64::from_le_bytes(r.take(8)?.try_into().ok()?) as usize;
    let dp = r.take(dp_len)?;
    let mut nodes = Rd { b: dp, p: 0 };
    let mut parts = Vec::new();
    let mut media = None;
    while let (Some(t), Some(st), Some(len)) = (nodes.u8(), nodes.u8(), nodes.u16()) {
        if len < 4 {
            break;
        }
        let body = nodes.take(len as usize - 4)?;
        match (t, st) {
            (0x7f, 0xff) => break,
            // Media / File Path
            (4, 4) => {
                let s: Vec<u16> = body
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                parts.push(
                    String::from_utf16_lossy(&s)
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
            // Media / Hard Drive -> partition number
            (4, 1) if body.len() >= 4 => {
                media = Some(format!(
                    "HD({})",
                    u32::from_le_bytes(body[..4].try_into().ok()?)
                ));
            }
            // Media / PIWG firmware file (image inside a firmware volume)
            (4, 6) if body.len() >= 16 => {
                parts.push(format!("FvFile({})", Guid::from_slice(body)?));
            }
            // Messaging / URI (HTTP boot)
            (3, 24) => parts.push(String::from_utf8_lossy(body).into_owned()),
            _ => {}
        }
    }
    if parts.is_empty() {
        return media;
    }
    // Firmware may split a path across several File Path nodes
    // ("\EFI\Microsoft\Boot" + "bootmgfw.efi"); rejoin with one separator.
    let mut path = String::new();
    for p in parts {
        if !path.is_empty()
            && !path.ends_with('\\')
            && !p.starts_with('\\')
            && !p.starts_with("FvFile")
        {
            path.push('\\');
        }
        path.push_str(&p);
    }
    Some(match media {
        Some(m) => format!("{m}{path}"),
        None => path,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct Authority {
    pub variable: String,
    pub subject: Option<String>,
    pub sha256: Option<String>,
}

/// EV_EFI_VARIABLE_AUTHORITY on PCR7: which db entry authorised each image.
pub fn authorities(log: &EventLog) -> Vec<Authority> {
    let mut out: Vec<Authority> = Vec::new();
    for ev in log
        .events
        .iter()
        .filter(|e| e.pcr == 7 && e.etype == EV_EFI_VARIABLE_AUTHORITY)
    {
        let Some(v) = parse_var_event(&ev.data) else {
            continue;
        };
        // VariableData is one EFI_SIGNATURE_DATA: owner GUID + payload.
        let payload = v.data.get(16..).unwrap_or(&[]);
        let cert = siglist::summarize(payload);
        let a = Authority {
            variable: v.name,
            subject: cert.as_ref().map(|c| {
                if c.common_name.is_empty() {
                    c.subject.clone()
                } else {
                    c.common_name.clone()
                }
            }),
            sha256: cert.map(|c| c.sha256),
        };
        if !out
            .iter()
            .any(|o| o.sha256 == a.sha256 && o.subject == a.subject)
        {
            out.push(a);
        }
    }
    out
}

#[cfg(test)]
pub mod build {
    //! Minimal crypto-agile log writer for tests.
    use super::*;

    pub fn spec_header(algs: &[(u16, u16)]) -> Vec<u8> {
        let mut ev = SPEC_ID_03.to_vec();
        ev.extend_from_slice(&0u32.to_le_bytes()); // platform class
        ev.extend_from_slice(&[0, 2, 0, 2]); // minor, major, errata, uintn
        ev.extend_from_slice(&(algs.len() as u32).to_le_bytes());
        for (a, s) in algs {
            ev.extend_from_slice(&a.to_le_bytes());
            ev.extend_from_slice(&s.to_le_bytes());
        }
        ev.push(0); // vendor info size
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&EV_NO_ACTION.to_le_bytes());
        v.extend_from_slice(&[0u8; 20]);
        v.extend_from_slice(&(ev.len() as u32).to_le_bytes());
        v.extend(ev);
        v
    }

    pub fn event(pcr: u32, etype: u32, algs: &[u16], data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&pcr.to_le_bytes());
        v.extend_from_slice(&etype.to_le_bytes());
        v.extend_from_slice(&(algs.len() as u32).to_le_bytes());
        for a in algs {
            v.extend_from_slice(&a.to_le_bytes());
            v.extend(hash(*a, &[data]).unwrap());
        }
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(data);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    fn sample() -> Vec<u8> {
        let algs = [ALG_SHA1, ALG_SHA256];
        let mut log = spec_header(&[(ALG_SHA1, 20), (ALG_SHA256, 32)]);
        log.extend(event(0, 0x8, &algs, b"firmware v1.0"));
        log.extend(event(
            7,
            EV_EFI_ACTION,
            &algs,
            b"Calling EFI Application from Boot Option",
        ));
        for pcr in 0..8 {
            log.extend(event(pcr, EV_SEPARATOR, &algs, &[0, 0, 0, 0]));
        }
        log
    }

    #[test]
    fn parses_agile_log() {
        let l = parse(&sample()).unwrap();
        assert!(l.crypto_agile);
        assert_eq!(l.banks, vec![ALG_SHA1, ALG_SHA256]);
        assert_eq!(l.events.len(), 10);
        assert_eq!(l.trailing, 0);
        assert!(verify_self_describing(&l).is_empty());
    }

    #[test]
    fn replay_matches_manual_extend() {
        let l = parse(&sample()).unwrap();
        let r = replay(&l);
        let sep = hash(ALG_SHA256, &[&[0, 0, 0, 0]]).unwrap();
        let p1 = hash(ALG_SHA256, &[&[0u8; 32], &sep]).unwrap();
        assert_eq!(r[&ALG_SHA256][1], p1);
        assert_eq!(r[&ALG_SHA256][8], vec![0u8; 32]);
    }

    #[test]
    fn startup_locality_seeds_pcr0() {
        let mut log = spec_header(&[(ALG_SHA256, 32)]);
        let mut sl = STARTUP_LOCALITY.to_vec();
        sl.push(3);
        log.extend(event(0, EV_NO_ACTION, &[ALG_SHA256], &sl));
        let l = parse(&log).unwrap();
        assert_eq!(l.startup_locality, 3);
        assert_eq!(replay(&l)[&ALG_SHA256][0][31], 3);
    }

    #[test]
    fn detects_tampered_event_data() {
        let mut log = sample();
        let n = log.len();
        log[n - 1] = 1; // last separator now says "error" but digest says 0
        let l = parse(&log).unwrap();
        assert_eq!(verify_self_describing(&l).len(), 2);
    }

    #[test]
    fn truncated_tail_is_reported_not_fatal() {
        let mut log = sample();
        log.extend_from_slice(&[1, 0, 0, 0, 4]);
        let l = parse(&log).unwrap();
        assert_eq!(l.events.len(), 10);
        assert_eq!(l.trailing, 5);
    }

    #[test]
    fn image_path_from_device_path() {
        let mut dp = vec![4, 1, 42, 0];
        dp.extend_from_slice(&1u32.to_le_bytes());
        dp.extend_from_slice(&[0u8; 38 - 4]);
        let file: Vec<u8> = "\\EFI\\BOOT\\BOOTX64.EFI\0"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        dp.extend_from_slice(&[4, 4]);
        dp.extend_from_slice(&((file.len() + 4) as u16).to_le_bytes());
        dp.extend(file);
        dp.extend_from_slice(&[0x7f, 0xff, 4, 0]);
        let mut ev = vec![0u8; 24];
        ev.extend_from_slice(&(dp.len() as u64).to_le_bytes());
        ev.extend(dp);
        assert_eq!(
            image_path(&ev).as_deref(),
            Some("HD(1)\\EFI\\BOOT\\BOOTX64.EFI")
        );
    }

    #[test]
    fn split_file_path_nodes_are_joined() {
        let node = |s: &str| {
            let f: Vec<u8> = format!("{s}\0")
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect();
            let mut n = vec![4, 4];
            n.extend_from_slice(&((f.len() + 4) as u16).to_le_bytes());
            n.extend(f);
            n
        };
        let mut dp = node("\\EFI\\Microsoft\\Boot");
        dp.extend(node("bootmgfw.efi"));
        dp.extend_from_slice(&[0x7f, 0xff, 4, 0]);
        let mut ev = vec![0u8; 24];
        ev.extend_from_slice(&(dp.len() as u64).to_le_bytes());
        ev.extend(dp);
        assert_eq!(
            image_path(&ev).as_deref(),
            Some("\\EFI\\Microsoft\\Boot\\bootmgfw.efi")
        );
    }
}
