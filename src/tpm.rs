//! Locating the firmware event log and reading live PCR values.
//!
//! PCRs are read with a raw TPM2_PCR_Read built and parsed here — through the
//! Linux resource manager (`/dev/tpmrm0`) or Windows TBS — so no tpm2-tools /
//! tss stack is required. TPM2_PCR_Read is a read-only command.

use std::collections::BTreeMap;
use std::path::Path;
#[cfg(not(windows))]
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

#[cfg(not(windows))]
use crate::tcg::alg_name;
use crate::tcg::NUM_PCRS;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_CC_PCR_READ: u32 = 0x0000_017E;

pub fn pcr_read_command(alg: u16, pcrs: &[usize]) -> Vec<u8> {
    let mut select = [0u8; 3];
    for &p in pcrs.iter().filter(|p| **p < NUM_PCRS) {
        select[p / 8] |= 1 << (p % 8);
    }
    let mut c = Vec::with_capacity(20);
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes()); // patched below
    c.extend_from_slice(&TPM_CC_PCR_READ.to_be_bytes());
    c.extend_from_slice(&1u32.to_be_bytes()); // TPML_PCR_SELECTION.count
    c.extend_from_slice(&alg.to_be_bytes());
    c.push(3);
    c.extend_from_slice(&select);
    let len = c.len() as u32;
    c[2..6].copy_from_slice(&len.to_be_bytes());
    c
}

/// Returns (pcr index -> digest) for whatever the TPM chose to return.
pub fn parse_pcr_read_response(r: &[u8]) -> Result<Vec<(usize, Vec<u8>)>> {
    let be16 = |p: usize| -> Result<u16> {
        Ok(u16::from_be_bytes(
            r.get(p..p + 2).context("short response")?.try_into()?,
        ))
    };
    let be32 = |p: usize| -> Result<u32> {
        Ok(u32::from_be_bytes(
            r.get(p..p + 4).context("short response")?.try_into()?,
        ))
    };
    let rc = be32(6)?;
    if rc != 0 {
        bail!("TPM2_PCR_Read failed: TPM_RC 0x{rc:x}");
    }
    let mut p = 14; // header(10) + pcrUpdateCounter(4)
    let nsel = be32(p)?;
    p += 4;
    let mut indices = Vec::new();
    for _ in 0..nsel {
        p += 2; // hash alg
        let sz = *r.get(p).context("short selection")? as usize;
        p += 1;
        let bytes = r.get(p..p + sz).context("short selection")?;
        for (i, b) in bytes.iter().enumerate() {
            for bit in 0..8 {
                if b & (1 << bit) != 0 {
                    indices.push(i * 8 + bit);
                }
            }
        }
        p += sz;
    }
    let ndig = be32(p)? as usize;
    p += 4;
    if ndig != indices.len() {
        bail!(
            "TPM returned {ndig} digests for {} selected PCRs",
            indices.len()
        );
    }
    let mut out = Vec::with_capacity(ndig);
    for idx in indices {
        let sz = be16(p)? as usize;
        p += 2;
        out.push((idx, r.get(p..p + sz).context("short digest")?.to_vec()));
        p += sz;
    }
    Ok(out)
}

/// Read PCRs 0..24 of one bank, looping because a TPM returns at most 8
/// digests per PCR_Read.
pub fn read_bank(
    transport: &mut dyn FnMut(&[u8]) -> Result<Vec<u8>>,
    alg: u16,
) -> Result<Vec<Option<Vec<u8>>>> {
    let mut got: Vec<Option<Vec<u8>>> = vec![None; NUM_PCRS];
    for _ in 0..NUM_PCRS {
        let want: Vec<usize> = (0..NUM_PCRS).filter(|i| got[*i].is_none()).collect();
        if want.is_empty() {
            break;
        }
        let resp = transport(&pcr_read_command(alg, &want))?;
        let vals = parse_pcr_read_response(&resp)?;
        if vals.is_empty() {
            break; // bank not allocated
        }
        for (i, d) in vals {
            if i < NUM_PCRS {
                got[i] = Some(d);
            }
        }
    }
    Ok(got)
}

pub struct Live {
    pub source: String,
    pub banks: BTreeMap<u16, Vec<Option<Vec<u8>>>>,
}

#[cfg(not(windows))]
pub fn default_log_path() -> Option<PathBuf> {
    let p = PathBuf::from("/sys/kernel/security/tpm0/binary_bios_measurements");
    p.exists().then_some(p)
}

#[cfg(not(windows))]
pub fn read_log() -> Result<(Vec<u8>, String)> {
    let p = default_log_path()
        .context("no TPM event log exposed (securityfs not mounted, or no TPM)")?;
    let data =
        std::fs::read(&p).with_context(|| format!("reading {} (needs root)", p.display()))?;
    Ok((data, p.display().to_string()))
}

/// Live PCRs: sysfs (kernel >= 5.12, world-readable) first, then a raw
/// PCR_Read through the kernel resource manager.
#[cfg(not(windows))]
pub fn read_live(algs: &[u16], sysfs_root: Option<&Path>) -> Option<Live> {
    let root = sysfs_root
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/sys/class/tpm/tpm0"));
    let mut banks = BTreeMap::new();
    for &alg in algs {
        let dir = root.join(format!("pcr-{}", alg_name(alg)));
        if !dir.is_dir() {
            continue;
        }
        let vals = (0..NUM_PCRS)
            .map(|i| {
                std::fs::read_to_string(dir.join(i.to_string()))
                    .ok()
                    .and_then(|s| hex::decode(s.trim()).ok())
            })
            .collect();
        banks.insert(alg, vals);
    }
    if !banks.is_empty() {
        return Some(Live {
            source: root.display().to_string(),
            banks,
        });
    }
    if sysfs_root.is_some() {
        return None;
    }
    let dev = ["/dev/tpmrm0", "/dev/tpm0"]
        .into_iter()
        .find(|d| Path::new(d).exists())?;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev)
        .ok()?;
    let mut transport = |cmd: &[u8]| -> Result<Vec<u8>> {
        use std::io::{Read, Write};
        f.write_all(cmd)?;
        let mut buf = vec![0u8; 4096];
        let n = f.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    };
    for &alg in algs {
        if let Ok(v) = read_bank(&mut transport, alg) {
            if v.iter().any(Option::is_some) {
                banks.insert(alg, v);
            }
        }
    }
    (!banks.is_empty()).then(|| Live {
        source: dev.to_string(),
        banks,
    })
}

#[cfg(windows)]
pub fn read_log() -> Result<(Vec<u8>, String)> {
    use windows_sys::Win32::System::TpmBaseServices::{
        Tbsi_Get_TCG_Log_Ex, TBS_TCGLOG_SRTM_CURRENT,
    };
    let mut len = 0u32;
    // SAFETY: size query with a null buffer, then a fill into a buffer of that size.
    unsafe {
        Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, std::ptr::null_mut(), &mut len);
        if len == 0 {
            bail!("TBS returned no event log (no TPM, or TBS service stopped)");
        }
        let mut buf = vec![0u8; len as usize];
        let rc = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, buf.as_mut_ptr(), &mut len);
        if rc != 0 {
            bail!("Tbsi_Get_TCG_Log_Ex: TBS error 0x{rc:x}");
        }
        buf.truncate(len as usize);
        Ok((buf, "TBS (SRTM current)".into()))
    }
}

#[cfg(windows)]
pub fn read_live(algs: &[u16], _sysfs_root: Option<&Path>) -> Option<Live> {
    use windows_sys::Win32::System::TpmBaseServices::*;
    let mut params = TBS_CONTEXT_PARAMS2 {
        version: TBS_CONTEXT_VERSION_TWO,
        Anonymous: TBS_CONTEXT_PARAMS2_0 {
            Anonymous: TBS_CONTEXT_PARAMS2_0_0 { _bitfield: 1 << 2 },
        }, // includeTpm20
    };
    let mut ctx: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: params is a valid TBS_CONTEXT_PARAMS2; ctx is closed below.
    if unsafe { Tbsi_Context_Create((&mut params as *mut TBS_CONTEXT_PARAMS2).cast(), &mut ctx) }
        != 0
    {
        return None;
    }
    let mut transport = |cmd: &[u8]| -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 4096];
        let mut n = buf.len() as u32;
        // SAFETY: ctx is live; cmd and buf are valid for their lengths.
        let rc = unsafe {
            Tbsip_Submit_Command(
                ctx,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                cmd.as_ptr(),
                cmd.len() as u32,
                buf.as_mut_ptr(),
                &mut n,
            )
        };
        if rc != 0 {
            bail!("Tbsip_Submit_Command: 0x{rc:x}");
        }
        buf.truncate(n as usize);
        Ok(buf)
    };
    let mut banks = BTreeMap::new();
    for &alg in algs {
        if let Ok(v) = read_bank(&mut transport, alg) {
            if v.iter().any(Option::is_some) {
                banks.insert(alg, v);
            }
        }
    }
    // SAFETY: ctx came from Tbsi_Context_Create.
    unsafe { Tbsip_Context_Close(ctx) };
    (!banks.is_empty()).then(|| Live {
        source: "TBS".into(),
        banks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcg::ALG_SHA256;

    #[test]
    fn command_layout() {
        let c = pcr_read_command(ALG_SHA256, &[0, 7, 23]);
        assert_eq!(c.len(), 20);
        assert_eq!(&c[..2], &[0x80, 0x01]);
        assert_eq!(u32::from_be_bytes(c[2..6].try_into().unwrap()), 20);
        assert_eq!(&c[6..10], &[0, 0, 1, 0x7e]);
        assert_eq!(&c[14..16], &[0, 0x0b]);
        assert_eq!(&c[16..], &[3, 0b1000_0001, 0, 0b1000_0000]);
    }

    fn fake_tpm(cmd: &[u8]) -> Result<Vec<u8>> {
        // Answer with at most 8 PCRs whose digest is [index; 32].
        let sel = &cmd[17..20];
        let mut idx: Vec<usize> = (0..24)
            .filter(|i| sel[i / 8] & (1 << (i % 8)) != 0)
            .collect();
        idx.truncate(8);
        let mut out_sel = [0u8; 3];
        for i in &idx {
            out_sel[i / 8] |= 1 << (i % 8);
        }
        let mut r = vec![0x80, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        r.extend_from_slice(&1u32.to_be_bytes());
        r.extend_from_slice(&ALG_SHA256.to_be_bytes());
        r.push(3);
        r.extend_from_slice(&out_sel);
        r.extend_from_slice(&(idx.len() as u32).to_be_bytes());
        for i in idx {
            r.extend_from_slice(&32u16.to_be_bytes());
            r.extend_from_slice(&[i as u8; 32]);
        }
        let len = r.len() as u32;
        r[2..6].copy_from_slice(&len.to_be_bytes());
        Ok(r)
    }

    #[test]
    fn read_bank_loops_over_eight_pcr_chunks() {
        let mut t = fake_tpm;
        let bank = read_bank(&mut t, ALG_SHA256).unwrap();
        assert!(bank.iter().all(Option::is_some));
        assert_eq!(bank[17].as_ref().unwrap()[0], 17);
    }

    #[test]
    fn error_rc_is_surfaced() {
        let r = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x84];
        assert!(parse_pcr_read_response(&r).is_err());
    }
}
