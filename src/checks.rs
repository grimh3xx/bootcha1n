//! Turns the collected boot-chain state into findings.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::efivar::ATTR_TIME_BASED_AUTH;
use crate::guid::{EFI_GLOBAL_VARIABLE, IMAGE_SECURITY_DATABASE, SHIM_LOCK};
use crate::report::{Finding, Severity};
use crate::siglist::{CertInfo, Payload, SigEntry};
use crate::tcg::{self, alg_name, Authority, EventLog};
use crate::tpm::Live;

#[derive(Debug, Default, Serialize)]
pub struct Db {
    pub present: bool,
    pub error: Option<String>,
    pub entries: Vec<SigEntry>,
    pub source: String,
    pub attributes: Option<u32>,
}

impl Db {
    pub fn certs(&self) -> impl Iterator<Item = &CertInfo> {
        self.entries.iter().filter_map(SigEntry::cert)
    }

    pub fn has_cn(&self, needle: &str) -> bool {
        self.certs()
            .any(|c| c.common_name.contains(needle) || c.subject.contains(needle))
    }

    pub fn hash_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e.payload, Payload::Hash { .. }))
            .count()
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Platform {
    pub uefi: bool,
    pub store: String,
    pub secure_boot: Option<bool>,
    pub setup_mode: Option<bool>,
    pub audit_mode: Option<bool>,
    pub deployed_mode: Option<bool>,
    pub vendor_keys: Option<bool>,
    pub access_error: Option<String>,
    /// Guest without its own firmware view (WSL2).
    pub not_applicable: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct Shim {
    pub mok_certs: Vec<String>,
    pub mok_hashes: usize,
    pub mokx_entries: usize,
    /// MokSBStateRT == 1  ->  shim told to skip signature validation.
    pub validation_disabled: bool,
    pub sbat_level: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PcrRow {
    pub bank: &'static str,
    pub pcr: usize,
    pub replayed: String,
    pub live: Option<String>,
    pub matches: Option<bool>,
}

#[derive(Debug, Default, Serialize)]
pub struct Measured {
    pub log_source: Option<String>,
    pub error: Option<String>,
    pub format: Option<String>,
    pub banks: Vec<&'static str>,
    pub events: usize,
    pub trailing_bytes: usize,
    pub live_source: Option<String>,
    pub pcrs: Vec<PcrRow>,
    pub measured_secure_boot: Option<bool>,
    pub authorities: Vec<Authority>,
    pub boot_images: Vec<String>,
    pub digest_mismatches: Vec<tcg::DigestMismatch>,
    pub debug_mode: bool,
    pub error_separators: Vec<u32>,
    pub event_types: BTreeMap<&'static str, usize>,
}

/// PCRs owned by platform firmware (TCG PFP); later PCRs are extended by
/// bootloaders/OS (IMA etc.) whose events do not live in this log.
pub const FIRMWARE_PCRS: std::ops::Range<usize> = 0..8;

pub fn measured(log: &EventLog, live: Option<&Live>) -> Measured {
    let mut m = Measured {
        format: log.spec.clone(),
        banks: log.banks.iter().map(|a| alg_name(*a)).collect(),
        events: log.events.len(),
        trailing_bytes: log.trailing,
        ..Default::default()
    };
    for ev in &log.events {
        *m.event_types.entry(tcg::event_name(ev.etype)).or_default() += 1;
        match ev.etype {
            tcg::EV_EFI_VARIABLE_DRIVER_CONFIG if ev.pcr == 7 => {
                if let Some(v) = tcg::parse_var_event(&ev.data) {
                    if v.name == "SecureBoot" && v.guid == EFI_GLOBAL_VARIABLE {
                        m.measured_secure_boot = v.data.first().map(|b| *b == 1);
                    }
                }
            }
            tcg::EV_EFI_ACTION if ev.data.starts_with(b"UEFI Debug Mode") => m.debug_mode = true,
            tcg::EV_SEPARATOR if ev.data == [1, 0, 0, 0] => m.error_separators.push(ev.pcr),
            tcg::EV_EFI_BOOT_SERVICES_APPLICATION => {
                if let Some(p) = tcg::image_path(&ev.data) {
                    m.boot_images.push(p);
                }
            }
            _ => {}
        }
    }
    m.authorities = tcg::authorities(log);
    m.digest_mismatches = tcg::verify_self_describing(log);

    let replayed = tcg::replay(log);
    if let Some(l) = live {
        m.live_source = Some(l.source.clone());
    }
    for (alg, pcrs) in &replayed {
        let live_bank = live.and_then(|l| l.banks.get(alg));
        for i in FIRMWARE_PCRS {
            let lv = live_bank.and_then(|b| b[i].as_ref());
            m.pcrs.push(PcrRow {
                bank: alg_name(*alg),
                pcr: i,
                replayed: hex::encode(&pcrs[i]),
                live: lv.map(hex::encode),
                matches: lv.map(|v| v == &pcrs[i]),
            });
        }
    }
    m
}

// Microsoft CA rotation (2011 -> 2023). The 2011 KEK and UEFI CAs expired in
// June 2026 and the Windows Production PCA 2011 in October 2026; db/dbx
// updates going forward are signed by the 2023 KEK.
const MS_KEK_2011: &str = "Microsoft Corporation KEK CA 2011";
const MS_KEK_2023: &str = "Microsoft Corporation KEK 2K CA 2023";
const MS_WIN_PCA_2011: &str = "Microsoft Windows Production PCA 2011";
const MS_WIN_CA_2023: &str = "Windows UEFI CA 2023";
const MS_UEFI_CA_2011: &str = "Microsoft Corporation UEFI CA 2011";
const MS_UEFI_CA_2023: &str = "Microsoft UEFI CA 2023";

/// The current Microsoft dbx carries several hundred SHA-256 revocations;
/// a list far below that has not received the published updates.
const DBX_STALE_BELOW: usize = 200;

pub struct Input<'a> {
    pub platform: &'a Platform,
    pub pk: &'a Db,
    pub kek: &'a Db,
    pub db: &'a Db,
    pub dbx: &'a Db,
    pub shim: &'a Shim,
    pub measured: Option<&'a Measured>,
    pub measured_error: Option<&'a str>,
    pub now: i64,
    pub locate: &'a dyn Fn(&str, &crate::guid::Guid) -> String,
}

pub fn run(i: &Input) -> Vec<Finding> {
    let mut f = Vec::new();
    let loc = |n: &str, g| (i.locate)(n, g);

    if i.platform.not_applicable {
        f.push(
            Finding::new("BOOT-017", Severity::Info, "Running inside WSL — host firmware is not visible")
                .detail("WSL2 boots its kernel directly from Hyper-V; Secure Boot and the TPM log belong to the Windows host.")
                .fix("Run bootcha1n.exe from an elevated Windows terminal."),
        );
        return f;
    }
    if !i.platform.uefi {
        f.push(
            Finding::new("BOOT-000", Severity::High, "System is not booted in UEFI mode")
                .detail("Legacy BIOS / CSM boot has no Secure Boot and no UEFI measured-boot chain; the bootloader is not verified before it runs.")
                .fix("Convert the disk to GPT (mbr2gpt on Windows), disable CSM in firmware setup and boot in native UEFI mode."),
        );
        return f;
    }
    if let Some(e) = &i.platform.access_error {
        f.push(
            Finding::new("BOOT-009", Severity::Info, "UEFI variables could not be read")
                .detail(e.clone())
                .fix("Re-run elevated (Windows: Administrator; Linux: efivarfs is normally world-readable)."),
        );
    }

    match i.platform.secure_boot {
        Some(false) => f.push(
            Finding::new("BOOT-001", Severity::High, "Secure Boot is disabled")
                .detail("Firmware will execute any bootloader, including bootkits (e.g. BlackLotus-class) that persist below the OS.")
                .fix("Enable Secure Boot in firmware setup. On Linux use a signed shim/grub/kernel chain or enroll your own keys (sbctl).")
                .source(loc("SecureBoot", &EFI_GLOBAL_VARIABLE)),
        ),
        None if i.platform.access_error.is_none() => f.push(
            Finding::new("BOOT-001", Severity::Medium, "SecureBoot variable is missing")
                .detail("Firmware does not expose SecureBoot; it may not implement UEFI Secure Boot at all.")
                .source(loc("SecureBoot", &EFI_GLOBAL_VARIABLE)),
        ),
        _ => {}
    }

    if i.platform.setup_mode == Some(true)
        || (!i.pk.present && i.pk.error.is_none() && i.platform.access_error.is_none())
    {
        f.push(
            Finding::new("BOOT-002", Severity::Critical, "Firmware is in Setup Mode (no Platform Key enrolled)")
                .detail("Without a PK, any software running in the OS can write PK/KEK/db/dbx and enroll its own keys, silently taking over the Secure Boot root of trust.")
                .fix("Enroll a PK (vendor defaults via firmware setup, or your own with sbctl/KeyTool) so the key databases become authenticated.")
                .source(loc("SetupMode", &EFI_GLOBAL_VARIABLE)),
        );
    }
    if i.platform.audit_mode == Some(true) {
        f.push(
            Finding::new("BOOT-010", Severity::High, "Firmware is in Audit Mode")
                .detail(
                    "Audit Mode records signature failures but still executes unauthorised images.",
                )
                .fix("Transition to User/Deployed Mode by enrolling a PK.")
                .source(loc("AuditMode", &EFI_GLOBAL_VARIABLE)),
        );
    }

    for (name, db, guid) in [
        ("PK", i.pk, &EFI_GLOBAL_VARIABLE),
        ("KEK", i.kek, &EFI_GLOBAL_VARIABLE),
        ("db", i.db, &IMAGE_SECURITY_DATABASE),
        ("dbx", i.dbx, &IMAGE_SECURITY_DATABASE),
    ] {
        if let Some(a) = db.attributes.filter(|a| a & ATTR_TIME_BASED_AUTH == 0) {
            f.push(
                Finding::new("BOOT-016", Severity::Critical, format!("{name} is not an authenticated variable"))
                    .detail(format!("Attributes 0x{a:x} lack TIME_BASED_AUTHENTICATED_WRITE_ACCESS, so firmware accepts unsigned writes: any OS-level administrator can replace {name} and subvert Secure Boot."))
                    .fix("Firmware defect — update firmware and report it to the OEM. Treat Secure Boot on this machine as untrusted until fixed.")
                    .source(loc(name, guid)),
            );
        }
    }

    for c in i.pk.certs() {
        if c.is_untrusted_test_key() {
            f.push(
                Finding::new("BOOT-003", Severity::Critical, "Platform Key is an untrusted reference/test key (PKfail)")
                    .detail(format!("PK subject \"{}\". These AMI/IBV sample keys shipped across many vendors and their private keys are public, so anyone can sign a KEK/db update or a bootloader that this machine will trust (CVE-2024-8105).", c.subject))
                    .evidence(format!("sha256 {}", c.sha256))
                    .fix("Install the OEM firmware update that replaces the PK, or reset to setup mode and enroll your own PK. Until then treat Secure Boot on this machine as bypassable.")
                    .source(loc("PK", &EFI_GLOBAL_VARIABLE)),
            );
        }
    }
    for (name, db, guid) in [
        ("KEK", i.kek, &EFI_GLOBAL_VARIABLE),
        ("db", i.db, &IMAGE_SECURITY_DATABASE),
    ] {
        for c in db.certs().filter(|c| c.looks_like_test_key()) {
            f.push(
                Finding::new("BOOT-004", Severity::High, format!("Test / sample certificate trusted in {name}"))
                    .detail(format!("\"{}\" looks like a development key; images signed with it will be allowed to boot.", c.subject))
                    .evidence(format!("sha256 {}", c.sha256))
                    .fix(format!("Remove the certificate from {name} (firmware setup → Key Management) or apply the vendor firmware update."))
                    .source(loc(name, guid)),
            );
        }
    }

    for (name, db) in [("PK", i.pk), ("KEK", i.kek), ("db", i.db)] {
        for c in db.certs().filter(|c| c.rsa_bits.is_some_and(|b| b < 2048)) {
            f.push(
                Finding::new(
                    "BOOT-011",
                    Severity::Medium,
                    format!("Weak RSA key in {name}"),
                )
                .detail(format!("\"{}\" uses {}.", c.common_name, c.key))
                .fix("Replace with a ≥2048-bit key."),
            );
        }
    }

    // Microsoft 2023 CA rotation — only meaningful when MS keys are in use.
    if i.kek.has_cn(MS_KEK_2011) && !i.kek.has_cn(MS_KEK_2023) {
        f.push(
            Finding::new("BOOT-005", Severity::Medium, "KEK not rotated to Microsoft KEK CA 2023")
                .detail("The 2011 Microsoft KEK has expired. Future db/dbx updates are signed by the 2023 KEK; without it this machine cannot apply new revocations.")
                .fix("Install the OEM firmware update or Windows Secure Boot certificate update (KB5025885 / AvailableUpdates servicing) that adds the 2023 KEK.")
                .source(loc("KEK", &EFI_GLOBAL_VARIABLE)),
        );
    }
    if i.db.has_cn(MS_WIN_PCA_2011) && !i.db.has_cn(MS_WIN_CA_2023) {
        f.push(
            Finding::new("BOOT-006", Severity::Medium, "db lacks Windows UEFI CA 2023")
                .detail("Windows boot managers signed after the 2011 PCA expiry chain to Windows UEFI CA 2023; without it in db, updated boot media will be refused and the BlackLotus mitigations cannot be completed.")
                .fix("Apply the Windows Secure Boot certificate update so 'Windows UEFI CA 2023' is added to db, then switch to the 2023-signed boot manager.")
                .source(loc("db", &IMAGE_SECURITY_DATABASE)),
        );
    }
    if i.db.has_cn(MS_UEFI_CA_2011) && !i.db.has_cn(MS_UEFI_CA_2023) {
        f.push(
            Finding::new("BOOT-007", Severity::Low, "db lacks Microsoft UEFI CA 2023 (third-party)")
                .detail("Third-party components (shim, option ROMs) signed after June 2026 chain to the 2023 third-party CA.")
                .fix("Apply the firmware / OS update that adds 'Microsoft UEFI CA 2023' and 'Microsoft Option ROM UEFI CA 2023'.")
                .source(loc("db", &IMAGE_SECURITY_DATABASE)),
        );
    }

    let expired: Vec<String> = [("PK", i.pk), ("KEK", i.kek), ("db", i.db)]
        .iter()
        .flat_map(|(n, db)| {
            db.certs()
                .filter(|c| c.expired_at(i.now))
                .map(move |c| format!("{n}: {} (until {})", c.common_name, c.not_after))
        })
        .collect();
    if !expired.is_empty() {
        let mut fi = Finding::new("BOOT-012", Severity::Info, format!("{} expired certificate(s) in the key hierarchy", expired.len()))
            .detail("UEFI does not enforce certificate validity at boot, so this does not break booting, but expired authorities stop receiving signed updates.");
        for e in expired {
            fi = fi.evidence(e);
        }
        f.push(fi);
    }

    if i.platform.secure_boot == Some(true) {
        if !i.dbx.present && i.dbx.error.is_none() {
            f.push(
                Finding::new("BOOT-008", Severity::High, "dbx (forbidden signature database) is empty or missing")
                    .detail("No revocations at all: every vulnerable-but-signed bootloader ever released (BootHole, BlackLotus' bootmgr, ...) is still trusted.")
                    .fix("Apply the current UEFI revocation list (Windows Update, or fwupd `fwupdmgr update` with the UEFI dbx plugin on Linux).")
                    .source(loc("dbx", &IMAGE_SECURITY_DATABASE)),
            );
        } else if i.dbx.present && i.dbx.hash_count() < DBX_STALE_BELOW {
            f.push(
                Finding::new("BOOT-008", Severity::Medium, format!("dbx looks stale ({} hash revocations)", i.dbx.hash_count()))
                    .detail(format!("Current UEFI revocation lists contain several hundred entries; fewer than {DBX_STALE_BELOW} indicates published revocations have not been applied. Heuristic — confirm against your vendor's dbx release."))
                    .fix("Update dbx (Windows Update / `fwupdmgr update`).")
                    .source(loc("dbx", &IMAGE_SECURITY_DATABASE)),
            );
        }
    }

    if i.shim.validation_disabled {
        f.push(
            Finding::new("BOOT-013", Severity::High, "shim signature validation is disabled (MokSBState)")
                .detail("`mokutil --disable-validation` was used: shim boots unsigned grub/kernels while firmware still reports Secure Boot as enabled.")
                .fix("Run `mokutil --enable-validation` and confirm in MokManager on next boot.")
                .source(loc("MokSBStateRT", &SHIM_LOCK)),
        );
    }
    if !i.shim.mok_certs.is_empty() || i.shim.mok_hashes > 0 {
        let mut fi = Finding::new("BOOT-014", Severity::Info, format!("{} Machine Owner Key(s) enrolled in shim", i.shim.mok_certs.len() + i.shim.mok_hashes))
            .detail("MOKs extend trust beyond db (DKMS signing keys, distro keys). Review that each one is expected.")
            .source(loc("MokListRT", &SHIM_LOCK));
        for c in &i.shim.mok_certs {
            fi = fi.evidence(c.clone());
        }
        f.push(fi);
    }

    if let Some(err) = i.measured_error {
        f.push(
            Finding::new("TPM-002", Severity::Medium, "No TPM measured-boot event log available")
                .detail(err.to_string())
                .fix("Enable the TPM (fTPM/PTT) in firmware. On Linux mount securityfs and run as root to read the log."),
        );
    }
    if let Some(m) = i.measured {
        measured_findings(m, i, &mut f);
    }
    f
}

fn measured_findings(m: &Measured, i: &Input, f: &mut Vec<Finding>) {
    let src = m.log_source.clone().unwrap_or_default();

    let mismatched: Vec<&PcrRow> = m.pcrs.iter().filter(|r| r.matches == Some(false)).collect();
    if !mismatched.is_empty() {
        let mut fi = Finding::new("TPM-001", Severity::High, "Event log does not replay to the live PCR values")
            .detail("Replaying the firmware event log does not reproduce the TPM's PCRs 0-7. Either the log is incomplete/tampered, or something extended firmware PCRs outside the log — both break remote attestation and BitLocker/TPM-sealed secrets' assumptions.")
            .fix("Compare against a known-good boot of the same firmware version; update firmware; investigate early-boot code if it persists.")
            .source(src.clone());
        for r in mismatched {
            let live = r.live.as_deref().unwrap_or("");
            fi = fi.evidence(format!(
                "{} PCR{} replay {}… live {}…",
                r.bank,
                r.pcr,
                short(&r.replayed),
                short(live)
            ));
        }
        f.push(fi);
    } else if m.live_source.is_none() && !m.pcrs.is_empty() {
        f.push(
            Finding::new("TPM-006", Severity::Info, "Live PCRs unavailable — log replayed but not verified")
                .detail("Run as root (Linux /dev/tpmrm0) or check that the TPM is present to compare the replay with the TPM itself."),
        );
    }

    if m.banks == ["sha1"] {
        f.push(
            Finding::new(
                "TPM-003",
                Severity::Low,
                "Measured boot uses only the SHA-1 PCR bank",
            )
            .detail("SHA-1 is collision-prone; attestation built on it is weak.")
            .fix(
                "Enable the SHA-256 PCR bank in firmware TPM settings (TPM 2.0 'PCR bank' option).",
            )
            .source(src.clone()),
        );
    }
    if m.debug_mode {
        f.push(
            Finding::new("TPM-004", Severity::High, "Firmware measured \"UEFI Debug Mode\"")
                .detail("The platform booted with firmware debug mode enabled, which typically relaxes or bypasses security checks.")
                .fix("Disable debug mode / install a production firmware build.")
                .source(src.clone()),
        );
    }
    if !m.error_separators.is_empty() {
        f.push(
            Finding::new("TPM-005", Severity::High, "Firmware recorded measurement errors (error separators)")
                .detail(format!("EV_SEPARATOR with value 1 on PCR {:?}: firmware failed to measure part of the boot chain.", m.error_separators))
                .source(src.clone()),
        );
    }
    if !m.digest_mismatches.is_empty() {
        let mut fi = Finding::new("TPM-007", Severity::Low, format!("{} log event(s) do not hash to their own digest", m.digest_mismatches.len()))
            .detail("For EV_SEPARATOR / EV_EFI_ACTION / EV_EFI_VARIABLE_DRIVER_CONFIG the digest must be the hash of the event data. A mismatch means the log text was edited, or the firmware has a known measurement quirk.")
            .source(src.clone());
        for d in m.digest_mismatches.iter().take(8) {
            fi = fi.evidence(format!("#{} PCR{} {} ({})", d.index, d.pcr, d.event, d.alg));
        }
        f.push(fi);
    }
    if let (Some(measured), Some(var)) = (m.measured_secure_boot, i.platform.secure_boot) {
        if measured != var {
            f.push(
                Finding::new(
                    "TPM-008",
                    Severity::High,
                    "Measured SecureBoot state disagrees with the live variable",
                )
                .detail(format!(
                    "PCR7 recorded SecureBoot={} but the variable now reads {}.",
                    measured as u8, var as u8
                ))
                .source(src.clone()),
            );
        }
    }
    if m.authorities.iter().any(|a| {
        a.subject
            .as_deref()
            .is_some_and(|s| s.contains(MS_WIN_PCA_2011))
    }) && i.db.has_cn(MS_WIN_CA_2023)
    {
        f.push(
            Finding::new("BOOT-015", Severity::Low, "Boot manager still verified by the 2011 Windows PCA")
                .detail("db already trusts Windows UEFI CA 2023, but this boot was authorised by the expired 2011 PCA, so the 2011 CA cannot yet be revoked.")
                .fix("Let Windows servicing install the 2023-signed boot manager, then add the 2011 PCA to dbx (Microsoft BlackLotus mitigation step).")
                .source(src),
        );
    }
}

fn short(hex: &str) -> &str {
    hex.get(..16).unwrap_or(hex)
}
