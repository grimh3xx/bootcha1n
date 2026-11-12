//! bootcha1n — read-only UEFI Secure Boot and TPM measured-boot auditor.
//!
//! Audits the boot chain from the firmware's root of trust down to the boot
//! manager: the Secure Boot key hierarchy (PK → KEK → db/dbx), shim/MOK state,
//! and the TCG event log, which is replayed per hash bank and checked against
//! the TPM's live PCRs. Nothing is written to firmware variables or the TPM.

mod checks;
mod efivar;
mod guid;
mod report;
mod siglist;
mod tcg;
mod tpm;
#[cfg(windows)]
mod winpriv;

use std::path::PathBuf;
use std::process::ExitCode;

use anstream::println;
use clap::Parser;
use owo_colors::OwoColorize;
use serde::Serialize;

use checks::{Db, Measured, Platform, Shim};
use efivar::{VarError, VarStore};
use guid::{Guid, EFI_GLOBAL_VARIABLE, IMAGE_SECURITY_DATABASE, SHIM_LOCK};
use report::{Finding, Severity};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO: &str = "https://github.com/grimh3xx/bootcha1n";

#[derive(Parser)]
#[command(
    name = "bootcha1n",
    version,
    about = "Read-only UEFI Secure Boot & TPM measured-boot auditor"
)]
struct Cli {
    /// Offline efivarfs directory (files named <Name>-<guid>, 4-byte attribute prefix)
    #[arg(long, value_name = "DIR")]
    efivars: Option<PathBuf>,
    /// TCG event log to audit instead of the running system's
    #[arg(long, value_name = "FILE")]
    eventlog: Option<PathBuf>,
    /// Directory laid out like /sys/class/tpm/tpm0 (pcr-sha256/0..23) for live PCRs
    #[arg(long, value_name = "DIR")]
    pcrs: Option<PathBuf>,
    /// Skip the measured-boot (TPM) part of the audit
    #[arg(long)]
    no_tpm: bool,
    /// Print every certificate and hash in PK/KEK/db/dbx
    #[arg(long)]
    certs: bool,
    /// Print the full event log
    #[arg(long)]
    events: bool,
    /// JSON output on stdout
    #[arg(long, conflicts_with = "sarif")]
    json: bool,
    /// SARIF 2.1.0 output on stdout
    #[arg(long)]
    sarif: bool,
    /// Lowest severity to report: info, low, medium, high, critical
    #[arg(long, default_value = "info", value_name = "LVL")]
    min_severity: String,
    #[arg(long)]
    no_color: bool,
}

#[derive(Serialize)]
struct Output<'a> {
    tool: &'static str,
    version: &'static str,
    platform: &'a Platform,
    pk: &'a Db,
    kek: &'a Db,
    db: &'a Db,
    dbx: &'a Db,
    shim: &'a Shim,
    measured_boot: Option<&'a Measured>,
    findings: &'a [Finding],
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.no_color {
        anstream::ColorChoice::Never.write_global();
    }
    let Some(min) = Severity::parse(&cli.min_severity) else {
        eprintln!("invalid --min-severity: {}", cli.min_severity);
        return ExitCode::from(64);
    };

    let store = efivar::open(cli.efivars.as_deref());
    let platform = read_platform(store.as_ref());
    let pk = read_db(store.as_ref(), "PK", &EFI_GLOBAL_VARIABLE);
    let kek = read_db(store.as_ref(), "KEK", &EFI_GLOBAL_VARIABLE);
    let db = read_db(store.as_ref(), "db", &IMAGE_SECURITY_DATABASE);
    let dbx = read_db(store.as_ref(), "dbx", &IMAGE_SECURITY_DATABASE);
    let shim = read_shim(store.as_ref());

    let mut event_log = None;
    let (measured, measured_err) = if cli.no_tpm {
        (None, None)
    } else {
        match load_log(&cli) {
            Ok((bytes, src)) => match tcg::parse(&bytes) {
                Ok(log) => {
                    let live = if cli.eventlog.is_some() && cli.pcrs.is_none() {
                        None
                    } else {
                        tpm::read_live(&log.banks, cli.pcrs.as_deref())
                    };
                    let mut m = checks::measured(&log, live.as_ref());
                    m.log_source = Some(src);
                    event_log = Some(log);
                    (Some(m), None)
                }
                Err(e) => (None, Some(format!("event log unparseable: {e}"))),
            },
            Err(e) => (None, Some(format!("{e:#}"))),
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let locate = |n: &str, g: &Guid| store.locate(n, g);
    let findings = checks::run(&checks::Input {
        platform: &platform,
        pk: &pk,
        kek: &kek,
        db: &db,
        dbx: &dbx,
        shim: &shim,
        measured: measured.as_ref(),
        measured_error: measured_err.as_deref(),
        now,
        locate: &locate,
    });
    let findings = report::filter_sort(findings, min);

    if cli.json {
        let out = Output {
            tool: "bootcha1n",
            version: VERSION,
            platform: &platform,
            pk: &pk,
            kek: &kek,
            db: &db,
            dbx: &dbx,
            shim: &shim,
            measured_boot: measured.as_ref(),
            findings: &findings,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("serializable")
        );
    } else if cli.sarif {
        let s = report::sarif("bootcha1n", VERSION, REPO, "firmware/uefi", &findings);
        println!(
            "{}",
            serde_json::to_string_pretty(&s).expect("serializable")
        );
    } else {
        banner();
        render_platform(&platform);
        render_keys(
            &[("PK", &pk), ("KEK", &kek), ("db", &db), ("dbx", &dbx)],
            cli.certs,
            now,
        );
        render_shim(&shim);
        if let Some(m) = &measured {
            render_measured(m, event_log.as_ref(), cli.events);
        } else if let Some(e) = &measured_err {
            report::section("measured boot");
            report::kv("status", e.yellow());
        }
        report::print_findings(&findings);
        report::print_summary(&findings);
    }
    ExitCode::from(report::worst(&findings))
}

fn load_log(cli: &Cli) -> anyhow::Result<(Vec<u8>, String)> {
    if let Some(p) = &cli.eventlog {
        return Ok((std::fs::read(p)?, p.display().to_string()));
    }
    tpm::read_log()
}

fn read_platform(store: &dyn VarStore) -> Platform {
    let mut p = Platform {
        store: store.describe(),
        ..Default::default()
    };
    match store.read("SecureBoot", &EFI_GLOBAL_VARIABLE) {
        Ok(v) => {
            p.uefi = true;
            p.secure_boot = v.data.first().map(|b| *b == 1);
        }
        Err(VarError::Unsupported(why)) => {
            p.uefi = !why.contains("not booted via UEFI") && !why.contains("legacy");
            p.not_applicable = why.starts_with("WSL");
            if p.uefi {
                p.access_error = Some(why);
            }
            return p;
        }
        Err(VarError::Denied(why)) | Err(VarError::Io(why)) => {
            p.uefi = true;
            p.access_error = Some(why);
            return p;
        }
        Err(VarError::NotFound) => p.uefi = true,
    }
    p.setup_mode = efivar::read_flag(store, "SetupMode", &EFI_GLOBAL_VARIABLE);
    p.audit_mode = efivar::read_flag(store, "AuditMode", &EFI_GLOBAL_VARIABLE);
    p.deployed_mode = efivar::read_flag(store, "DeployedMode", &EFI_GLOBAL_VARIABLE);
    p.vendor_keys = efivar::read_flag(store, "VendorKeys", &EFI_GLOBAL_VARIABLE);
    p
}

fn read_db(store: &dyn VarStore, name: &str, guid: &Guid) -> Db {
    let source = store.locate(name, guid);
    match store.read(name, guid) {
        Ok(v) => {
            let attributes = Some(v.attributes);
            match siglist::parse(&v.data) {
                Ok(entries) => Db {
                    present: !entries.is_empty(),
                    error: None,
                    entries,
                    source,
                    attributes,
                },
                Err(e) => Db {
                    present: true,
                    error: Some(e.to_string()),
                    entries: vec![],
                    source,
                    attributes,
                },
            }
        }
        Err(VarError::NotFound) => Db {
            source,
            ..Default::default()
        },
        Err(VarError::Denied(e) | VarError::Io(e) | VarError::Unsupported(e)) => Db {
            error: Some(e),
            source,
            ..Default::default()
        },
    }
}

fn read_shim(store: &dyn VarStore) -> Shim {
    let mut s = Shim::default();
    if let Ok(v) = store.read("MokListRT", &SHIM_LOCK) {
        for e in siglist::parse(&v.data).unwrap_or_default() {
            match e.cert() {
                Some(c) => s.mok_certs.push(if c.common_name.is_empty() {
                    c.subject.clone()
                } else {
                    c.common_name.clone()
                }),
                None => s.mok_hashes += 1,
            }
        }
    }
    if let Ok(v) = store.read("MokListXRT", &SHIM_LOCK) {
        s.mokx_entries = siglist::parse(&v.data).map_or(0, |e| e.len());
    }
    s.validation_disabled = efivar::read_flag(store, "MokSBStateRT", &SHIM_LOCK).unwrap_or(false);
    s.sbat_level = store.read("SbatLevelRT", &SHIM_LOCK).ok().map(|v| {
        String::from_utf8_lossy(&v.data)
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join(" | ")
    });
    s
}

fn banner() {
    println!();
    println!(
        "  {}{}  {}",
        "bootcha".bold().cyan(),
        "1n".bold().bright_blue(),
        format!("v{VERSION}").dimmed()
    );
    println!(
        "  {}",
        "UEFI Secure Boot & measured-boot auditor · read-only".dimmed()
    );
}

fn yn(v: Option<bool>) -> String {
    match v {
        Some(true) => "yes".green().to_string(),
        Some(false) => "no".red().to_string(),
        None => "—".dimmed().to_string(),
    }
}

fn render_platform(p: &Platform) {
    report::section("platform");
    report::kv("source", &p.store);
    if p.not_applicable {
        report::kv("boot mode", "n/a (virtualised guest)".yellow());
        return;
    }
    report::kv(
        "boot mode",
        if p.uefi {
            "UEFI".green().to_string()
        } else {
            "legacy BIOS".red().to_string()
        },
    );
    report::kv("Secure Boot", yn(p.secure_boot));
    report::kv(
        "Setup Mode",
        match p.setup_mode {
            Some(true) => "yes (no PK!)".red().bold().to_string(),
            Some(false) => "no".green().to_string(),
            None => "—".dimmed().to_string(),
        },
    );
    report::kv(
        "Audit Mode",
        match p.audit_mode {
            Some(true) => "ON".red().bold().to_string(),
            Some(false) => "off".green().to_string(),
            None => "—".dimmed().to_string(),
        },
    );
    report::kv("Deployed Mode", yn(p.deployed_mode));
    if let Some(v) = p.vendor_keys {
        report::kv("vendor keys untouched", yn(Some(v)));
    }
    if let Some(e) = &p.access_error {
        report::kv("access", e.yellow());
    }
}

fn render_keys(dbs: &[(&str, &Db)], verbose: bool, now: i64) {
    report::section("key hierarchy");
    for (name, db) in dbs {
        let certs = db.certs().count();
        let hashes = db.hash_count();
        let other = db.entries.len() - certs - hashes;
        let summary = if let Some(e) = &db.error {
            e.yellow().to_string()
        } else if !db.present {
            "empty".dimmed().to_string()
        } else {
            format!(
                "{certs} cert(s) · {hashes} hash(es){}",
                if other > 0 {
                    format!(" · {other} other")
                } else {
                    String::new()
                }
            )
        };
        report::kv(name, summary);
        let limit = if verbose {
            usize::MAX
        } else if *name == "dbx" {
            0
        } else {
            6
        };
        for c in db.certs().take(limit) {
            let mark = if c.is_untrusted_test_key() {
                "✗".red().bold().to_string()
            } else if c.expired_at(now) {
                "⌛".yellow().to_string()
            } else {
                "·".dimmed().to_string()
            };
            let name = if c.common_name.is_empty() {
                &c.subject
            } else {
                &c.common_name
            };
            println!(
                "      {mark} {:<44} {} {}",
                name,
                c.key.dimmed(),
                format!("→ {}", c.not_after).dimmed()
            );
        }
        if verbose {
            for e in &db.entries {
                match &e.payload {
                    siglist::Payload::Hash { alg, hex }
                    | siglist::Payload::CertHash { alg, hex } => {
                        println!("      {} {alg}:{}", "#".dimmed(), hex.dimmed())
                    }
                    siglist::Payload::Other { sig_type, len } => {
                        println!("      ? {sig_type} ({len} bytes)")
                    }
                    siglist::Payload::X509 { .. } => {}
                }
            }
        }
    }
}

fn render_shim(s: &Shim) {
    if s.mok_certs.is_empty()
        && s.mok_hashes == 0
        && !s.validation_disabled
        && s.sbat_level.is_none()
    {
        return;
    }
    report::section("shim / MOK");
    report::kv(
        "MOK certs / hashes",
        format!("{} / {}", s.mok_certs.len(), s.mok_hashes),
    );
    report::kv("MOKx revocations", s.mokx_entries);
    report::kv(
        "validation",
        if s.validation_disabled {
            "DISABLED".red().bold().to_string()
        } else {
            "enforced".green().to_string()
        },
    );
    if let Some(l) = &s.sbat_level {
        report::kv("SBAT level", l.dimmed());
    }
}

fn render_measured(m: &Measured, log: Option<&tcg::EventLog>, dump: bool) {
    report::section("measured boot");
    report::kv("event log", m.log_source.as_deref().unwrap_or("—"));
    report::kv("format", m.format.as_deref().unwrap_or("—"));
    report::kv("banks", m.banks.join(", "));
    report::kv(
        "events",
        format!(
            "{}{}",
            m.events,
            if m.trailing_bytes > 0 {
                format!(" (+{} trailing bytes)", m.trailing_bytes)
            } else {
                String::new()
            }
        ),
    );
    report::kv(
        "live PCRs",
        m.live_source.as_deref().unwrap_or("unavailable"),
    );
    if let Some(sb) = m.measured_secure_boot {
        report::kv("measured SecureBoot", yn(Some(sb)));
    }
    println!();
    for r in &m.pcrs {
        let status = match r.matches {
            Some(true) => "✓ match".green().to_string(),
            Some(false) => "✗ MISMATCH".red().bold().to_string(),
            None => "· replay only".dimmed().to_string(),
        };
        println!(
            "    {:<7} PCR{:<2} {}…  {}",
            r.bank,
            r.pcr,
            &r.replayed[..24],
            status
        );
    }
    if !m.authorities.is_empty() {
        println!();
        println!("    {}", "boot authorities (PCR7)".dimmed());
        for a in &m.authorities {
            println!(
                "      {} {} {}",
                "→".cyan(),
                a.subject.as_deref().unwrap_or("(hash entry)"),
                format!("[{}]", a.variable).dimmed()
            );
        }
    }
    if !m.boot_images.is_empty() {
        println!();
        println!("    {}", "boot applications loaded".dimmed());
        for p in &m.boot_images {
            println!("      {} {}", "▸".cyan(), p);
        }
    }
    if dump {
        if let Some(log) = log {
            println!();
            for ev in &log.events {
                let d = ev
                    .digests
                    .last()
                    .map(|(_, d)| hex::encode(&d[..8.min(d.len())]))
                    .unwrap_or_default();
                println!(
                    "    #{:<4} PCR{:<2} {:<34} {}… {}B",
                    ev.index,
                    ev.pcr,
                    tcg::event_name(ev.etype),
                    d.dimmed(),
                    ev.data.len()
                );
            }
        }
    }
}
