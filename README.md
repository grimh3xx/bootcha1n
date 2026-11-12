<img src="docs/banner.svg" alt="bootcha1n" width="100%">

[![build](https://img.shields.io/github/actions/workflow/status/grimh3xx/bootcha1n/build.yml?branch=main&style=flat-square&labelColor=111826&label=build)](https://github.com/grimh3xx/bootcha1n/actions)
[![license](https://img.shields.io/github/license/grimh3xx/bootcha1n?style=flat-square&labelColor=111826&color=22D3EE)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-2021-3B82F6?style=flat-square&labelColor=111826)
![platform](https://img.shields.io/badge/Windows%20%7C%20Linux-x64-22D3EE?style=flat-square&labelColor=111826)
![read-only](https://img.shields.io/badge/read--only-no%20firmware%20writes-34D399?style=flat-square&labelColor=111826)

**A read-only auditor for the UEFI boot chain, in Rust.** bootcha1n audits
the Secure Boot key hierarchy (PK → KEK → db / dbx) and the shim/MOK state.
It replays the TPM measured-boot event log bank by bank and checks the result
against the live PCRs. It never writes a firmware variable or extends a PCR.


<p align="center"><img src="docs/demo.svg" alt="bootcha1n demo" width="100%"></p>

<sub>Recorded from real output against `tests/fixtures/demo`, a deliberately weak machine (PKfail PK, test KEK, stale dbx, shim validation off, PCR4 tampered) built by `tools/make_fixture.py`. Regenerate with `python3 tools/gen_demo.py`.</sub>

## What it checks

| ID | Severity | Check |
|---|---|---|
| BOOT-000 | high | Machine booted in legacy BIOS / CSM mode |
| BOOT-001 | high | Secure Boot disabled |
| BOOT-002 | critical | Setup Mode: no Platform Key enrolled, so the key databases are writable from the OS |
| BOOT-003 | critical | **PKfail** (CVE-2024-8105): PK is an AMI/IBV "DO NOT TRUST" reference key |
| BOOT-004 | high | Test / sample certificates trusted in KEK or db |
| BOOT-005/006/007 | medium/low | Microsoft **2011 → 2023 CA rotation** not applied (KEK 2K CA 2023, Windows UEFI CA 2023, UEFI CA 2023) |
| BOOT-008 | high/medium | dbx empty or stale (published revocations not applied) |
| BOOT-010 | high | Audit Mode: unauthorised images still run |
| BOOT-011 | medium | RSA keys shorter than 2048 bits in the hierarchy |
| BOOT-012 | info | Expired certificates (UEFI does not enforce expiry, so this is informational) |
| BOOT-013 | high | shim validation disabled (`MokSBState`) |
| BOOT-014 | info | Machine Owner Keys enrolled |
| BOOT-015 | low | Boot manager still authorised by the expired 2011 Windows PCA |
| BOOT-016 | critical | PK/KEK/db/dbx are **not authenticated variables** (firmware accepts unsigned writes) |
| TPM-001 | high | Event log **does not replay** to the live PCRs 0–7 |
| TPM-002 | medium | No TPM event log available |
| TPM-003 | low | SHA-1-only PCR bank |
| TPM-004 | high | Firmware measured "UEFI Debug Mode" |
| TPM-005 | high | Error separators: firmware failed to measure part of the boot |
| TPM-007 | low | Log events whose digest is not the hash of their own data |
| TPM-008 | high | Measured SecureBoot state differs from the live variable |

## How it works (pure Rust, no external tools)

- **UEFI variables:** read from `efivarfs` on Linux and through
  `GetFirmwareEnvironmentVariableExW` on Windows. Each variable is parsed as
  an `EFI_SIGNATURE_LIST`; every X.509 entry is decoded (subject, issuer,
  validity, key size, SHA-256 fingerprint) and every hash entry is counted.
- **Event log:** read from `binary_bios_measurements` on Linux and
  `Tbsi_Get_TCG_Log_Ex` on Windows. Both the legacy SHA-1 and the crypto-agile
  TCG2 formats are parsed. PCRs are replayed per bank, with `StartupLocality`
  taken into account. The tool also extracts the Secure Boot configuration
  measured into PCR7, the db entries that authorised each boot image
  (`EV_EFI_VARIABLE_AUTHORITY`), and the device path of every boot application
  that was loaded.
- **Live PCRs:** sysfs `pcr-<alg>/N` is read first. Otherwise bootcha1n sends
  a raw `TPM2_PCR_Read`, built and parsed in-tree, through `/dev/tpmrm0` or
  Windows TBS. No tpm2-tools, no TSS.

## Install

**Pre-built binaries** (from [Releases](https://github.com/grimh3xx/bootcha1n/releases/latest)):

```sh
# Linux x64
curl -fsSL -o bootcha1n https://github.com/grimh3xx/bootcha1n/releases/latest/download/bootcha1n-linux-x64
chmod +x bootcha1n && sudo mv bootcha1n /usr/local/bin/
```

```powershell
# Windows x64 (PowerShell)
iwr https://github.com/grimh3xx/bootcha1n/releases/latest/download/bootcha1n-windows-x64.exe -OutFile bootcha1n.exe
.\bootcha1n.exe --help
```

**From source** (Rust 1.82+):

```sh
cargo install --git https://github.com/grimh3xx/bootcha1n
```

Needs an elevated shell on Windows (firmware variables) and root on Linux for the TPM event log. The binaries are not code-signed, so SmartScreen or Defender may flag
them heuristically. Build from source if you prefer to verify.

## Usage

```sh
bootcha1n                         # audit this machine (Windows: elevated shell)
bootcha1n --certs                 # also list every cert/hash in PK/KEK/db/dbx
bootcha1n --events                # dump the TCG event log
bootcha1n --json > boot.json      # machine-readable
bootcha1n --sarif > boot.sarif    # GitHub code scanning
bootcha1n --efivars ./dump --eventlog ./binary_bios_measurements   # offline triage
bootcha1n --min-severity medium   # filter
```

The exit code is the worst severity shown (0 = none/info … 4 = critical), so
it can gate CI or a fleet-compliance job. A usage error exits with 64.

Inside WSL2 the firmware belongs to the Windows host, so run `bootcha1n.exe`
there.

## Build

```sh
cargo build --release                                   # Linux
cargo build --release --target x86_64-pc-windows-gnu    # Windows from Linux
```

CI builds, lints (`clippy -D warnings`) and tests on Linux and Windows. It
publishes a release whenever the version in `Cargo.toml` changes.

## Scope

bootcha1n diagnoses; it does not remediate. Every finding includes the command
or setting that fixes it. Use it only on systems you own or are authorised to
assess.

MIT © grimh3xx
