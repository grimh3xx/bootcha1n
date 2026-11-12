//! Read-only access to UEFI variables.
//!
//! * Linux: `efivarfs` (`/sys/firmware/efi/efivars/<Name>-<guid>`), whose
//!   files carry a 4-byte attribute prefix before the payload.
//! * Windows: `GetFirmwareEnvironmentVariableExW` with
//!   `SeSystemEnvironmentPrivilege` enabled on our own token (requires an
//!   elevated shell). Nothing is ever written back.
//! * Offline: `--efivars <dir>` points at a copy of an efivarfs tree, which is
//!   how fixtures and fleet triage are done.

use std::path::{Path, PathBuf};

use crate::guid::Guid;

#[derive(Debug)]
pub enum VarError {
    NotFound,
    Denied(String),
    Unsupported(String),
    Io(String),
}

pub struct Var {
    pub attributes: u32,
    pub data: Vec<u8>,
}

#[cfg(test)]
pub const ATTR_BOOTSERVICE_ACCESS: u32 = 0x2;
#[cfg(test)]
pub const ATTR_RUNTIME_ACCESS: u32 = 0x4;
/// EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
pub const ATTR_TIME_BASED_AUTH: u32 = 0x20;

pub trait VarStore {
    fn read(&self, name: &str, guid: &Guid) -> Result<Var, VarError>;
    fn describe(&self) -> String;
    fn locate(&self, name: &str, guid: &Guid) -> String;
}

pub struct DirStore {
    root: PathBuf,
}

impl DirStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path(&self, name: &str, guid: &Guid) -> PathBuf {
        self.root.join(format!("{name}-{guid}"))
    }
}

impl VarStore for DirStore {
    fn read(&self, name: &str, guid: &Guid) -> Result<Var, VarError> {
        match std::fs::read(self.path(name, guid)) {
            Ok(raw) if raw.len() >= 4 => Ok(Var {
                attributes: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
                data: raw[4..].to_vec(),
            }),
            Ok(_) => Err(VarError::NotFound),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(VarError::NotFound),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(VarError::Denied(e.to_string()))
            }
            Err(e) => Err(VarError::Io(e.to_string())),
        }
    }

    fn describe(&self) -> String {
        format!("efivarfs {}", self.root.display())
    }

    fn locate(&self, name: &str, guid: &Guid) -> String {
        self.path(name, guid).display().to_string()
    }
}

/// Stand-in for machines booted in legacy/CSM mode or without any source.
#[cfg(not(windows))]
pub struct NoStore(pub String);

#[cfg(not(windows))]
impl VarStore for NoStore {
    fn read(&self, _: &str, _: &Guid) -> Result<Var, VarError> {
        Err(VarError::Unsupported(self.0.clone()))
    }
    fn describe(&self) -> String {
        format!("unavailable ({})", self.0)
    }
    fn locate(&self, name: &str, guid: &Guid) -> String {
        format!("{name}-{guid}")
    }
}

#[cfg(windows)]
pub use win::FirmwareStore;

#[cfg(windows)]
mod win {
    use super::*;
    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_ENVVAR_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_FUNCTION,
        ERROR_PRIVILEGE_NOT_HELD,
    };
    use windows_sys::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableExW;

    pub struct FirmwareStore {
        pub privileged: bool,
    }

    impl FirmwareStore {
        pub fn open() -> Self {
            Self {
                privileged: crate::winpriv::enable("SeSystemEnvironmentPrivilege"),
            }
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    impl VarStore for FirmwareStore {
        fn read(&self, name: &str, guid: &Guid) -> Result<Var, VarError> {
            let wname = wide(name);
            let wguid = wide(&format!("{{{guid}}}"));
            let mut cap = 16 * 1024;
            loop {
                let mut buf = vec![0u8; cap];
                let mut attrs = 0u32;
                // SAFETY: buffers are valid for the sizes passed; strings are NUL-terminated.
                let n = unsafe {
                    GetFirmwareEnvironmentVariableExW(
                        wname.as_ptr(),
                        wguid.as_ptr(),
                        buf.as_mut_ptr().cast(),
                        cap as u32,
                        &mut attrs,
                    )
                };
                if n != 0 {
                    buf.truncate(n as usize);
                    return Ok(Var {
                        attributes: attrs,
                        data: buf,
                    });
                }
                // SAFETY: trivially safe thread-local read.
                let err = unsafe { GetLastError() };
                match err {
                    ERROR_INSUFFICIENT_BUFFER if cap < 4 * 1024 * 1024 => cap *= 4,
                    ERROR_ENVVAR_NOT_FOUND => return Err(VarError::NotFound),
                    ERROR_PRIVILEGE_NOT_HELD => {
                        return Err(VarError::Denied("run from an elevated shell".into()))
                    }
                    ERROR_INVALID_FUNCTION => {
                        return Err(VarError::Unsupported("legacy BIOS / CSM boot".into()))
                    }
                    e => return Err(VarError::Io(format!("win32 error {e}"))),
                }
            }
        }

        fn describe(&self) -> String {
            format!(
                "Windows firmware API{}",
                if self.privileged {
                    ""
                } else {
                    " (SeSystemEnvironmentPrivilege unavailable)"
                }
            )
        }

        fn locate(&self, name: &str, guid: &Guid) -> String {
            format!("uefi:{name}-{guid}")
        }
    }
}

pub fn open(dir: Option<&Path>) -> Box<dyn VarStore> {
    if let Some(d) = dir {
        return Box::new(DirStore::new(d));
    }
    #[cfg(windows)]
    {
        Box::new(FirmwareStore::open())
    }
    #[cfg(not(windows))]
    {
        let efivars = Path::new("/sys/firmware/efi/efivars");
        if efivars.is_dir() {
            Box::new(DirStore::new(efivars))
        } else if is_wsl() {
            Box::new(NoStore(
                "WSL: firmware is owned by the Windows host — run bootcha1n.exe there".into(),
            ))
        } else if Path::new("/sys/firmware/efi").is_dir() {
            Box::new(NoStore("efivarfs not mounted".into()))
        } else {
            Box::new(NoStore("not booted via UEFI".into()))
        }
    }
}

/// WSL2 boots its kernel straight from Hyper-V, so the absence of
/// /sys/firmware/efi says nothing about the real machine.
#[cfg(not(windows))]
pub fn is_wsl() -> bool {
    std::path::Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
        || std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .is_ok_and(|r| r.to_ascii_lowercase().contains("microsoft"))
}

/// Single-byte boolean variables (SecureBoot, SetupMode, AuditMode, ...).
pub fn read_flag(store: &dyn VarStore, name: &str, guid: &Guid) -> Option<bool> {
    store
        .read(name, guid)
        .ok()
        .and_then(|v| v.data.first().map(|b| *b == 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guid::EFI_GLOBAL_VARIABLE;

    #[test]
    fn dirstore_strips_attribute_prefix() {
        let dir = std::env::temp_dir().join(format!("bootcha1n-efivar-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(format!("SecureBoot-{EFI_GLOBAL_VARIABLE}")),
            [6, 0, 0, 0, 1],
        )
        .unwrap();
        let s = DirStore::new(&dir);
        let v = s.read("SecureBoot", &EFI_GLOBAL_VARIABLE).unwrap();
        assert_eq!(v.attributes, ATTR_BOOTSERVICE_ACCESS | ATTR_RUNTIME_ACCESS);
        assert_eq!(v.data, [1]);
        assert_eq!(
            read_flag(&s, "SecureBoot", &EFI_GLOBAL_VARIABLE),
            Some(true)
        );
        assert!(matches!(
            s.read("SetupMode", &EFI_GLOBAL_VARIABLE),
            Err(VarError::NotFound)
        ));
        std::fs::remove_dir_all(dir).ok();
    }
}
