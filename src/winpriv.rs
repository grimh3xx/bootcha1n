//! Enable a named privilege on our own process token (Windows only).

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_SUCCESS, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Returns true only when the privilege is actually held and now enabled.
pub fn enable(name: &str) -> bool {
    let wname: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: plain Win32 calls with locally-owned, correctly sized buffers;
    // the token handle is closed before returning.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        let ok = LookupPrivilegeValueW(std::ptr::null(), wname.as_ptr(), &mut luid) != 0 && {
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            AdjustTokenPrivileges(token, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0
                // ERROR_NOT_ALL_ASSIGNED is reported via GetLastError on "success".
                && GetLastError() == ERROR_SUCCESS
        };
        CloseHandle(token);
        ok
    }
}
