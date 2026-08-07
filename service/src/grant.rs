//! the delegated rule-management grant.
//!
//! rule mutations are privileged, so by default they are only accepted on the
//! admin channel, which costs an elevation prompt every time. that is correct
//! but unusable when blocking an app is a routine action. instead the user
//! elevates once to authorize a specific desktop account; the engine records
//! that authorization in its own state directory, which only SYSTEM and
//! administrators can write. afterwards the telemetry channel accepts rule
//! mutations, but only from a peer that is already proven to be that account in
//! the active console session, and only while the grant file says so.
//!
//! the grant is therefore a deliberate, revocable widening of the boundary, not
//! a hole: establishing or revoking it still requires elevation, and the file
//! backing it sits under the same protected ACL as the rules themselves.

use std::path::PathBuf;

fn grant_file() -> PathBuf {
    crate::paths::data_dir().join("rule-grant")
}

/// the account the grant names, in a form the platform can compare a live peer
/// against: the user's SID on Windows, the numeric uid on Linux.
#[cfg(windows)]
pub type Account = String;
#[cfg(not(windows))]
pub type Account = u32;

/// whether `account` may change rules without elevating
pub fn allows(account: &Account) -> bool {
    match read() {
        Some(granted) => &granted == account,
        None => false,
    }
}

/// whether any grant is recorded at all, for the settings toggle
pub fn is_granted() -> bool {
    read().is_some()
}

fn read() -> Option<Account> {
    let raw = std::fs::read_to_string(grant_file()).ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    #[cfg(windows)]
    {
        Some(raw.to_string())
    }
    #[cfg(not(windows))]
    {
        raw.parse().ok()
    }
}

/// the on-disk form of an account, the inverse of what `read` parses
#[cfg(windows)]
fn encode(account: &Account) -> String {
    account.clone()
}

#[cfg(not(windows))]
fn encode(account: &Account) -> String {
    account.to_string()
}

/// record or clear the grant for `account`. only ever called from the elevated
/// admin channel.
pub fn set(account: &Account, granted: bool) -> std::io::Result<()> {
    let path = grant_file();
    if !granted {
        return match std::fs::remove_file(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        };
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, encode(account))?;
    // the state root's ACL already excludes non-administrators on Windows; on
    // Linux the file is inside a 0711 directory, so lock the file itself too
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// the account of the caller performing an elevated grant. on Windows the
/// elevated one-shot runs as the same user with a full token, so its own SID is
/// the account being authorized; on Linux pkexec runs it as root, so the
/// invoking user arrives in PKEXEC_UID.
#[cfg(windows)]
pub fn calling_account() -> std::io::Result<Account> {
    current_sid()
}

#[cfg(not(windows))]
pub fn calling_account() -> std::io::Result<Account> {
    if let Ok(uid) = std::env::var("PKEXEC_UID") {
        if let Ok(uid) = uid.trim().parse() {
            return Ok(uid);
        }
    }
    crate::paths::desktop_uid()
}

/// the SID of the process's own user, as a string
#[cfg(windows)]
pub fn current_sid() -> std::io::Result<String> {
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(std::io::Error::other)?;
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        let mut buffer = vec![0u8; needed as usize];
        let result = GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut _),
            needed,
            &mut needed,
        );
        let _ = windows::Win32::Foundation::CloseHandle(token);
        result.map_err(std::io::Error::other)?;
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        sid_to_string(user.User.Sid)
    }
}

/// the SID of the user owning `pid`, for identifying a pipe peer. the engine
/// runs as SYSTEM, so it can open any client's token.
#[cfg(windows)]
pub fn sid_of_process(pid: u32) -> std::io::Result<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let process =
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(std::io::Error::other)?;
        let mut token = windows::Win32::Foundation::HANDLE::default();
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token);
        let _ = CloseHandle(process);
        opened.map_err(std::io::Error::other)?;
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        let mut buffer = vec![0u8; needed as usize];
        let result = GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut _),
            needed,
            &mut needed,
        );
        let _ = CloseHandle(token);
        result.map_err(std::io::Error::other)?;
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        sid_to_string(user.User.Sid)
    }
}

#[cfg(windows)]
pub fn sid_to_string(sid: windows::Win32::Security::PSID) -> std::io::Result<String> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;

    unsafe {
        let mut text = windows::core::PWSTR::null();
        ConvertSidToStringSidW(sid, &mut text).map_err(std::io::Error::other)?;
        let value = text.to_string().map_err(std::io::Error::other)?;
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut _)));
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{encode, Account};

    fn sample() -> Account {
        #[cfg(windows)]
        {
            "S-1-5-21-1-2-3-1001".to_string()
        }
        #[cfg(not(windows))]
        {
            1000u32
        }
    }

    fn other() -> Account {
        #[cfg(windows)]
        {
            "S-1-5-21-1-2-3-1002".to_string()
        }
        #[cfg(not(windows))]
        {
            1001u32
        }
    }

    /// the same parse `read` performs, over an explicit string, so the test does
    /// not depend on the engine's real state directory
    fn decode(raw: &str) -> Option<Account> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        #[cfg(windows)]
        {
            Some(raw.to_string())
        }
        #[cfg(not(windows))]
        {
            raw.parse().ok()
        }
    }

    #[test]
    fn an_account_survives_the_round_trip_to_disk() {
        assert_eq!(decode(&encode(&sample())), Some(sample()));
    }

    #[test]
    fn a_grant_names_one_account_and_does_not_cover_another() {
        let granted = decode(&encode(&sample())).unwrap();
        assert_ne!(granted, other());
    }

    #[test]
    fn an_empty_or_blank_grant_file_authorizes_nobody() {
        assert!(decode("").is_none());
        assert!(decode("   \n").is_none());
    }
}
