//! Can this user, without admin rights, put a file into a folder (SPEC section 5's first
//! danger)? `AccessCheck` of the folder's security descriptor (its integrity label included)
//! against an identification token of this user without admin rights: its own token when the
//! app runs unelevated (the filtered token, admin groups deny-only), the linked limited token
//! when it runs elevated, and a standard user's token made from its own when there is no
//! linked token to have (UAC off, the built-in Administrator, Windows Sandbox: a full admin
//! token, which can write everywhere).

use crate::wide;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::SystemServices::MAXIMUM_ALLOWED;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::{FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE};

struct Owned(HANDLE);
impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: a handle this module opened, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Whose rights stand for "this user without admin rights".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Basis {
    /// The process's own token (unelevated: a standard user, or an admin's filtered token).
    Own,
    /// The linked limited token (running elevated under UAC).
    Linked,
    /// A standard user's rights, made from the own token (a full admin token with no linked
    /// one: UAC off, the built-in Administrator, Windows Sandbox).
    StandardUser,
}

/// The basis for a token of `elevation_type` whose Administrators group is (`admin`) or is not
/// enabled.
pub fn basis(elevation_type: TOKEN_ELEVATION_TYPE, admin: bool) -> Basis {
    if elevation_type == TokenElevationTypeFull {
        Basis::Linked
    } else if elevation_type == TokenElevationTypeDefault && admin {
        Basis::StandardUser
    } else {
        Basis::Own
    }
}

fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Result<Vec<u64>, String> {
    let mut sid = vec![0u64; (SECURITY_MAX_SID_SIZE as usize).div_ceil(8)];
    let mut size = SECURITY_MAX_SID_SIZE;
    // SAFETY: a buffer of SECURITY_MAX_SID_SIZE bytes.
    if unsafe { CreateWellKnownSid(kind, std::ptr::null_mut(), sid.as_mut_ptr().cast(), &mut size) } == 0 {
        return Err("a well-known SID could not be made".into());
    }
    Ok(sid)
}

/// The Administrators group is enabled in this process's token.
fn admin_enabled() -> bool {
    let Ok(admins) = well_known(WinBuiltinAdministratorsSid) else { return false };
    let mut member: windows_sys::core::BOOL = 0;
    // SAFETY: the process's own token (null), a valid SID.
    let ok = unsafe { CheckTokenMembership(std::ptr::null_mut(), admins.as_ptr() as PSID, &mut member) } != 0;
    ok && member != 0
}

/// This token's own user SID (TOKEN_USER, kept whole: the SID points into it).
fn user_sid(own: HANDLE) -> Result<Vec<u64>, String> {
    let mut need = 0u32;
    // SAFETY: a size query, then a buffer of that size.
    unsafe { GetTokenInformation(own, TokenUser, std::ptr::null_mut(), 0, &mut need) };
    let mut buf = vec![0u64; (need as usize).div_ceil(8).max(1)];
    if unsafe { GetTokenInformation(own, TokenUser, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need) } == 0 {
        return Err("this account's SID could not be read".into());
    }
    Ok(buf)
}

/// A standard user's token made from `own` (a primary token opened with TOKEN_QUERY |
/// TOKEN_DUPLICATE): Administrators deny-only, every privilege but traversal gone, access also
/// restricted to what this account itself and Everyone, Authenticated Users, Users and
/// INTERACTIVE may do (so this account's own folders stay its own, the same answer as its
/// filtered token gives under UAC), at medium integrity, as an identification token.
fn standard_user_token(own: HANDLE) -> Result<Owned, String> {
    let admins = well_known(WinBuiltinAdministratorsSid)?;
    let me = user_sid(own)?;
    // SAFETY: `me` holds a TOKEN_USER the call above filled.
    let me_sid = unsafe { (*(me.as_ptr() as *const TOKEN_USER)).User.Sid };
    let groups: Vec<Vec<u64>> = [WinWorldSid, WinAuthenticatedUserSid, WinBuiltinUsersSid, WinInteractiveSid].into_iter().map(well_known).collect::<Result<_, _>>()?;
    let disable = [SID_AND_ATTRIBUTES { Sid: admins.as_ptr() as PSID, Attributes: 0 }];
    let mut restrict: Vec<SID_AND_ATTRIBUTES> = groups.iter().map(|g| SID_AND_ATTRIBUTES { Sid: g.as_ptr() as PSID, Attributes: 0 }).collect();
    restrict.push(SID_AND_ATTRIBUTES { Sid: me_sid, Attributes: 0 });
    let mut rt: HANDLE = std::ptr::null_mut();
    // SAFETY: the SIDs above outlive the call; the new token is closed by `Owned`.
    if unsafe { CreateRestrictedToken(own, DISABLE_MAX_PRIVILEGE, 1, disable.as_ptr(), 0, std::ptr::null(), restrict.len() as u32, restrict.as_ptr(), &mut rt) } == 0 {
        return Err("a standard user's token could not be made".into());
    }
    let rt = Owned(rt);
    // An identification token of it, opened so its integrity can be lowered (the restricted
    // token's own handle has only the rights the original handle had).
    let mut imp: HANDLE = std::ptr::null_mut();
    // SAFETY: a duplicate closed by `Owned`.
    if unsafe { DuplicateTokenEx(rt.0, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_IMPERSONATE, std::ptr::null(), SecurityIdentification, TokenImpersonation, &mut imp) } == 0 {
        return Err("a standard user's token could not be duplicated".into());
    }
    let imp = Owned(imp);
    let medium = well_known(WinMediumLabelSid)?;
    let label = TOKEN_MANDATORY_LABEL { Label: SID_AND_ATTRIBUTES { Sid: medium.as_ptr() as PSID, Attributes: 0x20 /* SE_GROUP_INTEGRITY */ } };
    // SAFETY: a TOKEN_MANDATORY_LABEL whose SID outlives the call. Lowering is always allowed.
    if unsafe { SetTokenInformation(imp.0, TokenIntegrityLevel, (&label as *const TOKEN_MANDATORY_LABEL).cast(), (size_of::<TOKEN_MANDATORY_LABEL>() + medium.len() * 8) as u32) } == 0 {
        return Err("a standard user's token could not be set to medium integrity".into());
    }
    Ok(imp)
}

/// An identification-level token of this user without admin rights (`basis`).
fn limited_token() -> Result<Owned, String> {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut t: HANDLE = std::ptr::null_mut();
    // SAFETY: this process's token; closed by `Owned`.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut t) } == 0 {
        return Err("this process's token could not be read".into());
    }
    let own = Owned(t);
    let mut ty: TOKEN_ELEVATION_TYPE = 0;
    let mut n = 0u32;
    // SAFETY: a plain value the call fills.
    if unsafe { GetTokenInformation(own.0, TokenElevationType, (&mut ty as *mut TOKEN_ELEVATION_TYPE).cast(), 4, &mut n) } == 0 {
        return Err("this process's elevation could not be read".into());
    }
    let b = basis(ty, ty == TokenElevationTypeDefault && admin_enabled());
    if b == Basis::StandardUser {
        return standard_user_token(own.0);
    }
    if b == Basis::Linked {
        let mut linked = TOKEN_LINKED_TOKEN { LinkedToken: std::ptr::null_mut() };
        // SAFETY: the linked token (an identification token), closed by `Owned`.
        if unsafe { GetTokenInformation(own.0, TokenLinkedToken, (&mut linked as *mut TOKEN_LINKED_TOKEN).cast(), size_of::<TOKEN_LINKED_TOKEN>() as u32, &mut n) } != 0 && !linked.LinkedToken.is_null() {
            return Ok(Owned(linked.LinkedToken));
        }
        return Err("the limited token of this user could not be read".into());
    }
    let mut imp: HANDLE = std::ptr::null_mut();
    // SAFETY: a duplicate at identification level, closed by `Owned`.
    if unsafe { DuplicateToken(own.0, SecurityIdentification, &mut imp) } == 0 {
        return Err("this process's token could not be duplicated".into());
    }
    Ok(Owned(imp))
}

/// The rights this user (without admin) has on `dir`, from its security descriptor.
fn granted(dir: &[u16]) -> Result<u32, String> {
    let token = limited_token()?;
    granted_with(dir, token.0)
}

/// The rights `token` (an identification token) has on `dir`.
fn granted_with(dir: &[u16], token: HANDLE) -> Result<u32, String> {
    let z = wide::z(dir);
    // The label too: a folder labelled High with no-write-up is not writable at medium.
    let info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
    let mut need = 0u32;
    // SAFETY: a size query, then a buffer of that size.
    unsafe { GetFileSecurityW(z.as_ptr(), info, std::ptr::null_mut(), 0, &mut need) };
    if need == 0 {
        return Err(crate::fsprobe::reason(unsafe { windows_sys::Win32::Foundation::GetLastError() }));
    }
    let mut sd = vec![0u64; (need as usize).div_ceil(8)];
    if unsafe { GetFileSecurityW(z.as_ptr(), info, sd.as_mut_ptr().cast(), (sd.len() * 8) as u32, &mut need) } == 0 {
        return Err(crate::fsprobe::reason(unsafe { windows_sys::Win32::Foundation::GetLastError() }));
    }
    let mapping = GENERIC_MAPPING { GenericRead: FILE_GENERIC_READ, GenericWrite: FILE_GENERIC_WRITE, GenericExecute: FILE_GENERIC_EXECUTE, GenericAll: FILE_ALL_ACCESS };
    let mut privs = vec![0u64; 64];
    let mut plen = (privs.len() * 8) as u32;
    let mut mask = 0u32;
    let mut status = 0i32;
    // SAFETY: the descriptor read above, an identification token, the file mapping.
    let ok = unsafe { AccessCheck(sd.as_mut_ptr().cast(), token, MAXIMUM_ALLOWED, &mapping, privs.as_mut_ptr().cast(), &mut plen, &mut mask, &mut status) } != 0;
    if !ok {
        return Err(crate::host::code_words(unsafe { windows_sys::Win32::Foundation::GetLastError() }));
    }
    Ok(if status != 0 { mask } else { 0 })
}

/// This user (without admin) can add a file or a folder to `dir`.
pub fn user_can_add(dir: &[u16]) -> Result<bool, String> {
    granted(dir).map(|m| m & (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY) != 0)
}

/// This user (without admin) can make a folder in `dir`.
pub fn user_can_make_folder(dir: &[u16]) -> Result<bool, String> {
    granted(dir).map(|m| m & FILE_ADD_SUBDIRECTORY != 0)
}
