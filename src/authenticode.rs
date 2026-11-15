//! Who signed a match, and whether Windows trusts it (SPEC section 3; VibeVerify's
//! authenticode.rs, cut to what VibePath shows): `WinVerifyTrust` with the generic Authenticode
//! policy, no UI, revocation from the cache only (no network). Windows' own files carry no
//! signature of their own but are listed in a signed catalog: those are looked up in the
//! system's catalogs (portable executables only). The file is read through one handle held
//! without delete sharing, so nothing is renamed over it meanwhile. A file that cannot be read
//! is "unknown", never "not signed".
//!
//! Blocking (a catalog lookup hashes the whole file): call it on a worker.

use std::os::windows::io::AsRawHandle;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Signed and trusted. `catalog`: through a system catalog (Windows' own files).
    Signed { signer: String, catalog: bool, note: Option<String> },
    NotSigned,
    /// A kind of file Windows does not sign (a text file).
    NotSignable,
    /// Signed, but the signature fails.
    Invalid { signer: Option<String>, why: String },
    /// Signed and intact, but Windows does not vouch for the signer.
    Untrusted { signer: Option<String>, why: String },
    /// It could not be checked: unknown.
    Error(String),
}

const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;
const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B_0001;
const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;
const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B_0111;
const TRUST_E_SUBJECT_NOT_TRUSTED: u32 = 0x800B_0004;
const CERT_E_EXPIRED: u32 = 0x800B_0101;
const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
const CERT_E_CHAINING: u32 = 0x800B_010A;
const CERT_E_REVOKED: u32 = 0x800B_010C;
const CRYPT_E_FILE_ERROR: u32 = 0x8009_2003;
const CRYPT_E_NO_REVOCATION_CHECK: u32 = 0x8009_2012;
const CRYPT_E_REVOCATION_OFFLINE: u32 = 0x8009_2013;
const CRYPT_E_REVOKED: u32 = 0x8009_2010;

/// What a WinVerifyTrust answer means. Pure, so every code is tested.
pub fn classify(code: u32, signer: Option<String>, catalog: bool) -> Verdict {
    let invalid = |why: &str| Verdict::Invalid { signer: signer.clone(), why: why.into() };
    let untrusted = |why: &str| Verdict::Untrusted { signer: signer.clone(), why: why.into() };
    let named = || signer.clone().unwrap_or_else(|| "an unnamed publisher".into());
    match code {
        0 => Verdict::Signed { signer: named(), catalog, note: None },
        CRYPT_E_NO_REVOCATION_CHECK | CRYPT_E_REVOCATION_OFFLINE => Verdict::Signed { signer: named(), catalog, note: Some("revocation not checked (only Windows' cache is asked)".into()) },
        TRUST_E_NOSIGNATURE => Verdict::NotSigned,
        TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => Verdict::NotSignable,
        TRUST_E_BAD_DIGEST => invalid("the file was changed after it was signed"),
        TRUST_E_EXPLICIT_DISTRUST => invalid("the certificate is blocked on this computer"),
        CERT_E_REVOKED | CRYPT_E_REVOKED => invalid("the certificate was revoked"),
        CERT_E_EXPIRED => untrusted("the certificate has expired and the signature carries no timestamp"),
        CERT_E_UNTRUSTEDROOT => untrusted("Windows does not trust the certificate (self-signed or unknown authority)"),
        CERT_E_CHAINING => untrusted("the certificate does not chain to an authority Windows trusts"),
        TRUST_E_SUBJECT_NOT_TRUSTED => invalid("Windows does not trust it"),
        CRYPT_E_FILE_ERROR => Verdict::Error("Windows could not read the file to check it".into()),
        other => invalid(&format!("Windows refused it (code {other:#010X})")),
    }
}

/// A verdict in the row's words, and its state (1 good, 3 warning, 4 bad, 5 unknown, 2 quiet).
pub fn words(v: &Verdict) -> (String, i32) {
    match v {
        Verdict::Signed { signer, catalog, note } => {
            let mut s = format!("Signed by {signer}");
            if *catalog {
                s.push_str(" (through a Windows catalog)");
            }
            if let Some(n) = note {
                s.push_str(&format!("; {n}"));
            }
            (s, 1)
        }
        Verdict::NotSigned => ("Not signed".into(), 3),
        Verdict::NotSignable => ("Not a kind of file that is signed".into(), 2),
        Verdict::Invalid { signer, why } => (format!("Signature fails{}: {why}", signer.as_ref().map(|s| format!(" ({s})")).unwrap_or_default()), 4),
        Verdict::Untrusted { signer, why } => (format!("Signed{}, but {why}", signer.as_ref().map(|s| format!(" by {s}")).unwrap_or_default()), 3),
        Verdict::Error(e) => (format!("Unknown: {e}"), 5),
    }
}

unsafe fn signer_name(state: windows_sys::Win32::Foundation::HANDLE) -> Option<String> {
    use windows_sys::Win32::Security::Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW};
    use windows_sys::Win32::Security::WinTrust::{WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData};
    // SAFETY: the trust state of a verify call still open; every pointer checked.
    unsafe {
        if state.is_null() {
            return None;
        }
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
        if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
            return None;
        }
        let cert = (*(*sgnr).pasCertChain).pCert;
        if cert.is_null() {
            return None;
        }
        let mut buf = [0u16; 512];
        let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, std::ptr::null(), buf.as_mut_ptr(), buf.len() as u32);
        if n <= 1 {
            return None;
        }
        let s = crate::text::clean_wide(&buf[..n as usize - 1], 120);
        (!s.is_empty()).then_some(s)
    }
}

unsafe fn trust(mut data: windows_sys::Win32::Security::WinTrust::WINTRUST_DATA) -> (u32, Option<String>) {
    use windows_sys::Win32::Security::WinTrust::*;
    // SAFETY: the caller filled the union; verify, read the signer, close.
    unsafe {
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let code = WinVerifyTrust(std::ptr::null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast()) as u32;
        let signer = signer_name(data.hWVTStateData);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(std::ptr::null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast());
        (code, signer)
    }
}

fn is_pe(file: &std::fs::File) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = file;
    let mut b = [0u8; 2];
    let ok = f.seek(SeekFrom::Start(0)).is_ok() && f.read_exact(&mut b).is_ok() && &b == b"MZ";
    let _ = f.seek(SeekFrom::Start(0));
    ok
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

unsafe fn catalog(path: &Path, file: &std::fs::File) -> Option<(u32, Option<String>)> {
    use windows_sys::Win32::Security::Cryptography::Catalog::*;
    use windows_sys::Win32::Security::WinTrust::*;
    let handle = file.as_raw_handle();
    for alg in [windows_sys::core::w!("SHA256"), windows_sys::core::w!("SHA1")] {
        // SAFETY: the catalog admin calls in their documented order; every context released.
        unsafe {
            let mut admin: isize = 0;
            if CryptCATAdminAcquireContext2(&mut admin, std::ptr::null(), alg, std::ptr::null(), 0) == 0 {
                continue;
            }
            let mut len = 0u32;
            CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut len, std::ptr::null_mut(), 0);
            let mut hash = vec![0u8; len as usize];
            if len == 0 || CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut len, hash.as_mut_ptr(), 0) == 0 {
                CryptCATAdminReleaseContext(admin, 0);
                continue;
            }
            let info = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), len, 0, std::ptr::null_mut());
            if info == 0 {
                CryptCATAdminReleaseContext(admin, 0);
                continue;
            }
            let mut ci = CATALOG_INFO { cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32, wszCatalogFile: [0; 260] };
            let result = if CryptCATCatalogInfoFromContext(info, &mut ci, 0) != 0 {
                let tag: Vec<u16> = hex(&hash).encode_utf16().chain(std::iter::once(0)).collect();
                let member = crate::host::wide_path(path);
                let mut cat = WINTRUST_CATALOG_INFO {
                    cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                    pcwszCatalogFilePath: ci.wszCatalogFile.as_ptr(),
                    pcwszMemberTag: tag.as_ptr(),
                    pcwszMemberFilePath: member.as_ptr(),
                    hMemberFile: handle,
                    pbCalculatedFileHash: hash.as_mut_ptr(),
                    cbCalculatedFileHash: len,
                    hCatAdmin: admin,
                    ..Default::default()
                };
                let mut data = WINTRUST_DATA { dwUnionChoice: WTD_CHOICE_CATALOG, ..Default::default() };
                data.Anonymous.pCatalog = &mut cat;
                Some(trust(data))
            } else {
                None
            };
            CryptCATAdminReleaseCatalogContext(admin, info, 0);
            CryptCATAdminReleaseContext(admin, 0);
            if result.is_some() {
                return result;
            }
        }
    }
    None
}

/// The handle Windows checks through: without delete sharing (nothing is renamed over the name
/// meanwhile); a file another program holds with delete access is opened shared when it is a
/// portable executable (read through the handle only), else it is in use: unknown.
fn open_held(path: &Path) -> Result<std::fs::File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new().read(true).share_mode(1 | 2).open(path) {
        Ok(f) => Ok(f),
        Err(e) if e.raw_os_error() == Some(32) => {
            let f = std::fs::OpenOptions::new().read(true).share_mode(7).open(path).map_err(|e| e.to_string())?;
            if is_pe(&f) { Ok(f) } else { Err("the file is in use by another program".into()) }
        }
        Err(e) => Err(match e.raw_os_error() {
            Some(5) => "access denied".into(),
            Some(c) => crate::host::code_words(c as u32),
            None => e.to_string(),
        }),
    }
}

/// `path`'s signature.
pub fn check(path: &Path) -> Verdict {
    use windows_sys::Win32::Security::WinTrust::*;
    let file = match open_held(path) {
        Ok(f) => f,
        Err(e) => return Verdict::Error(e),
    };
    let wide = crate::host::wide_path(path);
    let mut info = WINTRUST_FILE_INFO { cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32, pcwszFilePath: wide.as_ptr(), hFile: file.as_raw_handle(), pgKnownSubject: std::ptr::null_mut() };
    let mut data = WINTRUST_DATA { dwUnionChoice: WTD_CHOICE_FILE, ..Default::default() };
    data.Anonymous.pFile = &mut info;
    // SAFETY: the union points at `info`, which lives through the call.
    let (code, signer) = unsafe { trust(data) };
    if code == TRUST_E_NOSIGNATURE && is_pe(&file) {
        // SAFETY: the open file's handle, held through the lookup.
        if let Some((c, s)) = unsafe { catalog(path, &file) } {
            return classify(c, s, true);
        }
    }
    classify(code, signer, false)
}
