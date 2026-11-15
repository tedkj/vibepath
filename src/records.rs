//! The helper's own undo records: what the elevated side changed, kept where only administrators
//! can write (`HKLM\SOFTWARE\VibePath`, one REG_BINARY value per change, named by its 128-bit
//! id). The journal in the user's profile is for showing and history; an Undo of Machine PATH
//! trusts only these records (the user's profile can be written without admin rights, so its
//! "value before" is not the helper's to restore).
//!
//! The key is made by the helper with its own security: owner Administrators, a protected DACL
//! of SYSTEM and Administrators full control, nobody else. Before a record is written or read,
//! the key's owner and DACL are checked again: an owner other than SYSTEM or Administrators (an
//! owner can always rewrite the DACL), no DACL, or any entry that lets someone else write means
//! the records are not trusted ("could not be read or kept"), never used.

use crate::env::{self, Kind};
use crate::wide::W;

pub type Id = [u8; 16];

/// The most records kept on a PC (the oldest go first), as many as the journal keeps per user.
pub const KEEP: usize = 200;
pub const KEY: &str = r"SOFTWARE\VibePath";
const VERSION: u8 = 1;
/// A record of a change written as REG_SZ (`encode`).
const VERSION_SZ: u8 = 2;
const NO_VALUE: u32 = u32::MAX;
/// The longest value a record holds (as the helper's wire).
const MAX_UNITS: usize = crate::helper::MAX_VALUE;

/// The records a prune removes, from every record's (time, value name): the oldest past `KEEP`
/// by their time, never `keep`, the one just written (FED6: with the clock set back, its time
/// reads older than the rest, and it went before Machine PATH was even written, leaving a change
/// the helper made and could not undo).
pub fn doomed(mut found: Vec<(u64, W)>, keep: &[u16]) -> Vec<W> {
    found.retain(|(_, n)| n != keep);
    if found.len() < KEEP {
        return Vec::new();
    }
    found.sort();
    let gone = found.len() + 1 - KEEP;
    found.into_iter().take(gone).map(|(_, n)| n).collect()
}

/// One change the helper made: Machine PATH was `before` (None: not there) and it wrote `after`
/// as `wrote` (REG_EXPAND_SZ; REG_SZ only for an Undo of a value that was one, FED1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Unix milliseconds when it was recorded (the oldest go first).
    pub at_ms: u64,
    pub before: Option<env::Value>,
    pub after: W,
    pub wrote: Kind,
}

/// Where the helper keeps its records (the tests and the fake PC hand it one in memory).
pub trait Records {
    /// A fresh id (None: no random numbers from the system).
    fn new_id(&self) -> Option<Id>;
    /// Record a change under `id`, before it is made (create-new: an id is never reused).
    fn put(&self, id: &Id, before: Option<&env::Value>, after: &[u16], wrote: Kind) -> Result<(), String>;
    /// The record under `id`: Ok(None) when there is none; Err when the records cannot be read
    /// or are not trusted (unknown, never "none").
    fn get(&self, id: &Id) -> Result<Option<Record>, String>;
}

fn put_units(out: &mut Vec<u8>, units: &[u16]) {
    out.extend_from_slice(&(units.len() as u32).to_le_bytes());
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
}

fn get_units(b: &[u8], at: usize) -> Option<(W, usize)> {
    let n = u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize;
    if n > MAX_UNITS {
        return None;
    }
    let bytes = b.get(at + 4..at + 4 + n * 2)?;
    Some((bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect(), at + 4 + n * 2))
}

/// version (u8), time (u64), before type (u32, `NO_VALUE` for none) and units, after units. A
/// change written as REG_SZ (an Undo, FED1) is version 2: the same, then the type written (u32,
/// 1); every other record keeps version 1 byte for byte (written as REG_EXPAND_SZ).
pub fn encode(r: &Record) -> Vec<u8> {
    let mut b = vec![if r.wrote == Kind::Sz { VERSION_SZ } else { VERSION }];
    b.extend_from_slice(&r.at_ms.to_le_bytes());
    match &r.before {
        Some(v) => {
            b.extend_from_slice(&v.kind.code().to_le_bytes());
            put_units(&mut b, &v.raw);
        }
        None => {
            b.extend_from_slice(&NO_VALUE.to_le_bytes());
            put_units(&mut b, &[]);
        }
    }
    put_units(&mut b, &r.after);
    if r.wrote == Kind::Sz {
        b.extend_from_slice(&Kind::Sz.code().to_le_bytes());
    }
    b
}

/// Strict: anything not exactly one record is None.
pub fn decode(b: &[u8]) -> Option<Record> {
    let version = *b.first()?;
    if version != VERSION && version != VERSION_SZ {
        return None;
    }
    let at_ms = u64::from_le_bytes(b.get(1..9)?.try_into().ok()?);
    let kind = u32::from_le_bytes(b.get(9..13)?.try_into().ok()?);
    let (before, at) = get_units(b, 13)?;
    let (after, mut end) = get_units(b, at)?;
    let wrote = if version == VERSION_SZ {
        if u32::from_le_bytes(b.get(end..end + 4)?.try_into().ok()?) != Kind::Sz.code() {
            return None;
        }
        end += 4;
        Kind::Sz
    } else {
        Kind::ExpandSz
    };
    if end != b.len() {
        return None;
    }
    let before = if kind == NO_VALUE {
        if !before.is_empty() {
            return None;
        }
        None
    } else {
        Some(env::Value { kind: Kind::from_code(kind), raw: before })
    };
    Some(Record { at_ms, before, after, wrote })
}

pub fn hex(id: &Id) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// An id from its 32 lower-case hex digits (as `hex` writes it); None for anything else.
pub fn parse_hex(s: &str) -> Option<Id> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut id = [0u8; 16];
    for (i, c) in s.as_bytes().chunks(2).enumerate() {
        id[i] = u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok()?;
    }
    Some(id)
}

/// Whose an ACE or owner is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Who {
    System,
    Admins,
    Other,
}

/// One ACE as read: its type, flags, access mask and whose it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ace {
    pub kind: u8,
    pub flags: u8,
    pub mask: u32,
    pub who: Who,
}

const ACCESS_DENIED: u8 = 1;
const INHERIT_ONLY: u8 = 8;
/// Every right that changes a key or its values or security: set value, create subkey, create
/// link, delete, write DAC, write owner, generic write, generic all, maximum allowed.
pub const WRITE_RIGHTS: u32 = 0x2 | 0x4 | 0x20 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x4000_0000 | 0x1000_0000 | 0x0200_0000;

/// Only SYSTEM and Administrators can change the key: owned by one of them (an owner can always
/// rewrite the DACL), a DACL (none would let everyone in), and no ACE that applies to the key
/// and is not a deny gives anyone else a write right. An ACE of a type other than allow or deny
/// is judged as an allow (callback and object ACEs are not expected here).
pub fn admin_only(owner: Who, dacl: Option<&[Ace]>) -> bool {
    if owner == Who::Other {
        return false;
    }
    let Some(aces) = dacl else { return false };
    !aces.iter().any(|a| a.kind != ACCESS_DENIED && a.flags & INHERIT_ONLY == 0 && a.mask & WRITE_RIGHTS != 0 && a.who == Who::Other)
}

/// The records of this PC, in `HKLM\SOFTWARE\VibePath` (the helper's process, elevated).
#[cfg(windows)]
pub mod sys {
    use super::*;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, LocalFree};
    use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Registry::*;

    pub struct Hklm;

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: opened below, closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn words(code: u32) -> String {
        format!("HKLM\\{KEY}: {}", crate::host::code_words(code))
    }

    /// The key, made with its own security when it is not there yet.
    fn create() -> Result<Key, String> {
        create_at(HKEY_LOCAL_MACHINE, KEY)
    }

    /// The key to read: None when it is not there.
    fn open() -> Result<Option<Key>, String> {
        open_at(HKEY_LOCAL_MACHINE, KEY)
    }

    /// `create` under any root (the tests use a throwaway key of HKCU's, never HKLM).
    fn create_at(root: HKEY, sub: &str) -> Result<Key, String> {
        let sddl = crate::host::wide("O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)");
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SDDL string; the descriptor is freed below.
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut psd, std::ptr::null_mut()) } == 0 {
            return Err(format!("HKLM\\{KEY}: its access rules could not be made"));
        }
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: psd, bInheritHandle: 0 };
        let name = crate::host::wide(sub);
        let mut hk: HKEY = std::ptr::null_mut();
        let mut disp = 0u32;
        // SAFETY: a NUL-terminated name, attributes that live through the call.
        let r = unsafe { RegCreateKeyExW(root, name.as_ptr(), 0, std::ptr::null(), REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &sa, &mut hk, &mut disp) };
        // SAFETY: made by the conversion above.
        unsafe { LocalFree(psd) };
        if r != 0 {
            return Err(words(r));
        }
        let k = Key(hk);
        trusted(&k)?;
        Ok(k)
    }

    /// `open` under any root (as `create_at`).
    fn open_at(root: HKEY, sub: &str) -> Result<Option<Key>, String> {
        let name = crate::host::wide(sub);
        let mut hk: HKEY = std::ptr::null_mut();
        // SAFETY: a NUL-terminated name.
        let r = unsafe { RegOpenKeyExW(root, name.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut hk) };
        if r == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if r != 0 {
            return Err(words(r));
        }
        let k = Key(hk);
        trusted(&k)?;
        Ok(Some(k))
    }

    fn who(sid: PSID) -> Who {
        // SAFETY: a SID inside a descriptor we hold.
        unsafe {
            if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
                Who::System
            } else if IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 {
                Who::Admins
            } else {
                Who::Other
            }
        }
    }

    /// The key's owner and DACL, judged by `admin_only`.
    fn trusted(k: &Key) -> Result<(), String> {
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut need = 0u32;
        // SAFETY: a size query.
        let r = unsafe { RegGetKeySecurity(k.0, info, std::ptr::null_mut(), &mut need) };
        if r != ERROR_INSUFFICIENT_BUFFER || need == 0 {
            return Err(words(r));
        }
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        let psd: PSECURITY_DESCRIPTOR = buf.as_mut_ptr().cast();
        // SAFETY: a buffer of `need` bytes.
        let r = unsafe { RegGetKeySecurity(k.0, info, psd, &mut need) };
        if r != 0 {
            return Err(words(r));
        }
        judge(psd)
    }

    /// A security descriptor's owner and DACL, judged by `admin_only` (the tests feed it
    /// descriptors made from SDDL: RPS-7).
    fn judge(psd: PSECURITY_DESCRIPTOR) -> Result<(), String> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut dflt = 0;
        let mut present = 0;
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: the descriptor read above; the pointers point into it.
        let ok = unsafe { GetSecurityDescriptorOwner(psd, &mut owner, &mut dflt) != 0 && GetSecurityDescriptorDacl(psd, &mut present, &mut acl, &mut dflt) != 0 };
        if !ok || owner.is_null() {
            return Err(format!("HKLM\\{KEY}: its owner could not be read"));
        }
        let owner = who(owner);
        let dacl = if present == 0 || acl.is_null() {
            None
        } else {
            let mut aces = Vec::new();
            // SAFETY: a DACL inside the descriptor; each ACE read through GetAce.
            unsafe {
                for i in 0..u32::from((*acl).AceCount) {
                    let mut p: *mut core::ffi::c_void = std::ptr::null_mut();
                    if GetAce(acl, i, &mut p) == 0 || p.is_null() {
                        return Err(format!("HKLM\\{KEY}: its access rules could not be read"));
                    }
                    let h = &*(p as *const ACE_HEADER);
                    // Allow and deny ACEs (and their callback forms) have the mask at 4 and the
                    // SID at 8; anything else is judged as someone else's.
                    let mask = std::ptr::read_unaligned((p as *const u8).add(4).cast::<u32>());
                    let who = if matches!(h.AceType, 0 | 1) { who((p as *mut u8).add(8).cast()) } else { Who::Other };
                    aces.push(Ace { kind: h.AceType, flags: h.AceFlags, mask, who });
                }
            }
            Some(aces)
        };
        if admin_only(owner, dacl.as_deref()) { Ok(()) } else { Err(format!("HKLM\\{KEY} can be changed by more than administrators")) }
    }

    fn value_name(id: &Id) -> W {
        crate::host::wide(&hex(id))
    }

    /// A value's bytes (None: not there).
    fn read_value(k: &Key, name: &[u16]) -> Result<Option<Vec<u8>>, String> {
        let mut ty = 0u32;
        let mut n = 0u32;
        // SAFETY: a size query of a NUL-terminated name.
        let r = unsafe { RegQueryValueExW(k.0, name.as_ptr(), std::ptr::null(), &mut ty, std::ptr::null_mut(), &mut n) };
        if r == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if r != 0 {
            return Err(words(r));
        }
        if ty != REG_BINARY {
            return Err(format!("HKLM\\{KEY}: a record that is not one"));
        }
        let mut b = vec![0u8; n as usize];
        // SAFETY: a buffer of `n` bytes.
        let r = unsafe { RegQueryValueExW(k.0, name.as_ptr(), std::ptr::null(), &mut ty, b.as_mut_ptr(), &mut n) };
        if r != 0 {
            return Err(words(r));
        }
        b.truncate(n as usize);
        Ok(Some(b))
    }

    /// The oldest records past `KEEP` go (only values that are records: anything else stays),
    /// never `keep`, the one just written (`doomed`).
    fn prune(k: &Key, keep: &[u16]) {
        let (mut count, mut max_name, mut max_data) = (0u32, 0u32, 0u32);
        // SAFETY: counts and sizes only.
        let r = unsafe { RegQueryInfoKeyW(k.0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut count, &mut max_name, &mut max_data, std::ptr::null_mut(), std::ptr::null_mut()) };
        if r != 0 || (count as usize) <= KEEP {
            return;
        }
        let mut found: Vec<(u64, W)> = Vec::new();
        let mut name = vec![0u16; max_name as usize + 1];
        let mut data = vec![0u8; max_data as usize];
        for i in 0..count {
            let mut nl = name.len() as u32;
            let mut dl = data.len() as u32;
            let mut ty = 0u32;
            // SAFETY: buffers of the sizes the key reported.
            let r = unsafe { RegEnumValueW(k.0, i, name.as_mut_ptr(), &mut nl, std::ptr::null(), &mut ty, data.as_mut_ptr(), &mut dl) };
            if r != 0 {
                break;
            }
            let n = name[..nl as usize].to_vec();
            if ty == REG_BINARY && parse_hex(&String::from_utf16_lossy(&n)).is_some()
                && let Some(rec) = decode(&data[..dl as usize])
            {
                found.push((rec.at_ms, n));
            }
        }
        for n in doomed(found, keep) {
            let z = crate::wide::z(&n);
            // SAFETY: a NUL-terminated name.
            unsafe { RegDeleteValueW(k.0, z.as_ptr()) };
        }
    }

    impl Records for Hklm {
        fn new_id(&self) -> Option<Id> {
            crate::helper::random_id()
        }

        fn put(&self, id: &Id, before: Option<&env::Value>, after: &[u16], wrote: Kind) -> Result<(), String> {
            let k = create()?;
            let name = value_name(id);
            if read_value(&k, &name)?.is_some() {
                return Err(format!("HKLM\\{KEY}: the record {} is there already", hex(id)));
            }
            let at_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
            let b = encode(&Record { at_ms, before: before.cloned(), after: after.to_vec(), wrote });
            // SAFETY: a NUL-terminated name and `b`'s bytes.
            let r = unsafe { RegSetValueExW(k.0, name.as_ptr(), 0, REG_BINARY, b.as_ptr(), b.len() as u32) };
            if r != 0 {
                return Err(words(r));
            }
            prune(&k, &crate::wide::w(&hex(id)));
            Ok(())
        }

        fn get(&self, id: &Id) -> Result<Option<Record>, String> {
            let Some(k) = open()? else { return Ok(None) };
            match read_value(&k, &value_name(id))? {
                None => Ok(None),
                Some(b) => decode(&b).map(Some).ok_or_else(|| format!("HKLM\\{KEY}: the record {} is garbled", hex(id))),
            }
        }
    }

}
