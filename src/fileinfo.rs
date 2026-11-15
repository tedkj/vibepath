//! What a match is (SPEC section 3): its kind, and for a program the architecture from its PE
//! header (the first 4 KiB), its version strings, size and time, a Scoop shim's target, a batch
//! file's first real line. The parsing is pure; `sys` reads, on a worker, never the UI thread.

use crate::wide::{self, w};

/// The kind of a match, by its extension (and its reparse point).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Program,
    Batch,
    PsScript,
    Shortcut,
    /// Opened with its association.
    Other,
    Alias,
}

impl Kind {
    pub fn word(&self) -> &'static str {
        match self {
            Kind::Program => "program",
            Kind::Batch => "batch file",
            Kind::PsScript => "PowerShell script",
            Kind::Shortcut => "shortcut",
            Kind::Other => "other",
            Kind::Alias => "App Execution Alias",
        }
    }
}

pub fn kind_of(path: &[u16], alias: bool) -> Kind {
    if alias {
        return Kind::Alias;
    }
    let ext = wide::extension(path).map(|e| wide::lossy(e).to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        ".exe" | ".com" | ".scr" => Kind::Program,
        ".bat" | ".cmd" => Kind::Batch,
        ".ps1" => Kind::PsScript,
        ".lnk" | ".pif" => Kind::Shortcut,
        _ => Kind::Other,
    }
}

/// The machine a PE file is built for, from its first bytes: "x64", "x86", "ARM64", "ARM64X"…
/// None: not a PE file (or cut short).
pub fn pe_arch(head: &[u8]) -> Option<&'static str> {
    if head.len() < 0x40 || &head[..2] != b"MZ" {
        return None;
    }
    let pe = u32::from_le_bytes(head[0x3C..0x40].try_into().ok()?) as usize;
    let sig = head.get(pe..pe.checked_add(6)?)?;
    if &sig[..4] != b"PE\0\0" {
        return None;
    }
    let machine = u16::from_le_bytes([sig[4], sig[5]]);
    Some(match machine {
        0x8664 => "x64",
        0x014C => "x86",
        0xAA64 => "ARM64",
        0xA641 => "ARM64EC",
        0xA64E => "ARM64X",
        0x01C4 => "ARM",
        0x0200 => "Itanium",
        _ => "another architecture",
    })
}

/// A Scoop shim's target: the `path = …` line of `<name>.shim` (quotes stripped).
pub fn shim_target(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        if !k.trim().eq_ignore_ascii_case("path") {
            return None;
        }
        let v = v.trim().trim_matches('"').trim();
        (!v.is_empty()).then(|| crate::text::clean_max(v, 260))
    })
}

/// A batch file's first line that says something: not empty, not `@echo off`, not a `rem` or
/// `::` comment. At most 200 characters, cleaned.
pub fn first_line(text: &str) -> Option<String> {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    text.lines().find_map(|l| {
        let t = l.trim();
        let low = t.to_ascii_lowercase();
        let bare = low.trim_start_matches('@').trim();
        if t.is_empty() || bare == "echo off" || bare.starts_with("echo off ") || bare == "rem" || bare.starts_with("rem ") || bare.starts_with("rem\t") || t.starts_with("::") {
            return None;
        }
        let s = crate::text::clean_max(t, 200);
        (!s.is_empty()).then_some(s)
    })
}

/// A file's identity for the session's cache: volume serial, 128-bit id, size and modified time.
pub type CacheKey = (u64, [u8; 16], u64, u64);

/// What the detail panel shows for a file match.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Details {
    pub arch: Option<String>,
    pub file_version: String,
    pub product: String,
    pub company: String,
    pub size: Option<u64>,
    /// FILETIME (100 ns since 1601), when it could be read.
    pub modified: Option<u64>,
    /// The signature in words ("Signed by Microsoft Windows", "not signed", "unknown: …").
    pub signer: String,
    /// The verdict's state: 1 good, 3 warning, 4 bad, 5 unknown, 2 quiet (not signable).
    pub signer_state: i32,
    pub shim: Option<String>,
    pub first_line: Option<String>,
    /// "runs through C:\Windows\py.exe" for a file opened by association.
    pub runs_through: Option<String>,
    /// The file could not be read (the version and signature are unknown): why.
    pub unread: Option<String>,
    pub key: Option<CacheKey>,
}

/// Version strings read from a file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Version {
    pub file_version: String,
    pub product: String,
    pub company: String,
}

/// The `want` bytes VerQueryValueW points at, cut to the part inside the version block `data`
/// (IN-VibePath-2): the pointer and length come from the file's own resource, so a damaged one
/// can name more than the block holds, or a place outside it. Nothing outside it: empty.
pub fn within(data: &[u8], at: usize, want: usize) -> &[u8] {
    let base = data.as_ptr() as usize;
    match at.checked_sub(base) {
        Some(off) if off < data.len() => &data[off..off + want.min(data.len() - off)],
        _ => &[],
    }
}

#[cfg(windows)]
pub mod sys {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;

    /// Errors that say a name is not there.
    pub fn not_there(code: u32) -> bool {
        matches!(code, 2 | 3 | 123 | 161 | 206 | 267)
    }

    fn open_shared(path: &[u16]) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new().read(true).share_mode(7).open(wide::path(path))
    }

    /// Volume serial and 128-bit id of an open file (zero when it has none).
    pub fn file_id(f: &std::fs::File) -> Option<(u64, [u8; 16])> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, FILE_ID_INFO, FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx};
        // SAFETY: plain structs filled by the calls, sizes given; the handle is the file's.
        unsafe {
            let mut info: FILE_ID_INFO = std::mem::zeroed();
            if GetFileInformationByHandleEx(f.as_raw_handle(), FileIdInfo, (&mut info as *mut FILE_ID_INFO).cast(), size_of::<FILE_ID_INFO>() as u32) != 0 {
                return Some((info.VolumeSerialNumber, info.FileId.Identifier));
            }
            let mut bh: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
            if GetFileInformationByHandle(f.as_raw_handle(), &mut bh) != 0 {
                let mut id = [0u8; 16];
                id[..8].copy_from_slice(&((u64::from(bh.nFileIndexHigh) << 32) | u64::from(bh.nFileIndexLow)).to_le_bytes());
                return Some((u64::from(bh.dwVolumeSerialNumber), id));
            }
        }
        None
    }

    /// The cache key of the file at `path` (identity plus size and time); None when it cannot
    /// be opened.
    pub fn cache_key(path: &[u16]) -> Option<CacheKey> {
        let f = open_shared(path).ok()?;
        let m = f.metadata().ok()?;
        let (vol, id) = file_id(&f)?;
        use std::os::windows::fs::MetadataExt;
        Some((vol, id, m.file_size(), m.last_write_time()))
    }

    /// The version strings in the file's own first language (US English as a fallback).
    /// Ok(None): it has none. Err: it could not be read now.
    pub fn version(path: &[u16]) -> Result<Option<Version>, String> {
        use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
        let z = wide::z(path);
        let no_version = |code: u32| not_there(code) || matches!(code, 11 | 193 | 1812 | 1813 | 1814 | 1815);
        // SAFETY: a NUL-terminated path; a buffer of the size asked.
        unsafe {
            let mut zero = 0u32;
            let size = GetFileVersionInfoSizeW(z.as_ptr(), &mut zero);
            if size == 0 {
                let e = windows_sys::Win32::Foundation::GetLastError();
                return if no_version(e) { Ok(None) } else { Err(crate::host::code_words(e)) };
            }
            if size > 4 * 1024 * 1024 {
                return Ok(None);
            }
            let mut data = vec![0u8; size as usize];
            if GetFileVersionInfoW(z.as_ptr(), 0, size, data.as_mut_ptr().cast()) == 0 {
                let e = windows_sys::Win32::Foundation::GetLastError();
                return if no_version(e) { Ok(None) } else { Err(crate::host::code_words(e)) };
            }
            // The value's address and its length (bytes for Translation, characters for a
            // string): read only through `within`, never past the block.
            let query = |sub: &str| -> Option<(usize, u32)> {
                let s = wide::z(&w(sub));
                let mut p: *mut core::ffi::c_void = std::ptr::null_mut();
                let mut len = 0u32;
                (VerQueryValueW(data.as_ptr().cast(), s.as_ptr(), &mut p, &mut len) != 0 && !p.is_null()).then_some((p as usize, len))
            };
            let mut langs: Vec<String> = Vec::new();
            if let Some((p, len)) = query("\\VarFileInfo\\Translation") {
                for c in super::within(&data, p, (len as usize / 4).min(4) * 4).as_chunks::<4>().0 {
                    let (lang, cp) = (u16::from_le_bytes([c[0], c[1]]), u16::from_le_bytes([c[2], c[3]]));
                    langs.push(format!("{lang:04x}{cp:04x}"));
                }
            }
            langs.extend(["040904b0".to_string(), "040904e4".to_string(), "000004b0".to_string()]);
            let text = |key: &str| -> String {
                for l in &langs {
                    if let Some((p, len)) = query(&format!("\\StringFileInfo\\{l}\\{key}")) {
                        let n = (len as usize).min(512);
                        let units: Vec<u16> = super::within(&data, p, n * 2).as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|&c| c != 0).collect();
                        return crate::text::clean_wide(&units, 120);
                    }
                }
                String::new()
            };
            let v = Version { file_version: text("FileVersion"), product: text("ProductName"), company: text("CompanyName") };
            Ok((v != Version::default()).then_some(v))
        }
    }

    /// The program a file's extension is opened with (`AssocQueryStringW`, ASSOCSTR_EXECUTABLE).
    pub fn association(path: &[u16]) -> Option<String> {
        use windows_sys::Win32::UI::Shell::{ASSOCF_INIT_IGNOREUNKNOWN, ASSOCF_NOTRUNCATE, ASSOCSTR_EXECUTABLE, AssocQueryStringW};
        let ext = wide::extension(path)?;
        let e = wide::z(ext);
        let verb = wide::z(&w("open"));
        let mut buf = vec![0u16; 1024];
        let mut n = buf.len() as u32;
        // SAFETY: NUL-terminated inputs, a buffer and its length in units.
        let r = unsafe { AssocQueryStringW(ASSOCF_INIT_IGNOREUNKNOWN | ASSOCF_NOTRUNCATE, ASSOCSTR_EXECUTABLE, e.as_ptr(), verb.as_ptr(), buf.as_mut_ptr(), &mut n) };
        if r != 0 || n < 2 {
            return None;
        }
        let s = wide::shown(&buf[..(n as usize - 1).min(buf.len())], 260);
        (!s.is_empty()).then_some(s)
    }

    /// Everything the detail panel shows for the file at `path`. For an alias, `read_from` is
    /// its target (version and signer come from there; WindowsApps may refuse: unknown).
    pub fn details(path: &[u16], read_from: &[u16]) -> Details {
        use std::io::Read;
        let mut d = Details::default();
        let kind = kind_of(path, false);
        match open_shared(read_from) {
            Ok(f) => {
                if let Ok(m) = f.metadata() {
                    use std::os::windows::fs::MetadataExt;
                    d.size = Some(m.file_size());
                    d.modified = Some(m.last_write_time());
                    if let Some((vol, id)) = file_id(&f) {
                        d.key = Some((vol, id, m.file_size(), m.last_write_time()));
                    }
                }
                let mut head = vec![0u8; 4096];
                let mut f2 = &f;
                let n = f2.read(&mut head).unwrap_or(0);
                head.truncate(n);
                d.arch = pe_arch(&head).map(str::to_string);
                if matches!(kind_of(read_from, false), Kind::Batch) || matches!(kind, Kind::Batch) {
                    d.first_line = first_line(&String::from_utf8_lossy(&head));
                }
            }
            Err(e) => {
                d.unread = Some(match e.raw_os_error() {
                    Some(5) => "access denied".to_string(),
                    Some(c) => crate::host::code_words(c as u32),
                    None => e.to_string(),
                });
            }
        }
        if d.arch.is_some() {
            match version(read_from) {
                Ok(Some(v)) => {
                    d.file_version = v.file_version;
                    d.product = v.product;
                    d.company = v.company;
                }
                Ok(None) => {}
                Err(e) => {
                    if d.unread.is_none() {
                        d.unread = Some(e);
                    }
                }
            }
        }
        // A Scoop shim: `<name>.shim` beside it.
        if matches!(kind, Kind::Program) {
            let mut shim = path.to_vec();
            if let Some(e) = wide::extension(&shim) {
                let n = shim.len() - e.len();
                shim.truncate(n);
            }
            shim.extend(w(".shim"));
            if let Ok(mut f) = open_shared(&shim) {
                let mut b = vec![0u8; 4096];
                let n = f.read(&mut b).unwrap_or(0);
                d.shim = shim_target(&String::from_utf8_lossy(&b[..n]));
            }
        }
        if matches!(kind, Kind::Other | Kind::PsScript) {
            d.runs_through = association(path).map(|a| format!("runs through {a}"));
        }
        if d.unread.is_some() && d.size.is_none() {
            d.signer = format!("unknown: {}", d.unread.clone().unwrap_or_default());
            d.signer_state = 5;
        } else {
            let (words, state) = crate::authenticode::words(&crate::authenticode::check(&wide::path(read_from)));
            d.signer = words;
            d.signer_state = state;
        }
        d
    }
}
