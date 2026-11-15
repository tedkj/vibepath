//! UTF-16 text as Windows hands it over. PATH entries, file names and the command typed are kept
//! as their exact units (a lone surrogate included: never through a lossy string, VibeRename
//! RR-7); only what is shown goes through `lossy` and `text::clean`.

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

/// Exact UTF-16 units, no terminating NUL.
pub type W = Vec<u16>;

pub fn w(s: &str) -> W {
    s.encode_utf16().collect()
}

pub fn of_os(s: &OsStr) -> W {
    s.encode_wide().collect()
}

pub fn os(units: &[u16]) -> OsString {
    OsString::from_wide(units)
}

pub fn path(units: &[u16]) -> std::path::PathBuf {
    std::path::PathBuf::from(os(units))
}

/// NUL-terminated, for a call.
pub fn z(units: &[u16]) -> W {
    let mut v = units.to_vec();
    v.push(0);
    v
}

/// For display only: a lone surrogate becomes U+FFFD.
pub fn lossy(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

/// Shown text: lossy, then cleaned (controls, bidi and zero-width characters gone).
pub fn shown(units: &[u16], max: usize) -> String {
    crate::text::clean_wide(units, max)
}

pub const BACKSLASH: u16 = b'\\' as u16;
pub const SLASH: u16 = b'/' as u16;
pub const DOT: u16 = b'.' as u16;
pub const COLON: u16 = b':' as u16;
pub const SEMI: u16 = b';' as u16;
pub const QUOTE: u16 = b'"' as u16;
pub const SPACE: u16 = b' ' as u16;
pub const PERCENT: u16 = b'%' as u16;

fn upper_ascii(u: u16) -> u16 {
    if (b'a' as u16..=b'z' as u16).contains(&u) { u - 32 } else { u }
}

/// Equal ignoring case the way the file system compares names: `CompareStringOrdinal` with
/// ignore-case (simple uppercase mapping, no locale). ASCII-only units take a fast path.
pub fn eq_ic(a: &[u16], b: &[u16]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if a.iter().chain(b).all(|&u| u < 0x80) {
        return a.iter().zip(b).all(|(&x, &y)| upper_ascii(x) == upper_ascii(y));
    }
    compare_ordinal_ic(a, b)
}

#[cfg(windows)]
fn compare_ordinal_ic(a: &[u16], b: &[u16]) -> bool {
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
    if a.len() > i32::MAX as usize || b.len() > i32::MAX as usize {
        return false;
    }
    // SAFETY: two buffers and their lengths in units.
    unsafe { CompareStringOrdinal(a.as_ptr(), a.len() as i32, b.as_ptr(), b.len() as i32, 1) == CSTR_EQUAL }
}

/// The last component's extension, with its dot (`.EXE`), when the last component has one.
/// A leading dot alone (`.gitignore`) counts as an extension, as Windows' own search does.
pub fn extension(name: &[u16]) -> Option<&[u16]> {
    let last = file_name(name);
    let dot = last.iter().rposition(|&u| u == DOT)?;
    Some(&last[dot..])
}

/// The last component (after the last `\`, `/` or a drive's `:`).
pub fn file_name(p: &[u16]) -> &[u16] {
    match p.iter().rposition(|&u| u == BACKSLASH || u == SLASH || u == COLON) {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

/// `dir\name`, one backslash between them.
pub fn join(dir: &[u16], name: &[u16]) -> W {
    let mut out = dir.to_vec();
    if !out.is_empty() && !matches!(out.last(), Some(&BACKSLASH) | Some(&SLASH)) {
        out.push(BACKSLASH);
    }
    out.extend_from_slice(name);
    out
}

/// The folder part of a path (without its trailing separator, a drive root keeps its `\`).
pub fn parent(p: &[u16]) -> W {
    match p.iter().rposition(|&u| u == BACKSLASH || u == SLASH) {
        Some(0) => p[..1].to_vec(),
        Some(i) if i == 2 && p.get(1) == Some(&COLON) => p[..3].to_vec(),
        Some(i) => p[..i].to_vec(),
        None => W::new(),
    }
}

pub fn contains(hay: &[u16], needle: &[u16]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|x| eq_ic(x, needle))
}

pub fn starts_with_ic(hay: &[u16], prefix: &[u16]) -> bool {
    hay.len() >= prefix.len() && eq_ic(&hay[..prefix.len()], prefix)
}

pub fn ends_with_ic(hay: &[u16], suffix: &[u16]) -> bool {
    hay.len() >= suffix.len() && eq_ic(&hay[hay.len() - suffix.len()..], suffix)
}

/// Split on `;`, keeping empty pieces (the caller decides what they mean).
pub fn split_semi(v: &[u16]) -> Vec<W> {
    v.split(|&u| u == SEMI).map(<[u16]>::to_vec).collect()
}

/// A total order for sorting names shown to the user: ASCII-uppercased units, then the units
/// themselves (never a locale compare: VibeRename RR-1).
pub fn sort_key(units: &[u16]) -> (Vec<u16>, Vec<u16>) {
    (units.iter().map(|&u| upper_ascii(u)).collect(), units.to_vec())
}
