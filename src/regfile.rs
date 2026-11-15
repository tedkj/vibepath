//! Export .reg (SPEC section 6): a PATH version as a file regedit imports. UTF-16 LE with a
//! BOM, `Windows Registry Editor Version 5.00`, the hive's key, and the value: `hex(2):` bytes
//! for REG_EXPAND_SZ (with its terminating NUL, wrapped the way regedit wraps), a quoted string
//! for REG_SZ. A REG_SZ holding a control character (a CR or LF above all) goes as `hex(1):`
//! bytes the same way (IN-VibePath-1): quoted, a line break would end the line in the file, and
//! a merge of the copy (regedit, elevated) would read what follows it as lines of its own, a
//! key of HKLM included.

use crate::env::{Hive, Kind, Value};

fn escape(units: &[u16]) -> Vec<u16> {
    let mut out = Vec::with_capacity(units.len());
    for &u in units {
        if u == b'\\' as u16 || u == b'"' as u16 {
            out.push(b'\\' as u16);
        }
        out.push(u);
    }
    out
}

/// A unit a quoted `.reg` string cannot hold as it is: C0 and C1 controls and DEL. A CR or LF
/// would end the line; the others are not text a value should carry quoted.
fn control(u: u16) -> bool {
    u < 0x20 || (0x7F..=0x9F).contains(&u)
}

/// The `"Path"=hex(2):…` line(s), as text: bytes as two hex digits, comma-separated, a line
/// break (`\` then two spaces) before a line would pass 80 characters.
fn hex_lines(prefix: &str, bytes: &[u8]) -> String {
    let mut out = String::from(prefix);
    let mut col = prefix.len();
    for (i, b) in bytes.iter().enumerate() {
        let item = if i + 1 < bytes.len() { format!("{b:02x},") } else { format!("{b:02x}") };
        if col + item.len() > 77 && i + 1 < bytes.len() {
            out.push_str("\\\r\n  ");
            col = 2;
        }
        out.push_str(&item);
        col += item.len();
    }
    out
}

/// The .reg file's bytes for `value` as the hive's Path.
pub fn export(hive: Hive, value: &Value) -> Vec<u8> {
    let mut text: Vec<u16> = Vec::new();
    let push = |t: &mut Vec<u16>, s: &str| t.extend(s.encode_utf16());
    push(&mut text, "Windows Registry Editor Version 5.00\r\n\r\n[");
    push(&mut text, hive.key());
    push(&mut text, "]\r\n");
    match value.kind {
        Kind::Sz if !value.raw.iter().any(|&u| control(u)) => {
            push(&mut text, "\"Path\"=\"");
            text.extend(escape(&value.raw));
            push(&mut text, "\"\r\n");
        }
        kind => {
            let mut bytes: Vec<u8> = value.raw.iter().flat_map(|u| u.to_le_bytes()).collect();
            bytes.extend([0, 0]);
            let tag = match kind {
                Kind::ExpandSz => "hex(2)".to_string(),
                Kind::Sz => "hex(1)".to_string(),
                k => format!("hex({:x})", k.code()),
            };
            push(&mut text, &hex_lines(&format!("\"Path\"={tag}:"), &bytes));
            push(&mut text, "\r\n");
        }
    }
    push(&mut text, "\r\n");
    let mut out = vec![0xFF, 0xFE];
    out.extend(text.iter().flat_map(|u| u.to_le_bytes()));
    out
}

/// A whole export as `export` writes it (RPS-4): the BOM and header, a `"Path"=` line, and the
/// blank line it ends with. A copy cut short anywhere fails this: only the end has two line
/// breaks in a row after the value.
pub fn whole(bytes: &[u8]) -> bool {
    let units = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect() };
    let mut head = vec![0xFF, 0xFE];
    head.extend(units("Windows Registry Editor Version 5.00\r\n\r\n["));
    let path = units("]\r\n\"Path\"=");
    bytes.len().is_multiple_of(2) && bytes.starts_with(&head) && bytes.windows(path.len()).any(|w| w == path.as_slice()) && bytes.ends_with(&units("\r\n\r\n"))
}

/// A copy `export` began and did not finish (RL-2): a start of its header, or the header and no
/// blank line after it (an export's only one there is its last line). Or a copy with a NUL text
/// unit anywhere (RL2-1, RL3-1): no `.reg` text holds U+0000 (a value is read up to its first
/// NUL, and UTF-8 text has no NUL byte at all), so it is data a power cut lost, wherever: the
/// size on disk and not the data (all NULs), the end lost, or the start or a middle lost (pages
/// flushed out of order). A copy saved again by another tool or edited (UTF-8, LF line breaks, a
/// line added, the BOM dropped) is not this: it is left alone.
pub fn cut_short(bytes: &[u8]) -> bool {
    // Whole UTF-16 units from the file's first byte, so the BOM, when there, is unit 0 and a
    // copy without one keeps its alignment. Only aligned units: an odd pair `00 00` is the high
    // byte of one character and the low byte of the next (U+4E00 after an ASCII letter).
    // A power cut loses whole sectors, so a loss always holds aligned NUL units.
    if bytes.as_chunks::<2>().0.contains(&[0, 0]) {
        return true;
    }
    let units = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect() };
    let mut head = vec![0xFF, 0xFE];
    head.extend(units("Windows Registry Editor Version 5.00\r\n\r\n["));
    let blank = units("\r\n\r\n");
    head.starts_with(bytes) || (bytes.starts_with(&head) && !bytes[head.len()..].windows(blank.len()).any(|w| w == blank.as_slice()))
}
