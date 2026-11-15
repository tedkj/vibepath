//! The one way in for a command (SPEC section 1): Enter, Resolve and the command line all go
//! through `command`. And the one way in for a folder added to PATH (section 6): `folder`.

use crate::wide::{QUOTE, W, w};

/// What was typed, as the resolver takes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// A name to search for (`python`, `python.exe`).
    Name(W),
    /// A path (it has `\`, `/` or a drive's `:`): no search, resolved against the current folder.
    Path(W),
}

impl Command {
    pub fn units(&self) -> &[u16] {
        match self {
            Command::Name(n) | Command::Path(n) => n,
        }
    }
}

/// The normaliser's answer: the command (or nothing to look up), and a note to show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parsed {
    pub command: Option<Command>,
    /// "Only the first word is looked up." / "Not a command name." / "".
    pub note: String,
}

pub const FIRST_WORD: &str = "Only the first word is looked up.";
pub const NOT_A_NAME: &str = "Not a command name.";

pub(crate) fn is_space(u: u16) -> bool {
    u == 0x20 || u == 0x09 || u == 0x3000 || u == 0xA0
}

fn trim(v: &[u16]) -> &[u16] {
    let start = v.iter().position(|&u| !is_space(u)).unwrap_or(v.len());
    let end = v.iter().rposition(|&u| !is_space(u)).map_or(start, |i| i + 1);
    &v[start..end]
}

/// Trim; strip one pair of surrounding quotes; text with whitespace outside quotes keeps its
/// first word (a quoted first word keeps its spaces); `* ? < > |`, a quote left inside, and
/// control characters are "Not a command name."; a name with `\`, `/` or `:` is a path.
pub fn command(typed: &[u16]) -> Parsed {
    let t = trim(typed);
    if t.is_empty() {
        return Parsed { command: None, note: String::new() };
    }
    // The first word: up to whitespace outside quotes.
    let mut quoted = false;
    let mut end = t.len();
    for (i, &u) in t.iter().enumerate() {
        if u == QUOTE {
            quoted = !quoted;
        } else if is_space(u) && !quoted {
            end = i;
            break;
        }
    }
    let first = &t[..end];
    let rest = trim(&t[end..]);
    let note = if rest.is_empty() { String::new() } else { FIRST_WORD.to_string() };
    // One pair of surrogate-free quotes around it (or around its start: `"C:\a b\x.exe"`).
    let name: W = if first.len() >= 2 && first[0] == QUOTE && first[first.len() - 1] == QUOTE {
        first[1..first.len() - 1].to_vec()
    } else {
        first.to_vec()
    };
    let name = trim(&name).to_vec();
    let bad = |u: u16| u < 0x20 || u == 0x7F || matches!(u, 0x2A | 0x3F | 0x3C | 0x3E | 0x7C | 0x22) || (0x80..0xA0).contains(&u);
    if name.is_empty() || name.iter().any(|&u| bad(u)) {
        return Parsed { command: None, note: NOT_A_NAME.to_string() };
    }
    let is_path = name.iter().any(|&u| u == b'\\' as u16 || u == b'/' as u16 || u == b':' as u16);
    Parsed { command: Some(if is_path { Command::Path(name) } else { Command::Name(name) }), note }
}

/// Why a folder cannot be added to PATH, or the entry to add (SPEC section 6, Add...): quotes
/// stripped, a file means its folder (`is_file` asks), a `;` refused (it would split the entry),
/// control characters refused. Kept as typed otherwise (`%VARS%` stay).
pub fn folder(typed: &[u16], is_file: &dyn Fn(&[u16]) -> bool) -> Result<W, String> {
    let t = trim(typed);
    let t: W = if t.len() >= 2 && t[0] == QUOTE && t[t.len() - 1] == QUOTE { t[1..t.len() - 1].to_vec() } else { t.to_vec() };
    let t = trim(&t).to_vec();
    if t.is_empty() {
        return Err("Type a folder or pick one.".into());
    }
    if t.contains(&crate::wide::SEMI) {
        return Err("A folder name cannot hold ';': PATH would split it in two.".into());
    }
    if t.iter().any(|&u| u == QUOTE || crate::helper::bad_char(u)) {
        return Err("Not a folder name.".into());
    }
    if is_file(&t) {
        let p = crate::wide::parent(&t);
        if p.is_empty() {
            return Err("Not a folder name.".into());
        }
        return Ok(p);
    }
    Ok(t)
}

/// The units of what was typed into a field.
pub fn units(s: &str) -> W {
    w(s)
}
