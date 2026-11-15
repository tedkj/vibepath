//! Where PATH comes from (SPEC sections 1 and 5): the registry's raw values, the environment
//! Windows builds for a new program (`CreateEnvironmentBlock`), this app's own, expansion for
//! this user, and the one equality every compare uses. The parsing and the equality are pure;
//! the Windows calls are in `sys`.

use crate::wide::{self, BACKSLASH, COLON, DOT, QUOTE, SLASH, W, eq_ic, w};

/// A registry value's type as the PATH table shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Kind {
    Sz,
    ExpandSz,
    /// Another type (a broken value): its number.
    Other(u32),
}

impl Kind {
    pub fn word(self) -> String {
        match self {
            Kind::Sz => "REG_SZ".into(),
            Kind::ExpandSz => "REG_EXPAND_SZ".into(),
            Kind::Other(n) => format!("type {n}"),
        }
    }

    pub fn code(self) -> u32 {
        match self {
            Kind::Sz => 1,
            Kind::ExpandSz => 2,
            Kind::Other(n) => n,
        }
    }

    pub fn from_code(n: u32) -> Kind {
        match n {
            1 => Kind::Sz,
            2 => Kind::ExpandSz,
            n => Kind::Other(n),
        }
    }

    /// The type an Undo writes a value back as (FED1): its own when it was a string (REG_SZ or
    /// REG_EXPAND_SZ), else REG_EXPAND_SZ. Every other write is REG_EXPAND_SZ.
    pub fn restored(self) -> Kind {
        match self {
            Kind::Sz => Kind::Sz,
            _ => Kind::ExpandSz,
        }
    }
}

/// A registry value: its type and its text exactly as stored (no terminating NUL).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Value {
    pub kind: Kind,
    pub raw: W,
}

/// A read of one value: there, not there, or not readable now (unknown, never "missing").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read {
    Value(Value),
    Missing,
    Error(String),
}

impl Read {
    pub fn value(&self) -> Option<&Value> {
        match self {
            Read::Value(v) => Some(v),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Hive {
    Machine,
    User,
}

impl Hive {
    pub fn word(self) -> &'static str {
        match self {
            Hive::Machine => "Machine",
            Hive::User => "User",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Hive::Machine => r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            Hive::User => r"HKEY_CURRENT_USER\Environment",
        }
    }
}

/// An environment: its variables in block order (`=C:`-style entries left out).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Env {
    pub vars: Vec<(W, W)>,
}

impl Env {
    /// A variable by name, ignoring case (the first, as Windows takes it).
    pub fn get(&self, name: &str) -> Option<&W> {
        let n = w(name);
        self.vars.iter().find(|(k, _)| eq_ic(k, &n)).map(|(_, v)| v)
    }

    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
}

/// Why a block could not be read as one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// No empty string ends it: cut short, or changed while it was read.
    NoEnd,
}

/// `NAME=value\0...\0\0` as variables. Entries starting with `=` (`=C:=C:\x`, `=ExitCode`) and
/// entries without `=` are skipped. The block must end with an empty string within `units`.
pub fn parse_block(units: &[u16]) -> Result<Env, BlockError> {
    let mut vars = Vec::new();
    let mut at = 0usize;
    loop {
        let end = at + units.get(at..).ok_or(BlockError::NoEnd)?.iter().position(|&u| u == 0).ok_or(BlockError::NoEnd)?;
        let entry = &units[at..end];
        if entry.is_empty() {
            return Ok(Env { vars });
        }
        if entry[0] != b'=' as u16
            && let Some(eq) = entry.iter().position(|&u| u == b'=' as u16) {
                vars.push((entry[..eq].to_vec(), entry[eq + 1..].to_vec()));
            }
        at = end + 1;
    }
}

/// A PATH as its entries in order, empty ones skipped (the environment's view: as Windows and
/// the shells take it).
pub fn entries(path: &[u16]) -> Vec<W> {
    wide::split_semi(path).into_iter().filter(|e| !e.is_empty()).collect()
}

fn is_sep(u: u16) -> bool {
    u == BACKSLASH || u == SLASH
}

/// Section 5's equality, the textual part: surrounding quotes and spaces trimmed, `/` as `\`,
/// `.` and `..` collapsed, the trailing `\` dropped except on a drive root. Case is left for
/// `same` (it compares ignoring case).
pub fn norm(entry: &[u16]) -> W {
    let trim = |v: &[u16]| -> W {
        let s = v.iter().position(|&u| u != b' ' as u16).unwrap_or(v.len());
        let e = v.iter().rposition(|&u| u != b' ' as u16).map_or(s, |i| i + 1);
        v[s..e].to_vec()
    };
    let mut t = trim(entry);
    while t.len() >= 2 && t[0] == QUOTE && t[t.len() - 1] == QUOTE {
        t = trim(&t[1..t.len() - 1]);
    }
    if t.len() == 1 && t[0] == QUOTE {
        t.clear();
    }
    let t: W = t.iter().map(|&u| if u == SLASH { BACKSLASH } else { u }).collect();
    // The prefix that `..` never climbs: `C:\`, `C:`, `\\server\share\`, `\`.
    let (prefix, rest): (W, &[u16]) = if t.len() >= 2 && t[1] == COLON {
        if t.len() >= 3 && t[2] == BACKSLASH { (t[..3].to_vec(), &t[3..]) } else { (t[..2].to_vec(), &t[2..]) }
    } else if t.len() >= 2 && t[0] == BACKSLASH && t[1] == BACKSLASH {
        // \\server\share
        let mut n = 0;
        let mut end = t.len();
        for (i, &u) in t.iter().enumerate().skip(2) {
            if u == BACKSLASH {
                n += 1;
                if n == 2 {
                    end = i + 1;
                    break;
                }
            }
        }
        (t[..end].to_vec(), &t[end..])
    } else if !t.is_empty() && t[0] == BACKSLASH {
        (t[..1].to_vec(), &t[1..])
    } else {
        (W::new(), &t[..])
    };
    let rooted = prefix.last() == Some(&BACKSLASH);
    let mut parts: Vec<&[u16]> = Vec::new();
    for p in rest.split(|&u| is_sep(u)) {
        if p.is_empty() || p == [DOT] {
            continue;
        }
        if p == [DOT, DOT] {
            match parts.last() {
                Some(last) if *last != [DOT, DOT] => {
                    parts.pop();
                }
                _ if rooted => {}
                _ => parts.push(p),
            }
            continue;
        }
        parts.push(p);
    }
    let mut out = prefix;
    for (i, p) in parts.iter().enumerate() {
        if i > 0 || (!out.is_empty() && !matches!(out.last(), Some(&BACKSLASH) | Some(&COLON))) {
            out.push(BACKSLASH);
        }
        out.extend_from_slice(p);
    }
    // `C:\x\` → `C:\x`; `C:\` stays; a UNC share root loses its last `\`.
    if out.len() > 3 && out.last() == Some(&BACKSLASH) {
        out.pop();
    }
    if out.is_empty() && !t.is_empty() && parts.is_empty() && rest.contains(&DOT) {
        out.push(DOT);
    }
    out
}

/// Two expanded entries are the same text (section 5, before identity).
pub fn same(a: &[u16], b: &[u16]) -> bool {
    eq_ic(&norm(a), &norm(b))
}

/// Where an entry of a context's PATH came from: "Machine PATH #4", "User PATH #2", or, for one
/// the registry does not have now, "PATH #3 (not in the registry now)". `typed` is the entry as
/// the registry has it when that differs from the expanded one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Label {
    pub source: String,
    pub typed: Option<W>,
    pub hive: Option<Hive>,
    /// 1-based position in its hive.
    pub index: usize,
}

/// One registry entry: as typed, and expanded (what the environment holds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegEntry {
    pub typed: W,
    pub expanded: W,
}

/// Labels for a context's PATH entries. The registry's entries are matched in order first (a
/// New window PATH is Machine then User), then anywhere (another program's PATH in another
/// order), each registry entry used once.
pub fn labels(path: &[W], machine: &[RegEntry], user: &[RegEntry]) -> Vec<Label> {
    let all: Vec<(Hive, usize, &RegEntry)> = machine.iter().enumerate().map(|(i, e)| (Hive::Machine, i + 1, e)).chain(user.iter().enumerate().map(|(i, e)| (Hive::User, i + 1, e))).collect();
    let mut used = vec![false; all.len()];
    let mut next = 0usize;
    let mut out = Vec::with_capacity(path.len());
    for (k, e) in path.iter().enumerate() {
        let found = if next < all.len() && same(&all[next].2.expanded, e) {
            Some(next)
        } else {
            (0..all.len()).find(|&i| !used[i] && same(&all[i].2.expanded, e))
        };
        match found {
            Some(i) => {
                used[i] = true;
                next = i + 1;
                let (hive, n, r) = all[i];
                let typed = (r.typed != r.expanded).then(|| r.typed.clone());
                out.push(Label { source: format!("{} PATH #{n}", hive.word()), typed, hive: Some(hive), index: n });
            }
            None => out.push(Label { source: format!("PATH #{} (not in the registry now)", k + 1), typed: None, hive: None, index: k + 1 }),
        }
    }
    out
}

/// `%NAME%` left in an expanded entry: a variable Windows did not know.
pub fn unexpanded(expanded: &[u16]) -> Option<String> {
    let p = crate::wide::PERCENT;
    let first = expanded.iter().position(|&u| u == p)?;
    let second = first + 1 + expanded[first + 1..].iter().position(|&u| u == p)?;
    let name = &expanded[first + 1..second];
    (!name.is_empty() && !name.contains(&BACKSLASH)).then(|| format!("%{}%", wide::lossy(name)))
}

/// Whether a value's units hold text after the first NUL (a REG_MULTI_SZ, or any value with a
/// NUL inside): a read shows it up to there only (FED2). Trailing NULs are no text.
pub fn text_after_nul(units: &[u16]) -> bool {
    units.iter().position(|&u| u == 0).is_some_and(|i| units[i..].iter().any(|&u| u != 0))
}

#[cfg(windows)]
pub mod sys {
    use super::*;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, HANDLE};
    use windows_sys::Win32::System::Registry::*;

    fn hkey(h: Hive) -> HKEY {
        match h {
            Hive::Machine => HKEY_LOCAL_MACHINE,
            Hive::User => HKEY_CURRENT_USER,
        }
    }

    pub fn subkey(h: Hive) -> &'static str {
        match h {
            Hive::Machine => r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            Hive::User => "Environment",
        }
    }

    /// A value read raw (`RRF_NOEXPAND`): its type and text up to its first NUL.
    pub(crate) fn read_value(root: HKEY, key: &str, name: &str, wow64_64: bool) -> Read {
        match read_units(root, key, name, wow64_64) {
            Ok((kind, units)) => Read::Value(Value { kind: Kind::from_code(kind), raw: units.into_iter().take_while(|&u| u != 0).collect() }),
            Err(r) => r,
        }
    }

    /// Whether a hive's Path holds text after its first NUL (FED2: `read` shows it up to there).
    /// False when it cannot be read (the read itself says so).
    pub fn holds_more(h: Hive) -> bool {
        matches!(read_units(hkey(h), subkey(h), "Path", false), Ok((_, u)) if text_after_nul(&u))
    }

    /// A value's type and every unit it holds (its NULs too), or the `Read` that says why not.
    fn read_units(root: HKEY, key: &str, name: &str, wow64_64: bool) -> Result<(u32, W), Read> {
        let k = crate::wide::z(&w(key));
        let n = crate::wide::z(&w(name));
        let flags = RRF_RT_ANY | RRF_NOEXPAND | if wow64_64 { RRF_SUBKEY_WOW6464KEY } else { 0 };
        let mut size = 0u32;
        let mut kind = 0u32;
        for _ in 0..4 {
            // SAFETY: NUL-terminated names; a size query, then a buffer of that size.
            let r = unsafe { RegGetValueW(root, k.as_ptr(), n.as_ptr(), flags, &mut kind, std::ptr::null_mut(), &mut size) };
            if r == ERROR_FILE_NOT_FOUND || r == ERROR_PATH_NOT_FOUND {
                return Err(Read::Missing);
            }
            if r != 0 {
                return Err(Read::Error(crate::host::code_words(r)));
            }
            let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
            let mut got = (buf.len() * 2) as u32;
            let r = unsafe { RegGetValueW(root, k.as_ptr(), n.as_ptr(), flags, &mut kind, buf.as_mut_ptr().cast(), &mut got) };
            if r == ERROR_MORE_DATA {
                size = got.max(size + 64);
                continue;
            }
            if r == ERROR_FILE_NOT_FOUND {
                return Err(Read::Missing);
            }
            if r != 0 {
                return Err(Read::Error(crate::host::code_words(r)));
            }
            let units = (got as usize / 2).min(buf.len());
            buf.truncate(units);
            return Ok((kind, buf));
        }
        Err(Read::Error("the value kept changing while it was read".into()))
    }

    pub fn read(h: Hive, name: &str) -> Read {
        read_value(hkey(h), subkey(h), name, false)
    }

    /// Write `raw` to a hive's Path as `kind`: REG_EXPAND_SZ, or REG_SZ for an Undo of a value
    /// that was one (`Kind::restored`); any other type is refused (ERROR_INVALID_PARAMETER). The
    /// User hive from the app; the Machine hive only from the elevated helper. The Win32 code on
    /// failure.
    pub fn write_path(h: Hive, raw: &[u16], kind: Kind) -> Result<(), u32> {
        let ty = match kind {
            Kind::Sz => REG_SZ,
            Kind::ExpandSz => REG_EXPAND_SZ,
            Kind::Other(_) => return Err(windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER),
        };
        let k = crate::wide::z(&w(subkey(h)));
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: a NUL-terminated subkey; the key is closed below.
        let r = unsafe { RegOpenKeyExW(hkey(h), k.as_ptr(), 0, KEY_SET_VALUE, &mut key) };
        if r != 0 {
            return Err(r);
        }
        let data = crate::wide::z(raw);
        let name = crate::wide::z(&w("Path"));
        // SAFETY: the data with its NUL, its size in bytes.
        let r = unsafe { RegSetValueExW(key, name.as_ptr(), 0, ty, data.as_ptr().cast(), (data.len() * 2) as u32) };
        unsafe { RegCloseKey(key) };
        if r != 0 { Err(r) } else { Ok(()) }
    }

    /// This PC's MachineGuid (64-bit view), "" when it cannot be read.
    pub fn machine_guid() -> String {
        match read_value(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", "MachineGuid", true) {
            Read::Value(v) => crate::wide::lossy(&v.raw).chars().filter(|c| c.is_ascii_hexdigit() || *c == '-').collect(),
            _ => String::new(),
        }
    }

    pub struct Token(pub HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            // SAFETY: opened by `own_token`, closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    pub fn own_token() -> Option<Token> {
        // SAFETY: the pseudo handle of this process, never closed.
        token_of(unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() })
    }

    /// `process`'s token, for query, duplicate and impersonate.
    fn token_of(process: HANDLE) -> Option<Token> {
        use windows_sys::Win32::Security::{TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY};
        use windows_sys::Win32::System::Threading::OpenProcessToken;
        let mut t: HANDLE = std::ptr::null_mut();
        // SAFETY: a process handle the caller holds; the token is closed by `Token`.
        let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &mut t) } != 0;
        // A `Token` only for a token that opened: built eagerly on failure, its Drop would close
        // NULL, clobbering the last error (and breaking into an attached debugger) (FA9).
        if ok { Some(Token(t)) } else { None }
    }

    /// This user's SID as text ("S-1-5-21-…"), "" when it cannot be read.
    pub fn user_sid() -> String {
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_USER, TokenUser};
        let Some(t) = own_token() else { return String::new() };
        let mut need = 0u32;
        // SAFETY: a size query, then a buffer of that size.
        unsafe { GetTokenInformation(t.0, TokenUser, std::ptr::null_mut(), 0, &mut need) };
        let mut buf = vec![0u64; (need as usize).div_ceil(8).max(8)];
        if unsafe { GetTokenInformation(t.0, TokenUser, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need) } == 0 {
            return String::new();
        }
        // SAFETY: the buffer holds a TOKEN_USER.
        let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
        let mut s: windows_sys::core::PWSTR = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 || s.is_null() {
            return String::new();
        }
        // SAFETY: a NUL-terminated string from the call, freed below.
        let out = unsafe {
            let n = (0..256).take_while(|&i| *s.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(s, n))
        };
        unsafe { windows_sys::Win32::Foundation::LocalFree(s.cast()) };
        out
    }

    /// A block Windows handed over as a pointer: its units up to and including the final empty
    /// string (at most `max` units).
    unsafe fn block_units(p: *const u16, max: usize) -> W {
        let mut out = W::new();
        let mut prev_nul = false;
        for i in 0..max {
            // SAFETY: the caller's block, read up to its double NUL.
            let u = unsafe { *p.add(i) };
            out.push(u);
            if u == 0 && (prev_nul || i == 0) {
                break;
            }
            prev_nul = u == 0;
        }
        out
    }

    /// The environment Windows builds for a program started now (`CreateEnvironmentBlock` with
    /// this process's token, nothing inherited): what a refreshed Explorer, Start or a new
    /// terminal tab hands on.
    pub fn new_window() -> Result<Env, String> {
        use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
        let t = own_token().ok_or("this process's token could not be read")?;
        let mut block: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: an out pointer; the block is destroyed below.
        if unsafe { CreateEnvironmentBlock(&mut block, t.0, 0) } == 0 || block.is_null() {
            return Err(format!("Windows did not build the environment ({})", std::io::Error::last_os_error()));
        }
        let units = unsafe { block_units(block as *const u16, 1 << 22) };
        unsafe { DestroyEnvironmentBlock(block) };
        parse_block(&units).map_err(|_| "the environment Windows built had no end".to_string())
    }

    /// This process's own environment.
    pub fn own() -> Env {
        use windows_sys::Win32::System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW};
        // SAFETY: the process's block, freed below.
        let p = unsafe { GetEnvironmentStringsW() };
        if p.is_null() {
            return Env::default();
        }
        let units = unsafe { block_units(p, 1 << 22) };
        unsafe { FreeEnvironmentStringsW(p) };
        parse_block(&units).unwrap_or_default()
    }

    /// `%VARS%` expanded for this user (`ExpandEnvironmentStringsForUserW`). A variable that is
    /// not defined stays as typed.
    pub fn expand(raw: &[u16]) -> W {
        use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsForUserW;
        if !raw.contains(&crate::wide::PERCENT) {
            return raw.to_vec();
        }
        let Some(t) = own_token() else { return raw.to_vec() };
        let src = crate::wide::z(raw);
        let mut size = 1024u32.max(raw.len() as u32 * 2 + 64);
        for _ in 0..4 {
            let mut buf = vec![0u16; size as usize];
            // SAFETY: a NUL-terminated source and a buffer of `size` units.
            if unsafe { ExpandEnvironmentStringsForUserW(t.0, src.as_ptr(), buf.as_mut_ptr(), size) } != 0 {
                let n = buf.iter().position(|&u| u == 0).unwrap_or(buf.len());
                buf.truncate(n);
                return buf;
            }
            if unsafe { windows_sys::Win32::Foundation::GetLastError() } != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER {
                break;
            }
            size = (size * 2).min(1 << 17);
        }
        raw.to_vec()
    }

    fn dir_of(f: unsafe extern "system" fn(*mut u16, u32) -> u32) -> W {
        let mut buf = vec![0u16; 520];
        // SAFETY: a buffer and its length.
        let n = unsafe { f(buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n == 0 || n >= buf.len() { W::new() } else { buf[..n].to_vec() }
    }

    /// System32, the Windows folder (`GetSystemWindowsDirectoryW`: the shared one on a terminal
    /// server), and `<Windows>\System`.
    pub fn system_dirs() -> (W, W, W) {
        use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW};
        let s32 = dir_of(GetSystemDirectoryW);
        let win = dir_of(GetSystemWindowsDirectoryW);
        let s16 = crate::wide::join(&win, &w("System"));
        (s32, win, s16)
    }

    pub fn profile_dir() -> W {
        use windows_sys::Win32::UI::Shell::FOLDERID_Profile;
        crate::host::known_folder(&FOLDERID_Profile).map(|p| crate::wide::of_os(p.as_os_str())).unwrap_or_default()
    }

    pub fn own_cwd() -> Option<W> {
        std::env::current_dir().ok().map(|p| crate::wide::of_os(p.as_os_str()))
    }

    /// The folder this exe runs from.
    pub fn own_dir() -> Option<W> {
        std::env::current_exe().ok().map(|p| crate::wide::parent(&crate::wide::of_os(p.as_os_str())))
    }

}
