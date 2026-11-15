//! Every file a command could mean, in the order each shell looks (SPEC section 2), over a file
//! system and a registry behind a trait: pure, so every order is tested on a fake one. The
//! orders were measured on Windows 11 26200:
//!
//! - cmd: built-ins (no path, no extension); the current folder unless
//!   `NoDefaultCurrentDirectoryInExePath` is defined; PATH. In each folder a name with an
//!   extension is tried as typed first, then the name plus each PATHEXT extension in PATHEXT
//!   order (a name without one: only the PATHEXT ones).
//! - PowerShell 7 and 5.1: aliases, functions, cmdlets (the built-in tables), then PATH only. In
//!   each folder: `.ps1`, then the PATHEXT extensions in order, then the name with no extension;
//!   a name with an extension: only as typed.
//! - Program (CreateProcess): the calling program's folder, the current folder unless
//!   `NoDefaultCurrentDirectoryInExePath`, System32, `<Windows>\System`, the Windows folder,
//!   PATH. `.exe` is added only to a name with no extension; PATHEXT is not used.
//! - Run box (ShellExecuteEx): App Paths (HKLM, then HKCU; an entry whose file is missing is
//!   passed over), the current folder (the variable does not stop it), System32, the Windows
//!   folder, PATH. The shell's own extension list (`.pif .com .exe .bat .lnk .cmd`), not
//!   PATHEXT, and only for a name with no extension. (Measured here and in Windows Sandbox: the
//!   documented order, App Paths last and the Windows folder before System32, is not what
//!   Windows 11 does.)

use crate::env::{self, Label};
use crate::wide::{self, DOT, W, eq_ic, join, w};

/// The five ways a command is started.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Shell {
    Cmd,
    Pwsh7,
    Ps51,
    Program,
    RunBox,
}

pub const SHELLS: [Shell; 5] = [Shell::Cmd, Shell::Pwsh7, Shell::Ps51, Shell::Program, Shell::RunBox];

impl Shell {
    pub fn word(self) -> &'static str {
        match self {
            Shell::Cmd => "cmd",
            Shell::Pwsh7 => "PowerShell 7",
            Shell::Ps51 => "Windows PowerShell 5.1",
            Shell::Program => "Program",
            Shell::RunBox => "Run box",
        }
    }

    /// The short name the summary line uses.
    pub fn short(self) -> &'static str {
        match self {
            Shell::Ps51 => "PowerShell 5.1",
            s => s.word(),
        }
    }

    pub fn index(self) -> usize {
        SHELLS.iter().position(|s| *s == self).unwrap_or(0)
    }

    pub fn from_index(i: usize) -> Shell {
        SHELLS.get(i).copied().unwrap_or(Shell::Cmd)
    }

    pub fn key(self) -> &'static str {
        match self {
            Shell::Cmd => "cmd",
            Shell::Pwsh7 => "pwsh",
            Shell::Ps51 => "ps51",
            Shell::Program => "program",
            Shell::RunBox => "run",
        }
    }

    pub fn from_key(k: &str) -> Option<Shell> {
        SHELLS.into_iter().find(|s| s.key() == k)
    }
}

/// cmd's built-in commands (they win for a name with no path and no extension).
pub const CMD_BUILTINS: &[&str] = &[
    "assoc", "break", "call", "cd", "chdir", "cls", "color", "copy", "date", "del", "dir", "echo", "endlocal", "erase", "exit", "for", "ftype", "goto", "if", "md", "mkdir", "mklink", "move", "path", "pause", "popd", "prompt", "pushd", "rd", "rem", "ren",
    "rename", "rmdir", "set", "setlocal", "shift", "start", "time", "title", "type", "ver", "verify", "vol",
];

/// The Run box's own extensions, in its order (measured: `.com .exe .bat .lnk .cmd`; `.pif` from
/// the shell's documented list, first).
pub const RUN_EXTS: &[&str] = &[".pif", ".com", ".exe", ".bat", ".lnk", ".cmd"];

/// One command from a PowerShell table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PsCommand {
    pub name: String,
    /// "Alias", "Function" or "Cmdlet".
    pub kind: String,
    /// An alias's command; a function's or cmdlet's module.
    pub target: String,
}

/// A PowerShell table (`assets\ps7.txt`, `ps51.txt`): `name<TAB>kind<TAB>target` lines.
pub fn parse_ps_table(text: &str) -> Vec<PsCommand> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split('\t');
            let (name, kind) = (it.next()?.trim(), it.next()?.trim());
            let target = it.next().unwrap_or("").trim();
            (!name.is_empty() && matches!(kind, "Alias" | "Function" | "Cmdlet")).then(|| PsCommand { name: name.into(), kind: kind.into(), target: target.into() })
        })
        .collect()
}

pub fn ps7() -> &'static [PsCommand] {
    static T: std::sync::OnceLock<Vec<PsCommand>> = std::sync::OnceLock::new();
    T.get_or_init(|| parse_ps_table(include_str!("../assets/ps7.txt")))
}

pub fn ps51() -> &'static [PsCommand] {
    static T: std::sync::OnceLock<Vec<PsCommand>> = std::sync::OnceLock::new();
    T.get_or_init(|| parse_ps_table(include_str!("../assets/ps51.txt")))
}

/// What one candidate path is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Probe {
    /// A file; `reparse` when it carries a reparse point (an App Execution Alias, a symlink);
    /// `name`: its name as the folder spells it, when that could be read.
    File { reparse: bool, name: Option<W> },
    /// A folder of that name: not a match.
    Dir,
    /// Not there (NotFound on the exact path, or its folder is not there).
    Missing,
}

/// An App Paths entry: its default value (quotes stripped, expanded) and its `Path` value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppPath {
    pub hive: env::Hive,
    pub target: W,
    pub extra_path: Option<W>,
    /// The target file is not there.
    pub missing: bool,
}

/// What the resolver asks of the system.
pub trait Lookup {
    /// Each candidate in `dir` (full paths). Err: the folder could not be read (access denied,
    /// a share that did not answer in time): its reason, and no answers.
    fn probe_all(&self, dir: &[u16], candidates: &[W]) -> Result<Vec<Probe>, String>;
    /// App Paths entries for `name` (`<name>.exe` already added where it applies), HKLM first.
    fn app_paths(&self, name: &[u16]) -> Vec<AppPath>;
}

/// Where a context's PATH and folders come from (SPEC section 1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Context {
    /// The PATH entries in order (empty ones skipped), as the environment has them.
    pub path: Vec<W>,
    /// The PATH value as one string: cmd reads it its own way (`cmd_path`). None: `path`
    /// joined by `;`.
    pub raw_path: Option<W>,
    /// Where each entry came from, one per entry.
    pub labels: Vec<Label>,
    /// PATHEXT's extensions in order, as written.
    pub pathext: Vec<W>,
    /// The current folder, when known.
    pub cwd: Option<W>,
    /// `NoDefaultCurrentDirectoryInExePath` is defined in the context's environment.
    pub no_cwd: bool,
    /// Program: the calling program's own folder (a running process's image folder); None for
    /// New window and This app ("the calling program's own folder comes first").
    pub caller_dir: Option<W>,
    pub system32: W,
    pub system16: W,
    pub windows: W,
}

/// Which step of a shell's search found a match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Builtin,
    PsTable,
    AppPaths,
    CallerDir,
    CurrentDir,
    System32,
    System16,
    Windows,
    /// PATH entry (0-based index into the context's PATH).
    Path(usize),
    /// The path typed (no search).
    Typed,
}

impl Step {
    fn words(&self) -> &'static str {
        match self {
            Step::Builtin => "the cmd built-in",
            Step::PsTable => "PowerShell's own commands",
            Step::AppPaths => "App Paths",
            Step::CallerDir => "the calling program's folder",
            Step::CurrentDir => "the current folder",
            Step::System32 => "System32",
            Step::System16 => "the Windows\\System folder",
            Step::Windows => "the Windows folder",
            Step::Path(_) => "PATH",
            Step::Typed => "the path typed",
        }
    }
}

/// One row of a resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    Builtin,
    Ps(PsCommand),
    File {
        path: W,
        step: Step,
        /// Where it came from, in words ("Machine PATH #4", "current folder", "System32").
        source: String,
        /// The PATH entry as typed in the registry, when it differs from its expansion.
        typed: Option<W>,
        /// Its candidate's rank within its folder (0 = tried first there).
        rank: usize,
        /// The extension the shell added (None: the name as typed).
        added: Option<W>,
        reparse: bool,
    },
    AppPath(AppPath),
    /// A folder that could not be read: a match may hide there.
    NotChecked { dir: W, source: String, reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub found: Found,
    /// What beats it ("shadowed by #1 (earlier PATH folder)"); None for the winner and for rows
    /// that are not matches.
    pub shadow: Option<String>,
    /// Its number among the matches (1 is the winner); 0 for a not-checked row.
    pub number: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resolution {
    pub rows: Vec<Row>,
    /// Lines the list says once ("PowerShell does not look in the current folder").
    pub notes: Vec<String>,
    /// The winner's row index.
    pub winner: Option<usize>,
    /// A folder before the winner (or anywhere, with no winner) was not checked.
    pub uncertain: bool,
}

impl Resolution {
    pub fn matches(&self) -> usize {
        self.rows.iter().filter(|r| r.number > 0).count()
    }

    pub fn winner_row(&self) -> Option<&Row> {
        self.winner.map(|i| &self.rows[i])
    }
}

fn has_ext(name: &[u16]) -> bool {
    wide::extension(name).is_some_and(|e| e.len() > 1 || e == [DOT])
}

/// The candidates one shell tries in one folder for `name`: (file name, the extension added).
pub fn candidates(shell: Shell, name: &[u16], pathext: &[W]) -> Vec<(W, Option<W>)> {
    let ext = has_ext(name);
    let plus = |e: &[u16]| -> (W, Option<W>) {
        let mut n = name.to_vec();
        n.extend_from_slice(e);
        (n, Some(e.to_vec()))
    };
    let mut out: Vec<(W, Option<W>)> = Vec::new();
    match shell {
        Shell::Cmd => {
            if ext {
                out.push((name.to_vec(), None));
            }
            out.extend(pathext.iter().map(|e| plus(e)));
        }
        Shell::Pwsh7 | Shell::Ps51 => {
            if ext {
                out.push((name.to_vec(), None));
            } else {
                out.push(plus(&w(".ps1")));
                out.extend(pathext.iter().filter(|e| !eq_ic(e, &w(".ps1"))).map(|e| plus(e)));
                out.push((name.to_vec(), None));
            }
        }
        Shell::Program => {
            if ext {
                out.push((name.to_vec(), None));
            } else {
                out.push(plus(&w(".exe")));
            }
        }
        Shell::RunBox => {
            if ext {
                out.push((name.to_vec(), None));
            } else {
                out.extend(RUN_EXTS.iter().map(|e| plus(&w(e))));
            }
        }
    }
    // The same file twice (a PATHEXT listing an extension twice) is one candidate.
    let mut seen: Vec<W> = Vec::new();
    out.retain(|(n, _)| {
        if seen.iter().any(|s| eq_ic(s, n)) {
            false
        } else {
            seen.push(n.clone());
            true
        }
    });
    out
}

/// PATHEXT as its extensions, empty ones skipped.
pub fn pathext_list(v: &[u16]) -> Vec<W> {
    env::entries(v).into_iter().map(|e| e.iter().copied().filter(|&u| u != b' ' as u16).collect()).filter(|e: &W| !e.is_empty()).collect()
}

/// A typed path made absolute against the current folder (textually; `.` and `..` collapsed).
pub fn absolute(typed: &[u16], cwd: Option<&[u16]>) -> Option<W> {
    let t: W = typed.iter().map(|&u| if u == wide::SLASH { wide::BACKSLASH } else { u }).collect();
    let bs = wide::BACKSLASH;
    let drive_abs = t.len() >= 3 && t[1] == wide::COLON && t[2] == bs;
    let unc = t.len() >= 2 && t[0] == bs && t[1] == bs;
    let full = if drive_abs || unc {
        t
    } else if t.first() == Some(&bs) {
        // Rooted: the current folder's drive.
        let c = cwd?;
        if c.len() >= 2 && c[1] == wide::COLON {
            let mut d = c[..2].to_vec();
            d.extend_from_slice(&t);
            d
        } else {
            return None;
        }
    } else if t.len() >= 2 && t[1] == wide::COLON {
        // Drive-relative (`C:x`): against the current folder when it is on that drive, else
        // that drive's root.
        let c = cwd.unwrap_or(&[]);
        if c.len() >= 2 && eq_ic(&c[..2], &t[..2]) {
            join(c, &t[2..])
        } else {
            t[..2].iter().copied().chain([bs]).chain(t[2..].iter().copied()).collect()
        }
    } else {
        join(cwd?, &t)
    };
    Some(env::norm(&full))
}

struct Search<'a> {
    lookup: &'a dyn Lookup,
    rows: Vec<Row>,
}

impl Search<'_> {
    #[allow(clippy::too_many_arguments)]
    fn folder(&mut self, shell: Shell, dir: &[u16], step: Step, source: &str, typed: Option<&W>, name: &[u16], pathext: &[W]) {
        if dir.is_empty() {
            return;
        }
        let cands = candidates(shell, name, pathext);
        let full: Vec<W> = cands.iter().map(|(n, _)| join(dir, n)).collect();
        match self.lookup.probe_all(dir, &full) {
            Ok(probes) => {
                for (rank, ((p, (_, added)), probe)) in full.into_iter().zip(cands).zip(probes).enumerate() {
                    if let Probe::File { reparse, name: real } = probe {
                        let p = match real {
                            Some(n) if eq_ic(&n, wide::file_name(&p)) => join(dir, &n),
                            _ => p,
                        };
                        self.rows.push(Row {
                            found: Found::File { path: p, step: step.clone(), source: source.to_string(), typed: typed.cloned(), rank, added, reparse },
                            shadow: None,
                            number: 0,
                        });
                    }
                }
            }
            Err(reason) => self.rows.push(Row { found: Found::NotChecked { dir: dir.to_vec(), source: source.to_string(), reason }, shadow: None, number: 0 }),
        }
    }

    /// PATH as `shell` reads it. cmd reads the value its own way (`cmd_path`); PowerShell drops
    /// each entry's leading white space; programs and the Run box take each entry as it is
    /// (measured, DECISIONS "PATH entries as each shell reads them").
    fn path(&mut self, shell: Shell, ctx: &Context, name: &[u16], notes: &mut Vec<String>) {
        let source_of = |i: usize| ctx.labels.get(i).map(|l| l.source.clone()).unwrap_or_else(|| format!("PATH #{}", i + 1));
        if shell == Shell::Cmd {
            let raw = ctx.raw_path.clone().unwrap_or_else(|| ctx.path.join(&wide::SEMI));
            let cp = cmd_path(&raw);
            let at = |offset: usize| piece_at(&raw, offset);
            for e in &cp.entries {
                let i = at(e.start).unwrap_or(0);
                self.entry(shell, ctx, i, &e.dir, name);
            }
            if let Some(stop) = cp.stop {
                let where_ = match at(stop) {
                    Some(i) if raw.get(stop) == Some(&wide::QUOTE) => format!("{}, an entry of quotes only", source_of(i)),
                    _ => "an empty entry at its start".to_string(),
                };
                notes.push(format!("cmd stops reading PATH at {where_}: it searches no folder after it."));
            }
            return;
        }
        for (i, e) in ctx.path.iter().enumerate() {
            let e: W = if matches!(shell, Shell::Pwsh7 | Shell::Ps51) { e[e.iter().take_while(|&&u| ps_space(u)).count()..].to_vec() } else { e.clone() };
            self.entry(shell, ctx, i, &e, name);
        }
    }

    /// One PATH folder (`i`: its entry in the context's PATH, for its label).
    fn entry(&mut self, shell: Shell, ctx: &Context, i: usize, e: &[u16], name: &[u16]) {
        let label = ctx.labels.get(i);
        let source = label.map(|l| l.source.clone()).unwrap_or_else(|| format!("PATH #{}", i + 1));
        let typed = label.and_then(|l| l.typed.as_ref());
        // A relative entry resolves against the context's current folder (that is the danger);
        // with no folder known it is not looked up at all (never against VibePath's own).
        let dir = if is_absolute(e) {
            e.to_vec()
        } else {
            match absolute(e, ctx.cwd.as_deref()) {
                Some(d) => d,
                None => {
                    self.rows.push(Row { found: Found::NotChecked { dir: e.to_vec(), source, reason: "relative: depends on the folder".into() }, shadow: None, number: 0 });
                    return;
                }
            }
        };
        self.folder(shell, &dir, Step::Path(i), &source, typed, name, &ctx.pathext);
    }
}

/// The white space cmd skips at the start of PATH (and only there): `iswspace` (Windows'
/// C1_SPACE: GetStringTypeW over every unit on this PC) plus its delimiters `,` and `=`.
/// Measured one by one (U+180E skipped; U+200B, U+FEFF and U+001C-U+001F not).
pub fn cmd_space(u: u16) -> bool {
    matches!(u, 0x09..=0x0D | 0x20 | 0x2C | 0x3D | 0x85 | 0xA0 | 0x1680 | 0x180E | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000)
}

/// The white space PowerShell drops at the start of each PATH entry (.NET's `TrimStart`:
/// Unicode White_Space; measured: U+180E and `,` are not dropped).
pub fn ps_space(u: u16) -> bool {
    char::from_u32(u32::from(u)).is_some_and(char::is_whitespace)
}

/// One folder as cmd reads PATH: `dir` with every quote removed; `start..end`: its units in
/// the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CmdEntry {
    pub dir: W,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CmdPath {
    pub entries: Vec<CmdEntry>,
    /// Where an empty entry ended cmd's reading, when the value goes on after it.
    pub stop: Option<usize>,
}

/// PATH as cmd reads it (measured, cmd.exe of Windows 11 26200, DECISIONS): white space
/// (`cmd_space`) skipped at the start of the value only; an entry runs to the next `;` outside
/// quotes (a `;` between quotes is part of it, an unmatched quote runs to the end); every quote
/// is removed; runs of `;` between entries are skipped; an entry that is empty after that (the
/// value starting with `;`, or `""`) ends the reading: nothing after it is searched. Leading
/// spaces of later entries and trailing spaces stay.
pub fn cmd_path(raw: &[u16]) -> CmdPath {
    let mut out = CmdPath::default();
    let n = raw.len();
    let mut i = raw.iter().take_while(|&&u| cmd_space(u)).count();
    while i < n {
        let start = i;
        let mut dir = W::new();
        let mut quoted = false;
        while i < n && (quoted || raw[i] != wide::SEMI) {
            if raw[i] == wide::QUOTE {
                quoted = !quoted;
            } else {
                dir.push(raw[i]);
            }
            i += 1;
        }
        if dir.is_empty() {
            if raw[i..].iter().any(|&u| u != wide::SEMI) {
                out.stop = Some(start);
            }
            break;
        }
        out.entries.push(CmdEntry { dir, start, end: i });
        while i < n && raw[i] == wide::SEMI {
            i += 1;
        }
    }
    out
}

/// The entry (an index into `env::entries(raw)`) whose units hold `offset`; None for a `;`.
pub fn piece_at(raw: &[u16], offset: usize) -> Option<usize> {
    let mut start = 0;
    let mut k = 0;
    for piece in raw.split(|&u| u == wide::SEMI) {
        let end = start + piece.len();
        if !piece.is_empty() {
            if (start..end).contains(&offset) {
                return Some(k);
            }
            k += 1;
        }
        start = end + 1;
    }
    None
}

fn is_absolute(p: &[u16]) -> bool {
    let bs = wide::BACKSLASH;
    let s = wide::SLASH;
    (p.len() >= 3 && p[1] == wide::COLON && (p[2] == bs || p[2] == s)) || (p.len() >= 2 && (p[0] == bs || p[0] == s) && (p[1] == bs || p[1] == s))
}

/// Every match for `cmd` in `shell` under `ctx`, numbered, with what beats each.
pub fn resolve(shell: Shell, cmd: &crate::input::Command, ctx: &Context, lookup: &dyn Lookup) -> Resolution {
    let mut s = Search { lookup, rows: Vec::new() };
    let mut notes = Vec::new();
    match cmd {
        crate::input::Command::Path(typed) => {
            match absolute(typed, ctx.cwd.as_deref()) {
                Some(full) => {
                    let dir = wide::parent(&full);
                    let name = wide::file_name(&full).to_vec();
                    s.folder(shell, &dir, Step::Typed, "the path typed", None, &name, &ctx.pathext);
                }
                None => notes.push("The current folder is not known here: a relative path cannot be resolved.".to_string()),
            }
            notes.push("A path is not searched for: only that folder is looked in.".to_string());
        }
        crate::input::Command::Name(name) => match shell {
            Shell::Cmd => {
                // A built-in has no dot, so a name with an extension is never one.
                if CMD_BUILTINS.iter().any(|b| eq_ic(&w(b), name)) {
                    s.rows.push(Row { found: Found::Builtin, shadow: None, number: 0 });
                }
                if ctx.no_cwd {
                    notes.push("NoDefaultCurrentDirectoryInExePath is set: cmd skips the current folder.".to_string());
                } else if let Some(c) = &ctx.cwd {
                    s.folder(shell, c, Step::CurrentDir, "current folder", None, name, &ctx.pathext);
                }
                s.path(shell, ctx, name, &mut notes);
                notes.push("Doskey macros are not read.".to_string());
            }
            Shell::Pwsh7 | Shell::Ps51 => {
                let table = if shell == Shell::Pwsh7 { ps7() } else { ps51() };
                let n = wide::lossy(name);
                for kind in ["Alias", "Function", "Cmdlet"] {
                    for c in table.iter().filter(|c| c.kind == kind && c.name.eq_ignore_ascii_case(&n) && w(&c.name).len() == name.len()) {
                        s.rows.push(Row { found: Found::Ps(c.clone()), shadow: None, number: 0 });
                    }
                }
                s.path(shell, ctx, name, &mut notes);
                notes.push("PowerShell does not look in the current folder (it needs .\\).".to_string());
                notes.push("Profile additions (aliases and functions from a profile) are not read.".to_string());
            }
            Shell::Program => {
                match &ctx.caller_dir {
                    Some(d) => s.folder(shell, d, Step::CallerDir, "the calling program's folder", None, name, &ctx.pathext),
                    None => notes.push("The calling program's own folder comes first: it depends on the program.".to_string()),
                }
                if ctx.no_cwd {
                    notes.push("NoDefaultCurrentDirectoryInExePath is set: the current folder is skipped.".to_string());
                } else if let Some(c) = &ctx.cwd {
                    s.folder(shell, c, Step::CurrentDir, "current folder", None, name, &ctx.pathext);
                }
                s.folder(shell, &ctx.system32.clone(), Step::System32, "System32", None, name, &ctx.pathext);
                s.folder(shell, &ctx.system16.clone(), Step::System16, "Windows\\System", None, name, &ctx.pathext);
                s.folder(shell, &ctx.windows.clone(), Step::Windows, "Windows folder", None, name, &ctx.pathext);
                s.path(shell, ctx, name, &mut notes);
                notes.push("Programs ignore PATHEXT: only .exe is added, so npm alone finds no npm.cmd.".to_string());
            }
            Shell::RunBox => {
                let key: W = if has_ext(name) { name.clone() } else { name.iter().copied().chain(w(".exe")).collect() };
                for a in lookup.app_paths(&key) {
                    s.rows.push(Row { found: Found::AppPath(a), shadow: None, number: 0 });
                }
                if let Some(c) = &ctx.cwd {
                    s.folder(shell, c, Step::CurrentDir, "current folder", None, name, &ctx.pathext);
                }
                s.folder(shell, &ctx.system32.clone(), Step::System32, "System32", None, name, &ctx.pathext);
                s.folder(shell, &ctx.windows.clone(), Step::Windows, "Windows folder", None, name, &ctx.pathext);
                s.path(shell, ctx, name, &mut notes);
                notes.push("The Run box tries its own extensions (.com .exe .bat .lnk .cmd), not PATHEXT.".to_string());
                notes.push("An elevated program's Run box skips HKCU App Paths.".to_string());
            }
        },
    }
    finish(shell, s.rows, notes)
}

fn ext_words(added: &Option<W>, path: &[u16]) -> String {
    match added {
        Some(e) => wide::lossy(e).to_uppercase(),
        None => format!("\"{}\"", wide::lossy(wide::file_name(path))),
    }
}

/// Number the matches, find the winner and say what beats every other match.
fn finish(shell: Shell, mut rows: Vec<Row>, notes: Vec<String>) -> Resolution {
    // Not matches: a folder that was not checked, and an App Paths entry whose file is missing
    // (the Run box goes on past it: measured).
    let mut n = 0;
    for r in rows.iter_mut() {
        let skip = match &r.found {
            Found::NotChecked { .. } => true,
            Found::AppPath(a) => a.missing,
            _ => false,
        };
        if !skip {
            n += 1;
            r.number = n;
        }
    }
    let winner = rows.iter().position(|r| r.number == 1);
    let uncertain = match winner {
        Some(wi) => rows[..wi].iter().any(|r| matches!(r.found, Found::NotChecked { .. })),
        None => rows.iter().any(|r| matches!(r.found, Found::NotChecked { .. })),
    };
    if let Some(wi) = winner {
        let wf = rows[wi].found.clone();
        for (i, r) in rows.iter_mut().enumerate() {
            if i == wi || r.number == 0 {
                continue;
            }
            r.shadow = Some(shadow_words(shell, &wf, &r.found));
        }
    }
    Resolution { rows, notes, winner, uncertain }
}

fn shadow_words(shell: Shell, winner: &Found, row: &Found) -> String {
    match winner {
        Found::Builtin => "shadowed by the cmd built-in".into(),
        Found::Ps(c) => format!("shadowed by #1 (a PowerShell {} comes before any file)", c.kind.to_lowercase()),
        Found::AppPath(_) => match row {
            Found::AppPath(_) => "shadowed by #1 (HKLM's App Paths come before HKCU's)".into(),
            _ => "shadowed by #1 (the Run box looks in App Paths first)".into(),
        },
        Found::File { path: wp, step: ws, rank: wr, added: wa, .. } => match row {
            Found::File { path: rp, step: rs, rank: rr, added: ra, .. } if ws == rs || (eq_ic(&wide::parent(wp), &wide::parent(rp))) => {
                if wr < rr {
                    let what = match shell {
                        Shell::Cmd if wa.is_none() => "the name as typed comes first".to_string(),
                        Shell::Cmd => format!("{} comes before {} in PATHEXT", ext_words(wa, wp), ext_words(ra, rp)),
                        Shell::Pwsh7 | Shell::Ps51 if wa.as_deref().is_some_and(|e| eq_ic(e, &w(".ps1"))) => "PowerShell takes .PS1 first".to_string(),
                        Shell::Pwsh7 | Shell::Ps51 => format!("PowerShell takes {} before {}", ext_words(wa, wp), ext_words(ra, rp)),
                        Shell::RunBox => format!("the Run box takes {} before {}", ext_words(wa, wp), ext_words(ra, rp)),
                        Shell::Program => "it comes first".to_string(),
                    };
                    format!("shadowed by #1 (same folder: {what})")
                } else {
                    "shadowed by #1 (the same folder, found again by another entry)".into()
                }
            }
            Found::File { step: Step::Path(_), .. } if matches!(ws, Step::Path(_)) => "shadowed by #1 (earlier PATH folder)".into(),
            Found::File { step: rs, .. } => format!("shadowed by #1 ({} is searched before {})", ws.words(), rs.words()),
            Found::AppPath(_) => format!("shadowed by #1 ({} is searched before App Paths)", ws.words()),
            _ => "shadowed by #1".into(),
        },
        Found::NotChecked { .. } => "shadowed by #1".into(),
    }
}

/// Where a row came from, in words (the detail panel's "Source").
pub fn step_source(f: &Found) -> String {
    match f {
        Found::Builtin => "built into cmd".into(),
        Found::Ps(c) => format!("PowerShell {}", c.kind.to_lowercase()),
        Found::AppPath(a) => format!("App Paths ({})", if a.hive == env::Hive::User { "HKCU" } else { "HKLM" }),
        Found::File { source, .. } | Found::NotChecked { source, .. } => source.clone(),
    }
}
