//! Stale PATH (SPEC section 4): a running program's PATH against the one Windows builds now.
//! Pure: the compare, the grouping into "Restart these" and their words.

use crate::env;
use crate::wide::{self, W};

/// Why no row is compared when the PATH Windows builds now could not be read.
pub const NO_FRESH: &str = "the PATH Windows builds now could not be read";

/// A process's PATH compared with the registry's now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The same entries in the same order.
    Current,
    /// An entry the registry has now is missing, or the registry's entries are in another
    /// order. `extra`: entries it has that the registry does not.
    Stale { missing: Vec<W>, extra: Vec<W>, reordered: bool },
    /// Every registry entry in order, plus its own (a venv, a developer prompt): not stale.
    Own { extra: Vec<W> },
    /// Its environment has no Path variable.
    NoPath,
    /// It could not be read: why ("elevated: …", "protected", "exited", "changed while read").
    Unknown(String),
    /// It was read, but there was nothing to compare it with (the PATH Windows builds now could
    /// not be read): why. Still usable as a context.
    NotCompared(String),
}

impl Verdict {
    pub fn stale(&self) -> bool {
        matches!(self, Verdict::Stale { .. })
    }

    pub fn word(&self) -> &'static str {
        match self {
            Verdict::Current => "current",
            Verdict::Stale { .. } => "stale",
            Verdict::Own { .. } => "own additions",
            Verdict::NoPath => "no PATH",
            Verdict::Unknown(_) => "unknown",
            Verdict::NotCompared(_) => "not compared",
        }
    }

    /// The family's state code: 1 ok, 3 warning, 2 quiet, 5 unknown.
    pub fn state(&self) -> i32 {
        match self {
            Verdict::Current | Verdict::Own { .. } => 1,
            Verdict::Stale { .. } => 3,
            Verdict::NoPath => 2,
            Verdict::Unknown(_) | Verdict::NotCompared(_) => 5,
        }
    }

    pub fn counts(&self) -> (usize, usize) {
        match self {
            Verdict::Stale { missing, extra, .. } => (missing.len(), extra.len()),
            Verdict::Own { extra } => (0, extra.len()),
            _ => (0, 0),
        }
    }

    /// The diff in lines: "missing: C:\Tools (added since it started)", "has: C:\Old (removed
    /// since)".
    pub fn lines(&self) -> Vec<String> {
        let shown = |x: &W| wide::shown(x, 260);
        match self {
            Verdict::Current => vec!["The same PATH as a program started now gets.".into()],
            Verdict::Stale { missing, extra, reordered } => {
                let mut v: Vec<String> = missing.iter().map(|m| format!("missing: {} (added since it started)", shown(m))).collect();
                v.extend(extra.iter().map(|x| format!("has: {} (removed since, or its own)", shown(x))));
                if *reordered && missing.is_empty() {
                    v.push("The registry's entries are in another order now.".into());
                }
                v
            }
            Verdict::Own { extra } => {
                let mut v = vec!["Every entry of the registry's PATH, in order, plus its own: not stale.".to_string()];
                v.extend(extra.iter().map(|x| format!("its own: {}", shown(x))));
                v
            }
            Verdict::NoPath => vec!["Its environment has no Path variable.".into()],
            Verdict::Unknown(why) => vec![format!("Could not be read: {why}.")],
            Verdict::NotCompared(why) => vec![format!("Read, but not compared: {why}.")],
        }
    }
}

/// Compare a process's PATH value with the registry's entries now (`fresh`, the New window
/// PATH split). Both are compared with section 5's equality.
pub fn compare(process_path: Option<&[u16]>, fresh: &[W]) -> Verdict {
    let Some(pp) = process_path else { return Verdict::NoPath };
    let have = env::entries(pp);
    let missing: Vec<W> = fresh.iter().filter(|f| !have.iter().any(|h| env::same(h, f))).cloned().collect();
    let extra: Vec<W> = have.iter().filter(|h| !fresh.iter().any(|f| env::same(h, f))).cloned().collect();
    // The fresh entries it has, in the registry's order (a subsequence of what it has)?
    let present: Vec<&W> = fresh.iter().filter(|f| have.iter().any(|h| env::same(h, f))).collect();
    let mut at = 0usize;
    for h in &have {
        if at < present.len() && env::same(h, present[at]) {
            at += 1;
        }
    }
    let in_order = at == present.len();
    if !missing.is_empty() || !in_order {
        return Verdict::Stale { missing, extra, reordered: !in_order };
    }
    if extra.is_empty() { Verdict::Current } else { Verdict::Own { extra } }
}

/// A process as the grouping needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    /// Its start (FILETIME): a PID is an identity only with it.
    pub start: u64,
    pub name: W,
    pub image: W,
    pub verdict: Verdict,
}

/// One line of "Restart these".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub name: String,
    pub image: W,
    /// Stale processes of it, the folded ones included.
    pub count: usize,
    pub words: String,
}

fn file_name_lower(p: &[u16]) -> String {
    wide::lossy(wide::file_name(p)).to_lowercase()
}

/// What to restart: one line per program (by image path), roots only (a stale process whose
/// parent is the same program and stale too is folded into it).
pub fn restart_lines(procs: &[Proc]) -> Vec<Line> {
    let stale: Vec<&Proc> = procs.iter().filter(|p| p.verdict.stale()).collect();
    let mut lines: Vec<Line> = Vec::new();
    for p in &stale {
        let key = if p.image.is_empty() { &p.name } else { &p.image };
        match lines.iter_mut().find(|l| wide::eq_ic(&l.image, key)) {
            Some(l) => l.count += 1,
            None => {
                let shown = wide::shown(wide::file_name(key), 120);
                let words = match file_name_lower(key).as_str() {
                    "code.exe" => "Close every VS Code window: Reload Window is not enough.".to_string(),
                    "explorer.exe" => "Explorer missed the change: Broadcast again, or sign out and in.".to_string(),
                    _ => format!("Close and reopen {shown}."),
                };
                lines.push(Line { name: shown, image: key.clone(), count: 1, words });
            }
        }
    }
    // Roots only: a line's count says how many processes; folding changes no count, it keeps
    // a child of the same stale program from making a line of its own (it shares the image).
    lines.sort_by_key(|l| (std::cmp::Reverse(l.count), wide::sort_key(&wide::of_os(std::ffi::OsStr::new(&l.name)))));
    lines
}

/// The processes that are roots of a stale group: not folded into a stale parent of the same
/// program (the parent's start no later than its own, so a reused PID is not taken for it).
pub fn roots(procs: &[Proc]) -> Vec<u32> {
    procs
        .iter()
        .filter(|p| p.verdict.stale())
        .filter(|p| !procs.iter().any(|q| q.pid == p.ppid && q.pid != p.pid && q.start <= p.start && q.verdict.stale() && wide::eq_ic(&q.image, &p.image)))
        .map(|p| p.pid)
        .collect()
}

/// The line under the list: "4 processes could not be read (elevated or protected)".
pub fn unread_words(procs: &[Proc]) -> Option<String> {
    // Not compared (the PATH Windows builds was not had) is no unread process: the banner says
    // that once.
    let n = procs.iter().filter(|p| matches!(&p.verdict, Verdict::Unknown(_))).count();
    (n > 0).then(|| format!("{} could not be read (elevated or protected).", if n == 1 { "1 process".to_string() } else { format!("{n} processes") }))
}

/// Terminals first in the context picker (they are where commands are typed).
pub fn is_terminal(name: &[u16]) -> bool {
    matches!(file_name_lower(name).as_str(), "cmd.exe" | "pwsh.exe" | "powershell.exe" | "bash.exe" | "wsl.exe" | "windowsterminal.exe" | "conemu64.exe" | "alacritty.exe" | "wezterm-gui.exe")
}
