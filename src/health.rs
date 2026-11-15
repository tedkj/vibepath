//! PATH health (SPEC section 5): every entry of Machine and User PATH in the order new programs
//! see them, with what is wrong with each, judged from facts read elsewhere (`fsprobe::Facts`).
//! Pure: every finding is tested alone and together.

use crate::env::{self, Hive, Kind, Read};
use crate::fsprobe::{Drive, Facts, State};
use crate::wide::{self, W, eq_ic, w};

/// The limit for one environment variable.
pub const MAX_VAR: usize = 32_767;
/// Where some installers and older tools cut a value.
pub const WARN_LEN: usize = 2_048;
/// Where `setx` cuts.
pub const SETX: usize = 1_024;

pub const DANGER: i32 = 4;
pub const WARN: i32 = 3;
pub const INFO: i32 = 2;
pub const UNKNOWN: i32 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub level: i32,
    pub text: String,
}

fn f(level: i32, text: impl Into<String>) -> Finding {
    Finding { level, text: text.into() }
}

/// One entry of a hive's Path, as typed and as the environment gets it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub hive: Hive,
    /// 1-based among the hive's entries that are not empty; 0 for an empty one.
    pub index: usize,
    pub typed: W,
    /// What the environment gets: expanded for a REG_EXPAND_SZ value, as typed for REG_SZ.
    pub expanded: W,
}

impl Entry {
    pub fn empty(&self) -> bool {
        self.typed.is_empty()
    }

    /// "Machine #4".
    pub fn label(&self) -> String {
        if self.index == 0 { format!("{} (empty)", self.hive.word()) } else { format!("{} #{}", self.hive.word(), self.index) }
    }
}

/// A hive's entries in order, the empty ones included (they are an Info finding). The ends of
/// the value (`;` first or last) make no entry.
pub fn entries_of(hive: Hive, read: &Read, expand: &dyn Fn(&[u16]) -> W) -> Vec<Entry> {
    let Some(v) = read.value() else { return Vec::new() };
    let parts = wide::split_semi(&v.raw);
    let last = parts.len().saturating_sub(1);
    let mut n = 0;
    let mut out = Vec::new();
    for (i, typed) in parts.into_iter().enumerate() {
        if typed.is_empty() && (i == 0 || i == last) {
            continue;
        }
        let index = if typed.is_empty() {
            0
        } else {
            n += 1;
            n
        };
        let expanded = if v.kind == Kind::ExpandSz { expand(&typed) } else { typed.clone() };
        out.push(Entry { hive, index, typed, expanded });
    }
    out
}

/// One table row: an entry and what is wrong with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub entry: Entry,
    /// None while its facts are being read ("Checking…").
    pub facts: Option<Facts>,
    pub findings: Vec<Finding>,
}

impl Row {
    pub fn level(&self) -> i32 {
        let ls: Vec<i32> = self.findings.iter().map(|f| f.level).collect();
        if ls.contains(&DANGER) {
            DANGER
        } else if ls.contains(&WARN) {
            WARN
        } else if ls.contains(&UNKNOWN) {
            UNKNOWN
        } else if ls.contains(&INFO) {
            INFO
        } else if self.facts.is_none() && !self.entry.empty() {
            0
        } else {
            1
        }
    }
}

/// What the whole table says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub rows: Vec<Row>,
    /// Findings about a value as a whole (lengths, types, System32, PATHEXT, setx).
    pub general: Vec<Finding>,
    pub header: String,
    pub dangers: usize,
    pub warnings: usize,
    /// Rows still being checked.
    pub checking: usize,
    pub merged_len: usize,
}

/// Everything the judge needs.
pub struct Input<'a> {
    pub machine: &'a Read,
    pub user: &'a Read,
    pub pathext_machine: &'a Read,
    pub pathext_user: &'a Read,
    pub rows: Vec<(Entry, Option<Facts>)>,
    /// The PATH `CreateEnvironmentBlock` built (None when it could not be had).
    pub built: Option<W>,
    pub system32: W,
}

/// A number with a no-break space between thousands: "32 767".
pub fn thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push('\u{00A0}');
        }
        out.push(c);
    }
    out
}

/// What cmd makes of the rows (`resolve::cmd_path` over the merged PATH rebuilt from them, so
/// the table says what the Command tab's model does): per row, the cmd entry it starts or
/// sits in (by index), whether cmd skipped its leading white space, and where cmd stopped.
struct CmdView {
    /// Per row: (first, last) cmd entry overlapping it.
    hits: Vec<Option<(usize, usize)>>,
    entries: Vec<crate::resolve::CmdEntry>,
    spans: Vec<(usize, usize)>,
    /// The row where cmd stopped (quotes only), or None with `stop_at_start`.
    stop_row: Option<usize>,
    stop_at_start: bool,
    /// Where cmd stopped, in the joined value.
    stop: Option<usize>,
    /// The joined value starts with `;` itself (not white space that cmd skips first).
    lead_semi: bool,
    /// Rows after the stop (not read by cmd).
    lost: usize,
}

fn cmd_view(rows: &[(Entry, Option<Facts>)], machine: &Read, user: &Read) -> CmdView {
    // The value's own first `;` makes no row (entries_of drops the ends) but ends cmd's reading.
    let first = [machine, user].into_iter().filter_map(|r| r.value()).find(|v| !v.raw.is_empty());
    let lead = first.is_some_and(|v| v.raw.first() == Some(&wide::SEMI));
    let mut joined = W::new();
    if lead {
        joined.push(wide::SEMI);
    }
    let mut spans = Vec::with_capacity(rows.len());
    for (k, (e, _)) in rows.iter().enumerate() {
        if k > 0 {
            joined.push(wide::SEMI);
        }
        let s = joined.len();
        joined.extend_from_slice(&e.expanded);
        spans.push((s, joined.len()));
    }
    let cp = crate::resolve::cmd_path(&joined);
    let hits = spans
        .iter()
        .map(|&(s, e)| {
            let over: Vec<usize> = cp.entries.iter().enumerate().filter(|(_, c)| c.start < e && c.end > s).map(|(i, _)| i).collect();
            Some((*over.first()?, *over.last()?))
        })
        .collect();
    let stop_row = cp.stop.and_then(|at| spans.iter().position(|&(s, e)| (s..e).contains(&at)));
    let lost = cp.stop.map_or(0, |at| rows.iter().zip(&spans).filter(|((r, _), (s, _))| *s > at && !r.empty()).count());
    CmdView { hits, entries: cp.entries, spans, stop_row, stop_at_start: cp.stop.is_some() && stop_row.is_none(), stop: cp.stop, lead_semi: joined.first() == Some(&wide::SEMI), lost }
}

fn absolute(p: &[u16]) -> bool {
    let t = env::norm(p);
    (t.len() >= 3 && t[1] == wide::COLON && t[2] == wide::BACKSLASH) || (t.len() >= 2 && t[0] == wide::BACKSLASH && t[1] == wide::BACKSLASH)
}

/// The merged value Windows would build: Machine's, then User's (each expanded when it is
/// REG_EXPAND_SZ), joined by `;`.
pub fn merged(machine: &Read, user: &Read, expand: &dyn Fn(&[u16]) -> W) -> W {
    let part = |r: &Read| -> Option<W> {
        let v = r.value()?;
        Some(if v.kind == Kind::ExpandSz { expand(&v.raw) } else { v.raw.clone() })
    };
    let mut out = W::new();
    if let Some(m) = part(machine) {
        out.extend(m);
    }
    if let Some(u) = part(user).filter(|u| !u.is_empty()) {
        if !out.is_empty() && out.last() != Some(&wide::SEMI) {
            out.push(wide::SEMI);
        }
        out.extend(u);
    }
    out
}

/// Judge every entry and the values as a whole.
pub fn judge(input: Input) -> Report {
    let entries: Vec<&Entry> = input.rows.iter().map(|(e, _)| e).collect();
    let sys32_at = entries.iter().position(|e| e.hive == Hive::Machine && env::same(&e.expanded, &input.system32));
    let cv = cmd_view(&input.rows, input.machine, input.user);
    let mut rows: Vec<Row> = Vec::with_capacity(entries.len());
    for (i, (e, facts)) in input.rows.iter().enumerate() {
        let mut out: Vec<Finding> = Vec::new();
        let machine = e.hive == Hive::Machine;
        if e.empty() {
            out.push(f(INFO, "An empty entry (;;): harmless, Windows skips it."));
            rows.push(Row { entry: e.clone(), facts: facts.clone(), findings: out });
            continue;
        }
        // An entry with a variable left in it is told as that (its root cause), not as relative.
        // An entry of quotes only is told as that (cmd stops there), not as relative.
        let only_quotes = e.expanded.iter().all(|&u| u == wide::QUOTE);
        if !absolute(&e.expanded) && env::unexpanded(&e.expanded).is_none() && !only_quotes {
            if machine {
                out.push(f(DANGER, "A relative entry: it resolves against whatever the current folder is, for every program that searches Machine PATH, admin programs and services too."));
            } else {
                out.push(f(WARN, "A relative entry: it resolves against whatever the current folder is."));
            }
        }
        if let Some(var) = env::unexpanded(&e.expanded) {
            let kind = if machine { input.machine } else { input.user }.value().map(|v| v.kind);
            if kind == Some(Kind::Sz) {
                out.push(f(WARN, format!("{var}: Windows does not expand a REG_SZ value: it must be REG_EXPAND_SZ.")));
            } else {
                out.push(f(WARN, format!("{var} is not defined when Windows builds the environment: the entry stays as typed.")));
            }
        }
        // Quotes and white space, as the Command tab's model reads them (measured per shell).
        let ex = &e.expanded;
        let row_of = |at: usize| cv.spans.iter().position(|&(s, end)| (s..end).contains(&at)).unwrap_or(i);
        match cv.hits[i] {
            Some((a, _)) if row_of(cv.entries[a].start) != i => {
                out.push(f(WARN, format!("cmd reads this as part of #{} (a ; between quotes): it does not search it as written.", row_of(cv.entries[a].start) + 1)));
            }
            Some((a, _)) if cv.entries[a].end > cv.spans[i].1 => {
                let last = row_of(cv.entries[a].end - 1);
                out.push(f(WARN, format!("cmd reads #{} to #{} as one folder, {} (a ; between quotes): it searches none of them as written.", i + 1, last + 1, wide::shown(&cv.entries[a].dir, 120))));
            }
            Some(_) if ex.contains(&wide::QUOTE) => out.push(f(WARN, "Quoted: cmd drops the quotes; PowerShell and programs look for a folder with quotes in its name.")),
            None if cv.stop_row == Some(i) => out.push(f(WARN, format!("Only quotes: cmd stops reading PATH here and does not search what follows ({}).", plural(cv.lost, "entry", "entries")))),
            None if ex.iter().all(|&u| u == wide::QUOTE) && cv.stop_row.is_none() && !cv.stop_at_start => out.push(f(INFO, "Only quotes: cmd stops reading PATH here (nothing comes after it).")),
            _ => {}
        }
        if ex.first().is_some_and(|&u| crate::resolve::ps_space(u)) {
            let cmd_drops = cv.hits[i].is_some_and(|(a, _)| cv.entries[a].start > cv.spans[i].0 && row_of(cv.entries[a].start) == i);
            // White space alone at the start of PATH, then `;`: cmd skips it and stops there.
            let cmd_stops = cv.spans[i].0 == 0 && cv.stop == Some(cv.spans[i].1) && ex.iter().all(|&u| crate::resolve::cmd_space(u));
            out.push(f(WARN, if cmd_stops {
                "Leading spaces: cmd skips them and stops reading PATH at the ; after them; PowerShell drops them; programs look for a folder with them in its name."
            } else if cmd_drops { "Leading spaces: cmd (at the start of PATH only) and PowerShell drop them; programs look for a folder with them in its name." } else { "Leading spaces: PowerShell drops them; cmd and programs look for a folder with them in its name." }));
        }
        if ex.last().is_some_and(|&u| crate::resolve::ps_space(u)) {
            out.push(f(WARN, "Trailing spaces: cmd, PowerShell and programs look for a folder with them in its name."));
        }
        // Duplicates: the same text (section 5's equality), else the same folder by identity.
        let earlier = entries[..i].iter().enumerate().find(|(_, x)| !x.empty() && env::same(&x.expanded, &e.expanded));
        let same_id = facts.as_ref().and_then(|fa| fa.id).and_then(|id| input.rows[..i].iter().enumerate().find(|(_, (x, xf))| !x.empty() && xf.as_ref().and_then(|z| z.id) == Some(id)).map(|(j, _)| j));
        if let Some((j, x)) = earlier {
            out.push(f(WARN, format!("#{} repeats #{} ({}): harmless, but the later one never wins.", i + 1, j + 1, x.label())));
        } else if let Some(j) = same_id {
            out.push(f(WARN, format!("#{} is the same folder as #{} under another name (a junction, 8.3 name or subst): the later one never wins.", i + 1, j + 1)));
        }
        if let Some(fa) = facts {
            match &fa.state {
                State::Dead => {
                    if machine && fa.creatable == Some(true) {
                        out.push(f(DANGER, "Not there, and you, or anything running as you, can create this folder: the same risk as a folder you can write to."));
                    } else {
                        out.push(f(WARN, "Dead: the folder is not there."));
                    }
                }
                State::NoDrive => out.push(f(WARN, format!("Dead: the drive {} is not there now (a removed USB drive, or an old letter).", drive_letter(&e.expanded)))),
                State::IsFile => out.push(f(WARN, "A file, not a folder: nothing is found in it.")),
                State::Unknown(why) => out.push(f(UNKNOWN, format!("Unknown: {why}."))),
                State::Folder | State::NotLooked => {}
            }
            if machine && fa.writable == Some(true) {
                let mut s = String::from("You can write here without admin rights. Services and admin programs search Machine PATH too, for programs started by name and for DLLs they cannot find in Windows' folders: anything running as you can drop a file here that later runs as administrator or SYSTEM");
                if sys32_at.is_none_or(|s32| i < s32) {
                    s.push_str(", and it beats Windows' own commands");
                }
                s.push('.');
                out.push(f(DANGER, s));
            }
            match fa.drive {
                Drive::Network => out.push(f(WARN, "On a network share: every lookup that misses waits on the network.")),
                Drive::Mapped if machine => out.push(f(WARN, "On a mapped drive: every lookup that misses waits on the network, and admin programs and services do not have your mapped drives.")),
                Drive::Mapped => out.push(f(WARN, "On a mapped drive: every lookup that misses waits on the network.")),
                Drive::Removable => out.push(f(WARN, "On a removable drive: missing whenever the drive is out.")),
                _ => {}
            }
        }
        rows.push(Row { entry: e.clone(), facts: facts.clone(), findings: out });
    }

    // The values as a whole.
    let mut general = Vec::new();
    let mut mcount = 0;
    let mut ucount = 0;
    for (hive, read) in [(Hive::Machine, input.machine), (Hive::User, input.user)] {
        match read {
            Read::Missing if hive == Hive::User => {}
            Read::Missing => general.push(f(DANGER, "Machine PATH is not there at all.")),
            Read::Error(e) => general.push(f(UNKNOWN, format!("{} PATH could not be read: {e}.", hive.word()))),
            Read::Value(v) => {
                let n = rows.iter().filter(|r| r.entry.hive == hive && !r.entry.empty()).count();
                if hive == Hive::Machine {
                    mcount = n;
                } else {
                    ucount = n;
                }
                match v.kind {
                    Kind::Sz if v.raw.contains(&wide::PERCENT) => general.push(f(WARN, format!("{} PATH is REG_SZ and holds %: Windows does not expand a REG_SZ value: it must be REG_EXPAND_SZ.", hive.word()))),
                    Kind::Other(t) => general.push(f(WARN, format!("{} PATH has registry type {t}, not a string: Windows may skip it.", hive.word()))),
                    _ => {}
                }
                let len = v.raw.len();
                if len == SETX {
                    general.push(f(WARN, format!("{} PATH is exactly 1\u{00A0}024 characters: setx cuts at 1\u{00A0}024, so this one may have been cut.", hive.word())));
                }
                if len > MAX_VAR {
                    general.push(f(DANGER, format!("{} PATH is {} characters, over the limit of 32\u{00A0}767.", hive.word(), thousands(len))));
                } else if len >= WARN_LEN {
                    general.push(f(WARN, format!("{} PATH is {} characters: some installers and older tools cut long values (at 2\u{00A0}048 and over).", hive.word(), thousands(len))));
                }
            }
        }
    }
    if cv.stop_at_start && cv.lost > 0 {
        let hive = if input.machine.value().is_some_and(|v| !v.raw.is_empty()) { Hive::Machine } else { Hive::User };
        let n = plural(cv.lost, "entry", "entries");
        general.push(f(WARN, if cv.lead_semi {
            format!("{} PATH starts with ;: cmd stops reading PATH there and searches none of it ({n}).", hive.word())
        } else {
            format!("{} PATH starts with white space and a ;: cmd skips the white space, stops reading PATH at the ; and searches none of it ({n}).", hive.word())
        }));
    }
    if input.machine.value().is_some() && sys32_at.is_none() {
        general.push(f(DANGER, "System32 is not in Machine PATH: Windows' own commands are not found by name."));
    }
    // PATHEXT: the user's replaces the machine's (only Path is merged).
    let pathext = input.pathext_user.value().or(input.pathext_machine.value());
    match pathext {
        Some(v) => {
            let exts = crate::resolve::pathext_list(&v.raw);
            for need in [".EXE", ".COM"] {
                if !exts.iter().any(|e| eq_ic(e, &w(need))) {
                    general.push(f(DANGER, format!("{need} is not in PATHEXT: cmd finds no {} by its bare name.", if need == ".EXE" { "program" } else { ".COM program" })));
                }
            }
        }
        None if matches!(input.pathext_machine, Read::Missing) && matches!(input.pathext_user, Read::Missing) => general.push(f(DANGER, "PATHEXT is not there: cmd finds no program by its bare name.")),
        None => {}
    }
    // setx PATH %PATH%: Machine entries copied into User PATH.
    let machine_entries: Vec<&Entry> = entries.iter().copied().filter(|e| e.hive == Hive::Machine && !e.empty()).collect();
    let copied = entries.iter().filter(|e| e.hive == Hive::User && !e.empty() && machine_entries.iter().any(|m| env::same(&m.expanded, &e.expanded))).count();
    if copied >= 3 || (copied > 0 && copied == machine_entries.len()) {
        general.push(f(WARN, format!("{copied} Machine PATH entries are repeated in User PATH: the `setx PATH %PATH%` mistake (Machine PATH copied into User PATH).")));
    }
    // The merged length (expanded), and whether Windows built the same.
    let merged_len = {
        let parts: Vec<&W> = entries.iter().map(|e| &e.expanded).collect();
        let raw_join: usize = parts.iter().map(|p| p.len()).sum::<usize>() + parts.len().saturating_sub(1);
        input.built.as_ref().map(|b| b.len()).unwrap_or(raw_join)
    };
    if merged_len > MAX_VAR {
        general.push(f(DANGER, format!("The merged PATH is {} characters, over the limit of 32\u{00A0}767 for one variable: new programs may get no PATH at all.", thousands(merged_len))));
    } else if merged_len >= WARN_LEN {
        general.push(f(WARN, format!("The merged PATH is {} characters: some installers and older tools cut long values (at 2\u{00A0}048 and over).", thousands(merged_len))));
    }
    if let Some(built) = &input.built {
        let ours: Vec<W> = entries.iter().filter(|e| !e.empty()).map(|e| e.expanded.clone()).collect();
        let theirs = env::entries(built);
        let missing: Vec<String> = ours.iter().filter(|o| !theirs.iter().any(|t| env::same(t, o))).map(|o| wide::shown(o, 120)).collect();
        let extra: Vec<String> = theirs.iter().filter(|t| !ours.iter().any(|o| env::same(t, o))).map(|t| wide::shown(t, 120)).collect();
        if !missing.is_empty() || !extra.is_empty() {
            let mut d = Vec::new();
            if !missing.is_empty() {
                d.push(format!("left out {}", missing.join(", ")));
            }
            if !extra.is_empty() {
                d.push(format!("added {}", extra.join(", ")));
            }
            general.push(f(WARN, format!("Windows built PATH differently: {}.", d.join("; "))));
        }
    }
    let all = rows.iter().flat_map(|r| r.findings.iter()).chain(general.iter());
    let (dangers, warnings) = all.fold((0, 0), |(d, wn), x| (d + usize::from(x.level == DANGER), wn + usize::from(x.level == WARN)));
    let checking = rows.iter().filter(|r| r.facts.is_none() && !r.entry.empty()).count();
    let mut header = format!(
        "Machine {} · User {} · merged {} of 32\u{00A0}767 characters · {} · {}",
        plural(mcount, "entry", "entries"),
        ucount,
        thousands(merged_len),
        plural(dangers, "danger", "dangers"),
        plural(warnings, "warning", "warnings")
    );
    if checking > 0 {
        header.push_str(" · Checking…");
    }
    Report { rows, general, header, dangers, warnings, checking, merged_len }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn drive_letter(p: &[u16]) -> String {
    let s = wide::lossy(p);
    s.get(..2).unwrap_or("").to_string()
}
