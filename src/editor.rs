//! The PATH editor (SPEC section 6): one hive's entries as typed, the edits, Tidy, and the diff
//! the Preview shows. Pure. Entries stay as typed (`%VARS%` kept); nothing here touches the
//! registry.

use crate::env::{self, Hive};
use crate::wide::{self, W, eq_ic};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Editor {
    pub hive: Hive,
    /// The value as loaded (type and raw text): what Apply checks the registry still holds.
    pub loaded: Option<env::Value>,
    /// The entries as typed, in order, empty ones included (the value's ends too, so an
    /// unchanged list writes back the very same text).
    pub entries: Vec<W>,
    /// The value holds text after its first NUL (only the part before is shown): it can't be
    /// changed here (RVD5). Set by whoever read it (`PathRead::hidden`).
    pub hidden: bool,
}

impl Editor {
    pub fn new(hive: Hive, loaded: Option<env::Value>) -> Editor {
        let entries = match &loaded {
            Some(v) if !v.raw.is_empty() => wide::split_semi(&v.raw),
            _ => Vec::new(),
        };
        Editor { hive, loaded, entries, hidden: false }
    }

    /// The value the editor would write.
    pub fn value(&self) -> W {
        self.entries.join(&wide::SEMI)
    }

    /// The entries no longer give the value as loaded: an edit was made (a type alone is none).
    pub fn edited(&self) -> bool {
        self.loaded.as_ref().map_or(&[][..], |v| v.raw.as_slice()) != self.value().as_slice()
    }

    pub fn changed(&self) -> bool {
        self.loaded.as_ref().map(|v| v.raw.as_slice()) != Some(self.value().as_slice()) || self.loaded.as_ref().is_some_and(|v| v.kind != env::Kind::ExpandSz)
    }

    /// Move entry `i` up (`up`) or down; the new index.
    pub fn shift(&mut self, i: usize, up: bool) -> usize {
        if up && i > 0 && i < self.entries.len() {
            self.entries.swap(i, i - 1);
            return i - 1;
        }
        if !up && i + 1 < self.entries.len() {
            self.entries.swap(i, i + 1);
            return i + 1;
        }
        i
    }

    pub fn remove(&mut self, i: usize) {
        if i < self.entries.len() {
            self.entries.remove(i);
        }
    }

    /// Add an entry after `after` (or at the end); its index.
    pub fn add(&mut self, entry: W, after: Option<usize>) -> usize {
        let at = after.map(|a| (a + 1).min(self.entries.len())).unwrap_or(self.entries.len());
        // An empty last entry (the value ended with `;`) stays last.
        let at = if after.is_none() && self.entries.last().is_some_and(|e| e.is_empty()) && !self.entries.is_empty() { self.entries.len() - 1 } else { at };
        self.entries.insert(at, entry);
        at
    }

    /// Entry `i` without the control and direction characters no PATH value may carry
    /// (`helper::bad_char`).
    pub fn clean(&mut self, i: usize) {
        if let Some(e) = self.entries.get_mut(i) {
            e.retain(|&u| !crate::helper::bad_char(u));
        }
    }

    /// The first entry holding such a character, and how many entries do.
    pub fn first_bad(&self) -> Option<(usize, usize)> {
        let bad: Vec<usize> = self.entries.iter().enumerate().filter(|(_, e)| e.iter().any(|&u| crate::helper::bad_char(u))).map(|(i, _)| i).collect();
        bad.first().map(|&i| (i, bad.len()))
    }

    pub fn edit(&mut self, i: usize, entry: W) {
        if let Some(e) = self.entries.get_mut(i) {
            *e = entry;
        }
    }

    /// Move entry `from` to just before entry `before` (Prepare the fix).
    pub fn move_before(&mut self, from: usize, before: usize) {
        if from >= self.entries.len() || before >= self.entries.len() || from == before {
            return;
        }
        let e = self.entries.remove(from);
        let at = if from < before { before - 1 } else { before };
        self.entries.insert(at, e);
    }

    /// Tidy: remove dead entries, repeats (the same text, or the same folder by identity, after
    /// an earlier entry of this hive, or for User PATH one Machine PATH already has) and empty
    /// ones. The first stays; an entry whose state is unknown, or on a drive that is not there
    /// now, is never removed. What was removed, as typed.
    pub fn tidy(&mut self, fact: &dyn Fn(&W) -> Tidy, machine_entries: &[W]) -> Vec<W> {
        let mut kept: Vec<(W, Tidy)> = Vec::new();
        let mut removed = Vec::new();
        for e in std::mem::take(&mut self.entries) {
            if e.is_empty() {
                removed.push(e);
                continue;
            }
            let t = fact(&e);
            let repeat = kept.iter().any(|(_, kt)| env::same(&kt.expanded, &t.expanded) || (t.id.is_some() && kt.id == t.id))
                || (self.hive == Hive::User && machine_entries.iter().any(|m| env::same(m, &t.expanded)));
            if (t.dead || repeat) && !t.unknown {
                removed.push(e);
                continue;
            }
            kept.push((e, t));
        }
        self.entries = kept.into_iter().map(|(e, _)| e).collect();
        removed
    }
}

/// What Tidy knows of one entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tidy {
    pub expanded: W,
    pub dead: bool,
    /// Access denied, a silent share, a drive that is not there now: never removed.
    pub unknown: bool,
    pub id: Option<(u64, [u8; 16])>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    Same,
    Added,
    Removed,
    Moved,
}

impl Mark {
    pub fn sign(self) -> &'static str {
        match self {
            Mark::Same => " ",
            Mark::Added => "+",
            Mark::Removed => "−",
            Mark::Moved => "↕",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffLine {
    pub mark: Mark,
    pub text: W,
}

fn key(e: &[u16]) -> W {
    let n = env::norm(e);
    n.iter().map(|&u| if (b'a' as u16..=b'z' as u16).contains(&u) { u - 32 } else { u }).collect()
}

/// The old and new values as lines: unchanged, added, removed (at its old place) and moved
/// (an entry both have, out of the longest run kept in order). Empty entries are not lines.
pub fn diff(old: &[W], new: &[W]) -> Vec<DiffLine> {
    let o: Vec<&W> = old.iter().filter(|e| !e.is_empty()).collect();
    let n: Vec<&W> = new.iter().filter(|e| !e.is_empty()).collect();
    let ok: Vec<W> = o.iter().map(|e| key(e)).collect();
    let nk: Vec<W> = n.iter().map(|e| key(e)).collect();
    // Longest common subsequence (the lists are short: at most a few hundred entries).
    let (a, b) = (ok.len(), nk.len());
    let mut t = vec![vec![0u16; b + 1]; a + 1];
    for i in (0..a).rev() {
        for j in (0..b).rev() {
            t[i][j] = if eq_ic(&ok[i], &nk[j]) { t[i + 1][j + 1] + 1 } else { t[i + 1][j].max(t[i][j + 1]) };
        }
    }
    let mut in_lcs_old = vec![false; a];
    let mut in_lcs_new = vec![false; b];
    let (mut i, mut j) = (0, 0);
    while i < a && j < b {
        if eq_ic(&ok[i], &nk[j]) {
            in_lcs_old[i] = true;
            in_lcs_new[j] = true;
            i += 1;
            j += 1;
        } else if t[i + 1][j] > t[i][j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    // Out of the run kept in order: an old entry and a new one with the same key are one entry
    // moved (paired one to one, so a removed repeat stays a removal); the rest are removed or
    // added.
    let mut moved_old = vec![false; a];
    let mut moved_new = vec![false; b];
    for j in (0..b).filter(|&j| !in_lcs_new[j]) {
        if let Some(i) = (0..a).find(|&i| !in_lcs_old[i] && !moved_old[i] && eq_ic(&ok[i], &nk[j])) {
            moved_old[i] = true;
            moved_new[j] = true;
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < a || j < b {
        if i < a && !in_lcs_old[i] {
            // Gone, or moved (then it shows at its new place).
            if !moved_old[i] {
                out.push(DiffLine { mark: Mark::Removed, text: o[i].clone() });
            }
            i += 1;
            continue;
        }
        if j < b && !in_lcs_new[j] {
            out.push(DiffLine { mark: if moved_new[j] { Mark::Moved } else { Mark::Added }, text: n[j].clone() });
            j += 1;
            continue;
        }
        if i < a && j < b {
            out.push(DiffLine { mark: Mark::Same, text: n[j].clone() });
            i += 1;
            j += 1;
        } else {
            break;
        }
    }
    out
}

/// "removed 2, moved 1, added 1" (or "no change").
pub fn summary(lines: &[DiffLine]) -> String {
    let c = |m: Mark| lines.iter().filter(|l| l.mark == m).count();
    let parts: Vec<String> = [(Mark::Removed, "removed"), (Mark::Moved, "moved"), (Mark::Added, "added")].iter().filter(|(m, _)| c(*m) > 0).map(|(m, w)| format!("{w} {}", c(*m))).collect();
    if parts.is_empty() { "no change".into() } else { parts.join(", ") }
}
