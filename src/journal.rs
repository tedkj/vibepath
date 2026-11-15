//! The journal (SPEC section 6): every PATH change, written "pending" before it is made and
//! "done" or "failed" after, in `journal.json` beside the app's local state. Per PC by its
//! MachineGuid and per user by SID (a portable stick's journal holds several). It follows the
//! state-file rules through `prefs::Store`: an unreadable file is never written over (the
//! changes wait in memory), a garbled one is kept aside and told: each as
//! `journal.json.broken-<yyyyMMdd-HHmmss>`, never over an older one (`open`, RL2-4).
//!
//! Undo writes an entry's old value back only while the value is still what the entry wrote.

use crate::env::{self, Hive, Kind};
use crate::wide::{self, W};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The most entries kept per PC and user (the oldest go; the original .reg files stay).
pub const KEEP: usize = 200;

/// A value as the journal keeps it: its registry type and its text. Text that is not valid
/// UTF-16 (a lone surrogate) is kept as its exact units in `units`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Value {
    pub kind: u32,
    pub raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub units: Option<Vec<u16>>,
}

impl Value {
    pub fn of(v: &env::Value) -> Value {
        match String::from_utf16(&v.raw) {
            Ok(s) => Value { kind: v.kind.code(), raw: s, units: None },
            Err(_) => Value { kind: v.kind.code(), raw: wide::lossy(&v.raw), units: Some(v.raw.clone()) },
        }
    }

    pub fn exact(&self) -> W {
        self.units.clone().unwrap_or_else(|| wide::w(&self.raw))
    }

    pub fn to_env(&self) -> env::Value {
        env::Value { kind: Kind::from_code(self.kind), raw: self.exact() }
    }

    /// The same type and the very same text.
    pub fn equals(&self, v: &env::Value) -> bool {
        Kind::from_code(self.kind) == v.kind && self.exact() == v.raw
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    /// Unique within its key (unix milliseconds, bumped on a clash).
    pub id: u64,
    /// Unix seconds.
    pub at: i64,
    /// "machine" or "user".
    pub hive: String,
    /// The value before (None: there was none).
    pub before: Option<Value>,
    /// The value after (None: the change removed it: Undo of a change that made User PATH).
    pub after: Option<Value>,
    /// "pending", "done", "failed", "declined", "refused", "unknown".
    pub state: String,
    /// The outcome in words.
    pub note: String,
    /// For an undo or a restore: the entry it went back to.
    pub undoes: Option<u64>,
    /// Machine PATH: the helper's own record of the change (32 hex digits), set when it was
    /// done. An Undo names it; the helper trusts its record, not this file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
}

impl Entry {
    pub fn hive(&self) -> Option<Hive> {
        match self.hive.as_str() {
            "machine" => Some(Hive::Machine),
            "user" => Some(Hive::User),
            _ => None,
        }
    }
}

pub fn hive_key(h: Hive) -> &'static str {
    match h {
        Hive::Machine => "machine",
        Hive::User => "user",
    }
}

/// The file: each PC's and user's entries under "<MachineGuid>|<SID>".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Journal {
    pub pcs: BTreeMap<String, Vec<Entry>>,
}

impl Journal {
    pub fn of(&self, key: &str) -> Vec<Entry> {
        self.pcs.get(key).cloned().unwrap_or_default()
    }

    /// Add or replace (by id) one entry; at most `KEEP` stay.
    pub fn put(&mut self, key: &str, e: Entry) {
        let v = self.pcs.entry(key.to_string()).or_default();
        match v.iter_mut().find(|x| x.id == e.id) {
            Some(x) => *x = e,
            None => v.push(e),
        }
        if v.len() > KEEP {
            let n = v.len() - KEEP;
            v.drain(..n);
        }
    }
}

pub type Store = crate::prefs::Store<Journal>;

/// The journal's store at `path`: a garbled file is kept as `journal.json.broken-<yyyyMMdd-HHmmss>`
/// (local time; `-2`, `-3`… in the same second), never over an older copy (RL2-4): each holds
/// the before-values of the changes it kept.
pub fn open(path: std::path::PathBuf) -> Store {
    Store::new(path).stamped(crate::host::file_stamp_now)
}

pub fn key(machine_guid: &str, sid: &str) -> String {
    format!("{machine_guid}|{sid}")
}

/// A new entry's id: unix milliseconds, past every id the key has.
pub fn next_id(existing: &[Entry], now_ms: u64) -> u64 {
    existing.iter().map(|e| e.id + 1).max().unwrap_or(0).max(now_ms)
}

/// Whether an entry can be undone now, and to what; why not, in words.
pub fn undo(e: &Entry, now: &env::Read) -> Result<Option<env::Value>, String> {
    if e.state != "done" {
        return Err("Only a change that was done can be undone.".into());
    }
    let now_v = match now {
        env::Read::Value(v) => Some(v),
        env::Read::Missing => None,
        env::Read::Error(why) => return Err(format!("PATH could not be read now ({why}).")),
    };
    let still = match (&e.after, now_v) {
        (Some(a), Some(v)) => a.equals(v),
        // It removed the value, and the value is still not there.
        (None, None) => true,
        _ => false,
    };
    if !still {
        return Err("PATH changed since: Undo would throw that away.".into());
    }
    if e.before.is_none() && e.hive() == Some(Hive::Machine) {
        return Err("Machine PATH was not there before: Undo would remove it.".into());
    }
    if e.hive() == Some(Hive::Machine) && record_id(e).is_none() {
        return Err(NO_RECORD.into());
    }
    Ok(e.before.as_ref().map(Value::to_env))
}

/// Why a Machine PATH change without the helper's record cannot be undone.
pub const NO_RECORD: &str = "The helper kept no record of this Machine PATH change (it was made before VibePath kept one, or it did not finish): Undo is off.";

/// The helper's record of a Machine PATH change, as the entry names it.
pub fn record_id(e: &Entry) -> Option<crate::records::Id> {
    e.record.as_deref().and_then(crate::records::parse_hex)
}

/// The one-line summary of an entry ("removed 2, moved 1").
pub fn summary(e: &Entry) -> String {
    let old = e.before.as_ref().map(|b| wide::split_semi(&b.exact())).unwrap_or_default();
    let mut s = match &e.after {
        None => "the value removed".to_string(),
        Some(after) => {
            let new = wide::split_semi(&after.exact());
            let mut s = crate::editor::summary(&crate::editor::diff(&old, &new));
            if e.before.as_ref().is_some_and(|b| b.kind != after.kind) {
                s = if s == "no change" { String::new() } else { format!("{s}, ") };
                s.push_str(&format!("{} to {}", Kind::from_code(e.before.as_ref().map(|b| b.kind).unwrap_or(0)).word(), Kind::from_code(after.kind).word()));
            }
            s
        }
    };
    if e.undoes.is_some() {
        s = format!("Undo: {s}");
    }
    s
}

/// The name of the first .reg copy of a hive's PATH on this PC for this user:
/// `original-<hive>-path-<8 hex of MachineGuid and SID>.reg` (several PCs share a portable
/// stick's folder; the file is made create-new, never overwritten).
pub fn original_name(h: Hive, machine_guid: &str, sid: &str) -> String {
    let mut x: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key(machine_guid, sid).bytes() {
        x ^= u64::from(b);
        x = x.wrapping_mul(0x0000_0100_0000_01B3);
    }
    format!("original-{}-path-{:08x}.reg", hive_key(h), x >> 32)
}
