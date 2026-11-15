//! Live checks for the developer, in a dev-hooks build only (never shipped). They run inside
//! Windows Sandbox (its own registry and Explorer), never against Ted's real PATH.
//!
//! `--dev-path-set <hive> <file> <out>`: the app's own Apply (journal, original copy, write or
//! the elevated helper, read back, broadcast, Explorer's PATH 2 s later) with the new value
//! read from `<file>` (UTF-8), the outcome written to `<out>`.
//! `--dev-undo <out>`: Undo of the newest change that was done (not an undo), the same way.

use crate::controller::{ApplyJob, apply_job};
use crate::env::{Hive, Kind};
use crate::system::System;
use std::ffi::OsString;
use std::path::PathBuf;

/// The dev command, if `args` is one: its exit code.
pub fn run(args: &[OsString]) -> Option<i32> {
    let a: Vec<String> = args.iter().map(|x| x.to_string_lossy().into_owned()).collect();
    match a.first().map(String::as_str) {
        Some("--dev-path-set") if a.len() == 4 => Some(path_set(&a[1], &a[2], &a[3])),
        Some("--dev-undo") if a.len() == 2 => Some(undo(&a[1])),
        Some(x) if x.starts_with("--dev-") => Some(2),
        _ => None,
    }
}

fn home() -> PathBuf {
    std::env::var_os("VIBEPATH_DEV_HOME").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join("local")
}

fn path_set(hive: &str, file: &str, out: &str) -> i32 {
    let hive = if hive.eq_ignore_ascii_case("machine") { Hive::Machine } else { Hive::User };
    let Ok(new) = std::fs::read_to_string(file) else { return 2 };
    let sys = crate::system::Real;
    let store = crate::journal::open(home().join("journal.json"));
    let jkey = crate::journal::key(&sys.machine_guid(), &sys.user_sid());
    let expected = sys.read(hive, "Path").value().cloned();
    let job = ApplyJob { hive, expected, new: crate::wide::w(new.trim_end_matches(['\r', '\n'])), kind: Kind::ExpandSz, undoes: None, record: None, delete: false, note: "dev".into() };
    let stop = std::sync::atomic::AtomicBool::new(false);
    let r = apply_job(&sys, &store, &jkey, Some(&home()), &job, crate::host::active_window(), &stop);
    let _ = std::fs::write(out, format!("{r:?}\n"));
    0
}

fn undo(out: &str) -> i32 {
    let sys = crate::system::Real;
    let store = crate::journal::open(home().join("journal.json"));
    let jkey = crate::journal::key(&sys.machine_guid(), &sys.user_sid());
    let Some(e) = store.load().of(&jkey).into_iter().rev().find(|e| e.state == "done" && e.undoes.is_none()) else { return 2 };
    let Some(hive) = e.hive() else { return 2 };
    let now = sys.read(hive, "Path");
    let r = match crate::journal::undo(&e, &now) {
        Err(why) => format!("refused: {why}"),
        Ok(back) => {
            let job = ApplyJob { hive, expected: now.value().cloned(), new: back.as_ref().map(|v| v.raw.clone()).unwrap_or_default(), kind: back.as_ref().map_or(Kind::ExpandSz, |v| v.kind.restored()), undoes: Some(e.id), record: crate::journal::record_id(&e), delete: back.is_none(), note: "undo".into() };
            let stop = std::sync::atomic::AtomicBool::new(false);
            format!("{:?}", apply_job(&sys, &store, &jkey, Some(&home()), &job, crate::host::active_window(), &stop))
        }
    };
    let _ = std::fs::write(out, format!("{r}\n"));
    0
}
