//! Everything the controller asks of Windows, behind one trait so the window tests run on a
//! fake PC (`fake::FakeSystem`) and never touch the registry. Every call here may block (the
//! registry, the file system, other processes' memory, the UAC prompt): workers only.

use crate::env::{self, Env, Hive};
use crate::fileinfo::Details;
use crate::fsprobe::Facts;
use crate::helper::{Outcome, Request};
use crate::peb::{ProcEnv, ProcList};
use crate::resolve::Lookup;
use crate::wide::W;
use std::sync::atomic::AtomicBool;

pub trait System: Send + Sync {
    /// A hive's `Path` or `PATHEXT`, raw.
    fn read(&self, hive: Hive, name: &str) -> env::Read;
    /// The environment Windows builds for a program started now.
    fn new_window(&self) -> Result<Env, String>;
    /// This app's own environment and current folder.
    fn own_env(&self) -> Env;
    fn own_cwd(&self) -> Option<W>;
    fn profile_dir(&self) -> W;
    /// System32, the Windows folder, `<Windows>\System`.
    fn system_dirs(&self) -> (W, W, W);
    /// `%VARS%` expanded for this user.
    fn expand(&self, raw: &[u16]) -> W;
    fn lookup(&self) -> &dyn Lookup;
    /// An App Execution Alias at `path` (None: not one, or not readable; the words why).
    fn alias(&self, path: &[u16]) -> Result<crate::alias::Alias, String>;
    /// The detail panel's facts for a file (`read_from`: an alias's target).
    fn details(&self, path: &[u16], read_from: &[u16]) -> Details;
    /// The identity, size and time of a file (the details cache's key).
    fn cache_key(&self, path: &[u16]) -> Option<crate::fileinfo::CacheKey>;
    /// What a PATH entry is on disk.
    fn facts(&self, expanded: &[u16], machine: bool) -> Facts;
    /// The processes, with whose they are, and what Windows would not say about them.
    fn processes(&self) -> ProcList;
    fn process_image(&self, pid: u32) -> Option<W>;
    fn process_env(&self, pid: u32, start: u64) -> Result<ProcEnv, String>;
    /// Write User PATH as `kind` (REG_EXPAND_SZ; REG_SZ only for an Undo of a value that was
    /// one), no admin.
    fn write_user_path(&self, raw: &[u16], kind: env::Kind) -> Result<(), u32>;
    /// Remove User PATH (Undo of a change that made it).
    fn delete_user_path(&self) -> Result<(), u32>;
    /// Whether a hive's Path holds text after its first NUL, which `read` leaves out (FED2).
    fn path_holds_more(&self, hive: Hive) -> bool;
    /// Machine PATH through the elevated helper (blocks while the UAC prompt is up).
    fn machine_path_set(&self, r: &Request, hwnd: isize, stop: &AtomicBool) -> Outcome;
    /// WM_SETTINGCHANGE "Environment" to every window.
    fn broadcast(&self) -> bool;
    fn machine_guid(&self) -> String;
    fn user_sid(&self) -> String;
    /// Unix milliseconds now.
    fn now_ms(&self) -> u64;
    /// A file (not a folder) is at `p` (the Add field's "a file means its folder").
    fn is_file(&self, p: &[u16]) -> bool;
    /// Write a file whole (`new_only`: the original .reg copy, `new_copy`): Ok(false) when
    /// `new_only` and a copy is there that is not cut short (left as it is); a copy cut short is
    /// set aside, never over another, and written again.
    fn write_file(&self, path: &std::path::Path, bytes: &[u8], new_only: bool) -> Result<bool, String>;
    /// Wait (the 2 s before Explorer is asked); the fake does not.
    fn pause(&self, ms: u64);
}

/// This PC.
pub struct Real;

impl System for Real {
    fn read(&self, hive: Hive, name: &str) -> env::Read {
        env::sys::read(hive, name)
    }
    fn new_window(&self) -> Result<Env, String> {
        env::sys::new_window()
    }
    fn own_env(&self) -> Env {
        env::sys::own()
    }
    fn own_cwd(&self) -> Option<W> {
        env::sys::own_cwd()
    }
    fn profile_dir(&self) -> W {
        env::sys::profile_dir()
    }
    fn system_dirs(&self) -> (W, W, W) {
        env::sys::system_dirs()
    }
    fn expand(&self, raw: &[u16]) -> W {
        env::sys::expand(raw)
    }
    fn lookup(&self) -> &dyn Lookup {
        &crate::fsprobe::RealFs
    }
    fn alias(&self, path: &[u16]) -> Result<crate::alias::Alias, String> {
        match crate::alias::read(path)? {
            Ok(a) => Ok(a),
            Err(crate::alias::Bad::OtherTag(t)) => Err(format!("another kind of reparse point (tag {t:#010X})")),
            Err(crate::alias::Bad::Malformed(why)) => Err(format!("an alias VibePath cannot read ({why})")),
        }
    }
    fn details(&self, path: &[u16], read_from: &[u16]) -> Details {
        crate::fileinfo::sys::details(path, read_from)
    }
    fn cache_key(&self, path: &[u16]) -> Option<crate::fileinfo::CacheKey> {
        crate::fileinfo::sys::cache_key(path)
    }
    fn facts(&self, expanded: &[u16], machine: bool) -> Facts {
        crate::fsprobe::facts(expanded, machine)
    }
    fn processes(&self) -> ProcList {
        crate::peb::sys::list()
    }
    fn process_image(&self, pid: u32) -> Option<W> {
        crate::peb::sys::image(pid)
    }
    fn process_env(&self, pid: u32, start: u64) -> Result<ProcEnv, String> {
        crate::peb::sys::read(pid, start)
    }
    fn write_user_path(&self, raw: &[u16], kind: env::Kind) -> Result<(), u32> {
        env::sys::write_path(Hive::User, raw, kind)
    }
    fn delete_user_path(&self) -> Result<(), u32> {
        use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RegDeleteKeyValueW};
        let k = crate::wide::z(&crate::wide::w("Environment"));
        let n = crate::wide::z(&crate::wide::w("Path"));
        // SAFETY: NUL-terminated names.
        let r = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, k.as_ptr(), n.as_ptr()) };
        if r == 0 || r == 2 { Ok(()) } else { Err(r) }
    }
    fn path_holds_more(&self, hive: Hive) -> bool {
        env::sys::holds_more(hive)
    }
    fn machine_path_set(&self, r: &Request, hwnd: isize, stop: &AtomicBool) -> Outcome {
        crate::helper::run(r, hwnd, stop)
    }
    fn broadcast(&self) -> bool {
        crate::broadcast::environment_changed()
    }
    fn machine_guid(&self) -> String {
        env::sys::machine_guid()
    }
    fn user_sid(&self) -> String {
        env::sys::user_sid()
    }
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }
    fn is_file(&self, p: &[u16]) -> bool {
        matches!(crate::fsprobe::attributes(p), Ok(Some(a)) if a & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY == 0)
    }
    fn write_file(&self, path: &std::path::Path, bytes: &[u8], new_only: bool) -> Result<bool, String> {
        if new_only {
            new_copy(path, bytes)
        } else {
            crate::prefs::write_atomic(path, bytes).map(|_| true).map_err(|e| e.to_string())
        }
    }
    fn pause(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// The original .reg copy (RPS-4): Ok(false) when one is there already (left as it is). Only one
/// cut short (`regfile::cut_short`: empty or unfinished, a crash before this was done by a
/// rename, or a NUL unit anywhere: data a power cut lost) is kept aside as `<name>.broken` (`.broken-2`… when taken: never over one, RL-2) and
/// written anew; one saved again or edited elsewhere stays. The copy is written to a temp file,
/// flushed, and only then takes its name, write-through and never over a file that is there,
/// so the name only ever holds a whole copy.
pub fn new_copy(path: &std::path::Path, bytes: &[u8]) -> Result<bool, String> {
    use std::io::Write;
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
    // A rename write-through and never over a file there: Err(the Win32 code).
    let moved = crate::prefs::move_new;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    match std::fs::read(path) {
        Ok(b) if !crate::regfile::cut_short(&b) => return Ok(false),
        Ok(_) => {
            let broken = crate::prefs::broken_path(path);
            let mut n = 1;
            loop {
                let mut to = broken.clone().into_os_string();
                if n > 1 {
                    to.push(format!("-{n}"));
                }
                match moved(path, std::path::Path::new(&to)) {
                    Ok(()) => break,
                    Err(ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS) if n < 20 => n += 1,
                    Err(code) => return Err(format!("a copy cut short is there and could not be kept aside: {}", crate::host::code_words(code))),
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    let pid = std::process::id();
    let mut n = 0;
    let (tmp, mut f) = loop {
        let tmp = path.with_extension(format!("{pid}-{n}.tmp"));
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 20 => n += 1,
            Err(e) => return Err(e.to_string()),
        }
    };
    let r = f.write_all(bytes).and_then(|_| f.sync_all());
    drop(f);
    let r = r.map_err(|e| e.to_string()).and_then(|_| match moved(&tmp, path) {
        Ok(()) => Ok(true),
        Err(ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS) => Ok(false),
        Err(code) => Err(crate::host::code_words(code)),
    });
    if r != Ok(true) {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}
