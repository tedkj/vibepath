//! A small JSON file the app remembers things in (theme, window choices, recent entries).
//! Missing or garbled means defaults, but a garbled file is never written over: the first save
//! keeps it aside as `prefs.json.broken` (replacing an older copy; VibeBackup BA-3), and the
//! window says so (a file that turns garbled while the window is open too: `take_garbled`). A
//! `stamped` store (VibePath's journal.json, RL2-4) never replaces an older copy: each one is
//! kept under its own name, `journal.json.broken-<yyyyMMdd-HHmmss>` (`-2`, `-3`… in one second). A
//! file that is there but cannot be read right now is never overwritten. The window's changes
//! are kept as changes, not as a merged value: every write reads the file afresh and puts the
//! unwritten changes onto what it read, so another instance's prefs stay, even when this window
//! started on defaults because the file could not be read then (R2-TRACE-1, R2-SCAN-1). Writes
//! happen off the UI thread, whole or not at all.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// One change of this window's to the prefs (set a field, remember an entry), applied onto the
/// newest prefs right before each write.
pub type Change<T> = Arc<dyn Fn(&mut T) + Send + Sync>;

pub struct Store<T> {
    path: PathBuf,
    /// This window's changes that are not in the file yet, oldest first.
    changes: Arc<Mutex<Vec<Change<T>>>>,
    /// This window's prefs as last loaded or written: what the changes go onto when the file is
    /// missing or garbled.
    own: Arc<Mutex<T>>,
    write: Arc<Mutex<()>>,
    /// `load` found the file garbled.
    broken: Arc<AtomicBool>,
    /// The garbled file `load` found (told at start); cleared once a good file is written.
    noted: Arc<AtomicBool>,
    /// A garbled file was kept aside and the good one not written yet.
    aside: Arc<AtomicBool>,
    /// A garbled file was kept aside and replaced that nobody has told the user about yet.
    garbled_new: Arc<AtomicBool>,
    /// No file at all (a portable copy on a stick that cannot be written): the changes live in
    /// memory for this run only.
    memory: bool,
    /// `stamped`: the time stamp a garbled copy's name gets (None: `.broken`, replaced).
    stamp: Option<fn() -> String>,
    /// Where the last garbled file was kept (what the window names).
    kept: Arc<Mutex<Option<PathBuf>>>,
    /// How many keeps have set `kept`, counted under its lock: a `load` that read a garble
    /// clears the name only when no keep came after its read (RI3-4).
    keeps: Arc<AtomicU64>,
}

impl<T> Clone for Store<T> {
    fn clone(&self) -> Self {
        Store {
            path: self.path.clone(),
            changes: self.changes.clone(),
            own: self.own.clone(),
            write: self.write.clone(),
            broken: self.broken.clone(),
            noted: self.noted.clone(),
            aside: self.aside.clone(),
            garbled_new: self.garbled_new.clone(),
            memory: self.memory,
            stamp: self.stamp,
            kept: self.kept.clone(),
            keeps: self.keeps.clone(),
        }
    }
}

/// A lock that a panic elsewhere does not turn into a second one (the test rigs flush in Drop).
fn lock<X>(m: &Mutex<X>) -> MutexGuard<'_, X> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Where a garbled file is kept: `prefs.json.broken`.
pub fn broken_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".broken");
    path.with_file_name(name)
}

/// A rename that never goes over a file there (no `MOVEFILE_REPLACE_EXISTING`: the new name is
/// made only when free, like a create-new), write-through: Err(the Win32 code).
pub fn move_new(from: &Path, to: &Path) -> Result<(), u32> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
    let z = |p: &Path| p.as_os_str().encode_wide().chain([0]).collect::<Vec<u16>>();
    let (from, to) = (z(from), z(to));
    // SAFETY: NUL-terminated paths. No MOVEFILE_REPLACE_EXISTING: a file there stays.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } != 0 {
        return Ok(());
    }
    // SAFETY: right after the failed call.
    Err(unsafe { GetLastError() })
}

/// Defaults when the file is missing or garbled; an error when it is there but unreadable now.
pub fn read<T: DeserializeOwned + Default>(path: &Path) -> std::io::Result<T> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(serde_json::from_str(&t).unwrap_or_default()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.kind() == std::io::ErrorKind::InvalidData => Ok(T::default()),
        Err(e) => Err(e),
    }
}

/// Whole or not at all: a crash mid-write leaves the old file. The temp file is this process's
/// own (named by its id, and made create-new), so neither a second instance writing at the same
/// moment nor a file of the user's that happens to have its name is ever written into or
/// removed: a name already taken moves on to the next.
pub fn write_atomic(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let pid = std::process::id();
    let mut n = 0;
    let (tmp, mut file) = loop {
        let tmp = path.with_extension(if n == 0 { format!("{pid}.tmp") } else { format!("{pid}-{n}.tmp") });
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 20 => n += 1,
            Err(e) => return Err(e),
        }
    };
    // On the disk before it takes the name (the journal's record must survive a power cut).
    let r = file.write_all(body).and_then(|_| file.sync_all());
    drop(file);
    let r = r.and_then(|_| std::fs::rename(&tmp, path));
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

impl<T: Serialize + DeserializeOwned + Default + Clone + PartialEq + Send + 'static> Store<T> {
    pub fn new(path: PathBuf) -> Store<T> {
        Store {
            path,
            changes: Default::default(),
            own: Default::default(),
            write: Default::default(),
            broken: Default::default(),
            noted: Default::default(),
            aside: Default::default(),
            garbled_new: Default::default(),
            memory: false,
            stamp: None,
            kept: Default::default(),
            keeps: Default::default(),
        }
    }

    /// Each garbled file kept under its own name, never over an older one (RL2-4):
    /// `<name>.broken-<stamp()>`, then `-2`, `-3`… while that is taken (no cap).
    pub fn stamped(self, stamp: fn() -> String) -> Store<T> {
        Store { stamp: Some(stamp), ..self }
    }

    /// Where the last garbled file was kept aside (None: none yet).
    pub fn kept_aside(&self) -> Option<PathBuf> {
        lock(&self.kept).clone()
    }

    /// The garbled file moved aside: `.broken` (replacing an older one), or for a `stamped`
    /// store a name of its own, never over a file there.
    fn keep_aside(&self) -> Option<PathBuf> {
        let Some(stamp) = self.stamp else {
            let to = broken_path(&self.path);
            return std::fs::rename(&self.path, &to).is_ok().then_some(to);
        };
        let mut base = broken_path(&self.path).into_os_string();
        base.push(format!("-{}", stamp()));
        let mut n = 1u64;
        loop {
            let mut to = base.clone();
            if n > 1 {
                to.push(format!("-{n}"));
            }
            let to = PathBuf::from(to);
            match move_new(&self.path, &to) {
                Ok(()) => return Some(to),
                Err(windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS | windows_sys::Win32::Foundation::ERROR_FILE_EXISTS) => n += 1,
                Err(_) => return None,
            }
        }
    }

    /// A store with no file: defaults at start, changes kept in memory, nothing ever written.
    pub fn memory() -> Store<T> {
        Store { memory: true, ..Store::new(PathBuf::new()) }
    }

    /// No file behind it (`memory`).
    pub fn in_memory(&self) -> bool {
        self.memory
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The prefs, defaults when missing, garbled or unreadable now. Reads only; a garbled file
    /// is noted (`broken`) and kept aside by the first write.
    pub fn load(&self) -> T {
        if self.memory {
            return lock(&self.own).clone();
        }
        // Before the read: a keep counted after this kept what this read may have seen.
        let keeps = self.keeps.load(Ordering::SeqCst);
        let v = match std::fs::read(&self.path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|_| {
                self.broken.store(true, Ordering::Relaxed);
                self.noted.store(true, Ordering::SeqCst);
                // This garble is not kept anywhere yet: a copy kept before holds an older one,
                // so the window must not name it (RL4-1). The next keep sets it again. Unless a
                // save beside this load kept it after the read (RI3-4): then the name is this
                // garble's copy, and stays.
                let mut kept = lock(&self.kept);
                if self.keeps.load(Ordering::SeqCst) == keeps {
                    *kept = None;
                }
                T::default()
            }),
            Err(_) => T::default(),
        };
        *lock(&self.own) = v.clone();
        v
    }

    /// `load` found the file garbled (the window tells the user).
    pub fn broken(&self) -> bool {
        self.broken.load(Ordering::Relaxed)
    }

    /// Whether a garbled file was kept aside and replaced since this was last asked (not the one
    /// `load` found at start, which the window tells by `broken`): the window says so once.
    pub fn take_garbled(&self) -> bool {
        self.garbled_new.swap(false, Ordering::SeqCst)
    }

    /// One change of this window's: kept until it is in the file, and written now (`flush`). Call
    /// it off the UI thread (it reads the file).
    pub fn change(&self, f: Change<T>) {
        lock(&self.changes).push(f);
        self.flush();
    }

    /// Write the unwritten changes: read the file afresh, put every change onto it in order,
    /// write the result, and only then forget the changes. While the file cannot be read nothing
    /// is written and the changes wait for the next write (one still waiting at exit is lost:
    /// never this window's defaults over a file it could not read). A garbled file is kept aside
    /// first (never written over), and a garbled or missing one is replaced by this window's
    /// own prefs with the changes.
    pub fn flush(&self) {
        let _w = lock(&self.write);
        let _ = self.write_changes();
    }

    /// One change that must be in the file before the caller goes on (the journal's record of a
    /// PATH change, SOL-PATH-1): written now with whatever else waits, or, when the file cannot
    /// be written, taken back out (it never lands later) and why in words. A memory store
    /// (the announced read-only portable mode) always takes it.
    pub fn save(&self, f: Change<T>) -> Result<(), String> {
        let _w = lock(&self.write);
        lock(&self.changes).push(f.clone());
        let r = self.write_changes();
        if r.is_err() {
            lock(&self.changes).retain(|c| !Arc::ptr_eq(c, &f));
        }
        r
    }

    /// `flush` under the write lock: Ok once nothing of this window's waits.
    fn write_changes(&self) -> Result<(), String> {
        let n = lock(&self.changes).len();
        if n == 0 {
            return Ok(());
        }
        if self.memory {
            let todo: Vec<Change<T>> = lock(&self.changes).drain(..n).collect();
            let mut own = lock(&self.own);
            for f in &todo {
                f(&mut own);
            }
            return Ok(());
        }
        let base = match std::fs::read(&self.path) {
            Ok(b) => match serde_json::from_slice::<T>(&b) {
                Ok(v) => Ok(v),
                // Garbled: kept aside (`keep_aside`), never written over.
                Err(_) => match self.keep_aside() {
                    Some(to) => {
                        let mut kept = lock(&self.kept);
                        *kept = Some(to);
                        self.keeps.fetch_add(1, Ordering::SeqCst);
                        drop(kept);
                        self.aside.store(true, Ordering::SeqCst);
                        Ok(lock(&self.own).clone())
                    }
                    None => Err("it is damaged and could not be kept aside".to_string()),
                },
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(lock(&self.own).clone()),
            Err(e) => Err(format!("it cannot be read now: {e}")),
        };
        let mut v = base?;
        let todo: Vec<Change<T>> = lock(&self.changes)[..n].to_vec();
        for f in &todo {
            f(&mut v);
        }
        let body = serde_json::to_vec_pretty(&v).map_err(|e| e.to_string())?;
        write_atomic(&self.path, &body).map_err(|e| format!("it cannot be written now: {e}"))?;
        lock(&self.changes).drain(..n);
        *lock(&self.own) = v;
        // Kept aside and replaced: now it is true to say so (unless it is the one told at start).
        if self.aside.swap(false, Ordering::SeqCst) && !self.noted.load(Ordering::SeqCst) {
            self.garbled_new.store(true, Ordering::SeqCst);
        }
        self.noted.store(false, Ordering::SeqCst);
        Ok(())
    }
}
