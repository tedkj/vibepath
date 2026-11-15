//! The file system as the resolver and the PATH table see it (SPEC sections 2 and 5): each
//! candidate checked with `GetFileAttributesExW` on the exact path, a folder on a network share
//! given 3 s (on its own thread: a dead share takes ~21 s to fail), App Paths read from the
//! registry, and the facts the PATH table judges an entry by. Only NotFound on the exact path
//! is "not there"; access denied or a share's silence is unknown.

use crate::env::{self, Hive};
use crate::resolve::{AppPath, Lookup, Probe};
use crate::wide::{self, W, w};
use std::time::Duration;

/// How long a network folder gets to answer.
pub const SHARE_WAIT: Duration = Duration::from_secs(3);

/// Errors that say a name is not there (no such file or folder, or a name that cannot be).
pub fn not_there(code: u32) -> bool {
    matches!(code, 2 | 3 | 123 | 161 | 206)
}

/// The drive a path is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drive {
    Local,
    /// A UNC path (`\\server\share`).
    Network,
    /// A mapped network drive letter.
    Mapped,
    Removable,
    /// A drive letter that is not there now.
    NoDrive,
    /// A relative path, or one Windows did not say.
    Unknown,
}

pub fn drive_of(p: &[u16]) -> Drive {
    let s = wide::lossy(p);
    let b = s.as_bytes();
    if s.starts_with(r"\\?\UNC\") || (s.starts_with(r"\\") && !s.starts_with(r"\\?\") && !s.starts_with(r"\\.\")) {
        return Drive::Network;
    }
    let rest = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let rb = rest.as_bytes();
    if rb.len() >= 2 && rb[0].is_ascii_alphabetic() && rb[1] == b':' {
        let root = w(&format!("{}:\\", rb[0] as char));
        // SAFETY: a NUL-terminated root.
        let t = unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(wide::z(&root).as_ptr()) };
        return match t {
            1 => Drive::NoDrive,
            2 => Drive::Removable,
            4 => Drive::Mapped,
            3 | 5 | 6 => Drive::Local,
            _ => Drive::Unknown,
        };
    }
    let _ = b;
    Drive::Unknown
}

/// The form a path is asked for in. Up to 259 units, the path as it is. A longer one fails as
/// "not there" (error 3 or 206) in an app that is not long-path aware, which VibePath is not, so
/// Tidy would call a working entry dead (FS28, X15WFS-10). It is asked for as a `\\?\` path
/// instead (`\\?\UNC\` for a share), after `GetFullPathNameW` has done what that form skips
/// (slashes, `.` and `..`, trailing dots and spaces). A path already in `\\?\` or `\\.\` form,
/// or one that does not resolve to a drive or share path, is left as it is.
pub fn probe_form(p: &[u16]) -> W {
    const MAX_PATH: usize = 260;
    let s = wide::lossy(p);
    if p.len() < MAX_PATH || s.starts_with(r"\\?\") || s.starts_with(r"\\.\") {
        return p.to_vec();
    }
    let z = wide::z(p);
    let mut buf: W = vec![0; 32_768];
    // SAFETY: a NUL-terminated path in, a buffer of the length passed out.
    let n = unsafe { windows_sys::Win32::Storage::FileSystem::GetFullPathNameW(z.as_ptr(), buf.len() as u32, buf.as_mut_ptr(), std::ptr::null_mut()) } as usize;
    if n == 0 || n >= buf.len() {
        return p.to_vec();
    }
    buf.truncate(n);
    let full = wide::lossy(&buf);
    let fb = full.as_bytes();
    if let Some(share) = full.strip_prefix(r"\\") {
        if share.starts_with(r"?\") || share.starts_with(r".\") {
            return p.to_vec();
        }
        let mut out = w(r"\\?\UNC\");
        out.extend_from_slice(&buf[2..]);
        return out;
    }
    if fb.len() >= 3 && fb[0].is_ascii_alphabetic() && fb[1] == b':' && fb[2] == b'\\' {
        let mut out = w(r"\\?\");
        out.extend_from_slice(&buf);
        return out;
    }
    p.to_vec()
}

/// One `GetFileAttributesExW` on the exact path (a long one in its `\\?\` form, `probe_form`):
/// Ok(Some(attributes)), Ok(None) when not there, Err(words) when it could not be told.
pub fn attributes(p: &[u16]) -> Result<Option<u32>, String> {
    use windows_sys::Win32::Storage::FileSystem::{GetFileAttributesExW, GetFileExInfoStandard, WIN32_FILE_ATTRIBUTE_DATA};
    let z = wide::z(&probe_form(p));
    let mut d: WIN32_FILE_ATTRIBUTE_DATA = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and the struct the call fills.
    if unsafe { GetFileAttributesExW(z.as_ptr(), GetFileExInfoStandard, (&mut d as *mut WIN32_FILE_ATTRIBUTE_DATA).cast()) } != 0 {
        return Ok(Some(d.dwFileAttributes));
    }
    let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    if not_there(code) { Ok(None) } else { Err(reason(code)) }
}

/// A failure in the words the list shows.
pub fn reason(code: u32) -> String {
    match code {
        5 => "access denied".into(),
        21 => "the drive is not ready".into(),
        53 | 67 | 1231 | 1232 | 64 | 59 => "the network path could not be reached".into(),
        1326 | 1244 | 86 => "the share asks for a sign-in".into(),
        c => crate::host::code_words(c),
    }
}

/// The name as the folder spells it (`FindFirstFileExW`; None when the folder cannot be listed).
fn real_name(p: &[u16]) -> Option<W> {
    use windows_sys::Win32::Storage::FileSystem::{FindClose, FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW, WIN32_FIND_DATAW};
    let z = wide::z(&probe_form(p));
    let mut d: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated name with no wildcards (the input refuses * and ?).
    let h = unsafe { FindFirstFileExW(z.as_ptr(), FindExInfoBasic, (&mut d as *mut WIN32_FIND_DATAW).cast(), FindExSearchNameMatch, std::ptr::null(), 0) };
    if h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return None;
    }
    unsafe { FindClose(h) };
    let n = d.cFileName.iter().position(|&u| u == 0).unwrap_or(d.cFileName.len());
    Some(d.cFileName[..n].to_vec())
}

fn probe_each(cands: &[W]) -> Result<Vec<Probe>, String> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT};
    let mut out = Vec::with_capacity(cands.len());
    for c in cands {
        out.push(match attributes(c)? {
            None => Probe::Missing,
            Some(a) if a & FILE_ATTRIBUTE_DIRECTORY != 0 => Probe::Dir,
            Some(a) => Probe::File { reparse: a & FILE_ATTRIBUTE_REPARSE_POINT != 0, name: real_name(c) },
        });
    }
    Ok(out)
}

/// Run `f` on its own thread and wait at most `wait`; the thread is left to finish on its own.
pub fn timed<T: Send + 'static>(wait: Duration, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(wait).ok()
}

fn needs_timer(dir: &[u16]) -> bool {
    matches!(drive_of(dir), Drive::Network | Drive::Mapped | Drive::Unknown)
}

/// The real file system and registry.
pub struct RealFs;

impl Lookup for RealFs {
    fn probe_all(&self, dir: &[u16], cands: &[W]) -> Result<Vec<Probe>, String> {
        if !needs_timer(dir) {
            return probe_each(cands);
        }
        let c = cands.to_vec();
        timed(SHARE_WAIT, move || probe_each(&c)).unwrap_or_else(|| Err(format!("the share did not answer in {} s", SHARE_WAIT.as_secs())))
    }

    fn app_paths(&self, name: &[u16]) -> Vec<AppPath> {
        use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        let mut out = Vec::new();
        for (hive, root) in [(Hive::Machine, HKEY_LOCAL_MACHINE), (Hive::User, HKEY_CURRENT_USER)] {
            let key = format!(r"Software\Microsoft\Windows\CurrentVersion\App Paths\{}", wide::lossy(name));
            if name.iter().any(|&u| (0xD800..0xE000).contains(&u)) {
                continue; // a key name with a lone surrogate cannot be asked for
            }
            let env::Read::Value(v) = env::sys::read_value(root, &key, "", false) else { continue };
            let target = strip_quotes(&env::sys::expand(&v.raw));
            if target.is_empty() {
                continue;
            }
            let extra = match env::sys::read_value(root, &key, "Path", false) {
                env::Read::Value(p) if !p.raw.is_empty() => Some(env::sys::expand(&p.raw)),
                _ => None,
            };
            let missing = matches!(attributes(&target), Ok(None));
            out.push(AppPath { hive, target, extra_path: extra, missing });
        }
        out
    }
}

/// An App Paths default value as a path: surrounding quotes and spaces stripped (some
/// installers write `"C:\x\y.exe"`).
pub fn strip_quotes(v: &[u16]) -> W {
    let t: W = v.iter().copied().skip_while(|&u| u == b' ' as u16).collect();
    let t: W = t.iter().rev().copied().skip_while(|&u| u == b' ' as u16).collect::<W>().into_iter().rev().collect();
    if t.len() >= 2 && t[0] == wide::QUOTE
        && let Some(end) = t[1..].iter().position(|&u| u == wide::QUOTE) {
            return t[1..1 + end].to_vec();
        }
    t
}

/// What a PATH entry is on disk (section 5), from the expanded entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Folder,
    IsFile,
    /// NotFound on the exact path, its parent answering.
    Dead,
    /// The drive letter is not there now.
    NoDrive,
    /// Could not be told: why.
    Unknown(String),
    /// Not looked at (a relative entry).
    NotLooked,
}

/// The facts the PATH table judges one entry by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    pub state: State,
    pub drive: Drive,
    /// The folder's identity (volume serial, 128-bit id), when it opened.
    pub id: Option<(u64, [u8; 16])>,
    /// Machine PATH only: this user (without admin) can add files or folders there.
    pub writable: Option<bool>,
    /// Machine PATH, a dead entry: the nearest existing parent lets this user make folders.
    pub creatable: Option<bool>,
}

fn folder_id(p: &[u16]) -> Option<(u64, [u8; 16])> {
    use std::os::windows::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new().share_mode(7).custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS).access_mode(0x80).open(wide::path(p)).ok()?;
    crate::fileinfo::sys::file_id(&f).filter(|(v, id)| *v != 0 && *id != [0; 16])
}

fn is_absolute(p: &[u16]) -> bool {
    let s = wide::lossy(p);
    let b = s.as_bytes();
    (b.len() >= 3 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')) || s.starts_with(r"\\") || s.starts_with("//")
}

fn facts_now(expanded: &[u16], machine: bool) -> Facts {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY;
    let drive = drive_of(expanded);
    let mut f = Facts { state: State::NotLooked, drive, id: None, writable: None, creatable: None };
    if !is_absolute(expanded) {
        return f;
    }
    if drive == Drive::NoDrive {
        f.state = State::NoDrive;
        return f;
    }
    let p = env::norm(expanded);
    f.state = match attributes(&p) {
        Ok(Some(a)) if a & FILE_ATTRIBUTE_DIRECTORY != 0 => State::Folder,
        Ok(Some(_)) => State::IsFile,
        Ok(None) => {
            // Dead only when its parent answers (exists or is itself not there).
            not_there_state(attributes(&wide::parent(&p)))
        }
        Err(e) => State::Unknown(e),
    };
    if f.state == State::Folder {
        f.id = folder_id(&p);
        if machine {
            f.writable = crate::acl::user_can_add(&p).ok();
        }
    }
    if f.state == State::Dead && machine {
        // The nearest parent that is there.
        let mut cur = wide::parent(&p);
        for _ in 0..64 {
            match attributes(&cur) {
                Ok(Some(_)) => {
                    f.creatable = crate::acl::user_can_make_folder(&cur).ok();
                    break;
                }
                Ok(None) => {
                    let up = wide::parent(&cur);
                    if up == cur || up.is_empty() {
                        break;
                    }
                    cur = up;
                }
                Err(_) => break,
            }
        }
    }
    f
}

/// An entry that is not there, by its parent's answer: dead when the parent answered (there, or
/// itself not there); unknown when the parent could not be asked (VIBEWARE "Unknown is its own
/// answer": only NotFound with its folder answering means gone).
pub fn not_there_state(parent: Result<Option<u32>, String>) -> State {
    match parent {
        Ok(_) => State::Dead,
        Err(e) => State::Unknown(e),
    }
}

/// The facts for one expanded entry; a network or mapped one gets `SHARE_WAIT`.
pub fn facts(expanded: &[u16], machine: bool) -> Facts {
    if !needs_timer(expanded) || !is_absolute(expanded) {
        return facts_now(expanded, machine);
    }
    let drive = drive_of(expanded);
    let e = expanded.to_vec();
    timed(SHARE_WAIT, move || facts_now(&e, machine)).unwrap_or(Facts {
        state: State::Unknown(format!("the share did not answer in {} s", SHARE_WAIT.as_secs())),
        drive,
        id: None,
        writable: None,
        creatable: None,
    })
}
