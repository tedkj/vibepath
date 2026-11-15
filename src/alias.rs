//! App Execution Aliases (SPEC section 3): the zero-byte reparse points in
//! `%LOCALAPPDATA%\Microsoft\WindowsApps` (`IO_REPARSE_TAG_APPEXECLINK`) that start a Store
//! app's program. The buffer is parsed strictly (every length checked, at most 16 KiB); the
//! reader opens the link itself, never its target, with no data access.

use crate::wide::{self, W, w};

pub const TAG_APPEXECLINK: u32 = 0x8000_001B;
/// MAXIMUM_REPARSE_DATA_BUFFER_SIZE.
pub const MAX_BUFFER: usize = 16 * 1024;

/// What an alias says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alias {
    pub version: u32,
    pub package: W,
    pub app_id: W,
    pub target: W,
    /// Version 3's fourth string (the app type), when there.
    pub app_type: Option<W>,
}

/// Why a reparse buffer is not a readable alias.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bad {
    /// Another kind of reparse point (a symlink, OneDrive's): its tag.
    OtherTag(u32),
    /// Short, lengths that do not add up, a string without its NUL, an empty package or target.
    Malformed(&'static str),
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
}

/// A REPARSE_DATA_BUFFER as an alias: tag, data length (u16), reserved (u16), then the data:
/// version (u32) and NUL-terminated UTF-16 strings (package family, app user model id, target
/// exe, and from version 3 the app type).
pub fn parse(buf: &[u8]) -> Result<Alias, Bad> {
    if buf.len() > MAX_BUFFER {
        return Err(Bad::Malformed("larger than a reparse point can be"));
    }
    let tag = u32_at(buf, 0).ok_or(Bad::Malformed("shorter than its header"))?;
    if tag != TAG_APPEXECLINK {
        return Err(Bad::OtherTag(tag));
    }
    let len = buf.get(4..6).map(|x| u16::from_le_bytes([x[0], x[1]]) as usize).ok_or(Bad::Malformed("shorter than its header"))?;
    let data = buf.get(8..8 + len).ok_or(Bad::Malformed("its data runs past the buffer"))?;
    let version = u32_at(data, 0).ok_or(Bad::Malformed("no version"))?;
    if data.len() % 2 != 0 {
        return Err(Bad::Malformed("an odd number of bytes"));
    }
    let units: Vec<u16> = data[4..].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let mut strings: Vec<W> = Vec::new();
    let mut at = 0usize;
    while at < units.len() && strings.len() < 4 {
        let Some(end) = units[at..].iter().position(|&u| u == 0) else {
            return Err(Bad::Malformed("a string without its end"));
        };
        strings.push(units[at..at + end].to_vec());
        at += end + 1;
    }
    if strings.len() < 3 {
        return Err(Bad::Malformed("fewer strings than an alias has"));
    }
    let mut it = strings.into_iter();
    let (package, app_id, target) = (it.next().unwrap_or_default(), it.next().unwrap_or_default(), it.next().unwrap_or_default());
    if package.is_empty() || target.is_empty() {
        return Err(Bad::Malformed("an empty package or target"));
    }
    let app_type = if version >= 3 { it.next().filter(|t| !t.is_empty()) } else { None };
    Ok(Alias { version, package, app_id, target, app_type })
}

/// What an alias is, for the row and the summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The Store's Python stub (App Installer's redirector): not Python.
    PythonStub,
    /// The Store's Python 3.x ("3.12"): real Python, through an alias.
    StorePython(String),
    /// The Python install manager.
    PythonManager,
    /// Any other package's alias.
    Other,
}

pub const STUB_PACKAGE: &str = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe";
pub const STUB_TARGET: &str = "AppInstallerPythonRedirector.exe";

pub fn kind(a: &Alias) -> Kind {
    let pkg = wide::lossy(&a.package);
    if wide::eq_ic(&a.package, &w(STUB_PACKAGE)) && wide::eq_ic(wide::file_name(&a.target), &w(STUB_TARGET)) {
        return Kind::PythonStub;
    }
    let lower = pkg.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("pythonsoftwarefoundation.python.") {
        let ver: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        let ver = ver.trim_end_matches('.').to_string();
        if !ver.is_empty() {
            return Kind::StorePython(ver);
        }
    }
    if lower.starts_with("pythonsoftwarefoundation.pythonmanager") {
        return Kind::PythonManager;
    }
    Kind::Other
}

/// The package family as shown: up to its `_publisher` part.
pub fn package_name(a: &Alias) -> String {
    let p = wide::shown(&a.package, 120);
    match p.rfind('_') {
        Some(i) if i > 0 => p[..i].to_string(),
        _ => p,
    }
}

/// The row's words for an alias.
pub fn words(a: &Alias) -> String {
    match kind(a) {
        Kind::PythonStub => "the Microsoft Store stub, not Python".into(),
        Kind::StorePython(v) => format!("the Store's Python {v}: real Python, through an alias"),
        Kind::PythonManager => "Python install manager".into(),
        Kind::Other => format!("App Execution Alias of {}", package_name(a)),
    }
}

/// Read the alias at `path`: opened as a reparse point with no data access, its buffer asked
/// with `FSCTL_GET_REPARSE_POINT`. Err: it could not be opened or asked (in words), or its
/// buffer is not an alias.
#[cfg(windows)]
pub fn read(path: &[u16]) -> Result<Result<Alias, Bad>, String> {
    read_raw(path).map(|b| parse(&b))
}

#[cfg(windows)]
pub fn read_raw(path: &[u16]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
    let p = wide::z(path);
    // SAFETY: a NUL-terminated path; no access asked (the reparse point itself, never its
    // target); closed below.
    let h = unsafe { CreateFileW(p.as_ptr(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, std::ptr::null_mut()) };
    if h == INVALID_HANDLE_VALUE {
        return Err(crate::host::code_words(unsafe { GetLastError() }));
    }
    let mut buf = vec![0u8; MAX_BUFFER];
    let mut got = 0u32;
    // SAFETY: a 16 KiB out buffer; the handle is ours.
    let ok = unsafe { DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, std::ptr::null(), 0, buf.as_mut_ptr().cast(), buf.len() as u32, &mut got, std::ptr::null_mut()) } != 0;
    let err = unsafe { GetLastError() };
    unsafe { CloseHandle(h) };
    if !ok {
        return Err(crate::host::code_words(err));
    }
    buf.truncate((got as usize).min(MAX_BUFFER));
    Ok(buf)
}
