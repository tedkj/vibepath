//! Machine PATH, in a short-lived elevated helper (SPEC section 7; the VibeLink and VibePrint
//! pattern). The app never runs elevated for this, not even when it was started elevated (one
//! code path). It creates a named pipe first (`\\.\pipe\vibepath-<128-bit random hex>`, one
//! instance, first instance only, remote clients rejected, a DACL for the current user's SID
//! only), then relaunches its own exe from its final path with `ShellExecuteExW` verb `runas`:
//! `VibePath.exe --helper machine-path-set <pipe>` (one UAC prompt; declining changes nothing).
//! The client must be that very process (`GetNamedPipeClientProcessId` against the PID
//! ShellExecuteEx returned) running this very exe (`QueryFullProcessImageNameW`, compared by file
//! identity); the helper connects at identification level and checks the server the same way.
//!
//! One job, no free paths: `machine-path-set` {expected type, expected raw value, new raw value}.
//! The helper reads Machine `Path` itself and refuses unless type and text equal the expected
//! ones exactly; refuses a new value over 32 766 units, with a control or bidi character, with no
//! entry equal to System32, or empty; writes REG_EXPAND_SZ to that one value; reads it back; and
//! answers done, refused or failed, each with the value as it is now. A watchdog ends it at 30 s.
//! The app treats every byte from the pipe as untrusted (`Decoder`: sizes capped per kind, order
//! enforced, parsed strictly), writes the journal and broadcasts.
//!
//! Undo is the helper's own memory, not the journal's: before every write the helper records
//! the value it is replacing and the one it writes (`records`, in an admin-only key) and answers
//! the record's id with Done. An Undo names that id; the helper refuses unless its record says
//! it wrote exactly the expected value over exactly the value the app asks back. No record (or
//! records it cannot trust) is no Undo, said so, never a silent restore.

use crate::env::{self, Kind};
use crate::records::{Id, Records};
use crate::wide::W;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How long the app waits for the helper to connect (the UAC prompt may sit there).
pub const CONNECT_WAIT: Duration = Duration::from_secs(120);
/// The helper ends itself at this age whatever happens.
pub const HARD_LIMIT: Duration = Duration::from_secs(30);
pub const PIPE_PREFIX: &str = r"\\.\pipe\vibepath-";
pub const JOB: &str = "machine-path-set";
/// The longest value one environment variable can hold (32 767 with its NUL).
pub const MAX_NEW: usize = 32_766;
/// The longest current value the helper and app pass around (a value can be over the limit).
pub const MAX_VALUE: usize = 65_536;

const KIND_HELLO: u8 = 1;
const KIND_DONE: u8 = 2;
const KIND_REFUSED: u8 = 3;
const KIND_FAILED: u8 = 4;
const KIND_REQUEST: u8 = 0x10;
const JOB_BYTE: u8 = 1;
/// The value-now's type code when it was not there or could not be read.
const NO_VALUE: u32 = u32::MAX;

pub const MAX_REQUEST: usize = 1 + 16 + 4 + 4 + 2 * MAX_VALUE + 1 + 16 + 4 + 2 * MAX_NEW;
/// Done: nonce, record id, value now. Refused and Failed: nonce, code, value now.
pub const MAX_ANSWER: usize = 16 + 16 + 4 + 4 + 2 * MAX_VALUE;

/// Why the helper refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Changed = 1,
    TooLong = 2,
    BadChar = 3,
    NoSystem32 = 4,
    Empty = 5,
    Unreadable = 6,
    /// An Undo the helper has no record of.
    NotRecorded = 7,
    /// An Undo that is not what the helper's record says it changed.
    NotAsRecorded = 8,
    /// The helper's records could not be read, written or trusted.
    NoRecords = 9,
}

pub const REASONS: [Reason; 9] = [Reason::Changed, Reason::TooLong, Reason::BadChar, Reason::NoSystem32, Reason::Empty, Reason::Unreadable, Reason::NotRecorded, Reason::NotAsRecorded, Reason::NoRecords];

impl Reason {
    pub fn words(self) -> &'static str {
        match self {
            Reason::Changed => "Machine PATH changed since you opened it (another program?)",
            Reason::TooLong => "the new value is over 32 766 characters",
            Reason::BadChar => "the new value holds a control or direction character",
            Reason::NoSystem32 => "the new value has no entry for System32",
            Reason::Empty => "the new value is empty",
            Reason::Unreadable => "the helper could not read Machine PATH",
            Reason::NotRecorded => "the helper has no record of that change on this PC (made before VibePath kept one, or on another PC), so it cannot undo it",
            Reason::NotAsRecorded => "that change is not what the helper recorded (the journal in your profile was changed since?); nothing was written",
            Reason::NoRecords => "the helper's own undo records (HKLM\\SOFTWARE\\VibePath) could not be read, written or trusted",
        }
    }
}

/// The job's request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// None: Machine PATH is expected not to be there (Apply then creates it).
    pub expected: Option<env::Value>,
    pub new: W,
    /// An Undo: the helper's record of the change it undoes (the app's journal is not trusted).
    pub undo: Option<Id>,
}

/// The value as the helper read it after: None when it was not there or not readable.
pub type Now = Option<env::Value>;

/// What the helper answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Written; the helper's record of this change (what an Undo of it names).
    Done(Now, Id),
    Refused(Reason, Now),
    /// The write failed (its Win32 code; 0: it read back differently).
    Failed(u32, Now),
}

fn put_value(out: &mut Vec<u8>, kind: u32, units: &[u16]) {
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(units.len() as u32).to_le_bytes());
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
}

fn put_now(out: &mut Vec<u8>, now: &Now) {
    match now {
        Some(v) => put_value(out, v.kind.code(), &v.raw[..v.raw.len().min(MAX_VALUE)]),
        None => put_value(out, NO_VALUE, &[]),
    }
}

/// Reads a (type, units) pair at `at`; the next offset.
fn get_value(b: &[u8], at: usize, max: usize) -> Option<(u32, W, usize)> {
    let kind = u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?);
    let n = u32::from_le_bytes(b.get(at + 4..at + 8)?.try_into().ok()?) as usize;
    if n > max {
        return None;
    }
    let bytes = b.get(at + 8..at + 8 + n * 2)?;
    Some((kind, bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect(), at + 8 + n * 2))
}

pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn hello(pid: u32) -> Vec<u8> {
    frame(KIND_HELLO, &pid.to_le_bytes())
}

/// The app's request: the job, a nonce, the expected value and the new one.
pub fn request(nonce: &[u8; 16], r: &Request) -> Vec<u8> {
    let mut b = vec![JOB_BYTE];
    b.extend_from_slice(nonce);
    match &r.expected {
        Some(e) => put_value(&mut b, e.kind.code(), &e.raw[..e.raw.len().min(MAX_VALUE)]),
        None => put_value(&mut b, NO_VALUE, &[]),
    }
    match &r.undo {
        Some(id) => {
            b.push(1);
            b.extend_from_slice(id);
        }
        None => b.push(0),
    }
    b.extend_from_slice(&(r.new.len() as u32).to_le_bytes());
    for u in &r.new {
        b.extend_from_slice(&u.to_le_bytes());
    }
    frame(KIND_REQUEST, &b)
}

/// The helper's reading of a request payload. None for anything not exactly one.
pub fn parse_request(b: &[u8]) -> Option<([u8; 16], Request)> {
    if b.len() > MAX_REQUEST || b.first() != Some(&JOB_BYTE) {
        return None;
    }
    let nonce: [u8; 16] = b.get(1..17)?.try_into().ok()?;
    let (kind, expected, at) = get_value(b, 17, MAX_VALUE)?;
    let (undo, at) = match b.get(at)? {
        0 => (None, at + 1),
        1 => (Some(b.get(at + 1..at + 17)?.try_into().ok()?), at + 17),
        _ => return None,
    };
    let n = u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize;
    if n > MAX_NEW + 1 {
        return None;
    }
    let bytes = b.get(at + 4..at + 4 + n * 2)?;
    if at + 4 + n * 2 != b.len() {
        return None;
    }
    let new = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    // "Not there" carries no text.
    let expected = if kind == NO_VALUE {
        if !expected.is_empty() {
            return None;
        }
        None
    } else {
        Some(env::Value { kind: Kind::from_code(kind), raw: expected })
    };
    Some((nonce, Request { expected, new, undo }))
}

pub fn answer(nonce: &[u8; 16], a: &Answer) -> Vec<u8> {
    let mut p = nonce.to_vec();
    let kind = match a {
        Answer::Done(now, id) => {
            p.extend_from_slice(id);
            put_now(&mut p, now);
            KIND_DONE
        }
        Answer::Refused(r, now) => {
            p.extend_from_slice(&(*r as u32).to_le_bytes());
            put_now(&mut p, now);
            KIND_REFUSED
        }
        Answer::Failed(code, now) => {
            p.extend_from_slice(&code.to_le_bytes());
            put_now(&mut p, now);
            KIND_FAILED
        }
    };
    frame(kind, &p)
}

/// A message from the helper as the app decodes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    Hello { pid: u32 },
    Answer(Answer),
}

/// Reads the helper's messages out of the byte stream. Strict: an unknown kind, a size over its
/// cap or not its own, a message before Hello, a second Hello, an answer to another request
/// (nonce), an unknown reason, a malformed value, anything after the answer: the stream is
/// broken for good (the helper is ours, so anything else means someone else).
pub struct Decoder {
    nonce: [u8; 16],
    buf: Vec<u8>,
    hello: bool,
    ended: bool,
    broken: bool,
}

impl Decoder {
    pub fn new(nonce: [u8; 16]) -> Decoder {
        Decoder { nonce, buf: Vec::new(), hello: false, ended: false, broken: false }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Msg>, String> {
        if self.broken {
            return Err("the helper's stream was already broken".into());
        }
        if self.ended && !bytes.is_empty() {
            return self.fail("bytes after its answer".into());
        }
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 5 {
                break;
            }
            if self.ended {
                return self.fail("bytes after its answer".into());
            }
            let kind = self.buf[0];
            let len = u32::from_le_bytes(self.buf[1..5].try_into().unwrap()) as usize;
            let fits = match kind {
                KIND_HELLO => len == 4,
                KIND_DONE => (16 + 16 + 8..=MAX_ANSWER).contains(&len),
                KIND_REFUSED | KIND_FAILED => (16 + 12..=16 + 12 + 2 * MAX_VALUE).contains(&len),
                k => return self.fail(format!("an unknown message ({k})")),
            };
            if !fits {
                return self.fail(format!("a message of {len} bytes (kind {kind})"));
            }
            if self.buf.len() < 5 + len {
                break;
            }
            let p: Vec<u8> = self.buf[5..5 + len].to_vec();
            self.buf.drain(..5 + len);
            let m = self.message(kind, &p)?;
            out.push(m);
        }
        if self.ended && !self.buf.is_empty() {
            return self.fail("bytes after its answer".into());
        }
        Ok(out)
    }

    fn now(&mut self, p: &[u8], at: usize) -> Result<Now, String> {
        match get_value(p, at, MAX_VALUE) {
            Some((kind, units, end)) if end == p.len() => {
                if kind == NO_VALUE {
                    if units.is_empty() { Ok(None) } else { self.fail("a missing value with text".into()) }
                } else {
                    Ok(Some(env::Value { kind: Kind::from_code(kind), raw: units }))
                }
            }
            _ => self.fail("a value that is not in shape".into()),
        }
    }

    fn message(&mut self, kind: u8, p: &[u8]) -> Result<Msg, String> {
        if kind != KIND_HELLO && !self.hello {
            return self.fail("a message before hello".into());
        }
        if kind == KIND_HELLO {
            if self.hello {
                return self.fail("a second hello".into());
            }
            self.hello = true;
            return Ok(Msg::Hello { pid: u32::from_le_bytes(p[..4].try_into().unwrap()) });
        }
        if p[..16] != self.nonce {
            return self.fail("an answer to another request".into());
        }
        let a = match kind {
            KIND_DONE => {
                let id: Id = p[16..32].try_into().unwrap();
                Answer::Done(self.now(p, 32)?, id)
            }
            KIND_REFUSED => {
                let code = u32::from_le_bytes(p[16..20].try_into().unwrap());
                let Some(r) = REASONS.into_iter().find(|r| *r as u32 == code) else { return self.fail(format!("an unknown refusal ({code})")) };
                Answer::Refused(r, self.now(p, 20)?)
            }
            _ => {
                let code = u32::from_le_bytes(p[16..20].try_into().unwrap());
                Answer::Failed(code, self.now(p, 20)?)
            }
        };
        self.ended = true;
        Ok(Msg::Answer(a))
    }

    fn fail<T>(&mut self, why: String) -> Result<T, String> {
        self.broken = true;
        self.buf.clear();
        Err(format!("the helper sent {why}"))
    }
}

/// The helper's arguments: `--helper machine-path-set <pipe>`, the pipe exactly as the app
/// makes it.
pub fn parse_args(args: &[String]) -> Option<String> {
    let [flag, job, pipe] = args else { return None };
    if flag != "--helper" || job != JOB {
        return None;
    }
    let hex = pipe.strip_prefix(PIPE_PREFIX)?;
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    Some(pipe.clone())
}

pub fn pipe_name(random: &[u8; 16]) -> String {
    format!("{PIPE_PREFIX}{}", random.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

pub type FileIdent = (u64, [u8; 16]);

/// Two identities are one file: equal, and neither the serial nor the id is zero.
pub(crate) fn same_id(a: FileIdent, b: FileIdent) -> bool {
    a == b && a.0 != 0 && a.1 != [0; 16]
}

pub(crate) fn fallback_id(serial: u32, index_high: u32, index_low: u32) -> FileIdent {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&((u64::from(index_high) << 32) | u64::from(index_low)).to_le_bytes());
    (u64::from(serial), id)
}

pub(crate) fn strip_verbatim(p: &[u16]) -> Option<Vec<u16>> {
    let s = String::from_utf16(p).ok()?;
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return Some(format!(r"\\{rest}").encode_utf16().collect());
    }
    let rest = s.strip_prefix(r"\\?\")?;
    let b = rest.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\').then(|| rest.encode_utf16().collect())
}

/// Why the helper ended before it connected, from its exit code (the helper's own codes: 5 the
/// pipe or its server was wrong, 3 not elevated). Another administrator's credentials at the
/// prompt run it as that account, which the pipe (this user's SID only) refuses: code 5.
pub fn gone_before_connect(exit: Option<u32>) -> String {
    match exit {
        Some(5) => "the helper could not reach VibePath (another administrator's credentials?): run VibePath in an administrator's session".into(),
        Some(3) => "Windows started the helper without administrator rights".into(),
        _ => "the helper ended before it connected".into(),
    }
}

/// Characters a PATH value must never carry: controls, and the bidirectional ones that make it
/// read otherwise than it is.
pub fn bad_char(u: u16) -> bool {
    u < 0x20 || u == 0x7F || (0x80..0xA0).contains(&u) || matches!(u, 0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069)
}

/// The `bad_char`s an entry holds, each once, in order, as "U+200F".
pub fn bad_chars_named(e: &[u16]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for &u in e.iter().filter(|&&u| bad_char(u)) {
        let n = format!("U+{u:04X}");
        if !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

/// An entry with each `bad_char` shown as `<U+200F>` (display cleaning would hide it).
pub fn escape_bad(e: &[u16]) -> W {
    let mut out = W::with_capacity(e.len());
    for &u in e {
        if bad_char(u) {
            out.extend(format!("<U+{u:04X}>").encode_utf16());
        } else {
            out.push(u);
        }
    }
    out
}

/// Machine PATH as the helper's job sees it (the tests hand it a fake).
pub trait MachinePath {
    fn read(&self) -> env::Read;
    /// Write it as `kind`: REG_EXPAND_SZ, or REG_SZ for an Undo of a value that was one.
    fn write(&self, raw: &[u16], kind: Kind) -> Result<(), u32>;
    fn system32(&self) -> W;
    fn expand(&self, raw: &[u16]) -> W;
}

/// The rules every PATH value written meets, Machine or User (one validator: the helper's job,
/// User PATH's Apply and the Preview's Apply button): no longer than one variable can be, no
/// control or direction character.
pub fn check_value(new: &[u16]) -> Option<Reason> {
    if new.len() > MAX_NEW {
        return Some(Reason::TooLong);
    }
    if new.iter().any(|&u| bad_char(u)) {
        return Some(Reason::BadChar);
    }
    None
}

/// Why a new Machine PATH cannot be written, before anything is read: `check_value`, and not
/// empty, and System32 in it.
pub fn check_new(new: &[u16], m: &dyn MachinePath) -> Option<Reason> {
    if new.iter().all(|&u| u == crate::wide::SEMI || u == crate::wide::SPACE) {
        return Some(Reason::Empty);
    }
    if let Some(r) = check_value(new) {
        return Some(r);
    }
    let sys = m.system32();
    if !env::entries(new).iter().any(|e| env::same(&m.expand(e), &sys)) {
        return Some(Reason::NoSystem32);
    }
    None
}

/// Whether the helper's own record of a change lets an Undo write `r.new` over `r.expected`:
/// the record must say the helper wrote exactly the expected value (as the type it recorded
/// writing) over a value with exactly the text asked back. The app's journal never decides this.
pub fn undo_matches(rec: &crate::records::Record, r: &Request) -> bool {
    let wrote = r.expected.as_ref().is_some_and(|e| e.kind == rec.wrote && e.raw == rec.after);
    let back = rec.before.as_ref().is_some_and(|b| b.raw == r.new);
    wrote && back
}

/// The job: check, (an Undo: the helper's record), compare, record, write, read back.
pub fn work(m: &dyn MachinePath, recs: &dyn Records, r: &Request) -> Answer {
    let now = || m.read().value().cloned();
    if let Some(why) = check_new(&r.new, m) {
        return Answer::Refused(why, now());
    }
    // Written as REG_EXPAND_SZ; an Undo writes the value back as the type its own record says
    // it had, when that was REG_SZ (FED1). The type is never the app's to choose.
    let mut kind = Kind::ExpandSz;
    if let Some(id) = &r.undo {
        match recs.get(id) {
            Err(_) => return Answer::Refused(Reason::NoRecords, now()),
            Ok(None) => return Answer::Refused(Reason::NotRecorded, now()),
            Ok(Some(rec)) if !undo_matches(&rec, r) => return Answer::Refused(Reason::NotAsRecorded, now()),
            Ok(Some(rec)) => kind = rec.before.as_ref().map_or(Kind::ExpandSz, |b| b.kind.restored()),
        }
    }
    let before = match m.read() {
        env::Read::Value(v) if r.expected.as_ref() == Some(&v) => Some(v),
        env::Read::Value(v) => return Answer::Refused(Reason::Changed, Some(v)),
        // Not there, as expected: the write creates it.
        env::Read::Missing if r.expected.is_none() => None,
        env::Read::Missing => return Answer::Refused(Reason::Changed, None),
        env::Read::Error(_) => return Answer::Refused(Reason::Unreadable, None),
    };
    // This change's own record first: no change is made that the helper could not undo.
    let Some(id) = recs.new_id() else { return Answer::Refused(Reason::NoRecords, before) };
    if recs.put(&id, before.as_ref(), &r.new, kind).is_err() {
        return Answer::Refused(Reason::NoRecords, before);
    }
    if let Err(code) = m.write(&r.new, kind) {
        return Answer::Failed(code, now());
    }
    let after = now();
    if after.as_ref().is_some_and(|v| v.kind == kind && v.raw == r.new) { Answer::Done(after, id) } else { Answer::Failed(0, after) }
}

/// The real Machine PATH (the helper's process, elevated).
pub struct RealMachine;

impl MachinePath for RealMachine {
    fn read(&self) -> env::Read {
        env::sys::read(env::Hive::Machine, "Path")
    }
    fn write(&self, raw: &[u16], kind: Kind) -> Result<(), u32> {
        env::sys::write_path(env::Hive::Machine, raw, kind)
    }
    fn system32(&self) -> W {
        env::sys::system_dirs().0
    }
    fn expand(&self, raw: &[u16]) -> W {
        expand_own(raw)
    }
}

/// `%VARS%` expanded in this process's environment (the helper's: Machine-level variables).
fn expand_own(raw: &[u16]) -> W {
    use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
    let src = crate::wide::z(raw);
    let mut buf = vec![0u16; 32_768];
    // SAFETY: a NUL-terminated source and a buffer of its length.
    let n = unsafe { ExpandEnvironmentStringsW(src.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n > buf.len() {
        return raw.to_vec();
    }
    buf.truncate(n.saturating_sub(1));
    buf
}

/// How a Machine PATH change ended, as the controller sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The user said no at the UAC prompt.
    Declined,
    /// It did not happen (why, in words).
    Failed(String),
    NeverConnected(String),
    /// The helper went away before it answered: whether it wrote is not known.
    Gone,
    Answer(Answer),
    /// The window closed meanwhile.
    Stopped,
}

#[cfg(windows)]
mod sys {
    use super::*;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::Win32::System::IO::*;
    use windows_sys::Win32::System::Pipes::*;
    use windows_sys::Win32::System::Threading::*;

    pub fn own_exe() -> Option<Vec<u16>> {
        use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
        let mut buf = vec![0u16; 32_768];
        // SAFETY: a buffer and its length in units.
        let n = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
        (n > 0 && n < buf.len()).then(|| buf[..n].to_vec())
    }

    pub fn image_of(pid: u32) -> Option<Vec<u16>> {
        // SAFETY: a query-only open of a process by id; closed below.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 32_768];
        let mut n = buf.len() as u32;
        // SAFETY: a buffer and its length in units.
        let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut n) } != 0;
        unsafe { CloseHandle(h) };
        ok.then(|| buf[..n as usize].to_vec())
    }

    pub fn file_id(path: &[u16]) -> Option<FileIdent> {
        let mut p = path.to_vec();
        p.push(0);
        // SAFETY: a NUL-terminated path, attributes only, sharing everything; closed below.
        let h = unsafe { CreateFileW(p.as_ptr(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: plain structs filled by the calls, sizes given.
        let id = unsafe {
            let mut info: FILE_ID_INFO = std::mem::zeroed();
            if GetFileInformationByHandleEx(h, FileIdInfo, (&mut info as *mut FILE_ID_INFO).cast(), size_of::<FILE_ID_INFO>() as u32) != 0 {
                Some((info.VolumeSerialNumber, info.FileId.Identifier))
            } else {
                let mut bh: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
                (GetFileInformationByHandle(h, &mut bh) != 0).then(|| fallback_id(bh.dwVolumeSerialNumber, bh.nFileIndexHigh, bh.nFileIndexLow))
            }
        };
        unsafe { CloseHandle(h) };
        id
    }

    pub fn same_file(a: &[u16], b: &[u16]) -> bool {
        match (file_id(a), file_id(b)) {
            (Some(x), Some(y)) => same_id(x, y),
            _ => false,
        }
    }

    /// The path the helper is started from: this exe's final path (VibeLink R-LINK-1: the
    /// elevated session has its own drive letters).
    pub fn launch_path() -> Option<Vec<u16>> {
        own_exe().map(|p| launch_path_of(&p))
    }

    pub(super) fn launch_path_of(p: &[u16]) -> Vec<u16> {
        final_path(p).map(plain_if_valid).unwrap_or_else(|| p.to_vec())
    }

    fn final_path(path: &[u16]) -> Option<Vec<u16>> {
        let mut p = path.to_vec();
        p.push(0);
        // SAFETY: a NUL-terminated path, attributes only, sharing everything; closed below.
        let h = unsafe { CreateFileW(p.as_ptr(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut buf = vec![0u16; 32_768];
        // SAFETY: a buffer and its length in units.
        let n = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) } as usize;
        unsafe { CloseHandle(h) };
        (n > 0 && n < buf.len()).then(|| buf[..n].to_vec())
    }

    fn plain_if_valid(verbatim: Vec<u16>) -> Vec<u16> {
        let Some(plain) = super::strip_verbatim(&verbatim) else { return verbatim };
        let mut z = plain.clone();
        z.push(0);
        let mut buf = vec![0u16; 32_768];
        // SAFETY: a NUL-terminated path, a buffer and its length in units.
        let n = unsafe { GetFullPathNameW(z.as_ptr(), buf.len() as u32, buf.as_mut_ptr(), std::ptr::null_mut()) } as usize;
        if plain.len() < MAX_PATH as usize && n > 0 && n < buf.len() && buf[..n] == plain[..] { plain } else { verbatim }
    }

    pub fn random16() -> Option<[u8; 16]> {
        use windows_sys::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
        let mut b = [0u8; 16];
        // SAFETY: a 16-byte buffer; the system's preferred generator.
        (unsafe { BCryptGenRandom(std::ptr::null_mut(), b.as_mut_ptr(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG) } == 0).then_some(b)
    }

    pub fn elevated() -> bool {
        let mut tok: HANDLE = std::ptr::null_mut();
        // SAFETY: the current process's token, query only; closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
            return false;
        }
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut n = 0u32;
        let ok = unsafe { GetTokenInformation(tok, TokenElevation, (&mut e as *mut TOKEN_ELEVATION).cast(), size_of::<TOKEN_ELEVATION>() as u32, &mut n) } != 0;
        unsafe { CloseHandle(tok) };
        ok && e.TokenIsElevated != 0
    }

    struct UserOnly {
        _token_user: Vec<u64>,
        _acl: Vec<u64>,
        sd: Box<SECURITY_DESCRIPTOR>,
    }

    fn user_only() -> Option<UserOnly> {
        let mut tok: HANDLE = std::ptr::null_mut();
        // SAFETY: the current process's token, query only; closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
            return None;
        }
        let mut need = 0u32;
        unsafe { GetTokenInformation(tok, TokenUser, std::ptr::null_mut(), 0, &mut need) };
        let mut tu = vec![0u64; (need as usize).div_ceil(8).max(8)];
        let ok = unsafe { GetTokenInformation(tok, TokenUser, tu.as_mut_ptr().cast(), (tu.len() * 8) as u32, &mut need) } != 0;
        unsafe { CloseHandle(tok) };
        if !ok {
            return None;
        }
        // SAFETY: the buffer holds a TOKEN_USER written by the call above.
        let sid = unsafe { (*(tu.as_ptr() as *const TOKEN_USER)).User.Sid };
        let sid_len = unsafe { GetLengthSid(sid) } as usize;
        let acl_len = size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() + sid_len;
        let mut acl = vec![0u64; acl_len.div_ceil(8)];
        let pacl = acl.as_mut_ptr() as *mut ACL;
        // SAFETY: an ACL buffer of `acl_len` bytes; one ACE for the user's SID.
        unsafe {
            if InitializeAcl(pacl, acl_len as u32, ACL_REVISION) == 0 || AddAccessAllowedAce(pacl, ACL_REVISION, GENERIC_READ | GENERIC_WRITE, sid) == 0 {
                return None;
            }
        }
        let mut sd: Box<SECURITY_DESCRIPTOR> = Box::new(unsafe { std::mem::zeroed() });
        let psd = (&mut *sd as *mut SECURITY_DESCRIPTOR).cast();
        // SAFETY: a descriptor in our memory, the DACL above (both outlive the pipe's creation).
        unsafe {
            if InitializeSecurityDescriptor(psd, 1) == 0 || SetSecurityDescriptorDacl(psd, 1, pacl, 0) == 0 {
                return None;
            }
        }
        Some(UserOnly { _token_user: tu, _acl: acl, sd })
    }

    pub struct Server {
        pub h: HANDLE,
        pub name: String,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            // SAFETY: created in `create`, closed once.
            unsafe { CloseHandle(self.h) };
        }
    }

    // SAFETY: the handle is used by one thread at a time (the job's worker).
    unsafe impl Send for Server {}

    pub fn create() -> Result<Server, String> {
        let r = random16().ok_or("no random numbers from the system")?;
        let name = pipe_name(&r);
        let sec = user_only().ok_or("the pipe's access rules could not be made")?;
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: (&*sec.sd as *const SECURITY_DESCRIPTOR) as *mut _, bInheritHandle: 0 };
        let w = crate::host::wide(&name);
        // SAFETY: a NUL-terminated name and attributes that live through the call.
        let h = unsafe {
            CreateNamedPipeW(w.as_ptr(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 64 * 1024, 64 * 1024, 0, &sa)
        };
        drop(sec);
        if h == INVALID_HANDLE_VALUE {
            return Err(format!("the pipe did not open ({})", std::io::Error::last_os_error()));
        }
        Ok(Server { h, name })
    }

    pub enum End {
        Done(u32),
        Deadline,
        Stopped,
        ProcessGone,
        Error(u32),
    }

    /// Wait for an overlapped operation in 100 ms steps until done, `deadline`, `stop`, or
    /// `process` ends; anything but done cancels it first.
    pub fn wait(h: HANDLE, ov: &mut OVERLAPPED, deadline: Instant, stop: &AtomicBool, process: HANDLE) -> End {
        loop {
            let mut n = 0u32;
            // SAFETY: the operation started on `h` with `ov`; a 100 ms wait.
            if unsafe { GetOverlappedResultEx(h, ov, &mut n, 100, 0) } != 0 {
                return End::Done(n);
            }
            let e = unsafe { GetLastError() };
            if e != WAIT_TIMEOUT && e != WAIT_IO_COMPLETION && e != ERROR_IO_INCOMPLETE {
                return End::Error(e);
            }
            let why = if Instant::now() >= deadline {
                Some(End::Deadline)
            } else if stop.load(Ordering::SeqCst) {
                Some(End::Stopped)
            } else if !process.is_null() && unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0 {
                Some(End::ProcessGone)
            } else {
                None
            };
            if let Some(w) = why {
                // SAFETY: cancel our own operation, then wait for it to finish with `ov`.
                unsafe {
                    CancelIoEx(h, ov);
                    let mut n = 0u32;
                    GetOverlappedResult(h, ov, &mut n, 1);
                }
                return w;
            }
        }
    }

    pub struct Event(pub HANDLE);
    impl Drop for Event {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    pub fn event() -> Event {
        // SAFETY: an unnamed manual-reset event.
        Event(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) })
    }

    pub fn overlapped(ev: &Event) -> OVERLAPPED {
        // SAFETY: all-zero is a valid OVERLAPPED.
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = ev.0;
        ov
    }

    /// The relaunch: this exe (from its final path), elevated, with the job's arguments. Blocks
    /// until the UAC prompt is answered. Ok(process handle), or Err(Win32 code): 1223 is "the
    /// user said no".
    pub fn relaunch(pipe: &str, hwnd: isize) -> Result<HANDLE, u32> {
        use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx};
        use windows_sys::Win32::UI::Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
        let mut file = launch_path().ok_or(2u32)?;
        file.push(0);
        let params = crate::host::wide(&format!("--helper {JOB} {pipe}"));
        let verb = crate::host::wide("runas");
        // SAFETY: COM for the shell on this thread; the struct's strings outlive the call.
        unsafe {
            CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32);
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
            info.hwnd = hwnd as *mut _;
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = params.as_ptr();
            info.nShow = 0;
            if ShellExecuteExW(&mut info) == 0 {
                return Err(GetLastError());
            }
            if info.hProcess.is_null() {
                return Err(ERROR_INVALID_HANDLE);
            }
            Ok(info.hProcess)
        }
    }

    /// One Machine PATH change, start to end, on the calling (worker) thread. `stop` ends it
    /// early (the window closed): the pipe closes, the helper sees it and exits.
    pub fn run(r: &Request, hwnd: isize, stop: &AtomicBool) -> Outcome {
        let started = Instant::now();
        let server = match create() {
            Ok(s) => s,
            Err(e) => return Outcome::Failed(e),
        };
        let process = match relaunch(&server.name, hwnd) {
            Ok(p) => p,
            Err(1223) => return Outcome::Declined,
            Err(e) => return Outcome::Failed(format!("the helper did not start ({})", crate::host::code_words(e))),
        };
        struct Proc(HANDLE);
        impl Drop for Proc {
            fn drop(&mut self) {
                unsafe { CloseHandle(self.0) };
            }
        }
        let proc_ = Proc(process);
        let pid = unsafe { GetProcessId(process) };
        if stop.load(Ordering::SeqCst) {
            return Outcome::Stopped;
        }
        let nonce = random16().unwrap_or([7; 16]);
        serve(&server, proc_.0, pid, r, nonce, started + CONNECT_WAIT, stop)
    }

    /// A process's exit code once it has ended (None while it runs, or when it cannot be read).
    fn exit_code(process: HANDLE) -> Option<u32> {
        let mut code = 0u32;
        // SAFETY: a process handle the caller holds open, a plain query.
        (unsafe { GetExitCodeProcess(process, &mut code) } != 0 && code != 259).then_some(code)
    }

    /// Wait for the helper (`pid`, started as `process`) to connect until `deadline`, check it
    /// is that process running this exe, send the request, then read its answer.
    pub fn serve(server: &Server, process: HANDLE, pid: u32, r: &Request, nonce: [u8; 16], deadline: Instant, stop: &AtomicBool) -> Outcome {
        let ev = event();
        let mut ov = overlapped(&ev);
        // SAFETY: an overlapped connect on our pipe.
        let c = unsafe { ConnectNamedPipe(server.h, &mut ov) };
        let err = unsafe { GetLastError() };
        if c == 0 && err != ERROR_PIPE_CONNECTED {
            if err != ERROR_IO_PENDING {
                return Outcome::Failed(format!("the pipe did not wait ({})", crate::host::code_words(err)));
            }
            match wait(server.h, &mut ov, deadline, stop, process) {
                End::Done(_) => {}
                End::Deadline => return Outcome::NeverConnected("the helper did not connect within 2 minutes".into()),
                End::Stopped => return Outcome::Stopped,
                End::ProcessGone => return Outcome::NeverConnected(gone_before_connect(exit_code(process))),
                End::Error(e) => return Outcome::Failed(format!("the pipe failed ({})", crate::host::code_words(e))),
            }
        }
        // Who connected: the process we started, running this exe.
        let mut client = 0u32;
        let ok = unsafe { GetNamedPipeClientProcessId(server.h, &mut client) } != 0;
        let same = match (own_exe(), image_of(client)) {
            (Some(a), Some(b)) => same_file(&a, &b),
            _ => false,
        };
        if !ok || client != pid || !same {
            return Outcome::Failed("something else connected to the helper's pipe: it was closed".into());
        }
        let never = AtomicBool::new(false);
        let end = Instant::now() + HARD_LIMIT + Duration::from_secs(5);
        {
            let req = request(&nonce, r);
            let ev = event();
            let mut ov = overlapped(&ev);
            // SAFETY: an overlapped write of `req`, waited for before `req` goes.
            let w = unsafe { WriteFile(server.h, req.as_ptr(), req.len() as u32, std::ptr::null_mut(), &mut ov) };
            if w == 0 && unsafe { GetLastError() } == ERROR_IO_PENDING {
                if !matches!(wait(server.h, &mut ov, end, &never, std::ptr::null_mut()), End::Done(_)) {
                    return Outcome::Gone;
                }
            } else if w == 0 {
                return Outcome::Gone;
            }
        }
        let mut dec = Decoder::new(nonce);
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let ev = event();
            let mut ov = overlapped(&ev);
            // SAFETY: an overlapped read into `buf`, waited for below before `buf` is touched.
            let rd = unsafe { ReadFile(server.h, buf.as_mut_ptr(), buf.len() as u32, std::ptr::null_mut(), &mut ov) };
            let err = unsafe { GetLastError() };
            let n = if rd != 0 {
                let mut n = 0u32;
                unsafe { GetOverlappedResult(server.h, &ov, &mut n, 1) };
                n
            } else if err == ERROR_IO_PENDING {
                match wait(server.h, &mut ov, end, stop, std::ptr::null_mut()) {
                    End::Done(n) => n,
                    End::Stopped => return Outcome::Stopped,
                    _ => return Outcome::Gone,
                }
            } else {
                return Outcome::Gone;
            };
            if n == 0 {
                return Outcome::Gone;
            }
            match dec.push(&buf[..n as usize]) {
                Ok(msgs) => {
                    for m in msgs {
                        match m {
                            Msg::Hello { pid: p } if p != pid => return Outcome::Failed("the helper said it was another process".into()),
                            Msg::Hello { .. } => {}
                            Msg::Answer(a) => return Outcome::Answer(a),
                        }
                    }
                }
                Err(e) => return Outcome::Failed(e),
            }
        }
    }

    // ---------- the helper's side ----------

    pub struct Client(pub HANDLE);
    impl Drop for Client {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    impl Client {
        pub fn send(&self, b: &[u8]) -> bool {
            let mut n = 0u32;
            // SAFETY: a synchronous write of `b`.
            unsafe { WriteFile(self.0, b.as_ptr(), b.len() as u32, &mut n, std::ptr::null_mut()) != 0 && n as usize == b.len() }
        }

        fn read_exact(&self, out: &mut [u8]) -> bool {
            let mut have = 0usize;
            while have < out.len() {
                let mut n = 0u32;
                // SAFETY: a synchronous read into the rest of `out`.
                if unsafe { ReadFile(self.0, out[have..].as_mut_ptr(), (out.len() - have) as u32, &mut n, std::ptr::null_mut()) } == 0 || n == 0 {
                    return false;
                }
                have += n as usize;
            }
            true
        }

        /// The app's request payload (None when the pipe breaks first or it is not one).
        pub fn read_request(&self) -> Option<Vec<u8>> {
            let mut h = [0u8; 5];
            if !self.read_exact(&mut h) || h[0] != KIND_REQUEST {
                return None;
            }
            let len = u32::from_le_bytes(h[1..5].try_into().unwrap()) as usize;
            if !(17..=MAX_REQUEST).contains(&len) {
                return None;
            }
            let mut b = vec![0u8; len];
            self.read_exact(&mut b).then_some(b)
        }
    }

    /// Connect to the app's pipe, identification-level only (the app cannot act as us), and
    /// check that its server is this exe.
    pub fn connect(pipe: &str) -> Option<Client> {
        let w = crate::host::wide(pipe);
        for _ in 0..3 {
            // SAFETY: a NUL-terminated name; the handle is ours.
            let h = unsafe { CreateFileW(w.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, std::ptr::null(), OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, std::ptr::null_mut()) };
            if h == INVALID_HANDLE_VALUE {
                if unsafe { GetLastError() } == ERROR_PIPE_BUSY {
                    unsafe { WaitNamedPipeW(w.as_ptr(), 2000) };
                    continue;
                }
                return None;
            }
            let c = Client(h);
            let mut server = 0u32;
            if unsafe { GetNamedPipeServerProcessId(h, &mut server) } == 0 {
                return None;
            }
            let (mine, theirs) = (own_exe()?, image_of(server)?);
            return same_file(&mine, &theirs).then_some(c);
        }
        None
    }
}

#[cfg(windows)]
pub use sys::{Client, connect, elevated, run, same_file, serve};

/// 128 random bits from the system (a record's id).
#[cfg(windows)]
pub fn random_id() -> Option<Id> {
    sys::random16()
}

/// This exe's final path (what the helper is started from; portable mode's exe path).
#[cfg(windows)]
pub fn launch_path_of_own() -> Option<W> {
    sys::launch_path()
}

/// The helper's whole life (`VibePath.exe --helper machine-path-set <pipe>`): the exit code.
/// 2: bad arguments or a malformed request, 3: not elevated, 4: the hard limit, 5: the pipe or
/// its server was wrong (or broke).
#[cfg(windows)]
pub fn run_helper(args: &[String]) -> i32 {
    let Some(pipe) = parse_args(args) else { return 2 };
    if !elevated() {
        return 3;
    }
    std::thread::spawn(|| {
        std::thread::sleep(HARD_LIMIT);
        // SAFETY: ends this process; Windows closes its handles with it.
        unsafe { windows_sys::Win32::System::Threading::ExitProcess(4) };
    });
    let Some(client) = connect(&pipe) else { return 5 };
    if !client.send(&hello(std::process::id())) {
        return 5;
    }
    let Some(req) = client.read_request() else { return 5 };
    let Some((nonce, r)) = parse_request(&req) else { return 2 };
    let a = work(&RealMachine, &crate::records::sys::Hklm, &r);
    if client.send(&answer(&nonce, &a)) { 0 } else { 5 }
}
