//! Other programs' environments (SPEC section 4), read from their memory without admin rights:
//! `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`, the PEB, its process parameters, then
//! the environment block (at most 4 MiB) and the current folder. A 32-bit process on 64-bit
//! Windows is read through its 32-bit PEB (the one its code changes). Offsets from the published
//! layouts (phnt), pinned by the unit tests and checked live against children started with a
//! known PATH. A read that fails or is cut short is unknown, with its reason, never "current".

use crate::env::{self, Env};
use crate::wide::W;

/// The most of an environment block read.
pub const MAX_BLOCK: usize = 4 * 1024 * 1024;

/// Where things are, for one bitness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// PEB.ProcessParameters.
    pub params: usize,
    /// RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath (a UNICODE_STRING).
    pub cwd: usize,
    /// RTL_USER_PROCESS_PARAMETERS.Environment.
    pub env: usize,
    /// RTL_USER_PROCESS_PARAMETERS.EnvironmentSize.
    pub env_size: usize,
    /// Pointer size: 8 or 4.
    pub ptr: usize,
    /// How much of the parameters to read (past `env_size`).
    pub params_len: usize,
}

pub const LAYOUT_64: Layout = Layout { params: 0x20, cwd: 0x38, env: 0x80, env_size: 0x3F0, ptr: 8, params_len: 0x400 };
pub const LAYOUT_32: Layout = Layout { params: 0x10, cwd: 0x24, env: 0x48, env_size: 0x290, ptr: 4, params_len: 0x298 };

fn ptr_at(b: &[u8], o: usize, size: usize) -> Option<u64> {
    let s = b.get(o..o + size)?;
    Some(if size == 8 { u64::from_le_bytes(s.try_into().ok()?) } else { u64::from(u32::from_le_bytes(s.try_into().ok()?)) })
}

/// A UNICODE_STRING in a parameters buffer: (length in bytes, buffer address).
pub fn unicode_string(b: &[u8], o: usize, l: &Layout) -> Option<(usize, u64)> {
    let len = u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?) as usize;
    // The buffer pointer follows Length and MaximumLength, aligned to the pointer size.
    let buf = ptr_at(b, o + l.ptr, l.ptr)?;
    Some((len, buf))
}

/// The environment's address and size, and the current folder's string, from the parameters.
pub fn parse_params(b: &[u8], l: &Layout) -> Option<(u64, usize, (usize, u64))> {
    let env = ptr_at(b, l.env, l.ptr)?;
    let size = ptr_at(b, l.env_size, l.ptr)? as usize;
    let cwd = unicode_string(b, l.cwd, l)?;
    Some((env, size, cwd))
}

/// A process's environment as read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcEnv {
    pub env: Env,
    pub cwd: Option<W>,
    pub wow64: bool,
}

/// A process in the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    /// Its creation time (FILETIME).
    pub start: u64,
    pub session: u32,
    pub name: W,
    /// Its user is this app's user (from Windows' process list); None when Windows did not say.
    pub ours: Option<bool>,
}

/// The process list, and what Windows would not say about it (None: all of it was said).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcList {
    pub procs: Vec<ProcInfo>,
    pub problem: Option<String>,
}

/// Bytes as UTF-16 units (an odd last byte is dropped).
pub fn units(b: &[u8]) -> W {
    b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
}

/// The block's units up to and including its final empty string, if it has one.
pub fn block_end(u: &[u16]) -> Option<usize> {
    if u.first() == Some(&0) {
        return Some(1);
    }
    u.windows(2).position(|x| x == [0, 0]).map(|i| i + 2)
}

/// Why an environment block could not be had from the parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockFail {
    /// A read failed (the process exited, or memory changed under the read).
    Unreadable,
    /// The parameters did not parse, or the block moved or changed size while it was read.
    Moved,
    /// No environment pointer.
    NoEnv,
    TooLarge,
}

/// The environment block and the current folder's string, from the parameters at `params`,
/// through `mem` (another process's memory: address, length). Two reads must agree: the
/// parameters are read again after the block, and a block that moved or changed size meanwhile
/// (the process set a variable: the old block is freed) is "changed while read", never parsed.
pub fn read_env_block(mem: &dyn Fn(u64, usize) -> Result<Vec<u8>, u32>, params: u64, l: &Layout) -> Result<(Vec<u8>, (usize, u64)), BlockFail> {
    let pb = mem(params, l.params_len).map_err(|_| BlockFail::Unreadable)?;
    let (env_addr, size, cwd) = parse_params(&pb, l).ok_or(BlockFail::Moved)?;
    if env_addr == 0 {
        return Err(BlockFail::NoEnv);
    }
    if size > MAX_BLOCK {
        return Err(BlockFail::TooLarge);
    }
    let raw = if size > 0 {
        mem(env_addr, size).map_err(|_| BlockFail::Unreadable)?
    } else {
        // No size recorded: read in steps until the block ends.
        let mut all = Vec::new();
        let mut step = 32 * 1024;
        loop {
            match mem(env_addr + all.len() as u64, step) {
                Ok(b) => all.extend(b),
                Err(_) if step > 4096 => {
                    step = 4096;
                    continue;
                }
                Err(_) => break,
            }
            if block_end(&units(&all)).is_some() || all.len() >= MAX_BLOCK {
                break;
            }
        }
        all
    };
    let again = mem(params, l.params_len).map_err(|_| BlockFail::Unreadable)?;
    match parse_params(&again, l) {
        Some((a, s, _)) if a == env_addr && s == size => Ok((raw, cwd)),
        _ => Err(BlockFail::Moved),
    }
}

#[cfg(windows)]
pub mod sys {
    use super::*;
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, GetLastError, HANDLE};
    use windows_sys::Win32::System::Threading::*;

    pub struct Handle(pub HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: opened here, closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    pub fn open(pid: u32, access: u32) -> Result<Handle, u32> {
        // SAFETY: a plain open by id.
        let h = unsafe { OpenProcess(access, 0, pid) };
        if h.is_null() { Err(unsafe { GetLastError() }) } else { Ok(Handle(h)) }
    }

    pub fn created(h: &Handle) -> Option<u64> {
        let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut e, mut k, mut u) = (z, z, z, z);
        // SAFETY: four FILETIMEs the call fills.
        (unsafe { GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) } != 0).then(|| (u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime))
    }

    fn exited(h: &Handle) -> bool {
        let mut code = 0u32;
        // SAFETY: a plain query.
        unsafe { GetExitCodeProcess(h.0, &mut code) != 0 && code != 259 }
    }

    /// The image path of a process (limited query access suffices, elevated ones too).
    pub fn image(pid: u32) -> Option<W> {
        let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION).ok()?;
        let mut buf = vec![0u16; 32_768];
        let mut n = buf.len() as u32;
        // SAFETY: a buffer and its length in units.
        (unsafe { QueryFullProcessImageNameW(h.0, 0, buf.as_mut_ptr(), &mut n) } != 0).then(|| buf[..n as usize].to_vec())
    }

    fn read_mem(h: &Handle, addr: u64, len: usize) -> Result<Vec<u8>, u32> {
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        let mut b = vec![0u8; len];
        let mut got = 0usize;
        // SAFETY: a buffer of `len` bytes; the address is the other process's, read only.
        let ok = unsafe { ReadProcessMemory(h.0, addr as *const _, b.as_mut_ptr().cast(), len, &mut got) } != 0;
        if !ok || got != len {
            return Err(unsafe { GetLastError() });
        }
        Ok(b)
    }

    fn is_protected(h: &Handle) -> bool {
        let mut info: u32 = 0xFFFF_FFFE;
        // SAFETY: a PROCESS_PROTECTION_LEVEL_INFORMATION (one u32).
        unsafe { GetProcessInformation(h.0, ProcessProtectionLevelInfo, (&mut info as *mut u32).cast(), 4) != 0 && info != 0xFFFF_FFFE }
    }

    fn elevated(h: &Handle) -> Option<bool> {
        use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
        let mut t: HANDLE = std::ptr::null_mut();
        // SAFETY: the process's token, query only; closed below.
        if unsafe { OpenProcessToken(h.0, TOKEN_QUERY, &mut t) } == 0 {
            return None;
        }
        let tok = Handle(t);
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut n = 0u32;
        let ok = unsafe { GetTokenInformation(tok.0, TokenElevation, (&mut e as *mut TOKEN_ELEVATION).cast(), 4, &mut n) } != 0;
        ok.then_some(e.TokenIsElevated != 0)
    }

    /// Why a process that is there could not be read.
    fn refusal(pid: u32, start: u64) -> String {
        match open(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
            Ok(h) => {
                if created(&h) != Some(start) || exited(&h) {
                    "exited".into()
                } else if is_protected(&h) {
                    "protected".into()
                } else {
                    match elevated(&h) {
                        Some(false) => "Windows refused to let it be read".into(),
                        _ => "elevated: Windows does not let a normal app read it".into(),
                    }
                }
            }
            Err(87) => "exited".into(),
            Err(_) => "protected".into(),
        }
    }

    /// Read process `pid` (started at `start`): its environment and current folder.
    pub fn read(pid: u32, start: u64) -> Result<ProcEnv, String> {
        use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation, ProcessWow64Information};
        let h = match open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ) {
            Ok(h) => h,
            Err(87) => return Err("exited".into()),
            Err(_) => return Err(refusal(pid, start)),
        };
        if created(&h) != Some(start) {
            return Err("exited".into());
        }
        let mut peb32: usize = 0;
        let mut ret = 0u32;
        // SAFETY: a pointer-sized out value.
        let st = unsafe { NtQueryInformationProcess(h.0, ProcessWow64Information, (&mut peb32 as *mut usize).cast(), 8, &mut ret) };
        let gone = |h: &Handle| if exited(h) { "exited".to_string() } else { "changed while read".to_string() };
        let (layout, peb) = if st >= 0 && peb32 != 0 {
            (LAYOUT_32, peb32 as u64)
        } else {
            let mut pbi = [0u64; 6];
            // SAFETY: a PROCESS_BASIC_INFORMATION (48 bytes) the call fills.
            let st = unsafe { NtQueryInformationProcess(h.0, ProcessBasicInformation, pbi.as_mut_ptr().cast(), 48, &mut ret) };
            if st < 0 || pbi[1] == 0 {
                return Err(gone(&h));
            }
            (LAYOUT_64, pbi[1])
        };
        let pp = read_mem(&h, peb + layout.params as u64, layout.ptr).map_err(|_| gone(&h))?;
        let params = ptr_at(&pp, 0, layout.ptr).ok_or("changed while read")?;
        if params == 0 {
            return Err(gone(&h));
        }
        let (raw, (cwd_len, cwd_ptr)) = read_env_block(&|a, n| read_mem(&h, a, n), params, &layout).map_err(|f| match f {
            BlockFail::Unreadable | BlockFail::NoEnv => gone(&h),
            BlockFail::Moved => "changed while read".to_string(),
            BlockFail::TooLarge => "its environment is larger than 4 MiB".to_string(),
        })?;
        let u = units(&raw);
        let env = env::parse_block(&u).map_err(|_| if exited(&h) { "exited".to_string() } else { "changed while read: the block has no end".to_string() })?;
        let cwd = if cwd_len > 0 && cwd_len <= 65_534 && cwd_ptr != 0 { read_mem(&h, cwd_ptr, cwd_len).ok().map(|b| units(&b)) } else { None };
        // The DosPath keeps its trailing backslash ("C:\x\"): the folder without it.
        let cwd = cwd.map(|mut c| {
            if c.len() > 3 && c.last() == Some(&crate::wide::BACKSLASH) {
                c.pop();
            }
            c
        });
        if exited(&h) {
            return Err("exited".into());
        }
        Ok(ProcEnv { env, cwd, wow64: layout.ptr == 4 })
    }

    /// Every process, with its parent, start time and session (one NtQuerySystemInformation
    /// call; VibeMeter's reading), and whose it is (WTSEnumerateProcessesEx gives each
    /// process's user SID without opening it, elevated ones too).
    pub fn list() -> ProcList {
        use windows_sys::Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation};
        const MISMATCH: i32 = 0xC000_0004u32 as i32;
        let mut size = 512 * 1024usize;
        let buf: Vec<u64> = loop {
            let mut buf: Vec<u64> = vec![0; size.div_ceil(8)];
            let mut ret = 0u32;
            // SAFETY: a buffer and its size in bytes.
            let st = unsafe { NtQuerySystemInformation(SystemProcessInformation, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut ret) };
            if st == MISMATCH && size < 64 * 1024 * 1024 {
                size = (ret as usize).max(size) + 64 * 1024;
                continue;
            }
            if st < 0 {
                return ProcList { procs: Vec::new(), problem: Some(format!("Windows did not list the processes (NTSTATUS {st:#010X})")) };
            }
            break buf;
        };
        // SAFETY: the buffer's own bytes.
        let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), buf.len() * 8) };
        let base = bytes.as_ptr() as usize;
        let rd32 = |o: usize| -> u32 { bytes.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0) };
        let rd64 = |o: usize| -> u64 { bytes.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0) };
        let (ours, problem) = match ours_by_pid() {
            Ok(m) => (m, None),
            Err(code) => (std::collections::HashMap::new(), Some(format!("Windows did not say whose each process is ({}): none can be shown as yours", crate::host::code_words(code)))),
        };
        let mut out = Vec::with_capacity(512);
        let mut off = 0usize;
        loop {
            if off + 256 > bytes.len() {
                break;
            }
            let next = rd32(off) as usize;
            let pid = rd64(off + 80) as u32;
            if pid != 0 && pid != 4 && rd32(off + 4) > 0 {
                let len = (rd32(off + 56) & 0xffff) as usize;
                let ptr = rd64(off + 64) as usize;
                let name = if len > 0 && ptr >= base && ptr + len <= base + bytes.len() { units(&bytes[ptr - base..ptr - base + len]) } else { W::new() };
                out.push(ProcInfo { pid, ppid: rd64(off + 88) as u32, start: rd64(off + 32), session: rd32(off + 100), name, ours: ours.get(&pid).copied() });
            }
            if next == 0 {
                break;
            }
            off += next;
        }
        ProcList { procs: out, problem }
    }

    /// pid → "its user is ours"; Err: the failing call's code.
    fn ours_by_pid() -> Result<std::collections::HashMap<u32, bool>, u32> {
        use windows_sys::Win32::Security::{EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
        use windows_sys::Win32::System::RemoteDesktop::{WTS_CURRENT_SERVER_HANDLE, WTS_PROCESS_INFO_EXW, WTSEnumerateProcessesExW, WTSFreeMemoryExW, WTSTypeProcessInfoLevel1};
        let mut map = std::collections::HashMap::new();
        let mut t: HANDLE = std::ptr::null_mut();
        // SAFETY: this process's token; closed by Handle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut t) } == 0 {
            return Err(unsafe { GetLastError() });
        }
        let tok = Handle(t);
        let mut need = 0u32;
        unsafe { GetTokenInformation(tok.0, TokenUser, std::ptr::null_mut(), 0, &mut need) };
        let mut tu = vec![0u64; (need as usize).div_ceil(8).max(8)];
        if unsafe { GetTokenInformation(tok.0, TokenUser, tu.as_mut_ptr().cast(), (tu.len() * 8) as u32, &mut need) } == 0 {
            return Err(unsafe { GetLastError() });
        }
        // SAFETY: the buffer holds a TOKEN_USER.
        let me = unsafe { (*(tu.as_ptr() as *const TOKEN_USER)).User.Sid };
        let mut level = 1u32;
        let mut info: windows_sys::core::PWSTR = std::ptr::null_mut();
        let mut count = 0u32;
        // SAFETY: level 1 gives WTS_PROCESS_INFO_EXW records, freed below.
        if unsafe { WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &mut level, 0xFFFF_FFFE /* WTS_ANY_SESSION */, &mut info, &mut count) } == 0 || info.is_null() {
            return Err(unsafe { GetLastError() });
        }
        // SAFETY: `count` records from the call.
        let recs = unsafe { std::slice::from_raw_parts(info as *const WTS_PROCESS_INFO_EXW, count as usize) };
        for r in recs {
            let mine = !r.pUserSid.is_null() && unsafe { EqualSid(r.pUserSid, me) } != 0;
            if !r.pUserSid.is_null() {
                map.insert(r.ProcessId, mine);
            }
        }
        unsafe { WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, info as *const _, count) };
        Ok(map)
    }
}
