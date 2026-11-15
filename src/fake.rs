//! A PC in memory for the tests: its registry values, files, aliases, processes and the elevated
//! helper, so the window tests drive the real controller without touching this PC. (Shipped in
//! the library like the siblings' `fake.rs`: the integration tests need it.)

use crate::alias::Alias;
use crate::env::{self, Env, Hive, Kind, Read, Value};
use crate::fileinfo::Details;
use crate::fsprobe::{Drive, Facts, State};
use crate::helper::{MachinePath, Outcome, Request};
use crate::peb::{ProcEnv, ProcInfo, ProcList};
use crate::records::{Id, Record, Records};
use crate::resolve::{AppPath, Lookup, Probe};
use crate::wide::{self, W, w};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

/// Files and folders by full path (case ignored), folders that cannot be read, App Paths.
#[derive(Clone, Default)]
pub struct FakeFs {
    /// By lower-case path: the path as spelt.
    pub files: HashMap<String, String>,
    pub dirs: HashSet<String>,
    pub aliases: HashSet<String>,
    pub unreadable: HashMap<String, String>,
    pub app_paths: Vec<(String, AppPath)>,
}

impl FakeFs {
    pub fn file(mut self, p: &str) -> Self {
        self.files.insert(p.to_lowercase(), p.to_string());
        self
    }
    pub fn dir(mut self, p: &str) -> Self {
        self.dirs.insert(p.to_lowercase());
        self
    }
    pub fn alias(mut self, p: &str) -> Self {
        self.files.insert(p.to_lowercase(), p.to_string());
        self.aliases.insert(p.to_lowercase());
        self
    }
    pub fn dead(mut self, dir: &str, why: &str) -> Self {
        self.unreadable.insert(dir.to_lowercase(), why.into());
        self
    }
}

impl Lookup for FakeFs {
    fn probe_all(&self, dir: &[u16], cands: &[W]) -> Result<Vec<Probe>, String> {
        if let Some(why) = self.unreadable.get(&wide::lossy(dir).to_lowercase()) {
            return Err(why.clone());
        }
        Ok(cands
            .iter()
            .map(|c| {
                let k = wide::lossy(c).to_lowercase();
                if let Some(real) = self.files.get(&k) {
                    Probe::File { reparse: self.aliases.contains(&k), name: Some(w(real.rsplit('\\').next().unwrap_or(real))) }
                } else if self.dirs.contains(&k) {
                    Probe::Dir
                } else {
                    Probe::Missing
                }
            })
            .collect())
    }

    fn app_paths(&self, name: &[u16]) -> Vec<AppPath> {
        let n = wide::lossy(name).to_lowercase();
        let mut v: Vec<AppPath> = self.app_paths.iter().filter(|(k, _)| k.to_lowercase() == n).map(|(_, a)| a.clone()).collect();
        v.sort_by_key(|a| a.hive != Hive::Machine);
        v
    }
}

/// A process on the fake PC.
#[derive(Clone)]
pub struct FakeProc {
    pub info: ProcInfo,
    pub image: Option<W>,
    pub env: Result<ProcEnv, String>,
}

/// The fake PC.
pub struct Pc {
    pub values: HashMap<(Hive, String), Read>,
    pub fs: FakeFs,
    pub aliases: HashMap<String, Alias>,
    pub details: HashMap<String, Details>,
    pub facts: HashMap<String, Facts>,
    pub procs: Vec<FakeProc>,
    /// What Windows would not say about the process list (WTS failed: whose is not known).
    pub procs_problem: Option<String>,
    pub own: Env,
    pub cwd: W,
    pub profile: W,
    /// Overrides the New window PATH (Windows building it differently).
    pub built_path: Option<W>,
    pub new_window_error: Option<String>,
    /// A User PATH write fails with this code.
    pub write_error: Option<u32>,
    /// A User PATH write lands as this instead (another program wrote at the same moment).
    pub user_lands_as: Option<W>,
    /// What the helper does: None plays the job on the fake Machine PATH; Some answers this.
    pub helper: Option<Outcome>,
    pub helper_runs: usize,
    /// The helper's own undo records (HKLM on a real PC); ids count up.
    pub records: HashMap<Id, Record>,
    pub records_made: u8,
    /// The records cannot be read or written (or are not trusted).
    pub records_broken: bool,
    pub user_writes: Vec<W>,
    pub broadcasts: usize,
    /// After a broadcast, Explorer (pid 4000) takes the new PATH.
    pub explorer_follows: bool,
    pub files_written: Vec<(std::path::PathBuf, Vec<u8>)>,
    /// A file write (not of a file already there) fails with this (a full disk, a stick pulled).
    pub write_file_error: Option<String>,
    /// Runs as a PATH is written (User, or the helper's job): the world changing meanwhile.
    pub during_write: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    /// Another program writes User PATH just before the n-th read of it from now (1: the next).
    pub user_set_before_read: Option<(usize, Read)>,
    pub now_ms: u64,
    /// These hives' Path holds text after its first NUL (what a read leaves out).
    pub hidden_text: Vec<Hive>,
}

pub struct FakeSystem {
    pub pc: Mutex<Pc>,
}

fn lock(m: &Mutex<Pc>) -> std::sync::MutexGuard<'_, Pc> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub const SYS32: &str = "C:\\Windows\\system32";

/// A start time for the fake processes (FILETIME): 23.10.2026 07:00 UTC.
pub const START: u64 = (1_792_738_800 + 11_644_473_600) * 10_000_000;

fn expand_on(pc: &Pc, raw: &[u16]) -> W {
    if !raw.contains(&wide::PERCENT) {
        return raw.to_vec();
    }
    let mut out = wide::lossy(raw);
    for (k, v) in &pc.own.vars {
        let name = format!("%{}%", wide::lossy(k)).to_lowercase();
        let value = wide::lossy(v);
        while let Some(i) = out.to_lowercase().find(&name) {
            out.replace_range(i..i + name.len(), &value);
        }
    }
    w(&out)
}

impl FakeSystem {
    /// A PC with Windows' own Machine PATH, an empty User PATH and the usual PATHEXT.
    pub fn new() -> FakeSystem {
        let own = Env { vars: vec![(w("SystemRoot"), w("C:\\Windows")), (w("USERPROFILE"), w("C:\\Users\\ted")), (w("LOCALAPPDATA"), w("C:\\Users\\ted\\AppData\\Local"))] };
        let mut values = HashMap::new();
        values.insert((Hive::Machine, "Path".into()), Read::Value(Value { kind: Kind::ExpandSz, raw: w("%SystemRoot%\\system32;%SystemRoot%;%SystemRoot%\\System32\\Wbem") }));
        values.insert((Hive::User, "Path".into()), Read::Missing);
        values.insert((Hive::Machine, "PATHEXT".into()), Read::Value(Value { kind: Kind::Sz, raw: w(".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC") }));
        values.insert((Hive::User, "PATHEXT".into()), Read::Missing);
        FakeSystem {
            pc: Mutex::new(Pc {
                values,
                fs: FakeFs::default(),
                aliases: HashMap::new(),
                details: HashMap::new(),
                facts: HashMap::new(),
                procs: Vec::new(),
                procs_problem: None,
                own,
                cwd: w("C:\\Users\\ted\\Projects"),
                profile: w("C:\\Users\\ted"),
                built_path: None,
                new_window_error: None,
                write_error: None,
                user_lands_as: None,
                helper: None,
                helper_runs: 0,
                records: HashMap::new(),
                records_made: 0,
                records_broken: false,
                user_writes: Vec::new(),
                broadcasts: 0,
                explorer_follows: true,
                files_written: Vec::new(),
                write_file_error: None,
                during_write: None,
                user_set_before_read: None,
                now_ms: 1_792_740_000_000,
                hidden_text: Vec::new(),
            }),
        }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Pc) -> R) -> R {
        f(&mut lock(&self.pc))
    }

    pub fn set(&self, hive: Hive, name: &str, kind: Kind, raw: &str) {
        self.with(|pc| pc.values.insert((hive, name.into()), Read::Value(Value { kind, raw: w(raw) })));
    }

    pub fn set_read(&self, hive: Hive, name: &str, r: Read) {
        self.with(|pc| pc.values.insert((hive, name.into()), r));
    }

    pub fn value(&self, hive: Hive, name: &str) -> Read {
        self.with(|pc| pc.values.get(&(hive, name.to_string())).cloned().unwrap_or(Read::Missing))
    }

    /// The PATH a program started now gets: Machine's then User's, expanded.
    pub fn merged(&self) -> W {
        self.with(|pc| merged_of(pc))
    }

    /// A process of this user with `path` as its PATH.
    pub fn add_proc(&self, pid: u32, ppid: u32, image: &str, path: Option<&str>) {
        let name = w(image.rsplit('\\').next().unwrap_or(image));
        let mut vars = vec![(w("SystemRoot"), w("C:\\Windows"))];
        if let Some(p) = path {
            vars.push((w("Path"), w(p)));
        }
        self.with(|pc| {
            pc.procs.push(FakeProc {
                info: ProcInfo { pid, ppid, start: START + u64::from(pid) * 10_000_000, session: 1, name, ours: Some(true) },
                image: Some(w(image)),
                env: Ok(ProcEnv { env: Env { vars }, cwd: Some(w("C:\\Users\\ted")), wow64: false }),
            })
        });
    }

    pub fn add_unreadable_proc(&self, pid: u32, image: &str, why: &str) {
        let name = w(image.rsplit('\\').next().unwrap_or(image));
        self.with(|pc| pc.procs.push(FakeProc { info: ProcInfo { pid, ppid: 1, start: START + u64::from(pid) * 10_000_000, session: 1, name, ours: Some(true) }, image: Some(w(image)), env: Err(why.into()) }));
    }
}

impl Default for FakeSystem {
    fn default() -> Self {
        Self::new()
    }
}

fn merged_of(pc: &Pc) -> W {
    if let Some(b) = &pc.built_path {
        return b.clone();
    }
    let get = |h: Hive| pc.values.get(&(h, "Path".to_string())).cloned().unwrap_or(Read::Missing);
    let (m, u) = (get(Hive::Machine), get(Hive::User));
    crate::health::merged(&m, &u, &|x| expand_on(pc, x))
}

struct FakeMachine<'a>(std::cell::RefCell<&'a mut Pc>);

impl MachinePath for FakeMachine<'_> {
    fn read(&self) -> Read {
        self.0.borrow().values.get(&(Hive::Machine, "Path".to_string())).cloned().unwrap_or(Read::Missing)
    }
    fn write(&self, raw: &[u16], kind: Kind) -> Result<(), u32> {
        if matches!(kind, Kind::Other(_)) {
            return Err(87);
        }
        self.0.borrow_mut().values.insert((Hive::Machine, "Path".into()), Read::Value(Value { kind, raw: raw.to_vec() }));
        Ok(())
    }
    fn system32(&self) -> W {
        w(SYS32)
    }
    fn expand(&self, raw: &[u16]) -> W {
        expand_on(&self.0.borrow(), raw)
    }
}

impl Records for FakeMachine<'_> {
    fn new_id(&self) -> Option<Id> {
        let mut pc = self.0.borrow_mut();
        pc.records_made += 1;
        Some([pc.records_made; 16])
    }
    fn put(&self, id: &Id, before: Option<&Value>, after: &[u16], wrote: Kind) -> Result<(), String> {
        let mut pc = self.0.borrow_mut();
        if pc.records_broken {
            return Err("access denied".into());
        }
        if pc.records.contains_key(id) {
            return Err("there already".into());
        }
        let at_ms = pc.now_ms;
        pc.records.insert(*id, Record { at_ms, before: before.cloned(), after: after.to_vec(), wrote });
        Ok(())
    }
    fn get(&self, id: &Id) -> Result<Option<Record>, String> {
        let pc = self.0.borrow();
        if pc.records_broken { Err("access denied".into()) } else { Ok(pc.records.get(id).cloned()) }
    }
}

impl crate::system::System for FakeSystem {
    fn read(&self, hive: Hive, name: &str) -> Read {
        if hive == Hive::User && name == "Path" {
            self.with(|pc| {
                if let Some((n, v)) = pc.user_set_before_read.take() {
                    if n <= 1 {
                        pc.values.insert((Hive::User, "Path".into()), v);
                    } else {
                        pc.user_set_before_read = Some((n - 1, v));
                    }
                }
            });
        }
        self.value(hive, name)
    }
    fn new_window(&self) -> Result<Env, String> {
        self.with(|pc| {
            if let Some(e) = &pc.new_window_error {
                return Err(e.clone());
            }
            let mut vars = pc.own.vars.clone();
            vars.retain(|(k, _)| !wide::eq_ic(k, &w("Path")) && !wide::eq_ic(k, &w("PATHEXT")));
            vars.push((w("Path"), merged_of(pc)));
            let pe = pc.values.get(&(Hive::User, "PATHEXT".to_string())).and_then(|r| r.value().cloned()).or_else(|| pc.values.get(&(Hive::Machine, "PATHEXT".to_string())).and_then(|r| r.value().cloned()));
            if let Some(p) = pe {
                vars.push((w("PATHEXT"), p.raw));
            }
            Ok(Env { vars })
        })
    }
    fn own_env(&self) -> Env {
        self.with(|pc| pc.own.clone())
    }
    fn own_cwd(&self) -> Option<W> {
        self.with(|pc| Some(pc.cwd.clone()))
    }
    fn profile_dir(&self) -> W {
        self.with(|pc| pc.profile.clone())
    }
    fn system_dirs(&self) -> (W, W, W) {
        (w(SYS32), w("C:\\Windows"), w("C:\\Windows\\System"))
    }
    fn expand(&self, raw: &[u16]) -> W {
        self.with(|pc| expand_on(pc, raw))
    }
    fn lookup(&self) -> &dyn Lookup {
        // The file system is cloned out per call through `FsView` (the lock is not held).
        self
    }
    fn alias(&self, path: &[u16]) -> Result<Alias, String> {
        self.with(|pc| pc.aliases.get(&wide::lossy(path).to_lowercase()).cloned().ok_or_else(|| "not an alias".to_string()))
    }
    fn details(&self, path: &[u16], _read_from: &[u16]) -> Details {
        self.with(|pc| {
            pc.details.get(&wide::lossy(path).to_lowercase()).cloned().unwrap_or_else(|| Details {
                arch: Some("x64".into()),
                file_version: "1.0.0".into(),
                product: "Test".into(),
                company: "Example".into(),
                size: Some(123_456),
                modified: Some(133_000_000_000_000_000),
                signer: "Not signed".into(),
                signer_state: 3,
                ..Details::default()
            })
        })
    }
    fn cache_key(&self, path: &[u16]) -> Option<crate::fileinfo::CacheKey> {
        let mut id = [0u8; 16];
        for (i, u) in path.iter().enumerate() {
            id[i % 16] ^= *u as u8;
        }
        Some((1, id, path.len() as u64, 7))
    }
    fn facts(&self, expanded: &[u16], machine: bool) -> Facts {
        self.with(|pc| {
            pc.facts.get(&wide::lossy(&env::norm(expanded)).to_lowercase()).cloned().unwrap_or(Facts { state: State::Folder, drive: Drive::Local, id: None, writable: if machine { Some(false) } else { None }, creatable: None })
        })
    }
    fn processes(&self) -> ProcList {
        self.with(|pc| ProcList { procs: pc.procs.iter().map(|p| p.info.clone()).collect(), problem: pc.procs_problem.clone() })
    }
    fn process_image(&self, pid: u32) -> Option<W> {
        self.with(|pc| pc.procs.iter().find(|p| p.info.pid == pid).and_then(|p| p.image.clone()))
    }
    fn process_env(&self, pid: u32, start: u64) -> Result<ProcEnv, String> {
        self.with(|pc| match pc.procs.iter().find(|p| p.info.pid == pid && p.info.start == start) {
            Some(p) => p.env.clone(),
            None => Err("exited".into()),
        })
    }
    fn write_user_path(&self, raw: &[u16], kind: Kind) -> Result<(), u32> {
        self.with(|pc| {
            if let Some(c) = pc.write_error {
                return Err(c);
            }
            if matches!(kind, Kind::Other(_)) {
                return Err(87);
            }
            pc.user_writes.push(raw.to_vec());
            if let Some(f) = &pc.during_write {
                f();
            }
            let landed = pc.user_lands_as.clone().unwrap_or_else(|| raw.to_vec());
            pc.values.insert((Hive::User, "Path".into()), Read::Value(Value { kind, raw: landed }));
            Ok(())
        })
    }
    fn delete_user_path(&self) -> Result<(), u32> {
        self.with(|pc| {
            pc.values.insert((Hive::User, "Path".into()), Read::Missing);
            Ok(())
        })
    }
    fn path_holds_more(&self, hive: Hive) -> bool {
        self.with(|pc| pc.hidden_text.contains(&hive))
    }
    fn machine_path_set(&self, r: &Request, _hwnd: isize, _stop: &AtomicBool) -> Outcome {
        self.with(|pc| {
            pc.helper_runs += 1;
            if let Some(f) = &pc.during_write {
                f();
            }
            if let Some(o) = pc.helper.clone() {
                return o;
            }
            let m = FakeMachine(std::cell::RefCell::new(pc));
            Outcome::Answer(crate::helper::work(&m, &m, r))
        })
    }
    fn broadcast(&self) -> bool {
        self.with(|pc| {
            pc.broadcasts += 1;
            if pc.explorer_follows {
                let m = merged_of(pc);
                for p in pc.procs.iter_mut().filter(|p| p.image.as_ref().is_some_and(|i| wide::ends_with_ic(i, &w("\\explorer.exe")))) {
                    if let Ok(e) = &mut p.env {
                        e.env.vars.retain(|(k, _)| !wide::eq_ic(k, &w("Path")));
                        e.env.vars.push((w("Path"), m.clone()));
                    }
                }
            }
            true
        })
    }
    fn machine_guid(&self) -> String {
        "3f2a91c0-1111-2222-3333-444455556666".into()
    }
    fn user_sid(&self) -> String {
        "S-1-5-21-1-2-3-1001".into()
    }
    fn now_ms(&self) -> u64 {
        self.with(|pc| {
            pc.now_ms += 1000;
            pc.now_ms
        })
    }
    fn is_file(&self, p: &[u16]) -> bool {
        self.with(|pc| pc.fs.files.contains_key(&wide::lossy(p).to_lowercase()))
    }
    fn write_file(&self, path: &std::path::Path, bytes: &[u8], new_only: bool) -> Result<bool, String> {
        self.with(|pc| {
            // As `system::new_copy`: a copy there counts unless it is cut short.
            if new_only && pc.files_written.iter().any(|(p, b)| p == path && !crate::regfile::cut_short(b)) {
                return Ok(false);
            }
            if let Some(why) = &pc.write_file_error {
                return Err(why.clone());
            }
            pc.files_written.push((path.to_path_buf(), bytes.to_vec()));
            Ok(true)
        })
    }
    fn pause(&self, _ms: u64) {}
}

impl Lookup for FakeSystem {
    fn probe_all(&self, dir: &[u16], cands: &[W]) -> Result<Vec<Probe>, String> {
        let fs = self.with(|pc| pc.fs.clone());
        fs.probe_all(dir, cands)
    }
    fn app_paths(&self, name: &[u16]) -> Vec<AppPath> {
        let fs = self.with(|pc| pc.fs.clone());
        fs.app_paths(name)
    }
}

/// The Store's Python stub as the alias reader gives it.
pub fn stub_alias() -> Alias {
    Alias {
        version: 3,
        package: w("Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"),
        app_id: w("Microsoft.DesktopAppInstaller_8wekyb3d8bbwe!PythonRedirector"),
        target: w("C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_1.29.380.0_x64__8wekyb3d8bbwe\\AppInstallerPythonRedirector.exe"),
        app_type: Some(w("0")),
    }
}
