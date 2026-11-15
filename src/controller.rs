//! The window's brain. It lives on the UI thread: it keeps the prefs (in memory, saved on the
//! prefs thread), the toasts, the four tabs' state, and hands work to workers. Every worker
//! answer carries the epoch (seq) it belongs to; an answer for another epoch does nothing. The
//! .slint files lay out what it hands them; every word and choice is made here.

use crate::check::{Dot, Fetched, Local, Release, Rows};
use crate::editor::{self, Editor, Mark};
use crate::env::{self, Hive, Kind};
use crate::fileinfo::{CacheKey, Details};
use crate::fsprobe::{Facts, State as FactState};
use crate::health::{self, Report};
use crate::helper::{self, Answer, Outcome};
use crate::input::{self, Command};
use crate::journal::{self, Entry};
use crate::peb::{ProcEnv, ProcInfo};
use crate::portable::Mode;
use crate::prefs::{Change, Store};
use crate::resolve::{self, Found, Resolution, SHELLS, Shell};
use crate::stale::{self, Verdict};
use crate::system::System;
use crate::text::clean_max;
use crate::wide::{self, W, w};
use crate::{Action, AppWindow, CheckDot, CheckRow, Line, Pair, Prefs, PreviewInfo, Row, Theme, ToastItem, ToastKind};
use slint::{ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel, Weak};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A dialog's answer, delivered on whatever thread the dialog ran (None: cancelled).
pub type Reply<T> = Box<dyn FnOnce(Option<T>) + Send>;

/// The save dialog: a suggested file name, and where the answer goes.
pub type SaveDialog = Box<dyn Fn(&str, Reply<PathBuf>)>;

/// What the controller needs from the outside world; the tests hand it fakes.
pub struct Services {
    pub copy: Box<dyn Fn(&str) -> bool>,
    /// A file shown selected in Explorer.
    pub reveal: Box<dyn Fn(&Path)>,
    /// An `ms-settings:` page (on a thread of its own in the real app).
    pub open_settings: Box<dyn Fn(&str)>,
    /// The folder picker; the answer comes back through the callback, on any thread.
    pub pick_folder: Box<dyn Fn(Reply<PathBuf>)>,
    /// The save dialog for a .reg file named so.
    pub save_file: SaveDialog,
    pub system: Arc<dyn System>,
    pub hwnd: Box<dyn Fn() -> isize>,
    pub utc_offset: Arc<dyn Fn(i64) -> i64 + Send + Sync>,
    /// Tests: workers run at once on the UI thread (or are held until `release`).
    pub manual: bool,
    pub hold: Cell<bool>,
    pub mode: Mode,
    /// Where journal.json and the original .reg copies live (None: a read-only stick).
    pub local_dir: Option<PathBuf>,
    /// A web page in the browser (About's link).
    pub open_url: Box<dyn Fn(&str)>,
    /// The install check's offline half, on its worker: this copy's files, their signatures and
    /// hashes (`trust::inspect_from`; true: installed, so the uninstaller too).
    pub inspect: Fetcher<bool, Local>,
    /// The install check's online half, on its worker: the release list at a path on the site,
    /// waited for at most `release.wait`. Only `main` hands in the real one (the exe's
    /// `net::fetch_release_list`, in no test build); the tests hand in fakes.
    pub fetch: Fetcher<str, Fetched>,
    /// What the check holds the list to: the app, its version, the list's key, the code signer.
    pub release: Release,
}

/// A blocking call the check's worker makes.
pub type Fetcher<A, R> = Arc<dyn Fn(&A) -> R + Send + Sync>;

impl Services {
    /// The real services. `fetch` is the release-list fetcher: `main` hands in the exe's
    /// `net::fetch_release_list`, and is the only place that names it.
    pub fn system(mode: Mode, local_dir: Option<PathBuf>, fetch: Fetcher<str, Fetched>) -> Services {
        // The exe's identity as this process started from it, taken now, before an install
        // could replace it, and handed to every check (FED3, RVD7).
        let started = crate::trust::exe_identity();
        Services {
            copy: Box::new(|t| crate::host::copy_text(t).is_ok()),
            reveal: Box::new(|p| {
                let _ = crate::host::reveal(p, true);
            }),
            open_settings: Box::new(|page| {
                let page = page.to_string();
                std::thread::spawn(move || {
                    if let Err(e) = crate::host::open_settings(&page) {
                        post(Msg::Failed(e));
                    }
                });
            }),
            pick_folder: Box::new(|done| crate::dialogs::pick_folder(Some(crate::host::active_window()), "Add a folder to PATH", done)),
            save_file: Box::new(|name, done| crate::dialogs::save_file(Some(crate::host::active_window()), "Export .reg", name, done)),
            system: Arc::new(crate::system::Real),
            hwnd: Box::new(crate::host::active_window),
            utc_offset: Arc::new(crate::host::utc_offset),
            manual: false,
            hold: Cell::new(false),
            mode,
            local_dir,
            // The shell can take a moment: never on the window's thread.
            open_url: Box::new(|u| {
                let u = u.to_string();
                std::thread::spawn(move || {
                    let _ = crate::host::open_url(&u);
                });
            }),
            inspect: Arc::new(move |installed: &bool| crate::trust::inspect_from(started, &crate::trust::own_exe(), *installed)),
            fetch,
            release: Release::this(),
        }
    }
}

/// How often the window looks whether a running check has its answer.
const CHECK_POLL_MS: u64 = 50;

/// What a portable copy leaves on this PC, and what Windows records of any program it runs:
/// said where portable mode is (the chip's tip; it was About's portable paragraph).
const PORTABLE_TRACE: &str = "Nothing goes to this PC but the PATH changes you apply (and the PC-wide PATH's undo records), and Windows still records that a program ran (Prefetch, recent-programs lists).";

/// `fetch` on a thread of its own, waited for at most `deadline` (FETCH_DEADLINE, review RAB-3):
/// past it the answer is `TimedOut`, whatever the site or a proxy is doing, and the thread is
/// left to end by itself (the real fetcher's read loop stops at the same deadline, and WinHTTP's
/// own timeouts bound each step); its late answer goes nowhere.
fn fetch_within(fetch: Fetcher<str, Fetched>, path: String, deadline: Duration) -> Fetched {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(fetch(&path));
    });
    match rx.recv_timeout(deadline) {
        Ok(f) => f,
        Err(RecvTimeoutError::Timeout) => Fetched::TimedOut,
        Err(RecvTimeoutError::Disconnected) => Fetched::Failed("the fetch stopped before it answered".into()),
    }
}

thread_local! {
    /// The window's controller, for workers' answers (they come back on this thread).
    static APP: RefCell<std::rc::Weak<App>> = const { RefCell::new(std::rc::Weak::new()) };
}

/// A message from outside the UI thread (a dialog's thread, the settings opener) to the app;
/// on the UI thread itself (the tests' dialogs answer at once) it is handled straight away.
fn post(m: Msg) {
    if let Some(app) = APP.with(|a| a.borrow().upgrade()) {
        app.handle(m);
        return;
    }
    let _ = slint::invoke_from_event_loop(move || {
        APP.with(|a| {
            if let Some(app) = a.borrow().upgrade() {
                app.handle(m);
            }
        })
    });
}

type PrefsChange = Change<Prefs>;
const PREFS_TELL_MS: u64 = 500;

fn prefs_writer(store: Store<Prefs>, pending: Arc<AtomicUsize>) -> Sender<PrefsChange> {
    let (tx, rx) = channel::<PrefsChange>();
    std::thread::spawn(move || {
        while let Ok(f) = rx.recv() {
            store.change(Arc::new(move |p: &mut Prefs| {
                *p = std::mem::take(p).sanitized();
                f(p);
            }));
            pending.fetch_sub(1, Ordering::SeqCst);
        }
    });
    tx
}

fn s(t: impl AsRef<str>) -> SharedString {
    t.as_ref().into()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Shown text from Windows' units: cleaned, at most `max` characters.
fn shown(u: &[u16], max: usize) -> String {
    wide::shown(u, max)
}

/// A long path for a row: its start and its end with an ellipsis between (the folder and the
/// file name both stay in sight).
pub fn middle(text: &str, max: usize) -> String {
    let n = text.chars().count();
    if n <= max || max < 9 {
        return text.to_string();
    }
    let keep = max - 1;
    let tail = keep * 2 / 3;
    let head = keep - tail;
    let a: String = text.chars().take(head).collect();
    let b: String = text.chars().skip(n - tail).collect();
    format!("{a}…{b}")
}

// ---------- action ids (the buttons Rust offers) ----------

pub mod act {
    pub const OPEN_ALIAS_SETTINGS: i32 = 1;
    pub const PREPARE_FIX: i32 = 2;
    pub const SHOW_IN_FOLDER: i32 = 3;
    pub const COPY_PATH: i32 = 4;
    pub const EDIT_USER: i32 = 10;
    pub const EDIT_MACHINE: i32 = 11;
    pub const BROADCAST: i32 = 12;
    pub const REFRESH_PATH: i32 = 13;
    pub const MOVE_UP: i32 = 20;
    pub const MOVE_DOWN: i32 = 21;
    pub const REMOVE: i32 = 22;
    pub const ADD: i32 = 23;
    pub const EDIT: i32 = 24;
    pub const TIDY: i32 = 25;
    pub const CANCEL_EDIT: i32 = 26;
    pub const PREVIEW: i32 = 27;
    pub const CLEAN_ENTRY: i32 = 28;
    pub const REFRESH_PROCS: i32 = 30;
    pub const USE_AS_CONTEXT: i32 = 31;
    pub const UNDO: i32 = 40;
    pub const RESTORE: i32 = 41;
    pub const EXPORT: i32 = 42;
    pub const REFRESH_HISTORY: i32 = 43;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Command,
    Path,
    Running,
    History,
}

impl Tab {
    fn index(self) -> i32 {
        match self {
            Tab::Command => 0,
            Tab::Path => 1,
            Tab::Running => 2,
            Tab::History => 3,
        }
    }

    fn of(i: i32) -> Tab {
        match i {
            1 => Tab::Path,
            2 => Tab::Running,
            3 => Tab::History,
            _ => Tab::Command,
        }
    }

    fn key(self) -> &'static str {
        match self {
            Tab::Command => "command",
            Tab::Path => "path",
            Tab::Running => "running",
            Tab::History => "history",
        }
    }

    fn from_key(k: &str) -> Tab {
        match k {
            "path" => Tab::Path,
            "running" => Tab::Running,
            "history" => Tab::History,
            _ => Tab::Command,
        }
    }
}

/// Where a resolution's PATH comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ctx {
    NewWindow,
    ThisApp,
    Process { pid: u32, start: u64, name: W, image: Option<W> },
}

impl Ctx {
    fn word(&self) -> String {
        match self {
            Ctx::NewWindow => "New window".into(),
            Ctx::ThisApp => "This app".into(),
            Ctx::Process { pid, name, .. } => format!("{} · {pid}", shown(name, 60)),
        }
    }
}

/// One resolution run's answer.
#[derive(Clone, Debug, Default)]
pub struct Resolved {
    pub command: Option<Command>,
    pub per: Vec<Resolution>,
    /// Aliases found among the matches, by lower-case path: the alias or why not read.
    pub aliases: HashMap<String, Result<crate::alias::Alias, String>>,
    pub cwd: Option<W>,
    pub read_at: i64,
    /// The context could not be read (its PATH): why.
    pub error: Option<String>,
    /// This app's PATH is older than the registry's.
    pub stale_note: Option<String>,
    /// PATHEXT was not in the context: cmd's default was used.
    pub pathext_note: Option<String>,
    /// The User PATH entries as typed and expanded, for Prepare the fix.
    pub user_entries: Vec<env::RegEntry>,
}

/// The PATH tab's read.
#[derive(Clone, Debug)]
pub struct PathRead {
    pub machine: env::Read,
    pub user: env::Read,
    pub pathext_machine: env::Read,
    pub pathext_user: env::Read,
    pub built: Option<W>,
    pub built_error: Option<String>,
    pub entries: Vec<health::Entry>,
    pub read_at: i64,
    /// The hives whose Path holds text after its first NUL (`System::path_holds_more`): shown
    /// only up to it, so the editor can't change it (RVD5).
    pub hidden: Vec<Hive>,
}

/// One process on the Running apps tab.
#[derive(Clone, Debug)]
pub struct ProcRow {
    pub info: ProcInfo,
    pub image: Option<W>,
    pub verdict: Verdict,
    pub cwd: Option<W>,
    pub wow64: bool,
}

/// How an Apply (or Undo) ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applied {
    /// Written and read back equal; what Explorer has now (None: not asked or not read).
    Done { hive: Hive, explorer: Option<bool>, entry: u64 },
    /// The value changed since the editor loaded it: nothing written; the value now.
    ChangedSince { hive: Hive, now: env::Read },
    /// Not done: why in words (failed, refused, declined, never connected).
    NotDone { hive: Hive, why: String, state: &'static str },
    /// The helper went away: whether it wrote is not known.
    Unknown { hive: Hive, why: String },
    /// Written, but its "done" entry (what Undo needs) could not be saved to journal.json (why):
    /// it waits in memory and is written as soon as the file can be.
    Unsaved { hive: Hive, why: String },
}

/// A helper's refusal in words, as `Applied::NotDone` says it.
pub fn helper_refused(r: helper::Reason) -> String {
    format!("the helper refused: {}.", r.words())
}

/// After an Undo is refused: what the Preview it opens shows (RU-5).
pub const BACK_PREVIEW: &str = "The Preview shows the way back to the value before that change, as a new change.";

/// After an Undo is refused while the editor holds edits not applied yet (RPS-5).
pub const EDITS_KEPT: &str = "The editor holds edits not applied yet, so they were kept: Apply or Cancel them, then Undo again for the way back.";

/// Why a change was refused or taken back because journal.json could not be saved.
fn journal_unsaved(why: &str, so: &str) -> String {
    format!("journal.json could not be saved ({why}), {so}: Undo needs it.")
}

/// The name a garbled journal.json was kept under (`journal.json.broken-<yyyyMMdd-HHmmss>`, RL2-4).
fn kept_name(store: &journal::Store) -> String {
    store.kept_aside().and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())).unwrap_or_else(|| "journal.json.broken-<date>-<time>".into())
}

/// A worker's answer, with the epoch it belongs to.
pub enum Msg {
    Resolved { seq: u64, out: Box<Resolved> },
    Details { path: W, details: Box<Details> },
    PathRead { seq: u64, read: Box<PathRead> },
    PathFacts { seq: u64, facts: Vec<Option<Facts>> },
    PreviewFacts { seq: u64, facts: Vec<(W, Facts)> },
    Procs { seq: u64, read: ProcsRead, read_at: i64 },
    Journal { entries: Vec<Entry>, note: String },
    Applied { seq: u64, outcome: Applied, journal: Vec<Entry> },
    Broadcasted { explorer: Option<bool> },
    Picked(Option<PathBuf>),
    Exported(Result<PathBuf, String>),
    Report(String),
    Failed(String),
}

/// The editor dialog's purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryPurpose {
    Add,
    Edit(usize),
}

#[derive(Default)]
struct State {
    prefs: Prefs,
    toast_seq: i32,
    toast_paths: HashMap<i32, PathBuf>,
    toast_time: HashMap<i32, (u64, u64)>,
    tab: Option<Tab>,
    // ---- Command ----
    command_text: String,
    /// The text last resolved (Escape in the field puts it back).
    committed: String,
    parse_note: String,
    shell: Option<Shell>,
    ctx: Option<Ctx>,
    /// Terminals for the context picker (and a chosen process that is not one).
    ctx_choices: Vec<Ctx>,
    /// New window's current folder (the profile folder until edited).
    cwd_new: Option<W>,
    cwd_committed: String,
    /// What Rust last put into the current-folder field.
    cwd_set: String,
    resolve_seq: u64,
    resolving: bool,
    resolved: Option<Resolved>,
    match_sel: usize,
    details: HashMap<W, Details>,
    details_pending: Vec<W>,
    // ---- PATH ----
    path_seq: u64,
    path_reading: bool,
    path: Option<PathRead>,
    facts: Vec<Option<Facts>>,
    facts_by_entry: HashMap<String, Facts>,
    path_sel: usize,
    editor: Option<Editor>,
    editor_sel: usize,
    /// The editor was reloaded by an Apply that found PATH changed; the read that follows tells
    /// whether that value hides text, and Apply is off until it lands (review RVD2-3).
    editor_unread: bool,
    /// The Preview reads PATH again when it opens (review RVD3-4): Apply is off until that read
    /// lands, and the Preview is shown from it.
    preview_reading: bool,
    /// Prepare the fix waits for the PATH read: the folder to move above WindowsApps.
    prepare: Option<(W, W)>,
    preview_seq: u64,
    preview_facts: HashMap<String, Facts>,
    entry_purpose: Option<EntryPurpose>,
    entry_first: String,
    apply_seq: u64,
    applying: bool,
    /// The entry the running apply undoes (None: an Apply or Restore).
    undoing: Option<Entry>,
    // ---- Running apps ----
    procs_seq: u64,
    procs_reading: bool,
    procs: Option<Vec<ProcRow>>,
    procs_problems: Vec<String>,
    procs_at: i64,
    procs_sel: usize,
    // ---- History ----
    journal: Vec<Entry>,
    journal_note: String,
    journal_loaded: bool,
    history_sel: usize,
    scroll_seq: i32,
    /// The install check: its number (an answer for another one does nothing), and while it
    /// runs, where its answer comes from.
    check_seq: u64,
    check_rx: Option<Receiver<(u64, Rows)>>,
}

/// Work the tests hold back until `release`.
type Held = Box<dyn FnOnce(&dyn Fn(Msg))>;

pub struct App {
    ui: Weak<AppWindow>,
    svc: Services,
    store: Store<Prefs>,
    journal: journal::Store,
    jkey: String,
    st: RefCell<State>,
    prefs_tx: Sender<PrefsChange>,
    prefs_pending: Arc<AtomicUsize>,
    toasts: Rc<VecModel<ToastItem>>,
    check_rows: Rc<VecModel<CheckRow>>,
    check_timer: Timer,
    me: RefCell<std::rc::Weak<App>>,
    inbox: Arc<Mutex<Vec<Msg>>>,
    held_jobs: RefCell<Vec<Held>>,
    /// Asks running work to end (the window closed).
    stop: Arc<AtomicBool>,
    /// The details cache for the session: identity, size and time → what was read.
    cache: Arc<Mutex<HashMap<CacheKey, Details>>>,
}

/// A row id for the list: the index into the tab's own list.
fn row_id(i: usize) -> i32 {
    i as i32
}

impl App {
    /// Wire the controller to a window made by `crate::window`.
    pub fn attach(ui: &AppWindow, store: Store<Prefs>, svc: Services) -> Rc<App> {
        let prefs = store.load().sanitized();
        let prefs_pending = Arc::new(AtomicUsize::new(0));
        let prefs_tx = prefs_writer(store.clone(), prefs_pending.clone());
        let journal = match &svc.local_dir {
            Some(d) => journal::open(d.join("journal.json")),
            None => journal::Store::memory(),
        };
        let jkey = journal::key(&svc.system.machine_guid(), &svc.system.user_sid());
        let tab = prefs.tab.as_deref().map(Tab::from_key).unwrap_or(Tab::Command);
        let shell = prefs.shell.as_deref().and_then(Shell::from_key).unwrap_or(Shell::Cmd);
        let app = Rc::new(App {
            ui: ui.as_weak(),
            svc,
            store,
            journal,
            jkey,
            st: RefCell::new(State { prefs, tab: Some(tab), shell: Some(shell), ctx: Some(Ctx::NewWindow), ..State::default() }),
            prefs_tx,
            prefs_pending,
            toasts: Rc::new(VecModel::default()),
            check_rows: Rc::new(VecModel::default()),
            check_timer: Timer::default(),
            me: RefCell::new(std::rc::Weak::new()),
            inbox: Arc::new(Mutex::new(Vec::new())),
            held_jobs: RefCell::new(Vec::new()),
            stop: Arc::new(AtomicBool::new(false)),
            cache: Arc::new(Mutex::new(HashMap::new())),
        });
        *app.me.borrow_mut() = Rc::downgrade(&app);
        APP.with(|a| *a.borrow_mut() = Rc::downgrade(&app));
        ui.set_toasts(ModelRc::from(app.toasts.clone()));
        ui.set_check_rows(ModelRc::from(app.check_rows.clone()));
        app.show_rows(&Rows::idle());
        ui.set_shells(ModelRc::new(VecModel::from(SHELLS.iter().map(|s| SharedString::from(s.word())).collect::<Vec<_>>())));
        app.wire(ui);
        if app.store.broken() {
            app.toast("prefs.json could not be read: the settings are back to their defaults, and the old file will be kept as prefs.json.broken.", ToastKind::Error, None);
        }
        if matches!(app.svc.mode, Mode::ReadOnly { .. }) {
            app.toast("Portable, read-only: settings and the journal will not be kept; Undo works until VibePath closes.", ToastKind::Info, None);
        }
        app.render();
        app
    }

    /// The first moves: the journal, the profile folder for New window, the terminals for the
    /// context picker, the PATH tab's read, and a command from the command line.
    pub fn start(&self, command: Option<std::ffi::OsString>) {
        self.load_journal();
        self.read_path();
        self.read_procs();
        if let Some(c) = command {
            let units = wide::of_os(&c);
            self.set_tab(Tab::Command);
            let text = wide::lossy(&units);
            self.st.borrow_mut().command_text = text.clone();
            if let Some(ui) = self.ui() {
                ui.set_command(s(&text));
            }
            self.resolve_units(units);
        } else {
            let tab = self.tab();
            self.on_tab_opened(tab);
        }
        if let Some(ui) = self.ui() {
            ui.invoke_focus_command();
        }
    }

    fn wire(self: &Rc<Self>, ui: &AppWindow) {
        macro_rules! on {
            ($setter:ident, |$a:ident $(, $arg:ident)*| $body:expr) => {{
                let w = Rc::downgrade(self);
                ui.$setter(move |$($arg),*| {
                    let Some($a) = w.upgrade() else { return Default::default() };
                    $body
                });
            }};
        }
        on!(on_toggle_theme, |a| a.toggle_theme());
        on!(on_copy_text, |a, t| (a.svc.copy)(&t));
        on!(on_toast_dismissed, |a, id| a.drop_toast(id));
        on!(on_toast_action, |a, id| a.toast_action(id));
        on!(on_dialogs_closed, |a| a.dialogs_closed());
        on!(on_command_edited, |a, t| a.st.borrow_mut().command_text = t.to_string());
        on!(on_command_escaped, |a| a.command_escaped());
        on!(on_resolve, |a| a.resolve());
        on!(on_copy_report, |a| a.copy_report());
        on!(on_tab_changed, |a, i| a.set_tab(Tab::of(i)));
        on!(on_shell_changed, |a, i| a.set_shell(Shell::from_index(i.max(0) as usize)));
        on!(on_context_changed, |a, i| a.set_context(i));
        on!(on_cwd_accepted, |a, t| a.cwd_accepted(&t));
        on!(on_cwd_escaped, |a| a.cwd_escaped());
        on!(on_action, |a, id| a.action(id));
        on!(on_row_clicked, |a, i| a.row_clicked(i));
        on!(on_row_opened, |a, i| a.row_opened(i));
        on!(on_preview_apply, |a| a.apply());
        on!(on_preview_cancel, |a| a.close_preview());
        on!(on_entry_edited, |a, t| a.entry_edited(&t));
        on!(on_entry_escaped, |a| a.entry_escaped());
        on!(on_entry_browse_clicked, |a| a.entry_browse());
        on!(on_entry_ok, |a| a.entry_ok());
        on!(on_entry_cancel, |a| a.entry_close());
        on!(on_key, |a, t, c, sh, alt| a.key(&t, c, sh, alt));
        on!(on_check_install, |a| a.check_install());
        on!(on_open_site, |a| (a.svc.open_url)(crate::check::SITE));
    }

    fn ui(&self) -> Option<AppWindow> {
        self.ui.upgrade()
    }

    // ---------- About's install check ----------

    /// "Check this install": one at a time, on a worker (it reads the files and may go online);
    /// the window looks for the answer every CHECK_POLL_MS meanwhile and goes on. Closing About
    /// leaves it running: the answer lands in the rows, which About shows when it opens again.
    fn check_install(&self) {
        let Some(ui) = self.ui() else { return };
        let seq = {
            let mut st = self.st.borrow_mut();
            if st.check_rx.is_some() {
                return;
            }
            st.check_seq += 1;
            st.check_seq
        };
        let (tx, rx) = channel();
        self.st.borrow_mut().check_rx = Some(rx);
        ui.set_checking(true);
        let (inspect, fetch, release) = (self.svc.inspect.clone(), self.svc.fetch.clone(), self.svc.release.clone());
        let installed = !self.svc.mode.portable();
        std::thread::spawn(move || {
            let local = inspect(&installed);
            // The exe updated or replaced under this one while it ran: nothing to compare (FED3).
            let rows = if local.replaced {
                crate::check::replaced_rows(&release, &local)
            } else {
                let fetched = fetch_within(fetch, crate::check::list_path(release.app), release.wait);
                crate::check::rows(&release, &local, fetched)
            };
            let _ = tx.send((seq, rows));
        });
        let w = self.me.borrow().clone();
        self.check_timer.start(TimerMode::Repeated, Duration::from_millis(CHECK_POLL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.poll_check();
            }
        });
    }

    /// The check's answer, once it is there: the rows, and the button back.
    fn poll_check(&self) {
        let got = {
            let st = self.st.borrow();
            let Some(rx) = st.check_rx.as_ref() else { return };
            match rx.try_recv() {
                Ok((seq, rows)) => Some((seq == st.check_seq).then_some(rows)),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Some(Rows::stopped())),
            }
        };
        let Some(rows) = got else { return };
        self.check_timer.stop();
        self.st.borrow_mut().check_rx = None;
        if let Some(rows) = rows {
            self.show_rows(&rows);
        }
        if let Some(ui) = self.ui() {
            ui.set_checking(false);
            ui.set_checked(true);
        }
    }

    fn show_rows(&self, rows: &Rows) {
        let dot = |d: Dot| match d {
            Dot::Idle => CheckDot::Idle,
            Dot::Ok => CheckDot::Ok,
            Dot::Warn => CheckDot::Warn,
            Dot::Danger => CheckDot::Danger,
        };
        let all: Vec<CheckRow> = rows.all().iter().map(|(name, r)| CheckRow { name: s(name), text: s(&r.text), dot: dot(r.dot) }).collect();
        self.check_rows.set_vec(all);
    }

    fn me(&self) -> std::rc::Weak<App> {
        self.me.borrow().clone()
    }

    fn sys(&self) -> Arc<dyn System> {
        self.svc.system.clone()
    }

    fn dialog_open(&self) -> bool {
        self.ui().is_some_and(|ui| ui.get_about_open() || ui.get_preview_open() || ui.get_entry_open())
    }

    fn now(&self) -> i64 {
        (self.svc.system.now_ms() / 1000) as i64
    }

    fn clock(&self, t: i64) -> String {
        crate::host::clock(t, (self.svc.utc_offset)(t))
    }

    fn date_time(&self, t: i64) -> String {
        crate::host::date_time(t, (self.svc.utc_offset)(t))
    }

    pub fn tab(&self) -> Tab {
        self.st.borrow().tab.unwrap_or(Tab::Command)
    }

    pub fn shell(&self) -> Shell {
        self.st.borrow().shell.unwrap_or(Shell::Cmd)
    }

    fn ctx(&self) -> Ctx {
        self.st.borrow().ctx.clone().unwrap_or(Ctx::NewWindow)
    }

    // ---------- prefs ----------

    pub fn prefs(&self) -> Prefs {
        self.st.borrow().prefs.clone()
    }

    pub fn save_prefs(&self, change: impl Fn(&mut Prefs) + Send + Sync + 'static) {
        let f: PrefsChange = Arc::new(change);
        f(&mut self.st.borrow_mut().prefs);
        self.prefs_pending.fetch_add(1, Ordering::SeqCst);
        if self.prefs_tx.send(f).is_err() {
            self.prefs_pending.fetch_sub(1, Ordering::SeqCst);
        }
        let w = self.me();
        Timer::single_shot(Duration::from_millis(PREFS_TELL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.tell_garbled();
            }
        });
    }

    fn tell_garbled(&self) {
        if self.store.take_garbled() {
            self.toast("prefs.json was damaged: it is kept as prefs.json.broken, and this window's settings are saved in its place.", ToastKind::Error, None);
        }
        if self.journal.take_garbled() {
            self.toast(&format!("journal.json was damaged: it is kept as {}, and this window's entries are saved in its place.", kept_name(&self.journal)), ToastKind::Error, None);
        }
    }

    /// At exit (and in tests): running work is told to end, the prefs thread hands its last
    /// change to the store (at most two seconds), then what is unwritten is written, the journal
    /// first, on a thread of its own, waited for at most two seconds too: a prefs file on a share
    /// that stopped answering never holds the window's thread for good (VibePing PING-8, review
    /// X15CON-4). A prefs thread still busy then is not waited for (the journal is still
    /// written): at exit the process ends it, and the changes it had not written are lost,
    /// unsaid.
    pub fn finish_prefs(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let start = Instant::now();
        let limit = Duration::from_secs(2);
        while self.prefs_pending.load(Ordering::SeqCst) > 0 && start.elapsed() < limit {
            std::thread::sleep(Duration::from_millis(2));
        }
        let store = (self.prefs_pending.load(Ordering::SeqCst) == 0).then(|| self.store.clone());
        let journal = self.journal.clone();
        let (tx, rx) = channel::<()>();
        std::thread::spawn(move || {
            journal.flush();
            if let Some(store) = store {
                store.flush();
            }
            let _ = tx.send(());
        });
        let _ = rx.recv_timeout(limit);
    }

    fn toggle_theme(&self) {
        let Some(ui) = self.ui() else { return };
        let theme = ui.global::<Theme>();
        let dark = !theme.get_dark();
        theme.set_dark(dark);
        self.save_prefs(move |p| p.theme = Some(if dark { "dark" } else { "light" }.into()));
    }

    // ---------- toasts ----------

    /// A toast, bottom right: errors stay 10 s, the rest 5 s. With `reveal` it offers "Show".
    pub fn toast(&self, text: &str, kind: ToastKind, reveal: Option<PathBuf>) {
        let id = {
            let mut st = self.st.borrow_mut();
            st.toast_seq += 1;
            let id = st.toast_seq;
            if let Some(p) = reveal.clone() {
                st.toast_paths.insert(id, p);
            }
            id
        };
        while self.toasts.row_count() >= 3 {
            let old = self.toasts.row_data(0).map(|t| t.id).unwrap_or(0);
            self.drop_toast(old);
        }
        self.toasts.push(ToastItem { id, text: s(text), kind, action: if reveal.is_some() { s("Show") } else { s("") } });
        self.arm_toast(id, if kind == ToastKind::Error { 10_000 } else { 5_000 });
    }

    /// A toast's timer, `ms` from now. Only its newest timer counts, and while a dialog is open
    /// it waits (`dialogs_closed` gives it its full time again).
    fn arm_toast(&self, id: i32, ms: u64) {
        let generation = {
            let mut st = self.st.borrow_mut();
            let t = st.toast_time.entry(id).or_insert((0, ms));
            t.0 += 1;
            t.0
        };
        let w = self.me();
        Timer::single_shot(Duration::from_millis(ms), move || {
            let Some(a) = w.upgrade() else { return };
            let current = a.st.borrow().toast_time.get(&id).is_some_and(|t| t.0 == generation);
            if current && !a.dialog_open() {
                a.drop_toast(id);
            }
        });
    }

    fn dialogs_closed(&self) {
        let all: Vec<(i32, u64)> = self.st.borrow().toast_time.iter().map(|(id, t)| (*id, t.1)).collect();
        for (id, ms) in all {
            self.arm_toast(id, ms);
        }
    }

    fn drop_toast(&self, id: i32) {
        if let Some(i) = self.toasts.iter().position(|t| t.id == id) {
            self.toasts.remove(i);
        }
        let mut st = self.st.borrow_mut();
        st.toast_time.remove(&id);
        st.toast_paths.remove(&id);
    }

    fn toast_action(&self, id: i32) {
        let p = self.st.borrow().toast_paths.get(&id).cloned();
        if let Some(p) = p {
            (self.svc.reveal)(&p);
        }
        self.drop_toast(id);
    }

    pub fn toast_texts(&self) -> Vec<String> {
        self.toasts.iter().map(|t| t.text.to_string()).collect()
    }

    // ---------- workers ----------

    /// Run `work` off the UI thread; each message it sends comes back to `handle` (tests: at
    /// once, or held until `release`). A burst of messages is one wake-up of the window.
    fn bg(&self, work: impl FnOnce(&dyn Fn(Msg)) + Send + 'static) {
        if self.svc.manual {
            if self.svc.hold.get() {
                self.held_jobs.borrow_mut().push(Box::new(work));
            } else {
                let out = RefCell::new(Vec::new());
                work(&|m| out.borrow_mut().push(m));
                for m in out.into_inner() {
                    self.handle(m);
                }
            }
            return;
        }
        let inbox = self.inbox.clone();
        let _ = std::thread::Builder::new().name("worker".into()).stack_size(2 * 1024 * 1024).spawn(move || {
            work(&|m| {
                let first = {
                    let mut i = lock(&inbox);
                    i.push(m);
                    i.len() == 1
                };
                if first {
                    let _ = slint::invoke_from_event_loop(|| {
                        APP.with(|a| {
                            if let Some(app) = a.borrow().upgrade() {
                                app.drain();
                            }
                        })
                    });
                }
            });
        });
    }

    fn drain(&self) {
        let msgs = std::mem::take(&mut *lock(&self.inbox));
        for m in msgs {
            self.handle(m);
        }
    }

    /// Tests: hold the workers' answers until `release` (or let them answer at once).
    pub fn set_hold(&self, on: bool) {
        self.svc.hold.set(on);
    }

    /// Tests: the work held back so far.
    pub fn held(&self) -> usize {
        self.held_jobs.borrow().len()
    }

    /// Tests: let the held work answer, in the order it was started (and what it starts).
    pub fn release(&self) {
        loop {
            let jobs = std::mem::take(&mut *self.held_jobs.borrow_mut());
            if jobs.is_empty() {
                return;
            }
            for j in jobs {
                let out = RefCell::new(Vec::new());
                j(&|m| out.borrow_mut().push(m));
                for m in out.into_inner() {
                    self.handle(m);
                }
            }
        }
    }

    /// Tests: let only held work number `i` answer now; the rest stay held.
    pub fn release_at(&self, i: usize) {
        let job = {
            let mut held = self.held_jobs.borrow_mut();
            if i >= held.len() {
                return;
            }
            held.remove(i)
        };
        let out = RefCell::new(Vec::new());
        job(&|m| out.borrow_mut().push(m));
        for m in out.into_inner() {
            self.handle(m);
        }
    }

    /// Tests: a worker's answer delivered as if a thread sent it.
    pub fn deliver(&self, m: Msg) {
        self.handle(m);
    }

    fn handle(&self, m: Msg) {
        match m {
            Msg::Resolved { seq, out } => {
                if seq != self.st.borrow().resolve_seq {
                    return; // an older run's answer
                }
                {
                    let mut st = self.st.borrow_mut();
                    st.resolving = false;
                    st.resolved = Some(*out);
                    st.match_sel = 0;
                }
                self.select_winner();
                self.render();
                self.load_details();
            }
            Msg::Details { path, details } => {
                {
                    let mut st = self.st.borrow_mut();
                    st.details_pending.retain(|p| *p != path);
                    st.details.insert(path, *details);
                }
                if self.tab() == Tab::Command {
                    self.render();
                }
            }
            Msg::PathRead { seq, read } => {
                if seq != self.st.borrow().path_seq {
                    return;
                }
                let (followed, reading, hive) = {
                    let mut st = self.st.borrow_mut();
                    st.facts = vec![None; read.entries.len()];
                    let followed = editor_follows(&mut st, &read);
                    st.path = Some(*read);
                    (followed, std::mem::take(&mut st.preview_reading), st.editor.as_ref().map(|e| e.hive))
                };
                self.after_path_read();
                self.render();
                let open = self.ui().is_some_and(|ui| ui.get_preview_open());
                if let (Followed::OverEdits, Some(hive)) = (followed, hive) {
                    // The edits were made on a value that is no longer there (RVD3-3): back to
                    // the editor, which holds it as it is now.
                    if let Some(ui) = self.ui() {
                        ui.set_preview_open(false);
                    }
                    self.toast(&changed_since(hive), ToastKind::Error, None);
                } else if open && (followed != Followed::No || reading) {
                    self.render_preview();
                }
            }
            Msg::PathFacts { seq, facts } => {
                if seq != self.st.borrow().path_seq {
                    return;
                }
                {
                    let mut st = self.st.borrow_mut();
                    st.path_reading = false;
                    let entries = st.path.as_ref().map(|p| p.entries.clone()).unwrap_or_default();
                    for (e, f) in entries.iter().zip(&facts) {
                        if let Some(f) = f {
                            st.facts_by_entry.insert(fact_key(&e.expanded), f.clone());
                        }
                    }
                    st.facts = facts;
                }
                self.render();
            }
            Msg::PreviewFacts { seq, facts } => {
                if seq != self.st.borrow().preview_seq {
                    return;
                }
                {
                    let mut st = self.st.borrow_mut();
                    for (e, f) in facts {
                        st.preview_facts.insert(fact_key(&e), f);
                    }
                }
                self.render_preview();
                self.render();
            }
            Msg::Procs { seq, read, read_at } => {
                if seq != self.st.borrow().procs_seq {
                    return;
                }
                {
                    let mut st = self.st.borrow_mut();
                    st.procs_reading = false;
                    st.procs_at = read_at;
                    st.procs = Some(read.rows);
                    st.procs_problems = read.problems;
                    st.ctx_choices = Vec::new();
                }
                self.fill_contexts();
                self.render();
            }
            Msg::Journal { entries, note } => {
                {
                    let mut st = self.st.borrow_mut();
                    st.journal = entries;
                    st.journal_note = note;
                    st.journal_loaded = true;
                }
                self.render();
            }
            Msg::Applied { seq, outcome, journal } => {
                if seq != self.st.borrow().apply_seq {
                    return;
                }
                {
                    let mut st = self.st.borrow_mut();
                    st.applying = false;
                    st.journal = journal;
                }
                self.tell_garbled();
                self.applied(outcome);
            }
            Msg::Broadcasted { explorer } => {
                match explorer {
                    Some(true) => self.toast("Broadcast: Explorer has the new PATH: new windows from Start, Run and Explorer get it.", ToastKind::Ok, None),
                    Some(false) => self.toast("Broadcast, but Explorer still has the old PATH: Broadcast again, or sign out and in.", ToastKind::Error, None),
                    None => self.toast("Broadcast: Explorer's PATH could not be read to check it.", ToastKind::Info, None),
                }
                self.read_procs();
            }
            Msg::Picked(p) => {
                if let Some(p) = p {
                    let units = wide::of_os(p.as_os_str());
                    let text = wide::lossy(&units);
                    if let Some(ui) = self.ui() {
                        ui.set_entry_text(s(&text));
                    }
                    self.entry_edited(&text);
                }
            }
            Msg::Exported(r) => match r {
                Ok(p) => self.toast(&format!("Exported {}.", clean_max(&p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), 80)), ToastKind::Ok, Some(p)),
                Err(e) => self.toast(&format!("Could not export: {}", clean_max(&e, 200)), ToastKind::Error, None),
            },
            Msg::Report(text) => {
                if (self.svc.copy)(&text) {
                    self.toast("Copied the report.", ToastKind::Ok, None);
                } else {
                    self.toast("Could not copy the report: the clipboard is busy.", ToastKind::Error, None);
                }
            }
            Msg::Failed(e) => self.toast(&clean_max(&e, 240), ToastKind::Error, None),
        }
    }

    // ---------- tabs ----------

    fn set_tab(&self, tab: Tab) {
        if self.tab() == tab {
            self.render();
            return;
        }
        self.st.borrow_mut().tab = Some(tab);
        let key = tab.key().to_string();
        self.save_prefs(move |p| p.tab = Some(key.clone()));
        self.on_tab_opened(tab);
        self.render();
        self.bump_scroll();
    }

    /// Opening a tab reads what it shows again (Running apps, History); PATH and Command keep
    /// their read until Refresh or Resolve.
    fn on_tab_opened(&self, tab: Tab) {
        match tab {
            Tab::Running => self.read_procs(),
            Tab::History => self.load_journal(),
            Tab::Path => {
                if self.st.borrow().path.is_none() && !self.st.borrow().path_reading {
                    self.read_path();
                }
            }
            Tab::Command => {}
        }
    }

    fn set_shell(&self, shell: Shell) {
        self.st.borrow_mut().shell = Some(shell);
        self.st.borrow_mut().match_sel = 0;
        let key = shell.key().to_string();
        self.save_prefs(move |p| p.shell = Some(key.clone()));
        self.select_winner();
        self.render();
        self.load_details();
    }

    // ---------- Command ----------

    fn command_escaped(&self) -> bool {
        let (text, committed) = {
            let st = self.st.borrow();
            (st.command_text.clone(), st.committed.clone())
        };
        if text == committed {
            return false;
        }
        self.st.borrow_mut().command_text = committed.clone();
        if let Some(ui) = self.ui() {
            ui.set_command(s(&committed));
        }
        true
    }

    /// Resolve (Enter, the button).
    pub fn resolve(&self) {
        let text = self.ui().map(|ui| ui.get_command().to_string()).unwrap_or_else(|| self.st.borrow().command_text.clone());
        self.st.borrow_mut().command_text = text.clone();
        self.resolve_units(input::units(&text));
    }

    fn resolve_units(&self, units: W) {
        let parsed = input::command(&units);
        let text = wide::lossy(&units);
        {
            let mut st = self.st.borrow_mut();
            st.committed = text.clone();
            st.parse_note = parsed.note.clone();
        }
        if self.tab() != Tab::Command {
            self.st.borrow_mut().tab = Some(Tab::Command);
        }
        let Some(cmd) = parsed.command else {
            let mut st = self.st.borrow_mut();
            st.resolve_seq += 1;
            st.resolving = false;
            st.resolved = None;
            drop(st);
            self.render();
            return;
        };
        if !text.trim().is_empty() {
            let t = text.trim().to_string();
            self.save_prefs(move |p| {
                p.recent.retain(|r| r != &t);
                p.recent.insert(0, t.clone());
                p.recent.truncate(10);
            });
        }
        let (seq, ctx, cwd_new) = {
            let mut st = self.st.borrow_mut();
            st.resolve_seq += 1;
            st.resolving = true;
            (st.resolve_seq, st.ctx.clone().unwrap_or(Ctx::NewWindow), st.cwd_new.clone())
        };
        self.render();
        let sys = self.sys();
        let now = self.now();
        self.bg(move |send| {
            let out = resolve_job(&*sys, cmd, ctx, cwd_new, now);
            send(Msg::Resolved { seq, out: Box::new(out) });
        });
    }

    /// The selected row starts on the winner.
    fn select_winner(&self) {
        let shell = self.shell();
        let mut st = self.st.borrow_mut();
        let w = st.resolved.as_ref().and_then(|r| r.per.get(shell.index())).and_then(|r| r.winner);
        st.match_sel = w.unwrap_or(0);
    }

    fn current_resolution(&self) -> Option<Resolution> {
        let shell = self.shell();
        self.st.borrow().resolved.as_ref().and_then(|r| r.per.get(shell.index()).cloned())
    }

    /// Read the selected file match's details (and the winner's) on a worker, once a session
    /// per file identity, size and time.
    fn load_details(&self) {
        let Some(res) = self.current_resolution() else { return };
        let sel = self.st.borrow().match_sel;
        let mut want: Vec<usize> = vec![sel];
        if let Some(wi) = res.winner {
            want.push(wi);
        }
        for i in want {
            let Some(row) = res.rows.get(i) else { continue };
            let path = match &row.found {
                Found::File { path, .. } => path.clone(),
                Found::AppPath(a) if !a.missing => a.target.clone(),
                _ => continue,
            };
            let read_from = self.read_from(&path);
            {
                let mut st = self.st.borrow_mut();
                if st.details.contains_key(&path) || st.details_pending.contains(&path) {
                    continue;
                }
                st.details_pending.push(path.clone());
            }
            let sys = self.sys();
            let cache = self.cache.clone();
            self.bg(move |send| {
                let d = details_job(&*sys, &cache, &path, &read_from);
                send(Msg::Details { path, details: Box::new(d) });
            });
        }
    }

    /// An alias's version and signer come from its target.
    fn read_from(&self, path: &[u16]) -> W {
        let st = self.st.borrow();
        match st.resolved.as_ref().and_then(|r| r.aliases.get(&wide::lossy(path).to_lowercase())) {
            Some(Ok(a)) => a.target.clone(),
            _ => path.to_vec(),
        }
    }

    fn set_context(&self, i: i32) {
        let choices = self.context_list();
        let Some(c) = choices.get(i.max(0) as usize).cloned() else { return };
        match c {
            ContextChoice::Ctx(ctx) => {
                self.st.borrow_mut().ctx = Some(ctx);
                self.render();
                if !self.st.borrow().committed.trim().is_empty() {
                    let t = self.st.borrow().committed.clone();
                    self.resolve_units(input::units(&t));
                }
            }
            ContextChoice::Other => {
                self.set_tab(Tab::Running);
                self.toast("Pick a program on Running apps, then Use as context.", ToastKind::Info, None);
                self.render();
            }
        }
    }

    fn cwd_accepted(&self, t: &str) {
        let units = input::units(t.trim());
        {
            let mut st = self.st.borrow_mut();
            st.cwd_new = if units.is_empty() { None } else { Some(units) };
            st.cwd_committed = t.trim().to_string();
            st.cwd_set = t.trim().to_string();
        }
        let c = self.st.borrow().committed.clone();
        if !c.trim().is_empty() {
            self.resolve_units(input::units(&c));
        } else {
            self.render();
        }
    }

    fn cwd_escaped(&self) -> bool {
        let Some(ui) = self.ui() else { return false };
        let committed = self.cwd_shown_text();
        if ui.get_cwd().as_str() == committed {
            return false;
        }
        ui.set_cwd(s(&committed));
        self.st.borrow_mut().cwd_set = committed;
        true
    }

    fn cwd_shown_text(&self) -> String {
        let st = self.st.borrow();
        match st.ctx.clone().unwrap_or(Ctx::NewWindow) {
            Ctx::NewWindow => st.cwd_new.as_ref().map(|c| wide::lossy(c)).or_else(|| st.resolved.as_ref().and_then(|r| r.cwd.as_ref()).map(|c| wide::lossy(c))).unwrap_or_default(),
            _ => st.resolved.as_ref().and_then(|r| r.cwd.as_ref()).map(|c| wide::lossy(c)).unwrap_or_default(),
        }
    }

    /// The context picker's entries: New window, This app, the terminals, the chosen process
    /// when it is not one, and "Another program…" (Running apps).
    fn context_list(&self) -> Vec<ContextChoice> {
        let st = self.st.borrow();
        let mut v = vec![ContextChoice::Ctx(Ctx::NewWindow), ContextChoice::Ctx(Ctx::ThisApp)];
        for c in &st.ctx_choices {
            v.push(ContextChoice::Ctx(c.clone()));
        }
        if let Some(c @ Ctx::Process { .. }) = &st.ctx
            && !st.ctx_choices.contains(c) {
                v.push(ContextChoice::Ctx(c.clone()));
            }
        v.push(ContextChoice::Other);
        v
    }

    fn fill_contexts(&self) {
        let mut st = self.st.borrow_mut();
        let Some(procs) = st.procs.as_ref() else { return };
        let mut terms: Vec<&ProcRow> = procs.iter().filter(|p| stale::is_terminal(&p.info.name) && !matches!(p.verdict, Verdict::Unknown(_))).collect();
        terms.sort_by_key(|p| (wide::sort_key(&p.info.name), p.info.pid));
        let list: Vec<Ctx> = terms.into_iter().take(30).map(|p| Ctx::Process { pid: p.info.pid, start: p.info.start, name: p.info.name.clone(), image: p.image.clone() }).collect();
        st.ctx_choices = list;
    }

    // ---------- PATH ----------

    fn read_path(&self) {
        let seq = {
            let mut st = self.st.borrow_mut();
            st.path_seq += 1;
            st.path_reading = true;
            st.path_seq
        };
        self.render();
        let sys = self.sys();
        let now = self.now();
        self.bg(move |send| {
            let read = path_read_job(&*sys, now);
            let entries = read.entries.clone();
            send(Msg::PathRead { seq, read: Box::new(read) });
            let facts = facts_job(&sys, &entries);
            send(Msg::PathFacts { seq, facts });
        });
    }

    /// After a PATH read: an editor opened by Prepare the fix gets its move.
    fn after_path_read(&self) {
        let pending = self.st.borrow_mut().prepare.take();
        if let Some((real, apps)) = pending {
            self.prepare_fix_now(&real, &apps);
        }
    }

    pub fn report(&self) -> Option<Report> {
        let st = self.st.borrow();
        let p = st.path.as_ref()?;
        let (s32, _, _) = self.svc.system.system_dirs();
        Some(health::judge(health::Input {
            machine: &p.machine,
            user: &p.user,
            pathext_machine: &p.pathext_machine,
            pathext_user: &p.pathext_user,
            rows: p.entries.iter().cloned().zip(st.facts.iter().cloned()).collect(),
            built: p.built.clone(),
            system32: s32,
        }))
    }

    fn open_editor(&self, hive: Hive) {
        let (loaded, hidden) = {
            let st = self.st.borrow();
            let Some(p) = st.path.as_ref() else { return };
            let hidden = p.hidden.contains(&hive);
            match if hive == Hive::Machine { &p.machine } else { &p.user } {
                env::Read::Value(v) => (Some(v.clone()), hidden),
                env::Read::Missing => (None, false),
                env::Read::Error(e) => {
                    let e = e.clone();
                    drop(st);
                    self.toast(&format!("{} PATH could not be read ({e}): it cannot be edited now.", hive.word()), ToastKind::Error, None);
                    return;
                }
            }
        };
        let mut st = self.st.borrow_mut();
        st.editor = Some(Editor { hidden, ..Editor::new(hive, loaded) });
        st.editor_sel = 0;
        st.tab = Some(Tab::Path);
        drop(st);
        self.render();
        self.bump_scroll();
    }

    fn editing(&self) -> bool {
        self.st.borrow().editor.is_some()
    }

    fn editor_facts(&self, typed: &W, hive: Hive) -> Option<Facts> {
        let st = self.st.borrow();
        let exp = self.expand_for(typed, hive, st.editor.as_ref().and_then(|e| e.loaded.as_ref()).map(|v| v.kind));
        st.facts_by_entry.get(&fact_key(&exp)).cloned().or_else(|| st.preview_facts.get(&fact_key(&exp)).cloned())
    }

    /// An entry as the environment gets it: expanded unless the value stays REG_SZ (the editor
    /// always writes REG_EXPAND_SZ, so its entries are expanded).
    fn expand_for(&self, typed: &W, _hive: Hive, _kind: Option<Kind>) -> W {
        self.svc.system.expand(typed)
    }

    fn editor_action(&self, id: i32) {
        let sel = self.st.borrow().editor_sel;
        match id {
            act::MOVE_UP | act::MOVE_DOWN => {
                let mut st = self.st.borrow_mut();
                if let Some(e) = st.editor.as_mut() {
                    let n = e.shift(sel, id == act::MOVE_UP);
                    st.editor_sel = n;
                }
                drop(st);
                self.bump_scroll();
            }
            act::REMOVE => {
                let mut st = self.st.borrow_mut();
                if let Some(e) = st.editor.as_mut() {
                    e.remove(sel);
                    let n = e.entries.len();
                    st.editor_sel = sel.min(n.saturating_sub(1));
                }
            }
            act::ADD => self.entry_open(EntryPurpose::Add),
            act::EDIT => {
                if self.st.borrow().editor.as_ref().is_some_and(|e| sel < e.entries.len()) {
                    self.entry_open(EntryPurpose::Edit(sel));
                }
            }
            act::TIDY => self.tidy(),
            act::CLEAN_ENTRY => {
                if let Some(e) = self.st.borrow_mut().editor.as_mut() {
                    e.clean(sel);
                }
            }
            act::CANCEL_EDIT => {
                self.st.borrow_mut().editor = None;
            }
            act::PREVIEW => self.open_preview(),
            _ => {}
        }
        self.render();
    }

    fn tidy(&self) {
        let (hive, machine_entries) = {
            let st = self.st.borrow();
            let Some(e) = st.editor.as_ref() else { return };
            let me: Vec<W> = st.path.as_ref().map(|p| p.entries.iter().filter(|x| x.hive == Hive::Machine && !x.empty()).map(|x| x.expanded.clone()).collect()).unwrap_or_default();
            (e.hive, me)
        };
        let fact = |typed: &W| {
            let exp = self.expand_for(typed, hive, None);
            let f = self.editor_facts(typed, hive);
            editor::Tidy {
                expanded: exp,
                dead: f.as_ref().is_some_and(|f| f.state == FactState::Dead),
                unknown: f.as_ref().is_none_or(|f| matches!(f.state, FactState::Unknown(_) | FactState::NoDrive | FactState::NotLooked)),
                id: f.and_then(|f| f.id),
            }
        };
        let removed = {
            let mut ed = self.st.borrow().editor.clone();
            let r = ed.as_mut().map(|e| e.tidy(&fact, &machine_entries)).unwrap_or_default();
            let mut st = self.st.borrow_mut();
            st.editor = ed;
            st.editor_sel = 0;
            r
        };
        let n = removed.iter().filter(|r| !r.is_empty()).count();
        let empties = removed.len() - n;
        let msg = match (n, empties) {
            (0, 0) => "Tidy found nothing to remove.".to_string(),
            (n, 0) => format!("Tidy removed {}: Preview shows what changes.", plural(n, "entry", "entries")),
            (0, e) => format!("Tidy removed {}.", plural(e, "empty entry", "empty entries")),
            (n, e) => format!("Tidy removed {} and {}: Preview shows what changes.", plural(n, "entry", "entries"), plural(e, "empty entry", "empty entries")),
        };
        self.toast(&msg, ToastKind::Info, None);
    }

    // ---- the entry dialog (Add…, Edit…) ----

    fn entry_open(&self, purpose: EntryPurpose) {
        let first = match purpose {
            EntryPurpose::Add => String::new(),
            EntryPurpose::Edit(i) => self.st.borrow().editor.as_ref().and_then(|e| e.entries.get(i)).map(|x| wide::lossy(x)).unwrap_or_default(),
        };
        {
            let mut st = self.st.borrow_mut();
            st.entry_purpose = Some(purpose);
            st.entry_first = first.clone();
        }
        if let Some(ui) = self.ui() {
            ui.set_entry_title(s(if matches!(purpose, EntryPurpose::Add) { "Add a folder" } else { "Edit the entry" }));
            ui.set_entry_ok_text(s(if matches!(purpose, EntryPurpose::Add) { "Add" } else { "Save" }));
            ui.set_entry_text(s(&first));
            ui.set_entry_problem(s(""));
            ui.set_entry_browse(true);
            ui.set_entry_open(true);
        }
    }

    fn entry_edited(&self, _t: &str) {
        if let Some(ui) = self.ui() {
            ui.set_entry_problem(s(""));
        }
    }

    fn entry_escaped(&self) -> bool {
        let Some(ui) = self.ui() else { return false };
        let first = self.st.borrow().entry_first.clone();
        if ui.get_entry_text().as_str() == first {
            return false;
        }
        ui.set_entry_text(s(&first));
        true
    }

    fn entry_browse(&self) {
        (self.svc.pick_folder)(Box::new(|p| post(Msg::Picked(p))));
    }

    fn entry_ok(&self) {
        let Some(ui) = self.ui() else { return };
        let typed = input::units(ui.get_entry_text().as_str());
        let sys = self.sys();
        // A file means its folder: a quick look on a local path only (a share would freeze the
        // window); a network path is taken as a folder.
        let is_file = |p: &[u16]| matches!(crate::fsprobe::drive_of(p), crate::fsprobe::Drive::Local | crate::fsprobe::Drive::Removable) && sys.is_file(p);
        match input::folder(&typed, &is_file) {
            Err(why) => ui.set_entry_problem(s(&why)),
            Ok(entry) => {
                let purpose = self.st.borrow().entry_purpose;
                let mut st = self.st.borrow_mut();
                let sel = st.editor_sel;
                if let Some(e) = st.editor.as_mut() {
                    match purpose {
                        Some(EntryPurpose::Edit(i)) => {
                            e.edit(i, entry.clone());
                            st.editor_sel = i;
                        }
                        _ => {
                            let after = if e.entries.is_empty() { None } else { Some(sel) };
                            let at = e.add(entry.clone(), after);
                            st.editor_sel = at;
                        }
                    }
                }
                drop(st);
                ui.set_entry_open(false);
                self.check_facts(vec![entry]);
                self.render();
                self.bump_scroll();
            }
        }
    }

    fn entry_close(&self) {
        if let Some(ui) = self.ui() {
            ui.set_entry_open(false);
        }
    }

    /// Facts for entries the PATH read did not have (added or edited ones), for the editor's
    /// rows, Tidy and the Preview.
    fn check_facts(&self, typed: Vec<W>) {
        let hive = self.st.borrow().editor.as_ref().map(|e| e.hive).unwrap_or(Hive::User);
        let sys = self.sys();
        let seq = self.st.borrow().preview_seq;
        let exps: Vec<W> = typed.iter().map(|t| sys.expand(t)).filter(|e| !self.st.borrow().facts_by_entry.contains_key(&fact_key(e)) && !self.st.borrow().preview_facts.contains_key(&fact_key(e))).collect();
        if exps.is_empty() {
            return;
        }
        self.bg(move |send| {
            let facts: Vec<(W, Facts)> = exps.iter().map(|e| (e.clone(), sys.facts(e, hive == Hive::Machine))).collect();
            send(Msg::PreviewFacts { seq, facts });
        });
    }

    // ---- Preview and Apply ----

    /// The Preview, from PATH read again (review RVD3-4): a value mended in regedit while the
    /// editor is open is seen by opening the Preview again, which its words say.
    fn open_preview(&self) {
        let missing: Vec<W> = {
            let mut st = self.st.borrow_mut();
            let Some(e) = st.editor.as_ref() else { return };
            let missing = e.entries.iter().filter(|x| !x.is_empty()).cloned().collect();
            st.preview_reading = true;
            missing
        };
        self.check_facts(missing);
        if let Some(ui) = self.ui() {
            ui.set_preview_open(true);
        }
        self.render_preview();
        self.read_path();
    }

    fn close_preview(&self) {
        if let Some(ui) = self.ui() {
            ui.set_preview_open(false);
        }
    }

    /// The new value judged as the PATH table would judge it.
    fn preview_report(&self, ed: &Editor) -> Report {
        let st = self.st.borrow();
        let p = st.path.as_ref();
        let new_value = env::Read::Value(env::Value { kind: Kind::ExpandSz, raw: ed.value() });
        let (machine, user) = match ed.hive {
            Hive::Machine => (new_value.clone(), p.map(|p| p.user.clone()).unwrap_or(env::Read::Missing)),
            Hive::User => (p.map(|p| p.machine.clone()).unwrap_or(env::Read::Missing), new_value.clone()),
        };
        let sys = self.svc.system.clone();
        let expand = |x: &[u16]| sys.expand(x);
        let mut es = health::entries_of(Hive::Machine, &machine, &expand);
        es.extend(health::entries_of(Hive::User, &user, &expand));
        let rows: Vec<(health::Entry, Option<Facts>)> = es.into_iter().map(|e| {
            let f = if e.empty() { None } else { st.facts_by_entry.get(&fact_key(&e.expanded)).cloned().or_else(|| st.preview_facts.get(&fact_key(&e.expanded)).cloned()) };
            (e, f)
        }).collect();
        let (s32, _, _) = sys.system_dirs();
        let built_now = Some(health::merged(&machine, &user, &expand));
        health::judge(health::Input {
            machine: &machine,
            user: &user,
            pathext_machine: p.map(|p| &p.pathext_machine).unwrap_or(&env::Read::Missing),
            pathext_user: p.map(|p| &p.pathext_user).unwrap_or(&env::Read::Missing),
            rows,
            built: built_now,
            system32: s32,
        })
    }

    fn render_preview(&self) {
        let Some(ui) = self.ui() else { return };
        if !ui.get_preview_open() {
            return;
        }
        let Some(ed) = self.st.borrow().editor.clone() else { return };
        let old: Vec<W> = ed.loaded.as_ref().map(|v| wide::split_semi(&v.raw)).unwrap_or_default();
        let diff = editor::diff(&old, &ed.entries);
        let lines: Vec<Line> = diff
            .iter()
            .map(|d| Line {
                text: s(format!("{} {}", d.mark.sign(), shown(&d.text, 400))),
                state: match d.mark {
                    Mark::Added => 1,
                    Mark::Removed => 4,
                    Mark::Moved => 6,
                    Mark::Same => 2,
                },
                mono: true,
                strong: false,
            })
            .collect();
        let mut notes: Vec<Line> = Vec::new();
        let summary = editor::summary(&diff);
        let changed = ed.changed();
        notes.push(Line { text: s(format!("{}: {}.", ed.hive.word(), if changed && summary == "no change" { "the text changes (case, spaces or empty entries)".to_string() } else { summary.clone() })), state: 2, mono: false, strong: true });
        // A value shown only in part (another type, text hidden after its first NUL) can't be
        // changed here: said in place of a conversion Apply would refuse, and Apply off (RVD5).
        let partial = ed.loaded.as_ref().and_then(|v| partial_value(ed.hive, v.kind, ed.hidden, false));
        if let Some(v) = &ed.loaded
            && v.kind != Kind::ExpandSz
            && partial.is_none()
        {
            notes.push(Line { text: s(format!("{} to REG_EXPAND_SZ (Windows' own type for Path).", v.kind.word())), state: 3, mono: false, strong: false });
        }
        let report = self.preview_report(&ed);
        notes.push(Line { text: s(format!("Merged after: {} of 32\u{a0}767 characters.", health::thousands(report.merged_len))), state: 2, mono: false, strong: false });
        // The findings the new value has: the general ones and those of the edited hive's entries.
        let before = self.report();
        let had: Vec<String> = before.as_ref().map(|r| r.rows.iter().flat_map(|x| x.findings.iter().map(|f| f.text.clone())).chain(r.general.iter().map(|g| g.text.clone())).collect()).unwrap_or_default();
        let mut n = 0;
        for f in report.general.iter().chain(report.rows.iter().filter(|r| r.entry.hive == ed.hive).flat_map(|r| r.findings.iter())) {
            if f.level < health::WARN && f.level != health::UNKNOWN {
                continue;
            }
            n += 1;
            if n > 12 {
                break;
            }
            let fresh = !had.contains(&f.text);
            notes.push(Line { text: s(format!("{}{}", if fresh { "New: " } else { "Still: " }, f.text)), state: f.level, mono: false, strong: false });
        }
        if report.checking > 0 {
            notes.push(Line { text: s("Checking the new entries…"), state: 0, mono: false, strong: false });
        }
        // A value no Apply would write (the helper's rules, for both hives): said, and Apply off.
        let refused = helper::check_value(&ed.value());
        if let Some(r) = refused {
            // R-PATH-3: a hidden character is named with its entry, so it can be cleaned.
            let text = match ed.first_bad() {
                Some((i, n)) if matches!(r, helper::Reason::BadChar) => {
                    let more = if n > 1 { format!(" (and {} more)", plural(n - 1, "entry", "entries")) } else { String::new() };
                    format!("Apply is off: entry #{}{more} holds a hidden control or direction character ({}): Clean or Remove it in the editor.", i + 1, helper::bad_chars_named(&ed.entries[i]).join(", "))
                }
                _ => format!("Apply is off: {}.", r.words()),
            };
            notes.insert(1, Line { text: s(text), state: health::DANGER, mono: false, strong: true });
        }
        // The read this Preview started (RVD3-4): off until it lands; a read that failed keeps
        // it off, saying how to try again. Either way the type and hidden text the editor holds
        // are not fresh, so "can't be changed here" waits for a read that worked.
        let (reading, failed, unread) = {
            let st = self.st.borrow();
            let failed = st.path.as_ref().and_then(|p| match if ed.hive == Hive::Machine { &p.machine } else { &p.user } {
                env::Read::Error(e) => Some(e.clone()),
                _ => None,
            });
            (st.preview_reading, failed, st.editor_unread)
        };
        if let Some(why) = partial.as_ref().filter(|_| !reading && failed.is_none()) {
            notes.insert(1, Line { text: s(format!("Apply is off: {why}")), state: health::DANGER, mono: false, strong: true });
        }
        if reading {
            notes.insert(1, Line { text: s(format!("Reading {} PATH again…", ed.hive.word())), state: 0, mono: false, strong: false });
        } else if let Some(e) = &failed {
            notes.insert(1, Line { text: s(format!("Apply is off: {} PATH could not be read again ({e}). Close this and open Preview again to try again.", ed.hive.word())), state: health::DANGER, mono: false, strong: true });
        } else if unread {
            // Reloaded by an Apply that found PATH changed: off until a read says whether the
            // new value hides text (review RVD2-3).
            notes.insert(1, Line { text: s(format!("Apply is off until {} PATH is read again. Close this and open Preview again to read it.", ed.hive.word())), state: 0, mono: false, strong: false });
        }
        let busy = self.st.borrow().applying;
        let admin = ed.hive == Hive::Machine;
        ui.set_preview(PreviewInfo {
            title: s(format!("Preview: {} PATH", ed.hive.word())),
            lines: ModelRc::new(VecModel::from(lines)),
            notes: ModelRc::new(VecModel::from(notes)),
            apply: s(if admin { "Apply…" } else { "Apply" }),
            admin,
            can_apply: changed && refused.is_none() && partial.is_none() && !unread && !reading && failed.is_none(),
            busy,
        });
    }

    /// Apply the editor's value (steps 1-6 of SPEC section 6) on a worker.
    fn apply(&self) {
        let Some(ed) = self.st.borrow().editor.clone() else { return };
        if self.st.borrow().applying || !ed.changed() {
            return;
        }
        let seq = {
            let mut st = self.st.borrow_mut();
            st.apply_seq += 1;
            st.applying = true;
            st.undoing = None;
            st.apply_seq
        };
        self.render_preview();
        let job = ApplyJob {
            hive: ed.hive,
            expected: ed.loaded.clone(),
            new: ed.value(),
            kind: Kind::ExpandSz,
            undoes: None,
            record: None,
            delete: false,
            note: String::new(),
        };
        self.run_apply(seq, job);
    }

    fn run_apply(&self, seq: u64, job: ApplyJob) {
        let sys = self.sys();
        let store = self.journal.clone();
        let jkey = self.jkey.clone();
        let local = self.svc.local_dir.clone();
        let hwnd = (self.svc.hwnd)();
        let stop = self.stop.clone();
        self.bg(move |send| {
            let outcome = apply_job(&*sys, &store, &jkey, local.as_deref(), &job, hwnd, &stop);
            let journal = store.load().of(&jkey);
            send(Msg::Applied { seq, outcome, journal });
        });
    }

    fn applied(&self, outcome: Applied) {
        match outcome {
            Applied::Done { hive, explorer, .. } => {
                self.st.borrow_mut().editor = None;
                if let Some(ui) = self.ui() {
                    ui.set_preview_open(false);
                }
                let tail = match explorer {
                    Some(true) => "Explorer has the new PATH: new windows from Start, Run and Explorer get it.",
                    Some(false) => "Explorer still has the old PATH: Broadcast again, or sign out and in.",
                    None => "Explorer's PATH could not be read to check it.",
                };
                self.toast(&format!("{} PATH changed (Undo is in History). {tail}", hive.word()), if explorer == Some(false) { ToastKind::Error } else { ToastKind::Ok }, None);
                self.read_path();
                self.read_procs();
            }
            Applied::ChangedSince { hive, now } => {
                // Reload, nothing written. Whether the new value hides text after its first part
                // comes with the read below, never from the old value: Apply is off until it
                // lands (review RVD2-3).
                let mut st = self.st.borrow_mut();
                if let Some(e) = st.editor.as_mut().filter(|e| e.hive == hive) {
                    *e = Editor::new(hive, now.value().cloned());
                    st.editor_sel = 0;
                    st.editor_unread = true;
                }
                drop(st);
                if let Some(ui) = self.ui() {
                    ui.set_preview_open(false);
                }
                self.toast(&changed_since(hive), ToastKind::Error, None);
                self.read_path();
            }
            Applied::NotDone { hive, why, .. } => {
                // RU-5: an Undo the helper has no record of: the way back as a new change.
                let undone = self.st.borrow_mut().undoing.take();
                let back = undone.filter(|_| why == helper_refused(helper::Reason::NotRecorded)).and_then(|e| e.before);
                match back {
                    Some(b) => self.way_back(hive, &format!("Not done: {why}"), &b),
                    None => {
                        self.toast(&format!("Not done: {why}"), ToastKind::Error, None);
                        self.render_preview();
                    }
                }
            }
            Applied::Unknown { hive, why } => {
                if let Some(ui) = self.ui() {
                    ui.set_preview_open(false);
                }
                self.st.borrow_mut().editor = None;
                self.toast(&format!("{} PATH: {why} Whether it was changed is not known: the PATH tab shows it as it is now.", hive.word()), ToastKind::Error, None);
                self.read_path();
            }
            Applied::Unsaved { hive, why } => {
                if let Some(ui) = self.ui() {
                    ui.set_preview_open(false);
                }
                self.st.borrow_mut().editor = None;
                self.toast(&format!("{} PATH changed, but its Undo could not be saved to journal.json ({why}). VibePath tries again when History is opened, at the next change and when it closes; if it still cannot, the Undo is lost.", hive.word()), ToastKind::Error, None);
                self.read_path();
                self.read_procs();
            }
        }
        self.render();
    }

    fn broadcast(&self) {
        let sys = self.sys();
        self.bg(move |send| {
            sys.broadcast();
            sys.pause(2000);
            send(Msg::Broadcasted { explorer: explorer_has_new_path(&*sys) });
        });
    }

    // ---- Prepare the fix ----

    /// The Store stub wins and a real Python is found later: when both their folders are in
    /// User PATH and WindowsApps comes first, (real folder, WindowsApps folder).
    fn fix_candidates(&self) -> Option<(W, W)> {
        let res = self.current_resolution()?;
        let st = self.st.borrow();
        let r = st.resolved.as_ref()?;
        let wi = res.winner?;
        let Found::File { path: stub, .. } = &res.rows[wi].found else { return None };
        if !matches!(r.aliases.get(&wide::lossy(stub).to_lowercase()), Some(Ok(a)) if crate::alias::kind(a) == crate::alias::Kind::PythonStub) {
            return None;
        }
        let real = real_python(&res, &r.aliases)?;
        let Found::File { path: real_path, .. } = &res.rows[real].found else { return None };
        let (apps, real_dir) = (wide::parent(stub), wide::parent(real_path));
        let pos = |d: &W| r.user_entries.iter().position(|e| env::same(&e.expanded, d));
        match (pos(&apps), pos(&real_dir)) {
            (Some(a), Some(b)) if b > a => Some((r.user_entries[b].typed.clone(), r.user_entries[a].typed.clone())),
            _ => None,
        }
    }

    fn prepare_fix(&self) {
        let Some((real, apps)) = self.fix_candidates() else { return };
        self.st.borrow_mut().tab = Some(Tab::Path);
        if self.st.borrow().path.is_none() || self.st.borrow().path_reading {
            self.st.borrow_mut().prepare = Some((real, apps));
            if !self.st.borrow().path_reading {
                self.read_path();
            }
            self.render();
            return;
        }
        self.prepare_fix_now(&real, &apps);
    }

    fn prepare_fix_now(&self, real: &W, apps: &W) {
        self.open_editor(Hive::User);
        let mut st = self.st.borrow_mut();
        let Some(ed) = st.editor.as_mut() else { return };
        let (Some(from), Some(before)) = (ed.entries.iter().position(|e| e == real), ed.entries.iter().position(|e| e == apps)) else { return };
        ed.move_before(from, before);
        let at = ed.entries.iter().position(|e| e == real).unwrap_or(0);
        st.editor_sel = at;
        drop(st);
        self.toast("The editor has your Python's folder moved above WindowsApps: Preview, then Apply, to make it so.", ToastKind::Info, None);
        self.render();
        self.bump_scroll();
    }

    // ---------- Running apps ----------

    fn read_procs(&self) {
        let seq = {
            let mut st = self.st.borrow_mut();
            st.procs_seq += 1;
            st.procs_reading = true;
            st.procs_seq
        };
        self.render();
        let sys = self.sys();
        let now = self.now();
        self.bg(move |send| {
            let read = procs_job(&*sys);
            send(Msg::Procs { seq, read, read_at: now });
        });
    }

    fn use_as_context(&self) {
        let p = {
            let st = self.st.borrow();
            sorted_procs(st.procs.as_deref().unwrap_or(&[])).get(st.procs_sel).map(|p| (*p).clone())
        };
        let Some(p) = p else { return };
        self.st.borrow_mut().ctx = Some(Ctx::Process { pid: p.info.pid, start: p.info.start, name: p.info.name.clone(), image: p.image.clone() });
        self.set_tab(Tab::Command);
        let c = self.st.borrow().committed.clone();
        if !c.trim().is_empty() {
            self.resolve_units(input::units(&c));
        }
    }

    // ---------- History ----------

    fn load_journal(&self) {
        let store = self.journal.clone();
        let key = self.jkey.clone();
        let memory = store.in_memory();
        self.bg(move |send| {
            // An entry still waiting (its save failed) is tried again first.
            store.flush();
            let j = store.load();
            let blind = !memory && std::fs::read(store.path()).is_err_and(|e| e.kind() != std::io::ErrorKind::NotFound);
            let note = if store.broken() && store.kept_aside().is_some() {
                format!("journal.json could not be read: it is kept as {}, and this window's entries are saved in its place.", kept_name(&store))
            } else if store.broken() {
                "journal.json could not be read: it will be kept as journal.json.broken-<date>-<time> at the next change.".to_string()
            } else if blind {
                "journal.json cannot be read now: changes are kept in memory and written once it can be read.".to_string()
            } else {
                String::new()
            };
            send(Msg::Journal { entries: j.of(&key), note });
        });
    }

    fn history_entry(&self) -> Option<Entry> {
        let st = self.st.borrow();
        let mut v: Vec<&Entry> = st.journal.iter().collect();
        v.reverse();
        v.get(st.history_sel).map(|e| (*e).clone())
    }

    fn undo(&self) {
        let Some(e) = self.history_entry() else { return };
        let Some(hive) = e.hive() else { return };
        let now = self.svc.system.read(hive, "Path");
        match journal::undo(&e, &now) {
            Err(why) => {
                // RU-5: the way back is the value before this change (this entry's own version is
                // the value now), as a previewed new change, when there is one to go to.
                let back = e.before.as_ref().filter(|b| match &now {
                    env::Read::Value(v) => !b.equals(v),
                    env::Read::Missing => true,
                    env::Read::Error(_) => false,
                });
                match back {
                    Some(b) => self.way_back(hive, &why, b),
                    None => self.toast(&why, ToastKind::Error, None),
                }
            }
            Ok(back) => {
                if self.st.borrow().applying {
                    return;
                }
                let seq = {
                    let mut st = self.st.borrow_mut();
                    st.apply_seq += 1;
                    st.applying = true;
                    st.undoing = Some(e.clone());
                    st.apply_seq
                };
                let job = ApplyJob {
                    hive,
                    expected: now.value().cloned(),
                    new: back.as_ref().map(|v| v.raw.clone()).unwrap_or_default(),
                    kind: back.as_ref().map_or(Kind::ExpandSz, |v| v.kind.restored()),
                    undoes: Some(e.id),
                    record: journal::record_id(&e),
                    delete: back.is_none(),
                    note: "undo".into(),
                };
                self.run_apply(seq, job);
                self.render();
            }
        }
    }

    /// Restore this version…: the Preview from the value now to the one this entry wrote.
    fn restore(&self) {
        let Some(e) = self.history_entry() else { return };
        let Some(hive) = e.hive() else { return };
        self.preview_version(hive, e.after.as_ref());
    }

    /// RU-5: a refused Undo's way back (the value before that change) as a previewed new change,
    /// unless the editor holds edits not applied yet: those are kept, never replaced unasked
    /// (RPS-5; the explicit "Restore this version…" still replaces them).
    fn way_back(&self, hive: Hive, why: &str, before: &journal::Value) {
        let edits = self.st.borrow().editor.as_ref().is_some_and(|ed| ed.entries != Editor::new(ed.hive, ed.loaded.clone()).entries);
        if edits {
            self.toast(&format!("{why} {EDITS_KEPT}"), ToastKind::Error, None);
            return;
        }
        // BACK_PREVIEW only once the Preview is open; otherwise `why` alone, beside the reason
        // `preview_version` already gave (RL-1).
        let text = if self.preview_version(hive, Some(before)) { format!("{why} {BACK_PREVIEW}") } else { why.to_string() };
        self.toast(&text, ToastKind::Error, None);
    }

    /// The editor holding `v` and its Preview from the value now (Restore this version…, and
    /// the way back when an Undo is refused). False when no Preview opened (its reason toasted).
    fn preview_version(&self, hive: Hive, v: Option<&journal::Value>) -> bool {
        if self.st.borrow().path.is_none() {
            self.toast("PATH is still being read: try again in a moment.", ToastKind::Info, None);
            return false;
        }
        self.open_editor(hive);
        // That hive's editor, or nothing (it could not be read): never the other hive's (RPS-6).
        if !self.st.borrow().editor.as_ref().is_some_and(|e| e.hive == hive) {
            return false;
        }
        {
            let mut st = self.st.borrow_mut();
            if let Some(ed) = st.editor.as_mut() {
                ed.entries = v.map(|a| wide::split_semi(&a.exact())).unwrap_or_default();
            }
        }
        // The editor's list shows that version too, not the value now it opened on.
        self.render();
        self.open_preview();
        true
    }

    fn export(&self) {
        let Some(e) = self.history_entry() else { return };
        let Some(hive) = e.hive() else { return };
        let name = format!("{}-path-{}.reg", journal::hive_key(hive), self.date_time(e.at).replace([' ', ':', '.'], "-"));
        let Some(after) = e.after.as_ref() else { return };
        let bytes = crate::regfile::export(hive, &after.to_env());
        let sys = self.sys();
        (self.svc.save_file)(
            &name,
            Box::new(move |p| {
                let Some(p) = p else { return };
                let r = sys.write_file(&p, &bytes, false).map(|_| p);
                post(Msg::Exported(r));
            }),
        );
    }

    // ---------- the list, keys and actions ----------

    fn rows_len(&self) -> usize {
        let st = self.st.borrow();
        match st.tab.unwrap_or(Tab::Command) {
            Tab::Command => {
                let shell = st.shell.unwrap_or(Shell::Cmd);
                st.resolved.as_ref().and_then(|r| r.per.get(shell.index())).map(|r| r.rows.len()).unwrap_or(0)
            }
            Tab::Path => match &st.editor {
                Some(e) => e.entries.len(),
                None => st.path.as_ref().map(|p| p.entries.len()).unwrap_or(0),
            },
            Tab::Running => st.procs.as_ref().map(|p| p.len()).unwrap_or(0),
            Tab::History => st.journal.len(),
        }
    }

    fn selected(&self) -> usize {
        let st = self.st.borrow();
        match st.tab.unwrap_or(Tab::Command) {
            Tab::Command => st.match_sel,
            Tab::Path if st.editor.is_some() => st.editor_sel,
            Tab::Path => st.path_sel,
            Tab::Running => st.procs_sel,
            Tab::History => st.history_sel,
        }
    }

    fn select(&self, i: usize) {
        let tab = self.tab();
        {
            let mut st = self.st.borrow_mut();
            match tab {
                Tab::Command => st.match_sel = i,
                Tab::Path if st.editor.is_some() => st.editor_sel = i,
                Tab::Path => st.path_sel = i,
                Tab::Running => st.procs_sel = i,
                Tab::History => st.history_sel = i,
            }
        }
        if tab == Tab::Command {
            self.load_details();
        }
        self.render();
    }

    fn row_clicked(&self, i: i32) {
        if i >= 0 {
            self.select(i as usize);
        }
    }

    /// A double-click: the row selected, and its main action (Edit… in the editor, Use as
    /// context on Running apps).
    fn row_opened(&self, i: i32) {
        if i < 0 {
            return;
        }
        self.select(i as usize);
        match self.tab() {
            Tab::Path if self.editing() => self.editor_action(act::EDIT),
            Tab::Running => self.use_as_context(),
            _ => {}
        }
    }

    fn bump_scroll(&self) {
        self.st.borrow_mut().scroll_seq += 1;
        self.render();
    }

    fn key(&self, t: &str, ctrl: bool, _shift: bool, alt: bool) -> bool {
        use slint::platform::Key;
        let is = |k: Key| t == SharedString::from(k).as_str();
        let n = self.rows_len();
        let sel = self.selected();
        if is(Key::F5) {
            match self.tab() {
                Tab::Command => self.resolve(),
                Tab::Path => self.read_path(),
                Tab::Running => self.read_procs(),
                Tab::History => self.load_journal(),
            }
            return true;
        }
        if ctrl && (t == "l" || t == "L") {
            if let Some(ui) = self.ui() {
                ui.invoke_focus_command();
            }
            return true;
        }
        if self.tab() == Tab::Path && self.editing() {
            if alt && (is(Key::UpArrow) || is(Key::DownArrow)) {
                self.editor_action(if is(Key::UpArrow) { act::MOVE_UP } else { act::MOVE_DOWN });
                return true;
            }
            if is(Key::Delete) {
                self.editor_action(act::REMOVE);
                return true;
            }
            if is(Key::F2) {
                self.editor_action(act::EDIT);
                return true;
            }
        }
        if n == 0 {
            return false;
        }
        let to = if is(Key::UpArrow) {
            sel.saturating_sub(1)
        } else if is(Key::DownArrow) {
            (sel + 1).min(n - 1)
        } else if is(Key::Home) {
            0
        } else if is(Key::End) {
            n - 1
        } else if is(Key::PageUp) {
            sel.saturating_sub(8)
        } else if is(Key::PageDown) {
            (sel + 8).min(n - 1)
        } else {
            return false;
        };
        self.select(to);
        self.bump_scroll();
        true
    }

    fn action(&self, id: i32) {
        match id {
            act::OPEN_ALIAS_SETTINGS => (self.svc.open_settings)("ms-settings:advanced-apps"),
            act::PREPARE_FIX => self.prepare_fix(),
            act::SHOW_IN_FOLDER | act::COPY_PATH => {
                let path = self.selected_match_path();
                if let Some(p) = path {
                    if id == act::COPY_PATH {
                        // Raw, as Windows has it (a lone surrogate cannot reach the clipboard
                        // as text: it is the one character shown as U+FFFD).
                        if (self.svc.copy)(&wide::lossy(&p)) {
                            self.toast("Copied the path.", ToastKind::Ok, None);
                        }
                    } else {
                        (self.svc.reveal)(&wide::path(&p));
                    }
                }
            }
            act::EDIT_USER => self.open_editor(Hive::User),
            act::EDIT_MACHINE => self.open_editor(Hive::Machine),
            act::BROADCAST => self.broadcast(),
            act::REFRESH_PATH => self.read_path(),
            act::MOVE_UP | act::MOVE_DOWN | act::REMOVE | act::ADD | act::EDIT | act::TIDY | act::CANCEL_EDIT | act::PREVIEW | act::CLEAN_ENTRY => self.editor_action(id),
            act::REFRESH_PROCS => self.read_procs(),
            act::USE_AS_CONTEXT => self.use_as_context(),
            act::UNDO => self.undo(),
            act::RESTORE => self.restore(),
            act::EXPORT => self.export(),
            act::REFRESH_HISTORY => self.load_journal(),
            _ => {}
        }
    }

    fn selected_match_path(&self) -> Option<W> {
        let res = self.current_resolution()?;
        let sel = self.st.borrow().match_sel;
        match &res.rows.get(sel)?.found {
            Found::File { path, .. } => Some(path.clone()),
            Found::AppPath(a) => Some(a.target.clone()),
            Found::NotChecked { dir, .. } => Some(dir.clone()),
            _ => None,
        }
    }

    // ---------- Copy report ----------

    fn copy_report(&self) -> bool {
        let sys = self.sys();
        let cache = self.cache.clone();
        let (cmd, ctx, cwd_new, shell) = {
            let st = self.st.borrow();
            (st.committed.clone(), st.ctx.clone().unwrap_or(Ctx::NewWindow), st.cwd_new.clone(), st.shell.unwrap_or(Shell::Cmd))
        };
        let now = self.now();
        let off = self.svc.utc_offset.clone();
        self.bg(move |send| {
            send(Msg::Report(report_job(&sys, &cache, &cmd, ctx, cwd_new, shell, now, &*off)));
        });
        false
    }

    // ---------- rendering ----------

    pub fn render(&self) {
        let Some(ui) = self.ui() else { return };
        let tab = self.tab();
        ui.set_tab(tab.index());
        ui.set_portable(self.svc.mode.portable());
        // The chip's tip says what Windows records anyway (it was About's portable paragraph).
        let tip = match &self.svc.mode {
            Mode::Portable { dir } => format!("Settings, the journal and the original PATH copies: {}. {PORTABLE_TRACE}", crate::portable::paths(dir).config.parent().map(|p| p.display().to_string()).unwrap_or_default()),
            Mode::ReadOnly { dir } => format!("Read-only: {} cannot be written; nothing is kept. {PORTABLE_TRACE}", dir.display()),
            Mode::Installed => String::new(),
        };
        ui.set_portable_tip(s(clean_max(&tip, 600)));
        let bits = if cfg!(target_pointer_width = "64") { "64-bit" } else { "32-bit" };
        let how = if self.svc.mode.portable() { "portable" } else { "installed for you" };
        ui.set_about_line(s(format!("version {} · {bits} · {how}", crate::VERSION)));
        {
            let st = self.st.borrow();
            ui.set_resolving(st.resolving);
            ui.set_shell(st.shell.unwrap_or(Shell::Cmd).index() as i32);
        }
        let choices = self.context_list();
        let ctx = self.ctx();
        ui.set_contexts(ModelRc::new(VecModel::from(choices.iter().map(|c| s(c.word())).collect::<Vec<_>>())));
        ui.set_context(choices.iter().position(|c| matches!(c, ContextChoice::Ctx(x) if *x == ctx)).unwrap_or(0) as i32);
        ui.set_cwd_shown(true);
        ui.set_cwd_editable(ctx == Ctx::NewWindow);
        // The current-folder field: Rust's text goes in only while the field still holds what
        // Rust last put there (a half-typed folder is never written over by a render).
        let cwd = self.cwd_shown_text();
        let last = self.st.borrow().cwd_set.clone();
        if ui.get_cwd().as_str() == last && cwd != last {
            ui.set_cwd(s(&cwd));
            self.st.borrow_mut().cwd_set = cwd;
        }
        let view = match tab {
            Tab::Command => self.view_command(),
            Tab::Path => self.view_path(),
            Tab::Running => self.view_running(),
            Tab::History => self.view_history(),
        };
        let sel = view.selected;
        ui.set_banner_lines(ModelRc::new(VecModel::from(view.banner)));
        ui.set_banner_actions(ModelRc::new(VecModel::from(view.actions)));
        ui.set_list_label(s(&view.label));
        let rows: Vec<Row> = view.rows.into_iter().enumerate().map(|(i, mut r)| {
            r.id = row_id(i);
            r.selected = i == sel;
            r
        }).collect();
        let n = rows.len();
        ui.set_rows(ModelRc::new(VecModel::from(rows)));
        ui.set_empty_text(s(&view.empty));
        ui.set_scroll_top(if n > 0 { sel.min(n - 1) as f32 * 46.0 } else { -1.0 });
        ui.set_scroll_seq(self.st.borrow().scroll_seq);
        ui.set_detail_title(s(&view.detail.title));
        ui.set_detail_state(view.detail.state);
        ui.set_detail_word(s(&view.detail.word));
        ui.set_detail_headline(s(&view.detail.headline));
        ui.set_detail_pairs(ModelRc::new(VecModel::from(view.detail.pairs)));
        ui.set_detail_lines(ModelRc::new(VecModel::from(view.detail.lines)));
        ui.set_detail_actions(ModelRc::new(VecModel::from(view.detail.actions)));
        ui.set_detail_empty(s(&view.detail.empty));
        let mut status = view.status;
        if self.svc.mode.portable() {
            status = format!("Portable · {status}");
        }
        ui.set_status_left(s(status));
        ui.set_status_right(s(""));
    }
}

/// What one tab shows.
#[derive(Default)]
struct View {
    banner: Vec<Line>,
    actions: Vec<Action>,
    label: String,
    rows: Vec<Row>,
    selected: usize,
    empty: String,
    detail: DetailView,
    status: String,
}

#[derive(Default)]
struct DetailView {
    title: String,
    state: i32,
    word: String,
    headline: String,
    pairs: Vec<Pair>,
    lines: Vec<Line>,
    actions: Vec<Action>,
    empty: String,
}

fn line(text: impl AsRef<str>, state: i32) -> Line {
    Line { text: s(text), state, mono: false, strong: false }
}

fn strong(text: impl AsRef<str>, state: i32) -> Line {
    Line { text: s(text), state, mono: false, strong: true }
}

fn mono(text: impl AsRef<str>, state: i32) -> Line {
    Line { text: s(text), state, mono: true, strong: false }
}

fn pair(k: &str, v: impl AsRef<str>, mono: bool) -> Pair {
    Pair { key: s(k), value: s(v), mono, section: false }
}

fn section(k: &str) -> Pair {
    Pair { key: s(k), value: s(""), mono: false, section: true }
}

fn action(id: i32, text: &str, admin: bool, primary: bool, enabled: bool) -> Action {
    Action { id, text: s(text), admin, primary, enabled }
}

fn row(number: String, title: String, sub: String, right: String, state: i32, mono: bool, a11y: String) -> Row {
    Row { id: 0, number: s(number), title: s(title), sub: s(sub), right: s(right), state, selected: false, mono, a11y: s(a11y) }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The key the facts of an entry are kept under: its section 5 form, lower case.
fn fact_key(expanded: &[u16]) -> String {
    wide::lossy(&env::norm(expanded)).to_lowercase()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ContextChoice {
    Ctx(Ctx),
    Other,
}

impl ContextChoice {
    fn word(&self) -> String {
        match self {
            ContextChoice::Ctx(c) => c.word(),
            ContextChoice::Other => "Another program… (Running apps)".into(),
        }
    }
}

/// The first row after the winner that is a real Python: a file named python*, not the stub.
fn real_python(res: &Resolution, aliases: &HashMap<String, Result<crate::alias::Alias, String>>) -> Option<usize> {
    let wi = res.winner?;
    res.rows.iter().enumerate().skip(wi + 1).find(|(_, r)| match &r.found {
        Found::File { path, .. } => {
            let name = wide::lossy(wide::file_name(path)).to_lowercase();
            let stub = matches!(aliases.get(&wide::lossy(path).to_lowercase()), Some(Ok(a)) if crate::alias::kind(a) == crate::alias::Kind::PythonStub);
            name.starts_with("python") && !stub
        }
        _ => false,
    }).map(|(i, _)| i)
}

/// A match in a few words for the summary line: "WindowsApps\python.exe (Store stub)".
fn winner_words(res: &Resolution, aliases: &HashMap<String, Result<crate::alias::Alias, String>>) -> String {
    let Some(r) = res.winner_row() else {
        return if res.uncertain { "not found (a folder was not checked)".into() } else { "not found".into() };
    };
    let mut t = match &r.found {
        Found::Builtin => "built into cmd".to_string(),
        Found::Ps(c) if c.kind == "Alias" => format!("alias of {}", c.target),
        Found::Ps(c) => format!("{} {}", c.kind.to_lowercase(), c.name),
        Found::File { path, .. } => {
            let dir = wide::parent(path);
            let folder = wide::lossy(wide::file_name(&dir));
            let mut t = format!("{}\\{}", shown(&w(&folder), 40), shown(wide::file_name(path), 60));
            match aliases.get(&wide::lossy(path).to_lowercase()) {
                Some(Ok(a)) if crate::alias::kind(a) == crate::alias::Kind::PythonStub => t.push_str(" (Store stub)"),
                Some(Ok(_)) => t.push_str(" (alias)"),
                _ => {}
            }
            t
        }
        Found::AppPath(a) => format!("App Paths: {}", shown(wide::file_name(&a.target), 60)),
        Found::NotChecked { .. } => "not checked".into(),
    };
    if res.uncertain {
        t.push_str(" (a folder before it was not checked)");
    }
    t
}

/// The summary line: the winner in all five shells.
pub fn summary_line(per: &[Resolution], aliases: &HashMap<String, Result<crate::alias::Alias, String>>) -> String {
    let mut parts = Vec::new();
    let mut prev: Option<String> = None;
    for (i, res) in per.iter().enumerate() {
        let shell = Shell::from_index(i);
        let words = winner_words(res, aliases);
        let shown_words = if prev.as_deref() == Some(words.as_str()) { "same".to_string() } else { words.clone() };
        parts.push(format!("{}: {shown_words}", shell.short()));
        prev = Some(words);
    }
    parts.join(" · ")
}

impl App {
    fn view_command(&self) -> View {
        let st = self.st.borrow();
        let shell = st.shell.unwrap_or(Shell::Cmd);
        let ctx = st.ctx.clone().unwrap_or(Ctx::NewWindow);
        let mut v = View { label: "Matches".into(), ..View::default() };
        if !st.parse_note.is_empty() {
            v.banner.push(line(&st.parse_note, if st.parse_note == input::NOT_A_NAME { 3 } else { 2 }));
        }
        let res = st.resolved.as_ref();
        let cur = res.and_then(|r| r.per.get(shell.index()));
        if st.resolving {
            v.banner.push(line("Checking…", 0));
        }
        if let Some(r) = res {
            if let Some(e) = &r.error {
                v.banner.push(line(format!("{}: {}", ctx.word(), e), 5));
            }
            if !r.per.is_empty() {
                v.banner.push(mono(summary_line(&r.per, &r.aliases), 2));
            }
            if let Some(n) = &r.stale_note {
                v.banner.push(line(n, 3));
            }
            if let Some(n) = &r.pathext_note {
                v.banner.push(line(n, 2));
            }
        }
        // The Store stub's warning, when it wins in the shell shown.
        let mut stub_wins = false;
        if let (Some(r), Some(c)) = (res, cur) {
            if let Some(Found::File { path, .. }) = c.winner_row().map(|x| &x.found)
                && let Some(Ok(a)) = r.aliases.get(&wide::lossy(path).to_lowercase())
                    && crate::alias::kind(a) == crate::alias::Kind::PythonStub {
                        stub_wins = true;
                        let real = real_python(c, &r.aliases).map(|i| format!("Your real Python is #{}.", c.rows[i].number)).unwrap_or_else(|| "No other match was found on this PATH.".into());
                        v.banner.push(strong(format!("This is the Microsoft Store stub, not Python. It opens the Store or prints 'Python was not found' and exits with code 9009; started from a script or another program it can hang. {real}"), 4));
                    }
            for n in &c.notes {
                v.banner.push(line(n, 2));
            }
        }
        if stub_wins {
            v.actions.push(action(act::OPEN_ALIAS_SETTINGS, "Open alias settings", false, false, true));
            if self.fix_candidates().is_some() {
                v.actions.push(action(act::PREPARE_FIX, "Prepare the fix", false, true, true));
            }
        }
        v.empty = match (res, st.resolving, st.committed.trim().is_empty()) {
            (_, true, _) => "Checking…".into(),
            (None, _, true) => "Type a command (python, npm, where, .\\tool) and press Enter.".into(),
            (None, _, false) if st.parse_note == input::NOT_A_NAME => "Not a command name.".into(),
            _ => "Not found: no file by this name in this shell's search.".into(),
        };
        if let (Some(r), Some(c)) = (res, cur) {
            v.selected = st.match_sel.min(c.rows.len().saturating_sub(1));
            for (i, x) in c.rows.iter().enumerate() {
                v.rows.push(match_row(x, i == c.winner.unwrap_or(usize::MAX), &r.aliases));
            }
            if let Some(x) = c.rows.get(v.selected) {
                v.detail = self.match_detail(x, c.winner == Some(v.selected), shell, &r.aliases, &st);
            }
        }
        v.detail.empty = "Select a match to see what it is.".into();
        let matches = cur.map(|c| c.matches()).unwrap_or(0);
        let read = res.map(|r| format!(" · PATH read {}", self.clock(r.read_at))).unwrap_or_default();
        v.status = format!("{} · {} · {}{read}", ctx.word(), shell.word(), plural(matches, "match", "matches"));
        v
    }

    fn match_detail(&self, x: &resolve::Row, winner: bool, shell: Shell, aliases: &HashMap<String, Result<crate::alias::Alias, String>>, st: &State) -> DetailView {
        let mut d = DetailView {
            word: if winner { "wins".into() } else if x.number == 0 { "not checked".into() } else { "shadowed".into() },
            state: if winner { 6 } else if x.number == 0 { 5 } else { 2 },
            ..DetailView::default()
        };
        d.headline = match (&x.shadow, winner) {
            (Some(sh), _) => format!("{} ({}).", capital(sh), "it does not run"),
            (None, true) => format!("Runs when {} is given this command.", match shell {
                Shell::Cmd => "cmd".to_string(),
                Shell::Pwsh7 => "PowerShell 7".into(),
                Shell::Ps51 => "Windows PowerShell 5.1".into(),
                Shell::Program => "a program starting it by name".into(),
                Shell::RunBox => "the Run box".into(),
            }),
            _ => String::new(),
        };
        d.pairs.push(section("Where"));
        d.pairs.push(pair("Source", resolve::step_source(&x.found), false));
        match &x.found {
            Found::Builtin => {
                d.title = "cmd built-in".into();
                d.pairs.push(pair("Kind", "built into cmd: no file runs", false));
            }
            Found::Ps(c) => {
                d.title = clean_max(&c.name, 80);
                d.pairs.push(pair("Kind", format!("PowerShell {}", c.kind.to_lowercase()), false));
                if !c.target.is_empty() {
                    d.pairs.push(pair(if c.kind == "Alias" { "Runs" } else { "Module" }, clean_max(&c.target, 120), true));
                }
                d.pairs.push(pair("Read from", "PowerShell's own table (-NoProfile): a profile can add more", false));
            }
            Found::NotChecked { dir, reason, .. } => {
                d.title = shown(wide::file_name(dir), 80);
                d.headline = format!("Not checked: {reason}. A match may hide here.");
                d.state = 5;
                d.pairs.push(pair("Folder", shown(dir, 2000), true));
            }
            Found::AppPath(a) => {
                d.title = shown(wide::file_name(&a.target), 80);
                d.pairs.push(pair("Full path", shown(&a.target, 2000), true));
                if a.missing {
                    d.pairs.push(pair("State", "missing: App Paths points at a file that is not there", false));
                }
                if let Some(p) = &a.extra_path {
                    d.pairs.push(pair("App Paths adds", format!("{} to PATH for this program", shown(p, 1000)), true));
                }
                self.file_pairs(&a.target, None, &mut d, st);
                d.actions.push(action(act::SHOW_IN_FOLDER, "Show in folder", false, false, !a.missing));
                d.actions.push(action(act::COPY_PATH, "Copy path", false, false, true));
            }
            Found::File { path, typed, .. } => {
                d.title = shown(wide::file_name(path), 80);
                d.pairs.push(pair("Full path", shown(path, 2000), true));
                if let Some(t) = typed {
                    d.pairs.push(pair("As typed", shown(t, 2000), true));
                }
                let alias = aliases.get(&wide::lossy(path).to_lowercase());
                self.file_pairs(path, alias, &mut d, st);
                d.actions.push(action(act::SHOW_IN_FOLDER, "Show in folder", false, false, true));
                d.actions.push(action(act::COPY_PATH, "Copy path", false, false, true));
                if let Some(Ok(a)) = alias
                    && crate::alias::kind(a) == crate::alias::Kind::PythonStub {
                        d.word = "Store stub".into();
                        d.state = 4;
                        d.actions.push(action(act::OPEN_ALIAS_SETTINGS, "Open alias settings", false, false, true));
                    }
            }
        }
        d
    }

    fn file_pairs(&self, path: &[u16], alias: Option<&Result<crate::alias::Alias, String>>, d: &mut DetailView, st: &State) {
        let kind = crate::fileinfo::kind_of(path, matches!(alias, Some(Ok(_))));
        d.pairs.push(section("What"));
        d.pairs.push(pair("Kind", kind.word(), false));
        match alias {
            Some(Ok(a)) => {
                d.pairs.push(pair("Alias", crate::alias::words(a), false));
                d.pairs.push(pair("Package", crate::alias::package_name(a), true));
                d.pairs.push(pair("Target", shown(&a.target, 2000), true));
            }
            Some(Err(e)) => d.pairs.push(pair("Reparse point", clean_max(e, 200), false)),
            None => {}
        }
        match st.details.get(path) {
            None => d.pairs.push(pair("Version", "Reading…", false)),
            Some(x) => {
                if let Some(r) = &x.runs_through {
                    d.pairs.push(pair("Runs", clean_max(r, 300), false));
                }
                if let Some(sh) = &x.shim {
                    d.pairs.push(pair("Scoop shim for", sh.clone(), true));
                }
                if let Some(l) = &x.first_line {
                    d.pairs.push(pair("First line", l.clone(), true));
                }
                if let Some(u) = &x.unread {
                    d.pairs.push(pair("Read", format!("unknown: {}", clean_max(u, 200)), false));
                }
                if let Some(a) = &x.arch {
                    d.pairs.push(pair("Architecture", a, false));
                }
                if !x.file_version.is_empty() {
                    d.pairs.push(pair("File version", &x.file_version, true));
                }
                if !x.product.is_empty() {
                    d.pairs.push(pair("Product", &x.product, false));
                }
                if !x.company.is_empty() {
                    d.pairs.push(pair("Company", &x.company, false));
                }
                if let Some(sz) = x.size {
                    d.pairs.push(pair("Size", format!("{} bytes", health::thousands(sz as usize)), true));
                }
                if let Some(m) = x.modified {
                    let unix = (m / 10_000_000) as i64 - 11_644_473_600;
                    d.pairs.push(pair("Modified", self.date_time(unix), true));
                }
                d.pairs.push(pair("Signature", clean_max(&x.signer, 300), false));
            }
        }
    }

    fn view_path(&self) -> View {
        let report = self.report();
        let st = self.st.borrow();
        let mut v = View { label: "PATH entries".into(), ..View::default() };
        let Some(p) = st.path.as_ref() else {
            v.banner.push(line("Checking…", 0));
            v.empty = "Reading PATH…".into();
            v.status = "PATH · reading".into();
            return v;
        };
        let report = report.unwrap_or_default();
        if let Some(ed) = &st.editor {
            v.banner.push(strong(format!("Editing {} PATH: nothing changes until you Apply in Preview.", ed.hive.word()), 6));
            v.banner.push(line("Move up and down with Alt+Up and Alt+Down, Delete removes, F2 edits.", 2));
            let n = ed.entries.len();
            let sel = st.editor_sel.min(n.saturating_sub(1));
            v.actions = vec![
                action(act::MOVE_UP, "Move up", false, false, n > 0 && sel > 0),
                action(act::MOVE_DOWN, "Move down", false, false, n > 0 && sel + 1 < n),
                action(act::REMOVE, "Remove", false, false, n > 0),
                action(act::ADD, "Add…", false, false, true),
                action(act::EDIT, "Edit…", false, false, n > 0),
                action(act::TIDY, "Tidy", false, false, n > 0),
                action(act::CANCEL_EDIT, "Cancel", false, false, true),
                action(act::PREVIEW, "Preview…", ed.hive == Hive::Machine, true, ed.changed()),
            ];
            v.selected = sel;
            for (i, typed) in ed.entries.iter().enumerate() {
                let exp = self.svc.system.expand(typed);
                let f = st.facts_by_entry.get(&fact_key(&exp)).or_else(|| st.preview_facts.get(&fact_key(&exp)));
                let state = match f.map(|f| &f.state) {
                    _ if typed.is_empty() => 2,
                    None => 0,
                    Some(FactState::Dead) | Some(FactState::NoDrive) | Some(FactState::IsFile) => 3,
                    Some(FactState::Unknown(_)) => 5,
                    _ => 1,
                };
                let what = match f.map(|f| &f.state) {
                    _ if typed.is_empty() => "empty entry".to_string(),
                    None => "Checking…".into(),
                    Some(FactState::Dead) => "dead: not there".into(),
                    Some(FactState::NoDrive) => "dead: its drive is not there".into(),
                    Some(FactState::IsFile) => "a file, not a folder".into(),
                    Some(FactState::Unknown(w)) => format!("unknown: {w}"),
                    Some(FactState::NotLooked) => "relative".into(),
                    Some(FactState::Folder) => "folder".into(),
                };
                // R-PATH-3: a hidden character no Apply writes, named and shown escaped.
                let bad = helper::bad_chars_named(typed);
                let (state, what) = if bad.is_empty() { (state, what) } else { (health::DANGER, format!("holds a hidden character ({}): Clean or Remove it", bad.join(", "))) };
                let exp_s = if exp != *typed { format!("{} · ", middle(&shown(&exp, 2000), 70)) } else { String::new() };
                let title = if typed.is_empty() { "(empty)".to_string() } else { middle(&shown(&helper::escape_bad(typed), 2000), 110) };
                v.rows.push(row(format!("#{}", i + 1), title.clone(), format!("{exp_s}{what}"), String::new(), state, true, format!("#{} {title}: {what}", i + 1)));
            }
            if let Some(typed) = ed.entries.get(sel) {
                let exp = self.svc.system.expand(typed);
                v.detail.title = if typed.is_empty() { "(empty)".into() } else { shown(wide::file_name(typed), 80) };
                v.detail.word = "editing".into();
                v.detail.state = 6;
                v.detail.pairs.push(pair("As typed", shown(&helper::escape_bad(typed), 2000), true));
                if exp != *typed {
                    v.detail.pairs.push(pair("Expanded", shown(&exp, 2000), true));
                }
                v.detail.pairs.push(pair("Position", format!("#{} of {}", sel + 1, n), false));
                let bad = helper::bad_chars_named(typed);
                if !bad.is_empty() {
                    v.detail.lines.push(line(format!("Holds a hidden control or direction character ({}): programs see another name than the one shown, and no Apply writes it. Clean removes the character; Remove removes the entry.", bad.join(", ")), health::DANGER));
                    v.detail.actions.push(action(act::CLEAN_ENTRY, "Clean", false, true, true));
                    v.detail.actions.push(action(act::REMOVE, "Remove", false, false, true));
                }
            }
            v.empty = format!("{} PATH is empty: Add… puts a folder in it.", ed.hive.word());
            v.status = format!("Editing {} PATH · {}", ed.hive.word(), plural(n, "entry", "entries"));
            return v;
        }
        v.banner.push(mono(&report.header, if report.dangers > 0 { 4 } else if report.warnings > 0 { 3 } else { 2 }));
        v.banner.push(line("New programs see Machine PATH first, then User PATH: nothing in User PATH can beat a folder in Machine PATH.", 2));
        if let Some(e) = &p.built_error {
            v.banner.push(line(format!("The PATH Windows builds for a new program could not be read: {e}."), 5));
        }
        let max_general = 6;
        for g in report.general.iter().take(max_general) {
            v.banner.push(line(&g.text, g.level));
        }
        if report.general.len() > max_general {
            v.banner.push(line(format!("And {} more: Copy report has them all.", report.general.len() - max_general), 2));
        }
        let user_ok = !matches!(p.user, env::Read::Error(_));
        let machine_ok = matches!(p.machine, env::Read::Value(_));
        v.actions = vec![
            action(act::EDIT_USER, "Edit User PATH", false, true, user_ok && !st.applying),
            action(act::EDIT_MACHINE, "Edit Machine PATH", true, false, machine_ok && !st.applying),
            action(act::BROADCAST, "Broadcast", false, false, true),
            action(act::REFRESH_PATH, if st.path_reading { "Checking…" } else { "Refresh" }, false, false, !st.path_reading),
        ];
        v.selected = st.path_sel.min(report.rows.len().saturating_sub(1));
        for (i, r) in report.rows.iter().enumerate() {
            let e = &r.entry;
            let level = r.level();
            let state = match level {
                health::DANGER => 4,
                health::WARN => 3,
                health::UNKNOWN => 5,
                health::INFO => 2,
                0 => 0,
                _ => 1,
            };
            let first = r.findings.first().map(|f| f.text.clone());
            let what = match (&first, r.facts.is_none() && !e.empty()) {
                (Some(t), _) => {
                    let more = r.findings.len().saturating_sub(1);
                    if more > 0 { format!("{t} (+{more})") } else { t.clone() }
                }
                (None, true) => "Checking…".into(),
                (None, false) => "ok".into(),
            };
            let exp_s = if e.expanded != e.typed && !e.empty() { format!("{} · ", middle(&shown(&e.expanded, 2000), 60)) } else { String::new() };
            let title = if e.empty() { "(empty)".to_string() } else { middle(&shown(&e.typed, 2000), 110) };
            v.rows.push(row(format!("#{}", i + 1), title.clone(), format!("{exp_s}{what}"), e.label(), state, true, format!("#{} {}, {}: {what}", i + 1, e.label(), title)));
        }
        if let Some(r) = report.rows.get(v.selected) {
            let e = &r.entry;
            v.detail.title = if e.empty() { "(empty)".into() } else { shown(wide::file_name(&e.typed), 80) };
            if v.detail.title.is_empty() {
                v.detail.title = shown(&e.typed, 80);
            }
            v.detail.state = match r.level() {
                health::DANGER => 4,
                health::WARN => 3,
                health::UNKNOWN => 5,
                0 => 0,
                _ => 1,
            };
            v.detail.word = match r.level() {
                health::DANGER => "danger",
                health::WARN => "warning",
                health::UNKNOWN => "unknown",
                health::INFO => "info",
                0 => "checking",
                _ => "ok",
            }
            .into();
            v.detail.pairs.push(pair("Where", format!("{} (#{} of the merged PATH)", e.label(), v.selected + 1), false));
            v.detail.pairs.push(pair("As typed", shown(&e.typed, 2000), true));
            if e.expanded != e.typed {
                v.detail.pairs.push(pair("Expanded", shown(&e.expanded, 2000), true));
            }
            if let Some(f) = &r.facts {
                let state = match &f.state {
                    FactState::Folder => "a folder".to_string(),
                    FactState::IsFile => "a file".into(),
                    FactState::Dead => "not there".into(),
                    FactState::NoDrive => "its drive is not there".into(),
                    FactState::Unknown(w) => format!("unknown: {w}"),
                    FactState::NotLooked => "relative: depends on the current folder".into(),
                };
                v.detail.pairs.push(pair("On disk", state, false));
                let drive = match f.drive {
                    crate::fsprobe::Drive::Local => "local",
                    crate::fsprobe::Drive::Network => "network share",
                    crate::fsprobe::Drive::Mapped => "mapped network drive",
                    crate::fsprobe::Drive::Removable => "removable drive",
                    crate::fsprobe::Drive::NoDrive => "no such drive now",
                    crate::fsprobe::Drive::Unknown => "not known",
                };
                v.detail.pairs.push(pair("Drive", drive, false));
                if e.hive == Hive::Machine {
                    v.detail.pairs.push(pair("You can write it", match f.writable {
                        Some(true) => "yes, without admin rights",
                        Some(false) => "no",
                        None => "not known",
                    }, false));
                }
            }
            v.detail.lines = r.findings.iter().map(|f| line(&f.text, f.level)).collect();
            if r.findings.is_empty() && r.facts.is_some() {
                v.detail.lines.push(line("Nothing to say about this entry.", 2));
            }
        }
        v.empty = "Machine PATH and User PATH are empty.".into();
        v.detail.empty = "Select an entry to see its findings.".into();
        v.status = format!("PATH · {} · read {}", report.header.split(" · ").take(2).collect::<Vec<_>>().join(" · "), self.clock(p.read_at));
        v
    }

    fn view_running(&self) -> View {
        let st = self.st.borrow();
        let mut v = View { label: "Running programs".into(), ..View::default() };
        v.actions = vec![action(act::REFRESH_PROCS, if st.procs_reading { "Checking…" } else { "Refresh" }, false, false, !st.procs_reading), action(act::BROADCAST, "Broadcast", false, false, true)];
        let Some(procs) = st.procs.as_ref() else {
            v.banner.push(line("Checking…", 0));
            v.empty = "Reading the running programs…".into();
            v.status = "Running apps · reading".into();
            return v;
        };
        let sorted = sorted_procs(procs);
        let sprocs: Vec<stale::Proc> = sorted.iter().map(|p| stale::Proc { pid: p.info.pid, ppid: p.info.ppid, start: p.info.start, name: p.info.name.clone(), image: p.image.clone().unwrap_or_default(), verdict: p.verdict.clone() }).collect();
        let lines = stale::restart_lines(&sprocs);
        for p in &st.procs_problems {
            v.banner.push(strong(p.clone(), 5));
        }
        if lines.is_empty() && st.procs_problems.is_empty() {
            v.banner.push(strong("Nothing is stale: every program read has the PATH a new one would get, or its own additions.", 1));
        } else if !lines.is_empty() {
            v.banner.push(strong("Restart these: they started before PATH changed, and a program never re-reads it.", 3));
            for l in lines.iter().take(8) {
                let count = if l.count > 1 { format!(" ({} processes)", l.count) } else { String::new() };
                v.banner.push(line(format!("{}{count}: {}", l.name, l.words), 3));
            }
            if lines.len() > 8 {
                v.banner.push(line(format!("And {} more programs below.", lines.len() - 8), 2));
            }
        }
        if let Some(u) = stale::unread_words(&sprocs) {
            v.banner.push(line(u, 5));
        }
        if st.procs_reading {
            v.banner.push(line("Checking…", 0));
        }
        v.selected = st.procs_sel.min(sorted.len().saturating_sub(1));
        for p in &sorted {
            let (missing, extra) = p.verdict.counts();
            let counts = match (missing, extra) {
                (0, 0) => String::new(),
                (m, 0) => format!(" · missing {m}"),
                (0, x) => format!(" · has {x} more"),
                (m, x) => format!(" · missing {m} · has {x} more"),
            };
            let why = match &p.verdict {
                Verdict::Unknown(w) | Verdict::NotCompared(w) => format!(": {w}"),
                _ => String::new(),
            };
            let started = self.clock(filetime_unix(p.info.start));
            let name = shown(&p.info.name, 80);
            v.rows.push(row(String::new(), name.clone(), format!("{}{why}{counts} · started {started}", p.verdict.word()), format!("PID {}", p.info.pid), p.verdict.state(), false, format!("{name}, PID {}: {}{counts}", p.info.pid, p.verdict.word())));
        }
        if let Some(p) = sorted.get(v.selected) {
            v.detail.title = shown(&p.info.name, 80);
            v.detail.word = p.verdict.word().into();
            v.detail.state = p.verdict.state();
            if p.verdict.stale() {
                let image = p.image.clone().unwrap_or_else(|| p.info.name.clone());
                v.detail.headline = stale::restart_lines(&[stale::Proc { pid: p.info.pid, ppid: 0, start: p.info.start, name: p.info.name.clone(), image, verdict: p.verdict.clone() }]).first().map(|l| l.words.clone()).unwrap_or_default();
            }
            v.detail.pairs.push(pair("PID", p.info.pid.to_string(), true));
            v.detail.pairs.push(pair("Started", self.date_time(filetime_unix(p.info.start)), true));
            if let Some(i) = &p.image {
                v.detail.pairs.push(pair("Program", shown(i, 2000), true));
            }
            if let Some(c) = &p.cwd {
                v.detail.pairs.push(pair("Current folder", shown(c, 2000), true));
            }
            if p.wow64 {
                v.detail.pairs.push(pair("Bitness", "32-bit (read through its 32-bit PEB)", false));
            }
            v.detail.lines = p.verdict.lines().into_iter().map(|l| {
                let state = if l.starts_with("missing") { 3 } else { 2 };
                line(l, state)
            }).collect();
            if !matches!(p.verdict, Verdict::Unknown(_)) {
                v.detail.actions.push(action(act::USE_AS_CONTEXT, "Use as context", false, false, true));
            }
        }
        v.empty = "No running program of yours could be listed.".into();
        v.detail.empty = "Select a program to see its PATH against the registry's.".into();
        let stale_n = sorted.iter().filter(|p| p.verdict.stale()).count();
        v.status = format!("Running apps · {} · {} stale · read {}", plural(sorted.len(), "process", "processes"), stale_n, self.clock(st.procs_at));
        v
    }

    fn view_history(&self) -> View {
        let st = self.st.borrow();
        let mut v = View { label: "PATH changes".into(), ..View::default() };
        if !st.journal_note.is_empty() {
            v.banner.push(line(&st.journal_note, 3));
        }
        if matches!(self.svc.mode, Mode::ReadOnly { .. }) {
            v.banner.push(line("Portable, read-only: the journal is kept in memory until VibePath closes.", 3));
        }
        let entries: Vec<&Entry> = st.journal.iter().rev().collect();
        v.banner.push(line(format!("{} on this PC, newest first. Undo writes the old value back only while PATH is still what the change wrote.", plural(entries.len(), "change", "changes")), 2));
        v.selected = st.history_sel.min(entries.len().saturating_sub(1));
        let sel = entries.get(v.selected).copied();
        let admin = sel.and_then(|e| e.hive()) == Some(Hive::Machine);
        let undoable = sel.is_some_and(|e| e.state == "done");
        v.actions = vec![
            action(act::UNDO, "Undo", admin, true, undoable && !st.applying),
            // A change that removed the value has no version to restore or export.
            action(act::RESTORE, "Restore this version…", admin, false, sel.is_some_and(|e| e.after.is_some()) && !st.applying),
            action(act::EXPORT, "Export .reg…", false, false, sel.is_some_and(|e| e.after.is_some())),
        ];
        for e in &entries {
            let hive = e.hive().map(|h| h.word()).unwrap_or("?");
            let state = match e.state.as_str() {
                "done" => 1,
                "failed" | "refused" => 4,
                "declined" | "pending" => 3,
                "unknown" => 5,
                _ => 2,
            };
            let summary = clean_max(&journal::summary(e), 120);
            v.rows.push(row(String::new(), summary.clone(), format!("{} · {}{}", self.date_time(e.at), e.state, if e.note.is_empty() { String::new() } else { format!(" · {}", clean_max(&e.note, 80)) }), hive.to_string(), state, false, format!("{hive} PATH, {}: {summary}, {}", self.date_time(e.at), e.state)));
        }
        if let Some(e) = sel {
            v.detail.title = format!("{} PATH", e.hive().map(|h| h.word()).unwrap_or("?"));
            v.detail.word = e.state.clone();
            v.detail.state = match e.state.as_str() {
                "done" => 1,
                "failed" | "refused" => 4,
                "unknown" => 5,
                _ => 3,
            };
            v.detail.headline = clean_max(&journal::summary(e), 200);
            v.detail.pairs.push(pair("When", self.date_time(e.at), true));
            if !e.note.is_empty() {
                v.detail.pairs.push(pair("Note", clean_max(&e.note, 300), false));
            }
            v.detail.pairs.push(pair("Type before", e.before.as_ref().map(|b| Kind::from_code(b.kind).word()).unwrap_or_else(|| "no value".into()), false));
            v.detail.pairs.push(pair("Type after", e.after.as_ref().map(|a| Kind::from_code(a.kind).word()).unwrap_or_else(|| "no value".into()), false));
            let old = e.before.as_ref().map(|b| wide::split_semi(&b.exact())).unwrap_or_default();
            let new = e.after.as_ref().map(|a| wide::split_semi(&a.exact())).unwrap_or_default();
            v.detail.lines = editor::diff(&old, &new)
                .iter()
                .map(|d| mono(format!("{} {}", d.mark.sign(), shown(&d.text, 400)), match d.mark {
                    Mark::Added => 1,
                    Mark::Removed => 4,
                    Mark::Moved => 6,
                    Mark::Same => 2,
                }))
                .collect();
        }
        v.empty = if st.journal_loaded { "No PATH change made with VibePath on this PC yet.".into() } else { "Reading the journal…".into() };
        v.detail.empty = "Select a change to see what it did.".into();
        v.status = format!("History · {}", plural(entries.len(), "change", "changes"));
        v
    }
}

fn capital(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn filetime_unix(ft: u64) -> i64 {
    (ft / 10_000_000) as i64 - 11_644_473_600
}

/// Stale first, then unknown, then the rest; by name, then PID (a total order).
fn sorted_procs(procs: &[ProcRow]) -> Vec<&ProcRow> {
    let mut v: Vec<&ProcRow> = procs.iter().collect();
    v.sort_by_key(|p| {
        let rank = match p.verdict {
            Verdict::Stale { .. } => 0,
            Verdict::Unknown(_) | Verdict::NotCompared(_) => 1,
            Verdict::NoPath => 2,
            _ => 3,
        };
        (rank, wide::sort_key(&p.info.name), p.info.pid)
    });
    v
}

/// One match as a row.
fn match_row(x: &resolve::Row, winner: bool, aliases: &HashMap<String, Result<crate::alias::Alias, String>>) -> Row {
    let number = if x.number > 0 { format!("#{}", x.number) } else { String::new() };
    let tail = match (&x.shadow, winner) {
        (Some(sh), _) => sh.clone(),
        (None, true) => "wins".into(),
        _ => String::new(),
    };
    match &x.found {
        Found::Builtin => row(number.clone(), "built into cmd".into(), format!("cmd built-in · {tail}"), String::new(), if winner { 6 } else { 2 }, false, format!("{number} built into cmd, {tail}")),
        Found::Ps(c) => {
            let what = if c.kind == "Alias" { format!("PowerShell alias of {}", c.target) } else { format!("PowerShell {} ({})", c.kind.to_lowercase(), if c.target.is_empty() { "built in" } else { c.target.as_str() }) };
            row(number.clone(), clean_max(&c.name, 80), format!("{what} · {tail}"), String::new(), if winner { 6 } else { 2 }, false, format!("{number} {}, {what}, {tail}", c.name))
        }
        Found::AppPath(a) => {
            let title = middle(&shown(&a.target, 2000), 110);
            let src = resolve::step_source(&x.found);
            let what = if a.missing { "missing: the file is not there, the Run box goes on past it".to_string() } else { tail.clone() };
            row(number.clone(), title.clone(), format!("{src} · {what}"), String::new(), if a.missing { 3 } else if winner { 6 } else { 2 }, true, format!("{number} {title}, {src}, {what}"))
        }
        Found::NotChecked { dir, source, reason } => {
            let title = middle(&shown(dir, 2000), 110);
            row(String::new(), title.clone(), format!("{source} · not checked: {reason}"), String::new(), 5, true, format!("{title}, not checked: {reason}"))
        }
        Found::File { path, source, .. } => {
            let title = middle(&shown(path, 2000), 110);
            let alias = aliases.get(&wide::lossy(path).to_lowercase());
            let kind = match alias {
                Some(Ok(a)) => crate::alias::words(a),
                Some(Err(e)) => clean_max(e, 80),
                None => crate::fileinfo::kind_of(path, false).word().to_string(),
            };
            let stub = matches!(alias, Some(Ok(a)) if crate::alias::kind(a) == crate::alias::Kind::PythonStub);
            let state = if stub && winner { 4 } else if winner { 6 } else { 2 };
            let src = clean_max(source, 80);
            row(number.clone(), title.clone(), format!("{src} · {kind} · {tail}"), String::new(), state, true, format!("{number} {title}, {src}, {kind}, {tail}"))
        }
    }
}

// ---------- the workers' jobs (no UI, testable) ----------

/// Resolve `cmd` in all five shells for `ctx`.
pub fn resolve_job(sys: &dyn System, cmd: Command, ctx: Ctx, cwd_new: Option<W>, now: i64) -> Resolved {
    let mut out = Resolved { command: Some(cmd.clone()), read_at: now, ..Resolved::default() };
    let (s32, win, s16) = sys.system_dirs();
    let (envr, cwd, caller): (Result<env::Env, String>, Option<W>, Option<W>) = match &ctx {
        Ctx::NewWindow => (sys.new_window(), Some(cwd_new.unwrap_or_else(|| sys.profile_dir())), None),
        Ctx::ThisApp => (Ok(sys.own_env()), sys.own_cwd(), None),
        Ctx::Process { pid, start, image, .. } => match sys.process_env(*pid, *start) {
            Ok(ProcEnv { env, cwd, .. }) => (Ok(env), cwd, image.as_ref().map(|i| wide::parent(i))),
            Err(e) => (Err(format!("its environment could not be read ({e})")), None, None),
        },
    };
    out.cwd = cwd.clone();
    let e = match envr {
        Ok(e) => e,
        Err(why) => {
            out.error = Some(why);
            env::Env::default()
        }
    };
    // The registry's entries, to say where each PATH entry came from.
    let expand = |x: &[u16]| sys.expand(x);
    let reg = |h: Hive| -> Vec<env::RegEntry> {
        health::entries_of(h, &sys.read(h, "Path"), &expand).into_iter().filter(|x| !x.empty()).map(|x| env::RegEntry { typed: x.typed, expanded: x.expanded }).collect()
    };
    let (machine, user) = (reg(Hive::Machine), reg(Hive::User));
    out.user_entries = user.clone();
    let path = e.get("PATH").map(|p| env::entries(p)).unwrap_or_default();
    let labels = env::labels(&path, &machine, &user);
    let pathext = match e.get("PATHEXT") {
        Some(p) => resolve::pathext_list(p),
        None => {
            if out.error.is_none() {
                out.pathext_note = Some("PATHEXT is not set in this context: cmd's own default (.COM;.EXE;.BAT;.CMD) is used.".into());
            }
            resolve::pathext_list(&w(".COM;.EXE;.BAT;.CMD"))
        }
    };
    if ctx == Ctx::ThisApp
        && let Ok(nw) = sys.new_window() {
            let fresh = nw.get("PATH").map(|p| env::entries(p)).unwrap_or_default();
            let v = stale::compare(e.get("PATH").map(|p| p.as_slice()), &fresh);
            if v.stale() {
                let (m, x) = v.counts();
                out.stale_note = Some(format!("VibePath was started before PATH changed: this app's PATH is stale (missing {m}, has {x} more). New window shows what a program started now gets."));
            }
        }
    let c = resolve::Context { path, raw_path: e.get("PATH").cloned(), labels, pathext, cwd, no_cwd: e.has("NoDefaultCurrentDirectoryInExePath"), caller_dir: caller, system32: s32, system16: s16, windows: win };
    let lookup = sys.lookup();
    for shell in SHELLS {
        out.per.push(resolve::resolve(shell, &cmd, &c, lookup));
    }
    // Aliases among the matches (a reparse point is read as one, quickly: local files only).
    for r in out.per.iter().flat_map(|r| r.rows.iter()) {
        if let Found::File { path, reparse: true, .. } = &r.found {
            let k = wide::lossy(path).to_lowercase();
            out.aliases.entry(k).or_insert_with(|| sys.alias(path));
        }
    }
    out
}

/// A file's details, from the session's cache when its identity, size and time are the same.
pub fn details_job(sys: &dyn System, cache: &Mutex<HashMap<CacheKey, Details>>, path: &[u16], read_from: &[u16]) -> Details {
    let key = sys.cache_key(read_from);
    if let Some(k) = key
        && let Some(d) = lock(cache).get(&k) {
            return d.clone();
        }
    let d = sys.details(path, read_from);
    // A read that failed is not kept, nor a signature Windows could not check (state 5,
    // "Unknown: …": in use, or WinVerifyTrust could not read it): the next look tries again.
    if let (Some(k), None, false) = (d.key.or(key), &d.unread, d.signer_state == 5) {
        lock(cache).insert(k, d.clone());
    }
    d
}

/// The PATH tab's read: both hives raw, PATHEXT, and the PATH Windows builds now.
pub fn path_read_job(sys: &dyn System, now: i64) -> PathRead {
    let machine = sys.read(Hive::Machine, "Path");
    let user = sys.read(Hive::User, "Path");
    let expand = |x: &[u16]| sys.expand(x);
    let mut entries = health::entries_of(Hive::Machine, &machine, &expand);
    entries.extend(health::entries_of(Hive::User, &user, &expand));
    let (built, built_error) = match sys.new_window() {
        Ok(e) => (e.get("PATH").cloned(), None),
        Err(e) => (None, Some(e)),
    };
    let hidden = [(Hive::Machine, &machine), (Hive::User, &user)].into_iter().filter(|(h, r)| matches!(r, env::Read::Value(_)) && sys.path_holds_more(*h)).map(|(h, _)| h).collect();
    PathRead { machine, user, pathext_machine: sys.read(Hive::Machine, "PATHEXT"), pathext_user: sys.read(Hive::User, "PATHEXT"), built, built_error, entries, read_at: now, hidden }
}

/// The facts of every entry, 16 at a time on threads of their own (a share gets its 3 s each,
/// side by side).
pub fn facts_job(sys: &Arc<dyn System>, entries: &[health::Entry]) -> Vec<Option<Facts>> {
    let mut out: Vec<Option<Facts>> = vec![None; entries.len()];
    let idx: Vec<usize> = (0..entries.len()).filter(|&i| !entries[i].empty()).collect();
    for chunk in idx.chunks(16) {
        let handles: Vec<(usize, std::thread::JoinHandle<Facts>)> = chunk
            .iter()
            .map(|&i| {
                let sys = sys.clone();
                let e = entries[i].expanded.clone();
                let machine = entries[i].hive == Hive::Machine;
                (i, std::thread::spawn(move || sys.facts(&e, machine)))
            })
            .collect();
        for (i, h) in handles {
            out[i] = h.join().ok();
        }
    }
    out
}

/// The Running apps tab's read: its rows, and what could not be told about all of them.
#[derive(Clone, Debug, Default)]
pub struct ProcsRead {
    pub rows: Vec<ProcRow>,
    /// Said in the banner: the PATH Windows builds could not be read, Windows did not say whose
    /// the processes are.
    pub problems: Vec<String>,
}

/// Every process of this user, read and compared with the PATH a program started now gets.
/// When that PATH cannot be read nothing is compared: every row is unknown, and the banner
/// says why (never "nothing is stale").
pub fn procs_job(sys: &dyn System) -> ProcsRead {
    let mut problems = Vec::new();
    let fresh: Result<Vec<W>, String> = sys.new_window().map(|e| e.get("PATH").map(|p| env::entries(p)).unwrap_or_default());
    if let Err(why) = &fresh {
        problems.push(format!("Nothing could be compared: {} ({why}).", stale::NO_FRESH));
    }
    let list = sys.processes();
    if let Some(p) = list.problem {
        problems.push(format!("{p}."));
    }
    let me = std::process::id();
    let mut out = Vec::new();
    for p in list.procs {
        if p.ours != Some(true) || p.pid == me {
            continue;
        }
        let image = sys.process_image(p.pid);
        let (verdict, cwd, wow64) = match sys.process_env(p.pid, p.start) {
            Ok(pe) => match &fresh {
                Ok(fresh) => (stale::compare(pe.env.get("PATH").map(|x| x.as_slice()), fresh), pe.cwd, pe.wow64),
                Err(why) => (Verdict::NotCompared(format!("{} ({why})", stale::NO_FRESH)), pe.cwd, pe.wow64),
            },
            Err(why) if why == "exited" => continue,
            Err(why) => (Verdict::Unknown(why), None, false),
        };
        out.push(ProcRow { info: p, image, verdict, cwd, wow64 });
    }
    ProcsRead { rows: out, problems }
}

/// Explorer has the PATH a program started now gets (None: no Explorer of ours could be read).
pub fn explorer_has_new_path(sys: &dyn System) -> Option<bool> {
    let fresh = sys.new_window().ok()?.get("PATH").cloned().map(|p| env::entries(&p))?;
    let mut any = None;
    for p in sys.processes().procs {
        if p.ours != Some(true) || !wide::eq_ic(&p.name, &w("explorer.exe")) {
            continue;
        }
        if let Ok(pe) = sys.process_env(p.pid, p.start) {
            let v = stale::compare(pe.env.get("PATH").map(|x| x.as_slice()), &fresh);
            let ok = matches!(v, Verdict::Current | Verdict::Own { .. });
            any = Some(any.unwrap_or(true) && ok);
        }
    }
    any
}

/// One PATH change, as Apply, Undo and Restore make it.
#[derive(Clone, Debug)]
pub struct ApplyJob {
    pub hive: Hive,
    /// What the editor loaded (None: there was no value).
    pub expected: Option<env::Value>,
    pub new: W,
    /// The type `new` is written as: REG_EXPAND_SZ; an Undo's is the type before
    /// (`Kind::restored`, FED1). For Machine PATH the helper takes it from its own record; this
    /// one is what the journal says.
    pub kind: Kind,
    pub undoes: Option<u64>,
    /// Undo of a Machine PATH change: the helper's record of it (what the helper checks).
    pub record: Option<crate::records::Id>,
    /// Undo of a change that made User PATH: remove the value.
    pub delete: bool,
    pub note: String,
}

/// Why a PATH value VibePath shows only in part can't be changed here, with what to do instead
/// (FED2, RVD5): another registry type (shown up to its first NUL), or text hidden after its first
/// NUL (`hidden`). The Preview says it with Apply off; `apply_job` refuses with it. The way back
/// is what reads PATH again from where the words are shown (review RVD3-4): opening the Preview
/// again from the editor, or Undo again on the History tab (`undo`).
fn partial_value(hive: Hive, kind: Kind, hidden: bool, undo: bool) -> Option<String> {
    let again = if undo { "press Undo again" } else { "open Preview again" };
    match kind {
        Kind::Other(t) => Some(format!("{} PATH can't be changed here. It has registry type {t}, not text, so VibePath shows only its first part, and writing would replace the whole value with that part. Recreate it as REG_EXPAND_SZ in regedit first, then {again}.", hive.word())),
        _ if hidden => Some(format!("{} PATH can't be changed here. It has more text hidden after the part shown, and writing would replace the whole value with that part. Open it in regedit and save it to keep only the part shown, then {again}.", hive.word())),
        _ => None,
    }
}

/// An Apply, or a read, found PATH changed under the editor: the editor holds it as it is now.
fn changed_since(hive: Hive) -> String {
    format!("{} PATH changed since you opened it (another program?). The editor holds it as it is now; nothing was written.", hive.word())
}

/// What an open editor took from a PATH read (`editor_follows`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Followed {
    No,
    Yes,
    /// Reloaded over edits made on a value that is no longer there.
    OverEdits,
}

/// An open editor after a PATH read (review RVD2-3), so its "can't be changed here" is never a
/// stale snapshot. With no edit in it, it is reloaded from the read. With edits, while the read
/// still shows the text it was loaded from, it keeps them and takes the registry type and
/// whether text hides after that part from the read; when the text differs it is left for
/// Apply's changed-since check, unless Apply is off for the value it was loaded from (shown only
/// in part, review RVD3-3: that check never runs then) or an Apply that found PATH changed has
/// just reloaded it (`editor_unread`): then it is reloaded, and the edits made on the old value
/// go. A read that failed changes nothing and keeps Apply off after such a reload.
fn editor_follows(st: &mut State, read: &PathRead) -> Followed {
    let unread = std::mem::take(&mut st.editor_unread);
    let Some(e) = st.editor.as_mut() else { return Followed::No };
    let now = match if e.hive == Hive::Machine { &read.machine } else { &read.user } {
        env::Read::Value(v) => Some(v.clone()),
        env::Read::Missing => None,
        env::Read::Error(_) => {
            st.editor_unread = unread;
            return Followed::No;
        }
    };
    let hidden = read.hidden.contains(&e.hive);
    let same = match (&e.loaded, &now) {
        (Some(l), Some(n)) => l.raw == n.raw,
        (None, None) => true,
        _ => false,
    };
    let partial = e.loaded.as_ref().is_some_and(|l| partial_value(e.hive, l.kind, e.hidden, false).is_some());
    if !e.edited() || (!same && (unread || partial)) {
        let followed = if e.edited() { Followed::OverEdits } else { Followed::Yes };
        *e = Editor { hidden, ..Editor::new(e.hive, now) };
        st.editor_sel = st.editor_sel.min(e.entries.len().saturating_sub(1));
        return followed;
    }
    if !same {
        return Followed::No;
    }
    if let (Some(l), Some(n)) = (e.loaded.as_mut(), now) {
        l.kind = n.kind;
    }
    e.hidden = hidden;
    Followed::Yes
}

/// Steps 1-6 of SPEC section 6, on a worker.
pub fn apply_job(sys: &dyn System, store: &journal::Store, jkey: &str, local: Option<&Path>, job: &ApplyJob, hwnd: isize, stop: &AtomicBool) -> Applied {
    let hive = job.hive;
    // User PATH meets the rules the helper holds Machine PATH to (the same validator and words).
    if hive == Hive::User
        && !job.delete
        && let Some(r) = helper::check_value(&job.new)
    {
        return Applied::NotDone { hive, why: format!("{}.", r.words()), state: "refused" };
    }
    // 1. The value again: as loaded, or nothing is written.
    let now = sys.read(hive, "Path");
    let same = match (&now, &job.expected) {
        (env::Read::Value(v), Some(e)) => v == e,
        (env::Read::Missing, None) => true,
        _ => false,
    };
    if !same {
        return Applied::ChangedSince { hive, now };
    }
    // FED2: a value that is not one string (another registry type, or text after its first
    // NUL) reads as its first string only, and a write would replace all of it with that part:
    // nothing is written over it.
    if let env::Read::Value(v) = &now
        && let Some(why) = partial_value(hive, v.kind, !matches!(v.kind, Kind::Other(_)) && sys.path_holds_more(hive), job.undoes.is_some())
    {
        return Applied::NotDone { hive, why, state: "refused" };
    }
    // No PATH write without its Undo on disk (SOL-PATH-1): the original copy and the pending
    // entry are saved first, or nothing is changed. (A read-only stick's journal is in memory,
    // as announced at start.)
    // 3. The first change on this PC: the original value as a .reg copy, never overwritten.
    if let (Some(dir), Some(orig)) = (local, job.expected.as_ref()) {
        let name = journal::original_name(hive, jkey.split('|').next().unwrap_or(""), jkey.split('|').nth(1).unwrap_or(""));
        if let Err(why) = sys.write_file(&dir.join(&name), &crate::regfile::export(hive, orig), true) {
            return Applied::NotDone { hive, why: format!("the copy of the original {} PATH ({name}) could not be saved ({why}), so nothing was changed.", hive.word()), state: "refused" };
        }
    }
    // 2. The journal entry, pending.
    let existing = store.load().of(jkey);
    let id = journal::next_id(&existing, sys.now_ms());
    // Undo of a change that made User PATH removes the value: no value after.
    let after = (!job.delete).then(|| journal::Value::of(&env::Value { kind: job.kind, raw: job.new.clone() }));
    let entry = Entry { id, at: (sys.now_ms() / 1000) as i64, hive: journal::hive_key(hive).into(), before: job.expected.as_ref().map(journal::Value::of), after, state: "pending".into(), note: job.note.clone(), undoes: job.undoes, record: None };
    let key = jkey.to_string();
    let change = |e: Entry| -> crate::prefs::Change<journal::Journal> {
        let k = key.clone();
        Arc::new(move |j: &mut journal::Journal| j.put(&k, e.clone()))
    };
    // An outcome that is not the change's Undo: written when it can be (it waits otherwise).
    let put = |e: Entry| store.change(change(e));
    if let Err(why) = store.save(change(entry.clone())) {
        return Applied::NotDone { hive, why: journal_unsaved(&why, "so nothing was changed"), state: "refused" };
    }
    // 4-5. Write, read back.
    let finish = |state: &str, note: String| {
        let mut e = entry.clone();
        e.state = state.into();
        if !note.is_empty() {
            e.note = if e.note.is_empty() { note } else { format!("{}; {note}", e.note) };
        }
        put(e);
    };
    // Machine PATH: the helper's record of this change, for its Undo.
    let mut record = None;
    match hive {
        Hive::User => {
            let r = if job.delete { sys.delete_user_path() } else { sys.write_user_path(&job.new, job.kind) };
            if let Err(code) = r {
                let why = format!("User PATH could not be written ({}).", crate::host::code_words(code));
                finish("failed", why.clone());
                return Applied::NotDone { hive, why, state: "failed" };
            }
            let back = sys.read(hive, "Path");
            let ok = if job.delete { matches!(back, env::Read::Missing) } else { matches!(&back, env::Read::Value(v) if v.kind == job.kind && v.raw == job.new) };
            if !ok {
                let why = "User PATH read back differently: another program changed it at the same moment.".to_string();
                finish("failed", why.clone());
                return Applied::NotDone { hive, why, state: "failed" };
            }
        }
        Hive::Machine => {
            match sys.machine_path_set(&helper::Request { expected: job.expected.clone(), new: job.new.clone(), undo: job.record }, hwnd, stop) {
                Outcome::Answer(Answer::Done(_, id)) => record = Some(crate::records::hex(&id)),
                Outcome::Answer(Answer::Refused(helper::Reason::Changed, now)) => {
                    finish("refused", helper::Reason::Changed.words().into());
                    return Applied::ChangedSince { hive, now: now.map(env::Read::Value).unwrap_or(env::Read::Missing) };
                }
                Outcome::Answer(Answer::Refused(r, _)) => {
                    finish("refused", r.words().into());
                    return Applied::NotDone { hive, why: helper_refused(r), state: "refused" };
                }
                Outcome::Answer(Answer::Failed(code, _)) => {
                    let why = if code == 0 { "Machine PATH read back differently: another program changed it at the same moment.".to_string() } else { format!("Machine PATH could not be written ({}).", crate::host::code_words(code)) };
                    finish("failed", why.clone());
                    return Applied::NotDone { hive, why, state: "failed" };
                }
                Outcome::Declined => {
                    finish("declined", "administrator rights were declined".into());
                    return Applied::NotDone { hive, why: "administrator rights were declined.".into(), state: "declined" };
                }
                Outcome::NeverConnected(why) | Outcome::Failed(why) => {
                    finish("failed", why.clone());
                    return Applied::NotDone { hive, why: format!("{why}."), state: "failed" };
                }
                Outcome::Gone => {
                    finish("unknown", "the helper went away before it answered".into());
                    return Applied::Unknown { hive, why: "the helper went away before it answered.".into() };
                }
                Outcome::Stopped => {
                    finish("unknown", "VibePath closed while the helper worked".into());
                    return Applied::Unknown { hive, why: "VibePath closed meanwhile.".into() };
                }
            }
        }
    }
    // "done" is what Undo needs (and, for Machine PATH, the helper's record id).
    let done = Entry { state: "done".into(), record, ..entry.clone() };
    if let Err(why) = store.save(change(done.clone())) {
        // User PATH: taken back, but only while it still holds what was written (re-checked just
        // before: the registry has no true compare-and-swap); another program's value meanwhile
        // is never written over (RPS-1).
        let still = |r: &env::Read| if job.delete { matches!(r, env::Read::Missing) } else { matches!(r, env::Read::Value(v) if v.kind == job.kind && v.raw == job.new) };
        if hive == Hive::User && still(&sys.read(hive, "Path")) {
            let back = match &job.expected {
                Some(v) => sys.write_user_path(&v.raw, v.kind.restored()),
                None => sys.delete_user_path(),
            };
            if back.is_ok() {
                let now = sys.read(hive, "Path");
                let restored = match (&job.expected, &now) {
                    (Some(v), env::Read::Value(n)) => n.raw == v.raw,
                    (None, env::Read::Missing) => true,
                    _ => false,
                };
                if restored {
                    finish("failed", "journal.json could not be saved: taken back".into());
                    return Applied::NotDone { hive, why: journal_unsaved(&why, "so the change was taken back: User PATH holds its old value again"), state: "failed" };
                }
                // Written back, but not read back as such (RPS-2): not known, never "changed".
                finish("unknown", "journal.json could not be saved: taken back; could not be confirmed".into());
                return Applied::Unknown { hive, why: format!("journal.json could not be saved ({why}), so the change was taken back, but User PATH did not read back as its old value.") };
            }
        }
        // Machine PATH (taking it back would take a second UAC prompt), or a User PATH that could
        // not be put back (written again meanwhile, or the write back failed): the change is made; its Undo waits in memory and is written as soon as
        // journal.json can be (every later write, and at exit).
        put(done);
        sys.broadcast();
        return Applied::Unsaved { hive, why };
    }
    // 6. Broadcast, then ask Explorer 2 s later.
    sys.broadcast();
    sys.pause(2000);
    let explorer = explorer_has_new_path(sys);
    Applied::Done { hive, explorer, entry: id }
}

/// The plain-text report: the context, the five shells, the matches with source, version and
/// signer, then PATH with its findings and lengths. It reads everything itself.
#[allow(clippy::too_many_arguments)]
pub fn report_job(sysa: &Arc<dyn System>, cache: &Mutex<HashMap<CacheKey, Details>>, command: &str, ctx: Ctx, cwd_new: Option<W>, shell: Shell, now: i64, off: &dyn Fn(i64) -> i64) -> String {
    use crate::report::Section;
    let sys: &dyn System = &**sysa;
    let mut sections = Vec::new();
    sections.push(Section { title: format!("VibePath report, {}", crate::host::date_time(now, off(now))), lines: vec![format!("Context: {}", ctx.word()), format!("Shell shown: {}", shell.word())] });
    let parsed = input::command(&input::units(command));
    if let Some(cmd) = parsed.command {
        let r = resolve_job(sys, cmd, ctx, cwd_new, now);
        let mut lines = vec![format!("Command: {}", command.trim()), format!("Summary: {}", summary_line(&r.per, &r.aliases))];
        if let Some(e) = &r.error {
            lines.push(format!("Context: {e}"));
        }
        sections.push(Section { title: "Command".into(), lines });
        for (i, res) in r.per.iter().enumerate() {
            let mut lines = Vec::new();
            for x in &res.rows {
                let num = if x.number > 0 { format!("#{}", x.number) } else { "  ".into() };
                let (what, path) = match &x.found {
                    Found::Builtin => ("built into cmd".to_string(), None),
                    Found::Ps(c) => (format!("{} ({} {})", c.name, c.kind, c.target), None),
                    Found::File { path, .. } => (wide::lossy(path), Some(path.clone())),
                    Found::AppPath(a) => (format!("{}{}", wide::lossy(&a.target), if a.missing { " (missing)" } else { "" }), Some(a.target.clone())),
                    Found::NotChecked { dir, reason, .. } => (format!("{} (not checked: {reason})", wide::lossy(dir)), None),
                };
                lines.push(format!("{num} {what}"));
                lines.push(format!("     source: {}{}", resolve::step_source(&x.found), x.shadow.as_ref().map(|s| format!("; {s}")).unwrap_or_else(|| if x.number == 1 { "; wins".into() } else { String::new() })));
                if let Some(p) = path {
                    let read_from = match r.aliases.get(&wide::lossy(&p).to_lowercase()) {
                        Some(Ok(a)) => {
                            lines.push(format!("     alias: {}, target {}", crate::alias::words(a), wide::lossy(&a.target)));
                            a.target.clone()
                        }
                        _ => p.clone(),
                    };
                    let d = details_job(sys, cache, &p, &read_from);
                    let mut facts = Vec::new();
                    if let Some(a) = &d.arch {
                        facts.push(a.clone());
                    }
                    if !d.file_version.is_empty() {
                        facts.push(format!("version {}", d.file_version));
                    }
                    if !d.company.is_empty() {
                        facts.push(d.company.clone());
                    }
                    facts.push(d.signer.clone());
                    lines.push(format!("     {}", facts.join("; ")));
                }
            }
            if lines.is_empty() {
                lines.push("not found".into());
            }
            for n in &res.notes {
                lines.push(format!("({n})"));
            }
            sections.push(Section { title: format!("Matches in {}", Shell::from_index(i).word()), lines });
        }
    }
    let read = path_read_job(sys, now);
    let facts = facts_job(sysa, &read.entries);
    let (s32, _, _) = sys.system_dirs();
    let report = health::judge(health::Input { machine: &read.machine, user: &read.user, pathext_machine: &read.pathext_machine, pathext_user: &read.pathext_user, rows: read.entries.iter().cloned().zip(facts).collect(), built: read.built.clone(), system32: s32 });
    let mut lines = vec![report.header.replace('\u{a0}', " ")];
    for g in &report.general {
        lines.push(format!("{}: {}", level_word(g.level), g.text));
    }
    for (i, r) in report.rows.iter().enumerate() {
        let e = &r.entry;
        let exp = if e.expanded != e.typed { format!(" -> {}", wide::lossy(&e.expanded)) } else { String::new() };
        lines.push(format!("#{} {} {}{exp}", i + 1, e.label(), if e.empty() { "(empty)".into() } else { wide::lossy(&e.typed) }));
        for f in &r.findings {
            lines.push(format!("     {}: {}", level_word(f.level), f.text));
        }
    }
    sections.push(Section { title: "PATH".into(), lines });
    crate::report::text(&sections, crate::VERSION)
}

fn level_word(l: i32) -> &'static str {
    match l {
        health::DANGER => "danger",
        health::WARN => "warning",
        health::UNKNOWN => "unknown",
        _ => "info",
    }
}
