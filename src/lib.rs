//! VibePath: which program actually runs, and what your PATH hides. A VibeWare app: Rust and Slint on the software renderer,
//! one small exe, no runtime beside it.
//!
//! `controller` ties the app to the window, which only lays out and draws.

pub mod acl;
pub mod alias;
pub mod authenticode;
pub mod broadcast;
pub mod cli;
pub mod check;
pub mod controller;
#[cfg(feature = "dev-hooks")]
pub mod dev;
pub mod dialogs;
pub mod editor;
pub mod env;
pub mod fake;
pub mod fileinfo;
pub mod fsprobe;
pub mod health;
pub mod helper;
pub mod host;
pub mod input;
pub mod journal;
pub mod launch;
pub mod peb;
pub mod portable;
pub mod prefs;
pub mod records;
pub mod regfile;
pub mod report;
pub mod resolve;
pub mod stale;
pub mod system;
pub mod text;
pub mod wide;
pub mod trust;

use serde::{Deserialize, Serialize};
use slint::ComponentHandle;

slint::include_modules!();

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the window remembers between runs (prefs.json in %APPDATA%\com.tedkj.vibepath).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// "dark" or "light" once the user has picked one; until then the system's choice.
    pub theme: Option<String>,
    /// The last tab: "command", "path", "running", "history".
    pub tab: Option<String>,
    /// The shell shown: "cmd", "pwsh", "ps51", "program", "run".
    pub shell: Option<String>,
    /// The last 10 commands resolved, newest first.
    pub recent: Vec<String>,
}

impl Prefs {
    pub fn dark(&self) -> bool {
        match self.theme.as_deref() {
            Some("dark") => true,
            Some("light") => false,
            _ => host::system_dark(),
        }
    }

    /// Only the values the window offers survive a hand-edited file; the rest fall back.
    pub fn sanitized(mut self) -> Prefs {
        if !matches!(self.theme.as_deref(), None | Some("dark") | Some("light")) {
            self.theme = None;
        }
        if !matches!(self.tab.as_deref(), None | Some("command") | Some("path") | Some("running") | Some("history")) {
            self.tab = None;
        }
        if self.shell.as_deref().is_some_and(|s| resolve::Shell::from_key(s).is_none()) {
            self.shell = None;
        }
        self.recent.retain(|r| !r.trim().is_empty() && r.chars().count() <= 260);
        self.recent.truncate(10);
        self
    }
}

/// The window with its basics wired: theme, version, copying. The controller adds the rest (the
/// theme switch too: it saves on the prefs thread).
pub fn window(prefs: prefs::Store<Prefs>) -> Result<AppWindow, slint::PlatformError> {
    let ui = AppWindow::new()?;
    let p = prefs.load().sanitized();
    ui.global::<Theme>().set_dark(p.dark());
    ui.set_version(VERSION.into());
    ui.on_copy_text(|t| host::copy_text(&t).is_ok());
    Ok(ui)
}
