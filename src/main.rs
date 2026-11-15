// VibePath: one process, no browser engine, the software renderer.
#![windows_subsystem = "windows"]

use slint::ComponentHandle;

/// The real release-list fetcher (WinHTTP), the exe's alone: it is in no test build, not the
/// lib's, not the integration tests', not this exe's own unit tests', so no test can go online
/// (review RAB-2; tests/pe.rs checks this line).
#[cfg(not(test))]
mod net;

/// The window's Win32 handle, for `host::fit_to_work_area`.
fn hwnd_of(w: &slint::winit_030::winit::window::Window) -> Option<isize> {
    use slint::winit_030::winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match w.window_handle().ok()?.as_raw() {
        RawWindowHandle::Win32(h) => Some(h.hwnd.get()),
        _ => None,
    }
}

fn main() -> Result<(), slint::PlatformError> {
    // DLL hardening, first of all (VibeLink LINK-1): every DLL loaded from here on comes from
    // System32, never from the exe's own folder (a USB stick's, or the per-user install folder:
    // the elevated helper is this exe). The static imports are covered by the link flag
    // /DEPENDENTLOADFLAG:0x800 (build.rs).
    // SAFETY: a process-wide setting with a valid flag; nothing has been loaded by name yet.
    unsafe {
        use windows_sys::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories};
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    // No Windows "No Disk" box: a file call on an empty card reader or drive gets its error back
    // instead of a modal box (review fix-popup, RX1). tests/pe.rs checks this block comes next.
    // SAFETY: a process-wide setting with a valid flag, the bits already set kept.
    unsafe {
        use windows_sys::Win32::System::Diagnostics::Debug::{GetErrorMode, SEM_FAILCRITICALERRORS, SetErrorMode};
        SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS);
    }
    // The command line (cli.rs): `VibePath.exe [<command>]`, the admin helper's exact
    // `--helper machine-path-set <pipe>`, and in dev-hooks builds the live checks. Anything else
    // ends the process before any window, file or instance contact (exit code 2). args_os: an
    // argument that is not Unicode must not panic (panic = abort ends the app). A command typed
    // after the exe (`VibePath.exe python`) keeps its exact units.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let Some(start) = vibepath::cli::start(&args, cfg!(feature = "dev-hooks")) else { std::process::exit(2) };
    let (command, left_out) = match start {
        // The admin helper (relaunched elevated by Apply on Machine PATH): no window, one bounded
        // job. It refuses to run unelevated or without the app's pipe.
        vibepath::cli::Start::Helper(a) => std::process::exit(vibepath::helper::run_helper(&a)),
        // Live checks (dev-hooks builds only, never shipped): the marker the resolution tests start.
        #[cfg(feature = "dev-hooks")]
        vibepath::cli::Start::Dev(a) => std::process::exit(vibepath::dev::run(&a).unwrap_or(2)),
        #[cfg(not(feature = "dev-hooks"))]
        vibepath::cli::Start::Dev(_) => std::process::exit(2),
        vibepath::cli::Start::Command(c) => (Some(c), None),
        // Several files dropped on the exe (launch.rs): the first, and a toast for the rest.
        vibepath::cli::Start::Several(c, note) => (Some(c), Some(note)),
        vibepath::cli::Start::Window => (None, None),
    };
    // Portable (a `portable` file beside the exe, or a removable disk) is decided before any
    // prefs are read.
    let exe = vibepath::portable::own_final_path();
    #[allow(unused_mut)]
    let mut mode = vibepath::portable::detect(&exe);
    #[allow(unused_mut)]
    let mut paths = match &mode {
        vibepath::portable::Mode::Installed => vibepath::host::paths(),
        vibepath::portable::Mode::Portable { dir } | vibepath::portable::Mode::ReadOnly { dir } => vibepath::portable::paths(dir),
    };
    // Live checks and measurements only: the app's folders in a place of the developer's choosing,
    // so nothing touches the real profile. It wins over portable. Never in a shipped build.
    #[cfg(feature = "dev-hooks")]
    if let Some(home) = std::env::var_os("VIBEPATH_DEV_HOME").map(std::path::PathBuf::from) {
        paths = vibepath::host::Paths { config: home.join("config"), local_data: home.join("local") };
        if matches!(mode, vibepath::portable::Mode::ReadOnly { .. }) {
            mode = vibepath::portable::Mode::Installed;
        }
    }
    // The probe hands back the value it was asked about, and `main` goes on with that one only: the
    // old binding is gone (`dev_probe`, review RRF-2).
    #[cfg(feature = "dev-hooks")]
    let paths = dev_probe(paths);
    let read_only = matches!(mode, vibepath::portable::Mode::ReadOnly { .. });
    let prefs = if read_only { vibepath::prefs::Store::memory() } else { vibepath::prefs::Store::new(paths.config.join("prefs.json")) };
    let journal = if read_only { None } else { Some(paths.local_data.clone()) };
    let ui = vibepath::window(prefs.clone())?;
    // The one place that names the real release-list fetcher (tests/pe.rs checks it): every test
    // hands the controller a fake, so no test goes online. This exe's unit-test build has no
    // `net` and never runs `main`: it gets a stand-in that fetches nothing.
    #[cfg(not(test))]
    let fetch = std::sync::Arc::new(net::fetch_release_list);
    #[cfg(test)]
    let fetch = std::sync::Arc::new(|_: &str| vibepath::check::Fetched::Failed("a test build has no fetcher".into()));
    let svc = vibepath::controller::Services::system(mode, journal, fetch);
    let app = vibepath::controller::App::attach(&ui, prefs, svc);
    app.start(command);
    if let Some(note) = left_out {
        app.toast(&note, vibepath::ToastKind::Info, None);
    }
    // The window opens at its preferred size; on a small or highly scaled screen that runs past
    // the taskbar, so the first window event once it is on screen fits it into the monitor's work
    // area (X15A11Y-3), once (a minimized start waits for the restore, X15RFTP-4).
    let fitted = std::cell::Cell::new(false);
    {
        use slint::winit_030::{EventResult, WinitWindowAccessor};
        ui.window().on_winit_window_event(move |window, _| {
            if !fitted.get() && window.with_winit_window(hwnd_of).flatten().and_then(vibepath::host::fit_to_work_area).is_some() {
                fitted.set(true);
            }
            EventResult::Propagate
        });
    }
    let ran = ui.run();
    app.finish_prefs(); // stops the workers; a change from the last moments still on its way to disk
    drop(app);
    ran
}

/// Live checks only (review RRE-5, RRF-2): with VIBEPATH_DEV_PROBE set, `main` writes the
/// app's data folders, one a line on stdout, and ends (exit 0) right after the dev home, before
/// any of them is used and before any window. Else it hands back the value it was given,
/// unchanged, and `main` goes on with it (`let paths = dev_probe(paths);`), so the folders the
/// probe names are the ones `main` uses. tests/pe.rs asks this before it starts the exe for real
/// (`run_exe`): every folder must be inside the scratch dev home it gave, so an override that is
/// gone, compiled out or too late fails there, by what the exe does.
#[cfg(feature = "dev-hooks")]
fn dev_probe(paths: vibepath::host::Paths) -> vibepath::host::Paths {
    use std::io::Write;
    if std::env::var_os("VIBEPATH_DEV_PROBE").is_some() {
        let mut out = std::io::stdout().lock();
        for f in [&paths.config, &paths.local_data] {
            let _ = writeln!(out, "{}", f.display());
        }
        let _ = out.flush();
        std::process::exit(0);
    }
    paths
}
