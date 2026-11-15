//! The command line (the family rule, VibeTemplate; SPEC section 10): `VibePath.exe [<command>]`.
//! One command name opens the Command tab with it resolved (a file dropped on the exe is a full
//! path, so it is that command; several dropped files: the first, and a toast for the rest,
//! launch.rs); the elevated relaunch from helper.rs
//! is `--helper machine-path-set <pipe>`, taken only in exactly the shape `relaunch` sends; a
//! dev-hooks build also takes its live-check commands (dev.rs). Anything else is refused: `main`
//! ends with exit code 2 before any window, file or instance contact. Read from `args_os`: the
//! command keeps its exact units (a lone surrogate too); the helper's and the dev checks'
//! arguments must be Unicode.

use std::ffi::{OsStr, OsString};

/// What a start was asked for.
#[derive(Debug, PartialEq, Eq)]
pub enum Start {
    /// No arguments: the window.
    Window,
    /// `VibePath.exe <command>`: the window, the Command tab, this command resolved.
    Command(OsString),
    /// Several files dropped on the exe (launch.rs): as `Command` with the first, and this toast
    /// for the rest.
    Several(OsString, String),
    /// The admin helper, with its arguments as `helper::run_helper` takes them.
    Helper(Vec<String>),
    /// A dev-hooks build's live check, the flag first: `--dev-path-set <hive> <file> <out>` or
    /// `--dev-undo <out>`.
    Dev(Vec<OsString>),
}

/// An option, not a command: it starts with `-`, or what the Command field keeps of it
/// (`input::command`: trimmed, the first word, unquoted) does (RA-4: `" -x"` and `"\"-x\""` are
/// `-x` in the field). No command on PATH is named like one; a real `-x.exe` is still reached as
/// `.\-x.exe` or a full path, or typed into the field (DECISIONS "The command line").
fn option(a: &OsStr) -> bool {
    let kept = crate::input::command(&crate::wide::of_os(a)).command;
    a.as_encoded_bytes().first() == Some(&b'-') || kept.is_some_and(|c| c.units().first() == Some(&(b'-' as u16)))
}

/// The start the arguments (after the exe's own name) ask for, or None (exit code 2). `dev`:
/// this is a dev-hooks build, which also takes the live-check commands.
pub fn start(args: &[OsString], dev: bool) -> Option<Start> {
    let Some(first) = args.first() else { return Some(Start::Window) };
    if first == "--helper" {
        let a = args.iter().map(|x| x.to_str().map(str::to_string)).collect::<Option<Vec<String>>>()?;
        return crate::helper::parse_args(&a).map(|_| Start::Helper(a));
    }
    if dev && args.iter().all(|a| a.to_str().is_some()) && ((first == "--dev-path-set" && args.len() == 4) || (first == "--dev-undo" && args.len() == 2)) {
        return Some(Start::Dev(args.to_vec()));
    }
    if let Some((first, note)) = crate::launch::several(args) {
        return Some(Start::Several(typed(&first), note));
    }
    match args {
        [command] if !command.is_empty() && !option(command) => Some(Start::Command(typed(command))),
        _ => None,
    }
}

/// The command as the field takes it. A file dropped on the exe is a full path, which may hold a
/// space (`C:\Program Files\Git\cmd\git.exe`): the field keeps only the first word of text with a
/// space outside quotes, so such a path goes in quotes, and the whole of it is resolved. Anything
/// else, and a path that holds a `"` already, exactly as given.
fn typed(a: &OsStr) -> OsString {
    use std::os::windows::ffi::OsStrExt;
    if crate::launch::dropped_file(a) && a.encode_wide().any(crate::input::is_space) && !a.encode_wide().any(|u| u == crate::wide::QUOTE) {
        let mut q = OsString::from("\"");
        q.push(a);
        q.push("\"");
        q
    } else {
        a.to_os_string()
    }
}
