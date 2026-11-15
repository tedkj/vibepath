//! Files dropped on the exe or its shortcut. Windows starts the app with their paths as its
//! arguments. VibePath takes one command there (`VibePath.exe <command>`), and a full path is a
//! command (`C:\Tools\x.exe`), so one dropped file is resolved as its path, as before (cli.rs
//! quotes it when it holds a space). Several: VibePath resolves one command at a time, so it
//! resolves the first and a toast says the others were left out. They are told apart from
//! anything else by their shape alone (`dropped_file`): nothing asks the disk or a share about
//! them here. Several arguments that are not all dropped files stay exit 2, as before.

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

/// The longest name a toast shows; a longer one keeps its start and end around an ellipsis.
const LONGEST: usize = 60;

/// Several files dropped on the exe (two or more arguments, every one with a dropped file's
/// shape): the first, exactly as given, to resolve, and the toast for the rest. None for
/// anything else: `cli::start`'s own rule takes the line, as before.
pub fn several(args: &[OsString]) -> Option<(OsString, String)> {
    (args.len() > 1 && args.iter().all(|a| dropped_file(a))).then(|| (args[0].clone(), left_out(&args[1..])))
}

/// A dropped file's shape: an absolute path with a drive (`C:\...` or `C:/...`, any letter) or a
/// UNC or device path (`\\...`), once the spaces and `"` before it are trimmed (lossy: a name
/// that is not Unicode keeps its other characters). By the text alone, never by asking the disk
/// or the network. Explorer passes every dropped file so; a command name (`python`), a relative
/// path (`.\tool.exe`), a drive alone (`C:`) or drive-relative (`C:python`) is not one.
pub fn dropped_file(a: &OsStr) -> bool {
    let lossy = a.to_string_lossy();
    let t = lossy.trim_start_matches(|c: char| c.is_whitespace() || c == '"');
    let b = t.as_bytes();
    t.starts_with(r"\\") || (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/'))
}

/// The name a toast shows for a path (lossy). A Windows name never holds a `"`, so one is left
/// over from the command line's quoting (`"C:\Photos\"` ends in `\"`, an escaped quote): the
/// path is the text before it. Anything else, a `'` or a space included, belongs to the name. A
/// path with no name of its own shows its last folder (`C:\a\b\..` shows `a`) or its drive or
/// share (`C:\`), and a long name is cut in the middle.
fn shown(a: &OsStr) -> String {
    let lossy = a.to_string_lossy();
    let path = lossy.trim_start_matches('"').split('"').next().unwrap_or_default();
    let mut kept: Vec<Component> = Vec::new();
    for c in Path::new(path).components() {
        match (c, kept.last()) {
            (Component::ParentDir, Some(Component::Normal(_))) => {
                kept.pop();
            }
            (Component::ParentDir, Some(Component::RootDir)) => {}
            (c, _) => kept.push(c),
        }
    }
    let name = match kept.last() {
        Some(Component::Normal(n)) => n.to_string_lossy().into_owned(),
        Some(_) => kept.iter().collect::<PathBuf>().to_string_lossy().into_owned(),
        None => ".".to_string(),
    };
    let n = name.chars().count();
    if n <= LONGEST {
        return name;
    }
    let head: String = name.chars().take(LONGEST / 2).collect();
    let tail: String = name.chars().skip(n - (LONGEST - LONGEST / 2 - 1)).collect();
    format!("{head}\u{2026}{tail}")
}

/// The toast for the files not resolved: the first one's name (not its folder), and how many
/// more.
fn left_out(rest: &[OsString]) -> String {
    let name = shown(&rest[0]);
    let more = match rest.len() - 1 {
        0 => String::new(),
        n => format!(" and {n} more"),
    };
    format!("VibePath resolves one command at a time, so it left out {name}{more}.")
}
