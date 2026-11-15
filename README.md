# VibePath

Why does `python` run THAT one? VibePath shows why a command runs the program it does, and gives
you a safe way to clean up PATH, with a journal and undo. For Windows.

Type a command and see every file it could mean, in the order cmd, PowerShell 7, Windows
PowerShell 5.1, a program and the Run box would find them: which one wins, what it hides, and who
made and signed each file. Ask from a new window's point of view, from VibePath's own, or from any
running program of yours, such as that one terminal that acts up. Then PATH itself: what is dead,
doubled, broken or dangerous (a PC-wide PATH folder anyone can write to, for one), which running
programs still have an old PATH, and an editor with a preview before anything changes. It is
written in Rust with a native Slint interface, with no browser engine inside.

## What it does and doesn't do

- **It never runs a file it finds,** not even with `--version`, and never asks a shell. Everything
  comes from the registry, the file system and the running programs' memory.
- **Your PATH changes only when you apply an edit.** Every change is in the journal (the History
  tab) and can be undone. Before the first change to a PATH, VibePath saves a `.reg` copy of it as
  it was.
- **Admin rights only for the PC-wide PATH:** one Windows prompt per change, in a short helper that
  does that one job and exits. Your own PATH needs none, and VibePath itself never runs elevated.
- **Keeps** its settings in `%APPDATA%\com.tedkj.vibepath` and the PATH journal with the `.reg`
  copies in `%LOCALAPPDATA%\com.tedkj.vibepath`; undo records sit in the registry.
- **Portable:** with a file named `portable` beside `VibePath.exe`, or on a USB stick or SD card,
  it keeps everything in `VibePath-data` beside the exe instead.

## What it connects to

Only network shares that are on your PATH, to see that they exist, and getvibeware.com when you
press About's "Check this install". No accounts, no ads, no telemetry.

## Download

Get the installer from [Releases](https://github.com/tedkj/vibepath/releases), or from
[getvibeware.com](https://getvibeware.com). It installs for your user only, without admin rights.
The installer, `VibePath.exe` and its uninstaller are code signed by "Open Source Developer Ted
Kenneth Johansen" (the certificate's name; right-click, Properties › Digital Signatures). Compare
the installer's SHA-256 with the one on the release page:

```powershell
Get-FileHash .\VibePath_0.1.0-preview_x64-setup.exe
```

Uninstalling (Settings › Apps) removes the app and leaves your settings and the PATH journal where
they are, so a reinstall finds them.

## What is in this repository

| Folder | What it is |
|--------|-----------|
| `src/` | The app: command resolution per shell, the PATH checks, the editor and journal, the elevated helper. |
| `ui/` | The Slint interface (the VibeWare design system in `ui/vibeware/`). |
| `assets/` | The icon, the manifest and the PowerShell command tables (`tools/ps-builtins.ps1` writes them). |
| `installer/` | The NSIS installer and its build script. |
| `vendor/` | Slint's `i-slint-core` 1.18.1 with one small repaint fix; `vendor/README.md` says what changed and why. |

## Building from source

You need a current stable Rust toolchain on Windows (the MSVC target).

```sh
cargo build --release --locked
```

The app is then at `target\release\vibepath.exe`.

### Building the installer

`installer\build.ps1` builds the app and its installer,
`target\release\bundle\VibePath_<version>_x64-setup.exe`. It needs the official NSIS 3.13:
download `nsis-3.13.zip` from SourceForge (SHA-256
`ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8`) and unpack it to
`_tools\nsis-3.13` in the folder that holds this repository (`..\_tools\nsis-3.13`). The script
checks that whole folder against a pinned hash before it runs anything from it.
`installer\notices.ps1` writes `THIRD-PARTY-NOTICES.txt` for each build (every crate the app
links, with its licence text), and the installer puts it and `LICENSE` next to the app.

## License

[AGPL-3.0](LICENSE). Use it, change it, share it. If you hand out a changed version, or run one as
a service for other people, you share your changes under the same license. Slint is used under
its GPLv3 option.

Made in Norway by Ted K. Johansen.
