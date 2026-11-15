//! Windows' own folder picker and save dialog (the Common Item Dialog, through its COM vtable:
//! windows-sys carries no COM interfaces). Each runs on a thread of its own, owned by the app's
//! window: the dialog is modal to it while the app's event loop keeps running, and nothing
//! re-enters the UI thread's handlers. (VibeBackup's; the chosen path keeps its exact units.)

use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::core::{GUID, HRESULT, PCWSTR, PWSTR};

type Raw = *mut core::ffi::c_void;

#[repr(C)]
struct FileDialogVtbl {
    query_interface: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(Raw) -> u32,
    show: unsafe extern "system" fn(Raw, HWND) -> HRESULT,
    set_file_types: usize,
    set_file_type_index: usize,
    get_file_type_index: usize,
    advise: usize,
    unadvise: usize,
    set_options: unsafe extern "system" fn(Raw, u32) -> HRESULT,
    get_options: unsafe extern "system" fn(Raw, *mut u32) -> HRESULT,
    set_default_folder: usize,
    set_folder: unsafe extern "system" fn(Raw, Raw) -> HRESULT,
    get_folder: usize,
    get_current_selection: usize,
    set_file_name: unsafe extern "system" fn(Raw, PCWSTR) -> HRESULT,
    get_file_name: usize,
    set_title: unsafe extern "system" fn(Raw, PCWSTR) -> HRESULT,
    set_ok_button_label: unsafe extern "system" fn(Raw, PCWSTR) -> HRESULT,
    set_file_name_label: usize,
    get_result: unsafe extern "system" fn(Raw, *mut Raw) -> HRESULT,
}

#[repr(C)]
struct ShellItemVtbl {
    query_interface: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(Raw) -> u32,
    bind_to_handler: usize,
    get_parent: usize,
    get_display_name: unsafe extern "system" fn(Raw, i32, *mut PWSTR) -> HRESULT,
}

const IID_IFILEDIALOG: GUID = GUID::from_u128(0x42f85136_db7e_439c_85f1_e4075d135fc8);
const IID_ISHELLITEM: GUID = GUID::from_u128(0x43826d1e_e718_42ee_bc55_a1e261c37bfe);
const FOS_OVERWRITEPROMPT: u32 = 0x2;
const FOS_NOCHANGEDIR: u32 = 0x8;
const FOS_PICKFOLDERS: u32 = 0x20;
const FOS_FORCEFILESYSTEM: u32 = 0x40;
const FOS_PATHMUSTEXIST: u32 = 0x800;

unsafe fn vtbl<T>(p: Raw) -> &'static T {
    unsafe { &**(p as *mut *const T) }
}

fn item_for(path: &Path) -> Option<Raw> {
    use windows_sys::Win32::UI::Shell::SHCreateItemFromParsingName;
    let w = crate::host::wide_path(path);
    let mut item: Raw = std::ptr::null_mut();
    let hr = unsafe { SHCreateItemFromParsingName(w.as_ptr(), std::ptr::null_mut(), &IID_ISHELLITEM, &mut item) };
    if hr >= 0 && !item.is_null() { Some(item) } else { None }
}

/// The dialog itself, on the calling thread. `save`: a save dialog for `name`; else a folder picker.
fn run(owner: HWND, save: bool, title: &str, start: Option<&Path>, name: &str) -> Option<PathBuf> {
    use windows_sys::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize};
    use windows_sys::Win32::UI::Shell::{FileOpenDialog, FileSaveDialog, SIGDN_FILESYSPATH};
    unsafe {
        CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32);
        let mut dlg: Raw = std::ptr::null_mut();
        let clsid = if save { FileSaveDialog } else { FileOpenDialog };
        let mut out = None;
        if CoCreateInstance(&clsid, std::ptr::null_mut(), CLSCTX_INPROC_SERVER, &IID_IFILEDIALOG, &mut dlg) >= 0 && !dlg.is_null() {
            let v = vtbl::<FileDialogVtbl>(dlg);
            let mut opts = 0u32;
            (v.get_options)(dlg, &mut opts);
            opts |= FOS_FORCEFILESYSTEM | FOS_NOCHANGEDIR | FOS_PATHMUSTEXIST | if save { FOS_OVERWRITEPROMPT } else { FOS_PICKFOLDERS };
            (v.set_options)(dlg, opts);
            let t = crate::host::wide(title);
            (v.set_title)(dlg, t.as_ptr());
            if !save {
                let ok = crate::host::wide("Choose");
                (v.set_ok_button_label)(dlg, ok.as_ptr());
            }
            if let Some(dir) = start.and_then(|s| s.ancestors().find(|a| a.is_dir())).and_then(item_for) {
                (v.set_folder)(dlg, dir);
                (vtbl::<ShellItemVtbl>(dir).release)(dir);
            }
            if save {
                let n = crate::host::wide(name);
                (v.set_file_name)(dlg, n.as_ptr());
            }
            if (v.show)(dlg, owner) >= 0 {
                let mut item: Raw = std::ptr::null_mut();
                if (v.get_result)(dlg, &mut item) >= 0 && !item.is_null() {
                    let iv = vtbl::<ShellItemVtbl>(item);
                    let mut p: PWSTR = std::ptr::null_mut();
                    if (iv.get_display_name)(item, SIGDN_FILESYSPATH, &mut p) >= 0 && !p.is_null() {
                        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
                        out = Some(crate::host::path_from_wide(std::slice::from_raw_parts(p, len)));
                        CoTaskMemFree(p as *const _);
                    }
                    (iv.release)(item);
                }
            }
            (v.release)(dlg);
        }
        CoUninitialize();
        out
    }
}

/// A folder picker over `owner`; `done` hears the choice (None: cancelled), on the dialog's
/// thread. No start folder is given: one on a dead share froze the picker (C46).
pub fn pick_folder(owner: Option<isize>, title: &str, done: impl FnOnce(Option<PathBuf>) + Send + 'static) {
    let title = title.to_string();
    std::thread::spawn(move || done(run(owner.unwrap_or(0) as HWND, false, &title, None, "")));
}

/// A save dialog for `name` (Windows picks the folder it last used).
pub fn save_file(owner: Option<isize>, title: &str, name: &str, done: impl FnOnce(Option<PathBuf>) + Send + 'static) {
    let (title, name) = (title.to_string(), name.to_string());
    std::thread::spawn(move || done(run(owner.unwrap_or(0) as HWND, true, &title, None, &name)));
}
