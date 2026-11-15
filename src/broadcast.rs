//! Telling running programs that the environment changed (SPEC section 6): `WM_SETTINGCHANGE`
//! with "Environment" to every top-level window, each given at most 5 s and skipped when hung.
//! Explorer re-reads the registry then; most other programs never look. Blocking: on a worker.

/// Broadcast the change. True when the broadcast went out (whoever listened).
pub fn environment_changed() -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE};
    let what = crate::wide::z(&crate::wide::w("Environment"));
    let mut result: usize = 0;
    // SAFETY: a NUL-terminated string that lives through the call; the result is ours.
    unsafe { SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, what.as_ptr() as isize, SMTO_ABORTIFHUNG, 5000, &mut result) != 0 }
}
