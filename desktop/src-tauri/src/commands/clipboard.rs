//! Secret-safe clipboard writes (audit DT-2).
//!
//! The "copy secret" affordance used to go through
//! `tauri-plugin-clipboard-manager` from the webview, which is a plain
//! `arboard::set_text`: the copied password — and, in the create wizard, the
//! entire 24-word recovery mnemonic — carried no concealment markers, so it
//! landed in Windows Clipboard History / Cloud Clipboard and in every macOS
//! clipboard manager that honours `org.nspasteboard.ConcealedType`, where the
//! frontend's 30-second clear does not reach. The webview also held a
//! general-purpose clipboard-write capability.
//!
//! Both commands here run in the Rust trust boundary and set the platform
//! "transient / do not record" flags: on Windows
//! `ExcludeClipboardContentFromMonitorProcessing` and
//! `CanIncludeInClipboardHistory=0`, on macOS `org.nspasteboard.ConcealedType`.
//! The `clipboard-manager:allow-write-text` capability is no longer granted
//! to the webview; the plugin stays registered but is inert.
//!
//! The pasted value still lives in the OS clipboard until the frontend's
//! clear fires — that residual is unchanged and documented in the reveal
//! spec; what changes is that it is no longer *recorded* by history/sync
//! features.

use zeroize::Zeroize;

use crate::errors::AppError;

/// Place `text` on the OS clipboard with concealment flags, then wipe the
/// argument. Pure (no vault state), so it is exercised directly by tests.
pub fn copy_secret_text_impl(mut text: String) -> Result<(), AppError> {
    let result = write_concealed(&text);
    text.zeroize();
    result
}

/// Clear the OS clipboard (the frontend's timed / on-unmount clear).
pub fn clear_clipboard_impl() -> Result<(), AppError> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| AppError::Io {
        detail: format!("clipboard open failed: {e}"),
    })?;
    clipboard.clear().map_err(|e| AppError::Io {
        detail: format!("clipboard clear failed: {e}"),
    })
}

fn write_concealed(text: &str) -> Result<(), AppError> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| AppError::Io {
        detail: format!("clipboard open failed: {e}"),
    })?;
    let set = clipboard.set();
    #[cfg(target_os = "windows")]
    let set = {
        use arboard::SetExtWindows as _;
        set.exclude_from_history().exclude_from_monitoring()
    };
    #[cfg(target_os = "macos")]
    let set = {
        use arboard::SetExtApple as _;
        set.exclude_from_history()
    };
    set.text(text).map_err(|e| AppError::Io {
        detail: format!("clipboard write failed: {e}"),
    })
}

#[tauri::command]
pub fn copy_secret_text(text: String) -> Result<(), AppError> {
    copy_secret_text_impl(text)
}

#[tauri::command]
pub fn clear_clipboard() -> Result<(), AppError> {
    clear_clipboard_impl()
}
