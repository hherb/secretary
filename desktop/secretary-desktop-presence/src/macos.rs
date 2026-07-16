//! macOS Touch ID via LocalAuthentication. The ONLY `unsafe` in the codebase.
//!
//! Policy is `DeviceOwnerAuthenticationWithBiometrics` (Touch ID only — never
//! the account passcode, which would muddy the "Use Password" fallback story).
//! `evaluatePolicy:localizedReason:reply:` is asynchronous with a completion
//! block; we bridge it to a synchronous return over an mpsc channel so the
//! public `evaluate()` blocks until the outcome is known. The caller
//! (`authenticate_presence`) runs this off the async runtime via
//! `spawn_blocking`, so blocking here never stalls Tauri.

use std::sync::mpsc;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

use crate::{classify, PresenceAvailability, PresenceOutcome};

/// The fallback button title shown on the sheet. Tapping it yields
/// `LAError.userFallback` → `PresenceOutcome::Fallback` → password dialog.
const FALLBACK_TITLE: &str = "Use Password";

pub(crate) fn availability() -> PresenceAvailability {
    // SAFETY: `LAContext` is a plain NSObject subclass constructible from any
    // thread (`AnyThread`); `new` has no other preconditions.
    let context = unsafe { LAContext::new() };
    // SAFETY: no preconditions beyond a live context. objc2 converts the
    // ObjC `BOOL` + trailing `NSError**` out-param into a `Result`.
    let can = unsafe {
        context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
    };
    match can {
        Ok(()) => PresenceAvailability::Available,
        // Distinguish "no biometric enrolled" from "no hardware / disabled".
        Err(err) if err.code() as i64 == crate::LA_ERROR_BIOMETRY_NOT_ENROLLED => {
            PresenceAvailability::NotEnrolled
        }
        Err(_) => PresenceAvailability::NotAvailable,
    }
}

pub(crate) fn evaluate(reason: &str) -> PresenceOutcome {
    // LocalAuthentication raises NSInvalidArgumentException on an empty
    // localizedReason (documented: "must not be empty"), which would abort
    // the process rather than surface an error. Fail safe to the password
    // path instead — same direction as every other unusable-biometry case.
    if reason.is_empty() {
        return PresenceOutcome::Unavailable;
    }

    // SAFETY: see `availability` — `new` is preconditionless and AnyThread.
    let context = unsafe { LAContext::new() };
    // SAFETY: plain setter of a copied NSString property; no preconditions.
    unsafe {
        context.setLocalizedFallbackTitle(Some(&NSString::from_str(FALLBACK_TITLE)));
    }

    let (tx, rx) = mpsc::channel::<Result<(), i64>>();
    let reason_ns = NSString::from_str(reason);

    // Completion block: (success: Bool, error: *mut NSError) → Result<(), i64>,
    // sent over the channel. `RcBlock` heap-allocates and refcounts the
    // closure so the framework can retain it past this frame; the send is the
    // synchronization point back to the blocked `recv` below.
    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        let result = if success.as_bool() {
            Ok(())
        // SAFETY: on failure the framework passes either nil or a pointer to
        // a live autoreleased NSError, valid for the duration of the block
        // invocation; we only read `code()` inside that window.
        } else if let Some(err) = unsafe { error.as_ref() } {
            Err(err.code() as i64)
        } else {
            // Failure with no error object: 0 is not a mapped LAError code,
            // so `classify` fails safe to `Unavailable` (password path).
            Err(0)
        };
        // The receiver outlives every send: `evaluate` cannot return before
        // `recv` yields. A send error is therefore unreachable; ignore it.
        let _ = tx.send(result);
    });

    // SAFETY: `context` and `reason_ns` are alive for the duration of the
    // call; the reply block is refcounted (`RcBlock`), so the framework's
    // retained copy outlives this frame even though evaluation completes
    // asynchronously on a private queue.
    unsafe {
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
            &reason_ns,
            &reply,
        );
    }

    // Block until the completion block fires. A disconnected channel (the
    // framework dropped the block without ever calling it) fails safe.
    let outcome = match rx.recv() {
        Ok(result) => classify(result),
        Err(_) => PresenceOutcome::Unavailable,
    };
    // Keep the context alive until AFTER the reply: deallocating an LAContext
    // invalidates it, which would cancel an in-flight evaluation. Explicit
    // drop pins that ordering against future refactors.
    drop(context);
    outcome
}
