//! macOS Touch ID via LocalAuthentication. The ONLY `unsafe` in the codebase.
//!
//! Policy is `DeviceOwnerAuthenticationWithBiometrics` (Touch ID only — never
//! the account passcode, which would muddy the "Use Password" fallback story).
//! Deliberately NOT `…WithBiometricsOrWatch`: an Apple Watch approval is a
//! weaker proximity proof than a fingerprint, so clamshell-mode users fall to
//! the password dialog for now — widening to Watch is a product decision
//! deferred to the on-hardware follow-up (#442), not an omission.
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

/// Identity fn whose only job is the `Send` bound: the LocalAuthentication
/// reply block is invoked on a private framework queue (a different thread
/// from the constructing one), so every capture must be `Send` — route the
/// closure through here and the compiler enforces it.
fn require_send<F: Send>(f: F) -> F {
    f
}

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
    //
    // Send-soundness precondition: the framework invokes this block on a
    // private framework queue, i.e. on a different thread from the one that
    // constructed it — but `RcBlock::new` does NOT statically require the
    // closure to be `Send`. `require_send` makes the compiler enforce that
    // precondition: a future non-`Send` capture fails to build instead of
    // relying on a hand re-audit.
    let reply = RcBlock::new(require_send(move |success: Bool, error: *mut NSError| {
        let result = if success.as_bool() {
            Ok(())
        // SAFETY: on failure the framework passes either nil or a pointer to
        // a live autoreleased NSError, valid for the duration of the block
        // invocation; we only read `code()` inside that window.
        } else if let Some(err) = unsafe { error.as_ref() } {
            Err(err.code() as i64)
        } else {
            // Failure with no error object: the sentinel is not a mapped
            // LAError code (all real ones are negative), so `classify` fails
            // safe to `Unavailable` (password path).
            Err(crate::LA_ERROR_NONE_SENTINEL)
        };
        // The receiver outlives the FIRST send: `evaluate` cannot return
        // before `recv` yields. A send can still fail if the framework
        // invokes the block twice — the second send finds the receiver
        // already dropped — and that is exactly the case we want to ignore.
        let _ = tx.send(result);
    }));

    // TEMPORARY #442 on-hardware-proof instrumentation — REMOVE BEFORE MERGE.
    // This line firing is the evidence that evaluatePolicy was invoked; its
    // ABSENCE during a toggle-OFF gated write is the toggle-OFF proof.
    eprintln!("[#442-proof] evaluatePolicy: presenting Touch ID sheet (reason={reason:?})");

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
    // TEMPORARY #442 on-hardware-proof instrumentation — REMOVE BEFORE MERGE.
    // Logs the classified outcome so each proof scenario (authenticated /
    // cancelled / fallback) is log-correlated with what the user saw.
    eprintln!("[#442-proof] evaluatePolicy outcome: {outcome:?}");
    // Keep OUR strong reference to the context alive until AFTER the reply:
    // dropping releases the reference (the context deallocates — and thereby
    // invalidates, cancelling any in-flight evaluation — only if ours was the
    // last). Holding it past `recv` guarantees we never trigger that
    // invalidation while an evaluation is in flight; the explicit drop pins
    // the ordering against future refactors.
    drop(context);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_reason_fails_safe_to_unavailable() {
        // The empty-reason guard precedes every objc2 call, so this never
        // presents UI — safe to run on any macOS host, headless included.
        assert_eq!(evaluate(""), PresenceOutcome::Unavailable);
    }
}
