//! Proves the premise the #513 conversion rests on: a `Drop`-wiping wrapper
//! runs its destructor when the stack UNWINDS, not merely when a function
//! returns normally. Without this, every conversion in the slice is unfounded.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize;

use secretary_core::crypto::secret::Sensitive;

static WITNESS_DROPPED: AtomicBool = AtomicBool::new(false);

/// A `Zeroize` payload that records whether it was zeroized. `Sensitive<T>`
/// is `ZeroizeOnDrop`, so its drop glue calls `zeroize()` on the inner value —
/// observing that call is how we prove the wipe happened during the unwind.
#[derive(Default)]
struct Witness {
    wiped: bool,
}

impl Zeroize for Witness {
    fn zeroize(&mut self) {
        self.wiped = true;
        WITNESS_DROPPED.store(true, Ordering::SeqCst);
    }
}

#[test]
fn sensitive_wipes_the_inner_value_when_the_stack_unwinds() {
    WITNESS_DROPPED.store(false, Ordering::SeqCst);

    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _secret = Sensitive::new(Witness::default());
        panic!("simulated panic inside a bridge call");
    }));

    assert!(unwound.is_err(), "the closure must actually have panicked");
    assert!(
        WITNESS_DROPPED.load(Ordering::SeqCst),
        "Sensitive's Drop must zeroize the inner value while the stack unwinds; \
         if this fails, the entire #513 conversion rests on a false premise"
    );
}

#[test]
fn try_build_wipes_when_the_fill_closure_panics() {
    WITNESS_DROPPED.store(false, Ordering::SeqCst);

    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _r: Result<Sensitive<Witness>, ()> =
            Sensitive::try_build(Witness::default(), |_slot| {
                panic!("simulated panic partway through filling the slot");
            });
    }));

    assert!(
        unwound.is_err(),
        "the fill closure must actually have panicked"
    );
    assert!(
        WITNESS_DROPPED.load(Ordering::SeqCst),
        "try_build must wrap BEFORE filling, so a panic inside the fill still wipes"
    );
}

#[test]
fn try_build_wipes_when_the_fill_closure_returns_err() {
    WITNESS_DROPPED.store(false, Ordering::SeqCst);

    let r: Result<Sensitive<Witness>, &'static str> =
        Sensitive::try_build(Witness::default(), |_slot| Err("fill failed"));

    assert_eq!(r.err(), Some("fill failed"));
    assert!(
        WITNESS_DROPPED.load(Ordering::SeqCst),
        "the partially-filled slot must be wiped on the error path too"
    );
}

#[test]
fn build_runs_the_fill_and_the_writes_land() {
    let mut rng_bytes = [0u8; 32];
    getrandom_fill(&mut rng_bytes);

    let secret = Sensitive::build([0u8; 32], |slot| slot.copy_from_slice(&rng_bytes));

    assert_eq!(
        secret.expose(),
        &rng_bytes,
        "build's closure writes must reach the wrapped value"
    );
}

#[test]
fn try_build_ok_path_returns_the_filled_value() {
    let mut rng_bytes = [0u8; 32];
    getrandom_fill(&mut rng_bytes);

    let secret: Sensitive<[u8; 32]> = Sensitive::try_build([0u8; 32], |slot| -> Result<(), ()> {
        slot.copy_from_slice(&rng_bytes);
        Ok(())
    })
    .expect("an Ok fill yields a Sensitive");

    assert_eq!(secret.expose(), &rng_bytes);
}

/// Runtime-random test bytes. Hardcoded literal key material trips CodeQL,
/// so tests in this repo always draw at runtime.
///
/// Adapted from the task brief's `rand::rngs::OsRng` + `rand::RngCore`
/// (rand 0.9 dev-dependency): in the resolved `rand_core` 0.9, `OsRng`
/// implements only `TryRngCore`, not `RngCore`, so `.fill_bytes()` isn't
/// directly callable on it. `secretary-core` already depends on
/// `rand_core = "0.6"` as a normal (non-dev) dependency, whose `OsRng`
/// implements `RngCore` directly — the same idiom every other test in
/// `core/tests/` already uses (e.g. `share_block.rs`).
fn getrandom_fill(buf: &mut [u8; 32]) {
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(buf);
}
