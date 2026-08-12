//! Proves the premise the #513 conversion rests on: a `Drop`-wiping wrapper
//! runs its destructor when the stack UNWINDS, not merely when a function
//! returns normally. Without this, every conversion in the slice is unfounded.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use zeroize::Zeroize;

use secretary_core::crypto::secret::{SecretBytes, SecretString, Sensitive};

/// The witness tests below observe `Sensitive<T>`'s drop-time wipe, and only
/// `Sensitive<T>`'s. But `Sensitive` carries a minority of the #513 slice:
/// most converted sites wrap in `SecretBytes` or `SecretString`, which are
/// SEPARATE structs with their own `#[derive(Zeroize, ZeroizeOnDrop)]`.
///
/// `ZeroizeOnDrop` was, before this block, never used as a trait bound or a
/// static assertion anywhere in the tree — only inside `derive` lists. So
/// deleting it from either struct compiled clean and left the whole suite
/// green, silently un-fixing every site that relies on those two types.
/// Verified by mutation during the whole-branch review: removing it from
/// both derives kept `cargo test --release -p secretary-core` at 50/50
/// binaries passing.
///
/// This pins the derive itself. It is a compile-time check on the TRAIT, not
/// on the behaviour — `ZeroizeOnDrop` is a marker and could in principle be
/// hand-implemented without a wiping `Drop` — but combined with the derive it
/// closes the silent-removal path, which is the actual regression risk.
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<SecretBytes>();
    assert_zeroize_on_drop::<SecretString>();
    assert_zeroize_on_drop::<Sensitive<[u8; 32]>>();
};

/// A `Zeroize` payload that records whether it was zeroized, via a
/// private `Arc<AtomicBool>` handle owned separately by the test rather
/// than a process-wide `static`. `Sensitive<T>` is `ZeroizeOnDrop`, so its
/// drop glue calls `zeroize()` on the inner value — observing that call is
/// how we prove the wipe happened during the unwind.
///
/// A single shared `static WITNESS_DROPPED: AtomicBool` here would admit
/// two failure modes under `cargo test`'s default thread-parallel runner:
/// a FALSE PASS (test B resets the flag, test A's panic sets it moments
/// later on another thread, B then observes `true` and asserts its own,
/// broken mechanism worked), and a flake in the other direction (B's reset
/// lands between A's set and A's assert). Each test constructing its own
/// `Witness` — and holding the only other handle to its flag — makes that
/// cross-test channel impossible by construction rather than by discipline.
struct Witness {
    dropped: Arc<AtomicBool>,
}

impl Witness {
    /// Returns the witness plus a cloned handle to its drop flag. The
    /// witness itself is moved into the `Sensitive`/`try_build` call under
    /// test and becomes unreachable (by design — that's the panic/early-
    /// return path being exercised); the returned handle is how the test
    /// observes `zeroize()` having run after that.
    fn new() -> (Self, Arc<AtomicBool>) {
        let dropped = Arc::new(AtomicBool::new(false));
        (
            Witness {
                dropped: Arc::clone(&dropped),
            },
            dropped,
        )
    }
}

impl Zeroize for Witness {
    fn zeroize(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn sensitive_wipes_the_inner_value_when_the_stack_unwinds() {
    let (witness, dropped) = Witness::new();

    let unwound = catch_unwind(AssertUnwindSafe(move || {
        let _secret = Sensitive::new(witness);
        panic!("simulated panic inside a bridge call");
    }));

    assert!(unwound.is_err(), "the closure must actually have panicked");
    assert!(
        dropped.load(Ordering::SeqCst),
        "Sensitive's Drop must zeroize the inner value while the stack unwinds; \
         if this fails, the entire #513 conversion rests on a false premise"
    );
}

/// The negative control for every assertion in this file.
///
/// Each test above asserts "the flag became `true`". That is only evidence
/// of a wipe if the flag cannot become `true` for any other reason — so this
/// unwinds with a BARE `Witness`, not wrapped in anything, and asserts the
/// flag stays `false`. `Witness` implements `Zeroize` but not `Drop`, so
/// dropping one directly must do nothing; the only path to the flag is
/// `Sensitive`'s `ZeroizeOnDrop` glue calling `zeroize()`.
///
/// Without this, a future change that set the flag incidentally would leave
/// every test here passing while proving nothing. Same two-sided discipline
/// as the repo's hygiene guards, which all require a known-negative control
/// alongside the known-positive one.
#[test]
fn a_bare_witness_unwinding_does_not_set_the_flag() {
    let (witness, dropped) = Witness::new();

    let unwound = catch_unwind(AssertUnwindSafe(move || {
        let _bare = witness;
        panic!("simulated panic with no Sensitive wrapper in scope");
    }));

    assert!(unwound.is_err(), "the closure must actually have panicked");
    assert!(
        !dropped.load(Ordering::SeqCst),
        "a bare Witness must NOT set its own flag — if this fails, the wipe \
         assertions in this file are vacuous and prove nothing about Sensitive"
    );
}

#[test]
fn try_build_wipes_when_the_fill_closure_panics() {
    let (witness, dropped) = Witness::new();

    let unwound = catch_unwind(AssertUnwindSafe(move || {
        let _r: Result<Sensitive<Witness>, ()> = Sensitive::try_build(witness, |_slot| {
            panic!("simulated panic partway through filling the slot");
        });
    }));

    assert!(
        unwound.is_err(),
        "the fill closure must actually have panicked"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "try_build must wrap BEFORE filling, so a panic inside the fill still wipes"
    );
}

#[test]
fn try_build_wipes_when_the_fill_closure_returns_err() {
    let (witness, dropped) = Witness::new();

    let r: Result<Sensitive<Witness>, &'static str> =
        Sensitive::try_build(witness, |_slot| Err("fill failed"));

    assert_eq!(r.err(), Some("fill failed"));
    assert!(
        dropped.load(Ordering::SeqCst),
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
