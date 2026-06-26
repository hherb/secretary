#!/usr/bin/env bash
#
# check-lean-binding.sh — assert the lean mobile-binding feature boundary (#189).
#
# WHY THIS EXISTS
# ---------------
# `secretary-cli`'s `daemon` feature gates the headless-sync deps — `notify`
# (inotify/FSEvents/kqueue file watching) and `clap` (CLI arg parsing), among
# others. `secretary-ffi-bridge` depends on `secretary-cli` with
# `default-features = false`, deliberately keeping those deps out of the bridge
# and the two mobile bindings beneath it (`secretary-ffi-uniffi`,
# `secretary-ffi-py`). See `cli/Cargo.toml`'s `[features] daemon` and
# `docs/superpowers/specs/2026-06-26-lean-binding-ci-guard-189-design.md`.
#
# This "lean binding" property is build-context-dependent: under
# `cargo test --workspace`, Cargo unifies `daemon` ON for the bridge (the
# `secretary-sync` bin in the same package requires it). The guarantee only
# holds for the `-p`-scoped, `--no-default-features` resolution that excludes
# the bin target — which is exactly the context in which the shipped cdylib/.so
# is built. Nothing else in-repo prevents a future dependency edit from silently
# re-pulling `notify`/`clap` into the binding tree. This script is that tripwire.
#
# USAGE
# -----
#   bash ffi/scripts/check-lean-binding.sh              # guard the 3 binding crates
#   bash ffi/scripts/check-lean-binding.sh --self-test  # prove the matcher fires
#
# Exit 0 when every guarded crate's normal-edge dependency tree is free of the
# forbidden deps; exit non-zero (with the offending lines printed) otherwise.

set -euo pipefail

# Forbidden runtime deps, as a single line-anchored regex over `--prefix none`
# output (each line is `<pkg> v<x.y.z>`). One source of truth — do not scatter
# these literals. Anchored at line start so a crate merely *named* like these
# inside a path/description cannot trip it.
readonly FORBIDDEN_RE='^(clap|notify) '

# The binding crates that must stay lean. Order: outermost (mobile) first.
readonly GUARDED_CRATES=(
  secretary-ffi-uniffi
  secretary-ffi-py
  secretary-ffi-bridge
)

# A crate whose default features DO pull the forbidden deps — used by
# --self-test as a positive control so the matcher can never silently become
# vacuous (the #231 lesson: a "zero warnings" bar that checked nothing).
readonly POSITIVE_CONTROL_CRATE=secretary-cli

# Print the forbidden deps present on a crate's normal-edge tree, one per line
# (empty output ⇒ clean). `--no-default-features` matches the shipping context;
# `-e normal` scopes to linked/runtime edges (the deps that land in the
# artifact); `--prefix none` strips box-drawing chars so the anchor is robust.
forbidden_deps_in() {
  local crate=$1
  shift
  # grep returns 1 on no-match; that is the clean (success) case here, so
  # tolerate it without tripping `set -e` / `pipefail`.
  cargo tree -p "$crate" -e normal --prefix none "$@" 2>/dev/null \
    | { grep -E "$FORBIDDEN_RE" || true; }
}

run_guard() {
  local crate matches failed=0
  for crate in "${GUARDED_CRATES[@]}"; do
    matches=$(forbidden_deps_in "$crate" --no-default-features)
    if [[ -n "$matches" ]]; then
      echo "FAIL: forbidden daemon dep(s) reached $crate:" >&2
      while IFS= read -r line; do echo "    $line" >&2; done <<<"$matches"
      failed=1
    else
      echo "ok: $crate is lean (no clap/notify on normal edges)"
    fi
  done
  if (( failed )); then
    echo "" >&2
    echo "The lean mobile-binding boundary regressed. A dependency edit pulled" >&2
    echo "clap/notify into a binding tree. See cli/Cargo.toml [features] daemon." >&2
    return 1
  fi
  echo "All ${#GUARDED_CRATES[@]} binding crates are lean."
}

# Positive control: the matcher MUST flag both forbidden deps in the control
# crate built with default features. If it does not, the matcher is broken or
# the control crate changed — fail loudly rather than ship a vacuous guard.
run_self_test() {
  local matches
  # Default features (daemon ON) — note: no --no-default-features here.
  matches=$(forbidden_deps_in "$POSITIVE_CONTROL_CRATE")
  local missing=0 dep
  for dep in clap notify; do
    if ! grep -qE "^${dep} " <<<"$matches"; then
      echo "SELF-TEST FAIL: matcher did not flag '$dep' in $POSITIVE_CONTROL_CRATE" >&2
      missing=1
    fi
  done
  if (( missing )); then
    echo "The guard's matcher is not detecting known-present deps; it would be" >&2
    echo "vacuous. Refusing to vouch for the lean-binding check." >&2
    return 1
  fi
  echo "self-test ok: matcher flags clap+notify in $POSITIVE_CONTROL_CRATE (positive control)"
}

main() {
  case "${1:-}" in
    --self-test) run_self_test ;;
    "") run_guard ;;
    *)
      echo "usage: $0 [--self-test]" >&2
      return 2
      ;;
  esac
}

main "$@"
