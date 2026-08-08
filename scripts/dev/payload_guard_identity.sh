#!/usr/bin/env bash
# Dev-only: capture a deterministic transcript of the error-payload guard's
# OBSERVABLE BEHAVIOUR, for proving the #486 package split is inert.
#
# This script is deliberately NOT wired into CI. It is a manual diagnostic
# tool: a human (or Task 5's automated diff) runs it by hand before and after
# moving code, then diffs the two transcripts. Its absence from any workflow
# file is intentional, not an oversight.
#
# A green self-test is NOT sufficient evidence for code motion: it would stay
# green if a whole rule silently stopped running. This transcript additionally
# plants one violation per rule into a scratch copy of the tree and records
# the guard's full stderr — exercising the finding formatter, line numbers,
# allowlist keys and rule routing.
#
# SCOPE, stated precisely (#496 review): the plants below cover rules E1-E5
# across all FOUR scan roots. They do NOT cover the discovery/withdrawal
# tiers, the allowlist-matching path, or any individual rule ARM — a
# mutation to `foreign_use_names`' withdrawal pass, for instance, leaves
# every line of this transcript byte-identical. Read it as "each rule is
# still wired to each root it applies to", not as proof of identity.
#
# Until #496 it planted E1-E4 only, and nothing in either wrapper root — so
# it could not have detected E5 being switched off, nor a wrapper root
# dropping out of SCAN_ROOTS, which were two of that review's findings.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:?usage: payload_guard_identity.sh <outfile>}"
GUARD="scripts/check-error-payload-hygiene.py"

# Plant one violation per rule. Paths are relative to a scratch tree copy.
# E1: a core variant interpolating a runtime String.
PLANT_E1_FILE="core/src/zz_identity_probe.rs"
PLANT_E1='#[derive(thiserror::Error, Debug)]
pub enum ZzIdentityProbe {
    #[error("planted E1: {leak}")]
    Leak { leak: String },
}
'
# E2: a bridge declaration with an ungated String field.
PLANT_E2_FILE="ffi/secretary-ffi-bridge/src/zz_identity_probe.rs"
PLANT_E2='#[derive(thiserror::Error, Debug)]
pub enum ZzProbeError {
    #[error("planted E2")]
    Leak { not_a_gated_name: String },
}
'
# E3: a gated field built from an unsanctioned expression.
PLANT_E3_FILE="ffi/secretary-ffi-bridge/src/zz_identity_probe_e3.rs"
PLANT_E3='fn zz_probe(e: &std::io::Error) -> crate::error::vault::FfiVaultError {
    crate::error::vault::FfiVaultError::CorruptVault { detail: format!("planted E3: {e}") }
}
'
# E4: an impl GatedDetail outside detail.rs.
PLANT_E4_FILE="ffi/secretary-ffi-bridge/src/zz_identity_probe_e4.rs"
PLANT_E4='impl crate::error::detail::GatedDetail for secretary_core::vault::VaultError {}
'
# E5 (#496): a format! outside a wrapper crate's own detail.rs. Wrapper-only
# rule, so this is also the ONLY plant that proves the ffi-py root is being
# scanned at all.
PLANT_E5_FILE="ffi/secretary-ffi-py/src/zz_identity_probe_e5.rs"
PLANT_E5='pub fn zz_probe(a: &str) -> String {
    format!("planted E5: {a}")
}
'
# E3 in the OTHER wrapper root (#496): proves ffi-uniffi is scanned too, and
# that the wrapper roots take E3 as well as E5.
PLANT_E3W_FILE="ffi/secretary-ffi-uniffi/src/zz_identity_probe_e3w.rs"
PLANT_E3W='fn zz_probe(s: &str) -> crate::error::vault::FfiVaultError {
    crate::error::vault::FfiVaultError::CorruptVault { detail: s.to_owned() }
}
'

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
# Copy only what the guard reads, so the transcript is fast and stable.
mkdir -p "$scratch/scripts" "$scratch/core" "$scratch/ffi"
cp -R "$REPO_ROOT/scripts/." "$scratch/scripts/"
cp -R "$REPO_ROOT/core/src" "$scratch/core/src"
cp -R "$REPO_ROOT/ffi/." "$scratch/ffi/"

{
  echo "=== self-test ==="
  set +e
  out="$(cd "$scratch" && uv run "$GUARD" --self-test 2>&1)"
  rc=$?
  set -e
  printf '%s\n' "$out"
  echo "exit=$rc"

  echo "=== real scan, clean tree ==="
  set +e
  out="$(cd "$scratch" && uv run "$GUARD" 2>&1)"
  rc=$?
  set -e
  printf '%s\n' "$out"
  echo "exit=$rc"

  printf '%s' "$PLANT_E1" > "$scratch/$PLANT_E1_FILE"
  printf '%s' "$PLANT_E2" > "$scratch/$PLANT_E2_FILE"
  printf '%s' "$PLANT_E3" > "$scratch/$PLANT_E3_FILE"
  printf '%s' "$PLANT_E4" > "$scratch/$PLANT_E4_FILE"
  printf '%s' "$PLANT_E5" > "$scratch/$PLANT_E5_FILE"
  printf '%s' "$PLANT_E3W" > "$scratch/$PLANT_E3W_FILE"

  echo "=== real scan, six planted violations (E1-E5, all four roots) ==="
  set +e
  out="$(cd "$scratch" && uv run "$GUARD" 2>&1)"
  rc=$?
  set -e
  printf '%s\n' "$out"
  echo "exit=$rc"
} > "$OUT"

echo "wrote $OUT ($(wc -l < "$OUT") lines)"
