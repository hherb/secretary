#!/usr/bin/env bash
#
# Install the GTK3/WebKitGTK dev libraries the Tauri desktop crate
# (`secretary-desktop`) needs to compile on Linux CI runners, wrapped in a
# bounded retry with a per-attempt `timeout`.
#
# Why (#427): during PR #426's CI the plain `apt-get update && apt-get install`
# step hung ~30 min on a transient apt mirror / dpkg-lock blip and only died at
# the job-level `timeout-minutes` cap; a re-run passed in minutes. A per-attempt
# `timeout` + retry recovers from a transient blip in seconds, while a genuine
# (all-attempts) outage still fails the step RED — it must never
# green-with-missing-deps into an opaque downstream build break.
#
# Shared by all three workspace-compiling Linux CI legs (test.yml rust-test,
# rust-lint.yml clippy + doc) so the hardening cannot drift between them.
#
# Usage:
#   bash .github/scripts/install-tauri-linux-deps.sh               # real install
#   RETRY_SLEEP=0 bash .github/scripts/install-tauri-linux-deps.sh --self-test
#       # no apt; proves fail-red-on-outage + transient recovery
set -euo pipefail

# --- Tunables (named, not inline magic numbers; env-overridable for the self-test) ---
readonly MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"           # total apt tries before the step fails red
readonly UPDATE_TIMEOUT="${UPDATE_TIMEOUT:-120}"     # seconds — cap a hung `apt-get update`
readonly INSTALL_TIMEOUT="${INSTALL_TIMEOUT:-300}"   # seconds — cap a hung `apt-get install`
readonly RETRY_SLEEP="${RETRY_SLEEP:-15}"            # seconds between attempts

# GTK3 / WebKitGTK dev libs required to compile the Tauri desktop crate.
readonly PACKAGES=(
  libwebkit2gtk-4.1-dev
  libgtk-3-dev
  libayatana-appindicator3-dev
  librsvg2-dev
)

# Run "$@" up to MAX_ATTEMPTS times. Returns 0 on first success; between failed
# tries emits a ::warning:: and sleeps RETRY_SLEEP (skipped after the last try);
# emits a ::error:: and returns 1 if every attempt fails. The command runs as an
# `if` condition, so `set -e` is suppressed inside it — the post-loop `return 1`
# is the SOLE failure exit, closing the "last sleep succeeds → step greens" trap
# a naive `... && break` loop leaves open.
run_with_retries() {
  local attempt
  for (( attempt = 1; attempt <= MAX_ATTEMPTS; attempt++ )); do
    if "$@"; then
      return 0
    fi
    echo "::warning::apt attempt ${attempt}/${MAX_ATTEMPTS} failed or timed out"
    if (( attempt < MAX_ATTEMPTS )); then
      sleep "${RETRY_SLEEP}"
    fi
  done
  echo "::error::Tauri Linux dependency install failed after ${MAX_ATTEMPTS} attempts"
  return 1
}

# One apt attempt: refresh indices then install, each under its own `timeout`.
#
# The leading `dpkg --configure -a` is a bounded, best-effort repair: if a
# *prior* attempt's `apt-get install` was killed mid-transaction by its
# `timeout`, dpkg is left interrupted and the next `apt-get install` aborts
# ("dpkg was interrupted; run dpkg --configure -a") — a state the plain retry
# could not clear on its own. It is a no-op (exit 0, instant) on a healthy
# runner, so it costs nothing on the common path. `|| true` keeps it from being
# the attempt's exit status: the `&&` chain below stays the SOLE result, so the
# fail-red invariant is unchanged — a genuine outage still returns non-zero.
apt_install() {
  sudo timeout "${INSTALL_TIMEOUT}" dpkg --configure -a || true
  sudo timeout "${UPDATE_TIMEOUT}" apt-get update \
    && sudo timeout "${INSTALL_TIMEOUT}" apt-get install -y --no-install-recommends "${PACKAGES[@]}"
}

# Prove the retry logic without touching apt so a green guard is never vacuous
# (mirrors ffi/scripts/check-lean-binding.sh --self-test; #231).
self_test() {
  # (a) An always-failing command must exhaust retries and return non-zero.
  if run_with_retries false; then
    echo "SELF-TEST FAIL: all-failing command unexpectedly returned success"
    exit 1
  fi
  echo "SELF-TEST ok: all-failing command exhausted ${MAX_ATTEMPTS} attempts and failed red"

  # (b) A fail-once-then-succeed command must recover and return 0.
  local tries=0
  fail_then_succeed() {
    tries=$(( tries + 1 ))
    [ "${tries}" -ge 2 ]   # false on try 1, true on try 2+
  }
  if run_with_retries fail_then_succeed; then
    echo "SELF-TEST ok: transient failure recovered on retry (took ${tries} tries)"
  else
    echo "SELF-TEST FAIL: transient-failure command should have recovered"
    exit 1
  fi

  echo "SELF-TEST: all cases passed"
}

main() {
  if [[ "${1:-}" == "--self-test" ]]; then
    self_test
    return 0
  fi
  run_with_retries apt_install
}

main "$@"
