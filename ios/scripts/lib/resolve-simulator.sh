#!/usr/bin/env bash
# Resolve an iOS simulator *name* to a concrete UDID. Sourced by run-ios-tests.sh
# and run-ios-tsan.sh so the resolution logic lives in exactly one place.
#
# Usage:  source .../lib/resolve-simulator.sh; SIM_ID="$(resolve_simulator 'iPhone 16')"
# Echoes the UDID on stdout. On no match it prints the available-device list to
# stderr and returns 2 — the caller, under `set -e` with command substitution,
# aborts. (Bash note: `SIM_ID="$(resolve_simulator …)"` does propagate a non-zero
# return under `set -e`.)
resolve_simulator() {
    local sim_name="$1"
    local devices sim_id
    # Capture the device list ONCE: a genuine `simctl` failure aborts here under
    # `set -e` rather than being swallowed by the `|| true` below and misreported
    # as a missing device. The `|| true` then guards ONLY the grep pipeline, where
    # a no-match is legitimately empty.
    devices="$(xcrun simctl list devices available)"
    # Anchor the match to "<name> (" so "iPhone 16" does not also match
    # "iPhone 16 Pro" / "iPhone 16 Plus" / "iPhone 16e". `head -1` takes the first
    # matching device regardless of runtime (simctl groups by runtime); it assumes
    # every installed runtime is >= the Package.swift deployment floor (iOS 17).
    # NB: $sim_name is interpolated into an ERE — fine for real device names, which
    # contain no regex metacharacters.
    sim_id="$(printf '%s\n' "$devices" \
        | grep -E "^[[:space:]]*${sim_name} \(" \
        | head -1 \
        | grep -oE '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}' || true)"
    if [[ -z "$sim_id" ]]; then
        echo "ERROR: no available simulator named '$sim_name'. Available devices:" >&2
        printf '%s\n' "$devices" >&2
        echo "Set IOS_SIM to one of the device names listed above." >&2
        return 2
    fi
    printf '%s\n' "$sim_id"
}
