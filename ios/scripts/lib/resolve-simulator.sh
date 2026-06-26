#!/usr/bin/env bash
# Resolve an iOS simulator *name* to a concrete UDID. Sourced by run-ios-tests.sh
# and run-ios-tsan.sh so the resolution logic lives in exactly one place.
#
# Usage:  source .../lib/resolve-simulator.sh; SIM_ID="$(resolve_simulator 'iPhone 17')"
# Echoes the UDID on stdout. If the named device is absent it falls back to the
# first available iPhone (Apple rotates the simulators bundled with each runner
# image, so a hard-pin breaks CI on every image bump) and logs a WARN to stderr so
# the drift stays visible. Only when NO iPhone simulator exists at all does it
# print the available-device list to stderr and return 2 — the caller, under
# `set -e` with command substitution, aborts. (Bash note: `SIM_ID="$(resolve_simulator …)"`
# does propagate a non-zero return under `set -e`.)
resolve_simulator() {
    local sim_name="$1"
    local devices sim_id
    # The UUID shape printed by `simctl list devices` (e.g. "iPhone 17 (UDID) (Shutdown)").
    local uuid_re='[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'
    # Capture the device list ONCE: a genuine `simctl` failure aborts here under
    # `set -e` rather than being swallowed by the `|| true` below and misreported
    # as a missing device. The `|| true` then guards ONLY the grep pipeline, where
    # a no-match is legitimately empty.
    devices="$(xcrun simctl list devices available)"
    # Anchor the match to "<name> (" so "iPhone 17" does not also match
    # "iPhone 17 Pro" / "iPhone 17 Plus" / "iPhone 17e". `head -1` takes the first
    # matching device regardless of runtime (simctl groups by runtime); it assumes
    # every installed runtime is >= the Package.swift deployment floor (iOS 17).
    # NB: $sim_name is interpolated into an ERE — fine for real device names, which
    # contain no regex metacharacters.
    sim_id="$(printf '%s\n' "$devices" \
        | grep -E "^[[:space:]]*${sim_name} \(" \
        | head -1 \
        | grep -oE "$uuid_re" || true)"
    if [[ -z "$sim_id" ]]; then
        # Named device not on this runner image: fall back to the first available
        # iPhone (any model/runtime) rather than hard-failing. The "iPhone " prefix
        # (note the trailing space) excludes iPads; every installed runtime is
        # assumed >= the iOS 17 deployment floor, as above.
        sim_id="$(printf '%s\n' "$devices" \
            | grep -E "^[[:space:]]*iPhone .* \(" \
            | head -1 \
            | grep -oE "$uuid_re" || true)"
        if [[ -n "$sim_id" ]]; then
            echo "WARN: simulator '$sim_name' not available on this host; falling back to" >&2
            echo "      the first available iPhone ($sim_id). Set IOS_SIM to pin a device." >&2
        fi
    fi
    if [[ -z "$sim_id" ]]; then
        echo "ERROR: no iPhone simulator available (requested '$sim_name'). Available devices:" >&2
        printf '%s\n' "$devices" >&2
        echo "Set IOS_SIM to one of the device names listed above." >&2
        return 2
    fi
    printf '%s\n' "$sim_id"
}
