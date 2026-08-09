#!/usr/bin/env bash
# Assert the bridge's `test-support` feature is enabled ONLY from a
# [dev-dependencies] section (#500).
#
# `Detail::for_test` can mint a `Detail` from a runtime String. It is absent
# from non-test builds ONLY because resolver v2 declines to unify a
# DEV-dependency's features into them. Enabling the feature on a NORMAL
# dependency line puts the hatch into the shipped artifact, and nothing else
# in CI would notice. That single line is what this guard denies.
set -euo pipefail

readonly FEATURE="test-support"
readonly DEV_SECTION="dev-dependencies"

if [ "${1:-}" = "--self-test" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/good" "$tmp/bad"
    cat > "$tmp/good/Cargo.toml" <<'TOML'
[dev-dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
TOML
    cat > "$tmp/bad/Cargo.toml" <<'TOML'
[dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
TOML
    if "$0" "$tmp/good" >/dev/null 2>&1; then :; else
        echo "SELF-TEST FAIL: known-negative control was DENIED"; exit 1; fi
    if "$0" "$tmp/bad" >/dev/null 2>&1; then
        echo "SELF-TEST FAIL: known-positive control was NOT denied"; exit 1; fi
    echo "test-support placement self-test: OK (2/2 controls)"
    exit 0
fi

# Print every manifest section that enables $FEATURE, as "<file>:<section>".
scan() {
    local root="$1"
    find "$root" -name Cargo.toml -not -path '*/target/*' -print0 |
    while IFS= read -r -d '' f; do
        awk -v feat="$FEATURE" -v file="$f" '
            /^\[/ { section = $0; gsub(/[][]/, "", section) }
            index($0, feat) && index($0, "features") { print file ":" section }
        ' "$f"
    done
}

fail=0
while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    section="${hit##*:}"
    case "$section" in
        *"$DEV_SECTION"*) ;;
        *) echo "DENIED: $hit — '$FEATURE' may only be enabled from [$DEV_SECTION]"; fail=1 ;;
    esac
done < <(scan "${1:-.}")

[ "$fail" -eq 0 ] && echo "test-support placement: OK"
exit "$fail"
