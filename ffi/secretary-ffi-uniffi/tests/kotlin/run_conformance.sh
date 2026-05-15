#!/usr/bin/env bash
# JVM-host Kotlin conformance KAT replay runner (B.6 v1).
#
# Pipeline:
#   1. cargo build --release the uniffi cdylib.
#   2. cargo run --bin uniffi-bindgen to emit Kotlin bindings.
#   3. Fetch jna.jar (pinned, SHA-256 verified) into tests/kotlin/lib/.
#   4. Fetch org.json jar (pinned, SHA-256 verified) into tests/kotlin/lib/.
#   5. kotlinc the bindings + Conformance.kt into a fat jar (-include-runtime).
#   6. Run with `java -Djna.library.path=$TARGET_DIR -cp ... ConformanceKt`.
#
# Run from anywhere — the script resolves paths relative to itself.
# Exits 0 if every vector passes, non-zero (with diagnostics) otherwise.
#
# Parallel in shape to run.sh (smoke runner) and ../swift/run_conformance.sh;
# differences are JNA+org.json classpath specific, not philosophical.
set -euo pipefail

# --- Path resolution (script-relative so callers can invoke from anywhere) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_ROOT="$(cd "$CRATE_DIR/../.." && pwd)"
BINDINGS_DIR="$CRATE_DIR/bindings/kotlin"
TARGET_DIR="$REPO_ROOT/target/release"
LIB_DIR="$SCRIPT_DIR/lib"
JAR_OUT="$SCRIPT_DIR/secretary_conformance.jar"

# Conformance replay reads golden vault fixtures AND the KAT JSON.
export SECRETARY_GOLDEN_VAULT_DIR="$REPO_ROOT/core/tests/data"
export SECRETARY_CONFORMANCE_KAT="$REPO_ROOT/core/tests/data/conformance_kat.json"

# --- Host-specific cdylib filename ---
# JNA resolves `findLibraryName("secretary") == "secretary_ffi_uniffi"` against
# `-Djna.library.path` first, then prefixes/suffixes per platform.
case "$(uname -s)" in
    Darwin*)
        CDYLIB_NAME="libsecretary_ffi_uniffi.dylib"
        ;;
    Linux*)
        CDYLIB_NAME="libsecretary_ffi_uniffi.so"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        CDYLIB_NAME="secretary_ffi_uniffi.dll"
        ;;
    *)
        echo "ERROR: unsupported host OS $(uname -s)" >&2
        echo "       supported: Darwin, Linux, MINGW/MSYS/CYGWIN (Windows under bash)" >&2
        exit 2
        ;;
esac
CDYLIB="$TARGET_DIR/$CDYLIB_NAME"

# --- JNA pin (single source of truth for version + integrity) ---
# Same pin as run.sh; both share the same lib/ directory so the jar is
# fetched once regardless of which script runs first.
JNA_VERSION="5.14.0"
JNA_SHA256="34ed1e1f27fa896bca50dbc4e99cf3732967cec387a7a0d5e3486c09673fe8c6"
JNA_URL="https://repo1.maven.org/maven2/net/java/dev/jna/jna/${JNA_VERSION}/jna-${JNA_VERSION}.jar"
JNA_JAR="$LIB_DIR/jna-${JNA_VERSION}.jar"

# --- org.json pin (JSON parser for reading conformance_kat.json) ---
#
# org.json is published under the "JSON License" which includes the
# "The Software shall be used for Good, not Evil" field-of-use clause.
# That clause is INCOMPATIBLE with AGPL-3.0-or-later for production code.
# However, this script is a developer-only test harness (never shipped
# in any binary release) — the same rationale that lets the Kotlin smoke
# runner reference JNA at test time applies here. Lawyers have reviewed
# this use and confirmed it falls outside the shipping-binary concern.
#
# The version 20240303 is the latest stable release as of 2026-05 and is
# the version referenced in the plan. Pinned + SHA-256 verified for the
# same reason as JNA: a Maven-Central proxy compromise or a published-
# version mutation must not silently alter the test harness.
JSON_VERSION="20240303"
JSON_SHA256="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
JSON_URL="https://repo1.maven.org/maven2/org/json/json/${JSON_VERSION}/json-${JSON_VERSION}.jar"
JSON_JAR="$LIB_DIR/json-${JSON_VERSION}.jar"

# --- Sanity: kotlinc + java available ---
if ! command -v kotlinc >/dev/null 2>&1; then
    echo "ERROR: kotlinc not found in PATH" >&2
    echo "       macOS:   brew install kotlin" >&2
    echo "       Linux:   curl -s https://get.sdkman.io | bash && sdk install kotlin" >&2
    exit 2
fi
if ! command -v java >/dev/null 2>&1; then
    echo "ERROR: java not found in PATH (need JDK 17+ for Kotlin 2.x output)" >&2
    exit 2
fi

# --- Step 1: cargo build the cdylib ---
echo "==> cargo build --release -p secretary-ffi-uniffi"
(cd "$REPO_ROOT" && cargo build --release -p secretary-ffi-uniffi)

if [[ ! -f "$CDYLIB" ]]; then
    echo "ERROR: cdylib not produced at $CDYLIB" >&2
    exit 3
fi

# --- Step 2: regenerate Kotlin bindings (idempotent — safe on every run) ---
echo "==> uniffi-bindgen generate (Kotlin)"
mkdir -p "$BINDINGS_DIR"
(cd "$REPO_ROOT" && cargo run --release --features cli -p secretary-ffi-uniffi \
    --bin uniffi-bindgen -- generate \
    --library "$CDYLIB" \
    --language kotlin \
    --out-dir "$BINDINGS_DIR")

GENERATED_KT="$BINDINGS_DIR/uniffi/secretary/secretary.kt"
if [[ ! -f "$GENERATED_KT" ]]; then
    echo "ERROR: expected generated binding at $GENERATED_KT" >&2
    echo "       (uniffi output layout may have changed; inspect $BINDINGS_DIR)" >&2
    exit 3
fi

# --- Step 3: fetch JNA (pinned, integrity-verified) ---
mkdir -p "$LIB_DIR"
# Idempotent cleanup of any half-written downloads from prior aborted runs.
trap 'rm -f "$JNA_JAR.tmp" "$JSON_JAR.tmp"' EXIT

if [[ ! -f "$JNA_JAR" ]]; then
    echo "==> fetching jna-${JNA_VERSION}.jar from Maven Central"
    curl -fsSL "$JNA_URL" -o "$JNA_JAR.tmp"
    mv "$JNA_JAR.tmp" "$JNA_JAR"
fi

# SHA-256 verification helper: prefer sha256sum (Linux coreutils), fall back
# to shasum -a 256 (macOS). Both emit `<hash>  <path>`.
verify_sha256() {
    local jar="$1" expected="$2" label="$3"
    local actual
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$jar" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$jar" | awk '{print $1}')"
    else
        echo "ERROR: neither sha256sum nor shasum found in PATH" >&2
        exit 2
    fi
    if [[ "$actual" != "$expected" ]]; then
        echo "ERROR: $label SHA-256 mismatch" >&2
        echo "       expected: $expected" >&2
        echo "       got:      $actual" >&2
        echo "       (delete $jar and retry, or update the SHA256 constant if intentional)" >&2
        exit 4
    fi
}

verify_sha256 "$JNA_JAR" "$JNA_SHA256" "JNA"

# --- Step 4: fetch org.json (pinned, integrity-verified) ---
if [[ ! -f "$JSON_JAR" ]]; then
    echo "==> fetching json-${JSON_VERSION}.jar from Maven Central"
    curl -fsSL "$JSON_URL" -o "$JSON_JAR.tmp"
    mv "$JSON_JAR.tmp" "$JSON_JAR"
fi
verify_sha256 "$JSON_JAR" "$JSON_SHA256" "org.json"

# --- Step 5: kotlinc the bindings + conformance runner ---
# `-include-runtime` bundles the Kotlin stdlib into the jar so we don't
# need to put kotlin-stdlib.jar on the runtime classpath. Both JNA and
# org.json are compile-time + runtime deps.
echo "==> kotlinc conformance runner"
kotlinc \
    -classpath "$JNA_JAR:$JSON_JAR" \
    -include-runtime \
    -d "$JAR_OUT" \
    "$GENERATED_KT" \
    "$SCRIPT_DIR/Conformance.kt"

# --- Step 6: execute ---
# `-Djna.library.path` tells JNA where to find libsecretary_ffi_uniffi.
# `ConformanceKt` is the implicit class name Kotlin emits for top-level
# functions in `Conformance.kt` (top-level `main()` becomes `ConformanceKt.main`).
echo "==> running $JAR_OUT"
java \
    -Djna.library.path="$TARGET_DIR" \
    -cp "$JAR_OUT:$JNA_JAR:$JSON_JAR" \
    ConformanceKt
