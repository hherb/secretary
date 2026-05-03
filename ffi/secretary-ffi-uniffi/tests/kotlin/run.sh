#!/usr/bin/env bash
# JVM-host Kotlin smoke runner for the secretary uniffi bindings.
#
# Pipeline:
#   1. cargo build --release the uniffi cdylib.
#   2. cargo run --bin uniffi-bindgen to emit Kotlin bindings.
#   3. Fetch jna.jar (pinned, SHA-256 verified) into tests/kotlin/lib/.
#   4. kotlinc the bindings + Main.kt into a fat jar (-include-runtime).
#   5. Run with `java -Djna.library.path=$TARGET_DIR -cp ... MainKt`.
#
# Run from anywhere — the script resolves paths relative to itself.
# Exits 0 if every assertion passes, non-zero (with diagnostics) otherwise.
#
# Parallel in shape to ../swift/run.sh; differences are JNA-classpath
# specific, not philosophical.
set -euo pipefail

# --- Path resolution (script-relative so callers can invoke from anywhere) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_ROOT="$(cd "$CRATE_DIR/../.." && pwd)"
BINDINGS_DIR="$CRATE_DIR/bindings/kotlin"
TARGET_DIR="$REPO_ROOT/target/release"
LIB_DIR="$SCRIPT_DIR/lib"
JAR_OUT="$SCRIPT_DIR/secretary_smoke.jar"

# --- Host-specific cdylib filename (cargo emits different conventions per OS) ---
# JNA resolves `findLibraryName("secretary") == "secretary_ffi_uniffi"` against
# `-Djna.library.path` first, then prefixes/suffixes per platform. Cargo's
# cdylib output matches that convention: lib<name>.dylib (macOS),
# lib<name>.so (Linux), <name>.dll (Windows — no `lib` prefix).
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
# JNA is the runtime classpath dep that uniffi 0.31's Kotlin bindings
# require for `com.sun.jna.*` (Native, Pointer, Structure, Callback).
# Pinned + SHA-256 verified so a Maven-Central proxy compromise or a
# published-version mutation cannot silently flip the smoke runner's
# native bridge. The version is well off the crypto path (and JNA is
# only loaded by this smoke test, not by any shipping code), so semver
# pin discipline differs from the `tempfile = "=3.27.0"` exact-pin in
# core/Cargo.toml — but we still verify the bytes.
JNA_VERSION="5.14.0"
JNA_SHA256="34ed1e1f27fa896bca50dbc4e99cf3732967cec387a7a0d5e3486c09673fe8c6"
JNA_URL="https://repo1.maven.org/maven2/net/java/dev/jna/jna/${JNA_VERSION}/jna-${JNA_VERSION}.jar"
JNA_JAR="$LIB_DIR/jna-${JNA_VERSION}.jar"

# --- Sanity: kotlinc + java available ---
# Mirrors swift's "swiftc must be on PATH" expectation; install once
# via `brew install kotlin` (macOS) or `sdk install kotlin` (SDKMAN).
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
# `--features cli` enables the in-crate uniffi-bindgen binary (gated by
# `required-features = ["cli"]` so it stays out of default cdylib builds).
# `--release` matches step 1's profile so cargo reuses the compiled
# uniffi + transitive deps instead of recompiling them under the dev
# profile — bindgen itself doesn't need optimization, but profile parity
# saves a multi-minute second compile of the dependency tree.
echo "==> uniffi-bindgen generate (Kotlin)"
mkdir -p "$BINDINGS_DIR"
(cd "$REPO_ROOT" && cargo run --release --features cli -p secretary-ffi-uniffi \
    --bin uniffi-bindgen -- generate \
    --library "$CDYLIB" \
    --language kotlin \
    --out-dir "$BINDINGS_DIR")

# Resolve the generated source path. uniffi nests Kotlin output under
# `<out_dir>/uniffi/<namespace>/<namespace>.kt`; namespace comes from
# the UDL header (`namespace secretary` here), so the path is fixed.
GENERATED_KT="$BINDINGS_DIR/uniffi/secretary/secretary.kt"
if [[ ! -f "$GENERATED_KT" ]]; then
    echo "ERROR: expected generated binding at $GENERATED_KT" >&2
    echo "       (uniffi output layout may have changed; inspect $BINDINGS_DIR)" >&2
    exit 3
fi

# --- Step 3: fetch JNA (pinned, integrity-verified) ---
mkdir -p "$LIB_DIR"
if [[ ! -f "$JNA_JAR" ]]; then
    echo "==> fetching jna-${JNA_VERSION}.jar from Maven Central"
    curl -fsSL "$JNA_URL" -o "$JNA_JAR.tmp"
    mv "$JNA_JAR.tmp" "$JNA_JAR"
fi
# Always verify, even on a cached jar: a corrupted local file would
# produce a confusing kotlinc/JNA error rather than an obvious mismatch.
# Prefer `sha256sum` (Linux coreutils, single-purpose binary); fall back
# to `shasum -a 256` (macOS default, also widely present on Linux as a
# Perl script). Both emit `<hash>  <path>` so the awk slice is identical.
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA="$(sha256sum "$JNA_JAR" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA="$(shasum -a 256 "$JNA_JAR" | awk '{print $1}')"
else
    echo "ERROR: neither sha256sum nor shasum found in PATH" >&2
    echo "       install GNU coreutils (Linux) or Perl shasum (macOS default)" >&2
    exit 2
fi
if [[ "$ACTUAL_SHA" != "$JNA_SHA256" ]]; then
    echo "ERROR: JNA jar SHA-256 mismatch" >&2
    echo "       expected: $JNA_SHA256" >&2
    echo "       got:      $ACTUAL_SHA" >&2
    echo "       (delete $JNA_JAR and retry, or update JNA_SHA256 if intentional)" >&2
    exit 4
fi

# --- Step 4: kotlinc the bindings + smoke runner ---
# `-include-runtime` bundles the Kotlin stdlib into the jar so we don't
# need to put kotlin-stdlib.jar on the runtime classpath. The bindings
# only `import com.sun.jna.*`, so JNA is the sole compile-time dep.
echo "==> kotlinc smoke runner"
kotlinc \
    -classpath "$JNA_JAR" \
    -include-runtime \
    -d "$JAR_OUT" \
    "$GENERATED_KT" \
    "$SCRIPT_DIR/Main.kt"

# --- Step 5: execute ---
# `-Djna.library.path` tells JNA where to find libsecretary_ffi_uniffi.
# `MainKt` is the implicit class name Kotlin emits for top-level
# functions in `Main.kt` (top-level `main()` becomes `MainKt.main`).
echo "==> running $JAR_OUT"
java \
    -Djna.library.path="$TARGET_DIR" \
    -cp "$JAR_OUT:$JNA_JAR" \
    MainKt
