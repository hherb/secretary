import org.gradle.api.tasks.Exec
import org.gradle.nativeplatform.platform.internal.DefaultNativePlatform

plugins {
    id("com.android.library")
    kotlin("android")
}

// Repo root (the cargo workspace) is the parent of the `android/` gradle root project.
val repoRoot: java.io.File = rootProject.projectDir.parentFile
// Host cdylib extension for the bindgen metadata read: macOS → dylib, Linux → so.
// Windows is not a supported host for this FFI build (the project does not target it).
val hostCdylibExt: String = if (DefaultNativePlatform.getCurrentOperatingSystem().isMacOsX) "dylib" else "so"
val generatedBindingsDir = layout.buildDirectory.dir("generated/uniffi")

// Single source of truth for the NDK revision (reused by android.ndkVersion and cargo-ndk below).
val ndkVer = "29.0.14206865"

// SDK root for locating the NDK: honor the standard Android env vars (CI / Linux),
// falling back to the conventional macOS location for a bare local shell.
val androidSdkRoot: String = System.getenv("ANDROID_SDK_ROOT")
    ?: System.getenv("ANDROID_HOME")
    ?: "${System.getProperty("user.home")}/Library/Android/sdk"

android {
    namespace = "org.secretary.sync"
    compileSdk = 36
    ndkVersion = ndkVer

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Kotlin/JVM 21 bytecode (matches :vault-access jvmToolchain(21)).
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    // Host JVM unit tests use JUnit 5 (matches :vault-access).
    testOptions {
        unitTests.all { it.useJUnitPlatform() }
    }

    sourceSets {
        getByName("main") {
            // uniffi bindings are generated into build/ and never committed.
            kotlin.srcDir(generatedBindingsDir.map { it.dir("uniffi/secretary") })
        }
    }

    // The generated uniffi bindings are added as a source dir above, so lint scans them.
    // lint.xml scopes a NewApi suppression to that generated directory only (see #387).
    lint {
        lintConfig = file("lint.xml")
    }
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    api(project(":vault-access"))

    // uniffi 0.31 Kotlin bindings load the cdylib through JNA (aar variant for Android).
    // 5.14.0 satisfies uniffi's >=5.12 floor; fetched from mavenCentral (network available).
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    // SAF tree traversal for SafCloudFolderPort (slice 3). 1.0.1 is the current stable release;
    // used only by the safCloudFolderPort factory — the seam-based class body holds no SAF types.
    implementation("androidx.documentfile:documentfile:1.0.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core") {
        version { strictly("1.8.0") }
    }

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test") {
        version { strictly("1.8.0") }
    }
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // Instrumented (on-device) tests run JUnit4 via the AndroidJUnitRunner — a separate
    // world from the JUnit5 host unit tests above. runBlocking drives the real suspend
    // FFI calls on real dispatchers (no virtual-time scheduler — this is an integration test).
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("junit:junit:4.13.2")
}

// --- FFI build wiring -------------------------------------------------------

// The host cdylib whose embedded metadata uniffi-bindgen reads to generate Kotlin bindings.
// macOS → .dylib, Linux → .so (Windows is not a supported host for this project's FFI build).
val hostCdylib = repoRoot.resolve("target/release/libsecretary_ffi_uniffi.$hostCdylibExt")

// Build the host cdylib once, tracked, so the bindings task has a real input/output edge
// (no untracked product hiding inside a doFirst — safe under Gradle's build cache).
//
// Input boundary is `ffi/secretary-ffi-uniffi/src` ALONE (not the whole workspace closure)
// on purpose: this cdylib is consumed ONLY by uniffi-bindgen — it is never packaged. The
// generated Kotlin bindings derive solely from the uniffi scaffolding/checksums embedded by
// this crate (its `secretary.udl`), so a `core/` change that does not touch the FFI surface
// cannot change the bindings. cargo itself stays correct regardless (it tracks the full
// closure); narrowing Gradle's input here only governs when the bindings are regenerated.
// Contrast `cargoNdkBuildArm64` below, whose output IS packaged and is deliberately untracked.
val buildHostCdylib by tasks.registering(Exec::class) {
    workingDir = repoRoot
    inputs.dir(repoRoot.resolve("ffi/secretary-ffi-uniffi/src"))
    outputs.file(hostCdylib)
    commandLine("cargo", "build", "--release", "-p", "secretary-ffi-uniffi")
}

// Generate the uniffi Kotlin bindings from the host cdylib metadata.
val generateUniffiKotlinBindings by tasks.registering(Exec::class) {
    dependsOn(buildHostCdylib)
    workingDir = repoRoot
    inputs.dir(repoRoot.resolve("ffi/secretary-ffi-uniffi/src"))
    inputs.file(hostCdylib)
    outputs.dir(generatedBindingsDir)
    commandLine(
        "cargo", "run", "--release", "--features", "cli",
        "-p", "secretary-ffi-uniffi", "--bin", "uniffi-bindgen", "--",
        "generate",
        "--library", hostCdylib.absolutePath,
        "--language", "kotlin",
        "--out-dir", generatedBindingsDir.get().asFile.absolutePath,
    )
}

// Bindings must exist before Kotlin compiles.
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    dependsOn(generateUniffiKotlinBindings)
}

// Cross-build the cdylib for arm64-v8a and stage it into jniLibs. Wired onto the
// JNI-merge tasks below (the AAR/packaging path), never onto preBuild — so it stays
// off the host unit-test path.
//
// DELIBERATELY no Gradle inputs/outputs (so it always runs on the packaging path): unlike
// `buildHostCdylib`, this .so IS packaged into the AAR, and its runtime behavior depends on
// the whole cargo workspace closure (core + the bridge crate), not just `ffi/.../src`. A
// partial input declaration would let a `core/` change ship a STALE native lib in the AAR —
// a correctness hazard far worse than the cost it saves. cargo's own incremental build makes
// the always-run re-invocation a near-instant no-op when nothing changed, so we lean on cargo
// for freshness here rather than trying (and risking under-tracking) it in Gradle.
val cargoNdkBuildArm64 by tasks.registering(Exec::class) {
    workingDir = repoRoot
    environment("ANDROID_NDK_HOME", "$androidSdkRoot/ndk/$ndkVer")
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-o", layout.projectDirectory.dir("src/main/jniLibs").asFile.absolutePath,
        "build", "--release", "-p", "secretary-ffi-uniffi",
    )
}

// The arm64 .so is needed only to PACKAGE the AAR, never for host unit tests. Hooking the
// JNI-merge tasks (mergeDebugJniLibFolders / mergeReleaseJniLibFolders) keeps the cross-build
// off the testDebugUnitTest path — so the pure mapper/adapter host tests run with no NDK,
// no cargo-ndk, and no aarch64-linux-android target installed.
tasks.matching { it.name.endsWith("JniLibFolders") }.configureEach {
    dependsOn(cargoNdkBuildArm64)
}

// --- androidTest fixture staging ------------------------------------------

// Stage golden_vault_001 (+ its inputs JSON) from the canonical core/tests/data
// location into the androidTest assets. The destination is gitignored: the tracked
// fixture stays the single source of truth (no committed duplicate of a frozen KAT),
// mirroring how iOS stages it via build-xcframework.sh. `Copy` tracks `from`/`into`
// as inputs/outputs automatically, so Gradle skips the copy when the fixture is unchanged.
val stageGoldenVaultForAndroidTest by tasks.registering(Copy::class) {
    val fixtureRoot = repoRoot.resolve("core/tests/data")
    from(fixtureRoot.resolve("golden_vault_001")) { into("golden_vault_001") }
    from(fixtureRoot.resolve("golden_vault_001_inputs.json"))
    into(layout.projectDirectory.dir("src/androidTest/assets"))
}

// The androidTest asset merge must see the staged fixture.
tasks.matching { it.name == "mergeDebugAndroidTestAssets" }.configureEach {
    dependsOn(stageGoldenVaultForAndroidTest)
}
