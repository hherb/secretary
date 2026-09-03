// Repo root (the cargo workspace) is the parent of the `android/` gradle root project.
val repoRoot: java.io.File = rootProject.projectDir.parentFile

plugins {
    id("com.android.application")
    kotlin("android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.secretary.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.secretary.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildFeatures {
        compose = true
    }

    testOptions {
        unitTests.all { it.useJUnitPlatform() }
    }
}

kotlin {
    jvmToolchain(21)
}

// Same test-tooling version forces as :sync-ui: the API-36 emulator needs Espresso 3.7.0
// (InputManager reflection removed in API 35+), and the espresso-pulled coroutines BOM
// constraint must yield to the workspace 1.8.0 production pin. See :sync-ui/build.gradle.kts
// for the full rationale.
configurations.configureEach {
    resolutionStrategy {
        force("androidx.test.espresso:espresso-core:3.7.0")
        force("androidx.test.espresso:espresso-idling-resource:3.7.0")
        force("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")
        force("org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.8.0")
        force("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.0")
    }
}

dependencies {
    // :kit brings the real makeVaultSync + the packaged arm64 .so (transitively into the APK).
    // :sync-ui brings SyncScreen + VaultSyncViewModel. :vault-access (the pure model) is
    // transitive via both, declared explicitly for the model types used in the unlock orchestration.
    // :browse-ui brings BrowseScreen + VaultBrowseViewModel (and transitively VaultBrowseModel).
    implementation(project(":kit"))
    implementation(project(":sync-ui"))
    implementation(project(":vault-access"))
    implementation(project(":browse-ui"))

    val composeBom = platform("androidx.compose:compose-bom:2025.05.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // BiometricPrompt + CryptoObject for the device-secret unlock gate. Pulls androidx.fragment
    // transitively; declared explicitly because MainActivity extends FragmentActivity.
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.8.5")

    // Explicit version: the only contributor of a concrete activity-compose version was the
    // debugImplementation `ui-tooling` (a `debug`-only transitive), which does not extend into
    // the androidTest compile classpath — so a bare coordinate left debugAndroidTestCompileClasspath
    // unable to resolve a version. 1.9.3 is the release aligned with the lifecycle 2.8.x line pinned
    // below (1.8.x predates 2.8 and would be a cross-line pairing).
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core") {
        version { strictly("1.8.0") }
    }
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android") {
        version { strictly("1.8.0") }
    }

    // --- Host JUnit5 unit tests (pure helpers) ---
    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test") {
        version { strictly("1.8.0") }
    }

    // --- Instrumented tests (real .so makeVaultSync smoke on the emulator) ---
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("junit:junit:4.13.2")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test") {
        version { strictly("1.8.0") }
    }
    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

// --- DEBUG-ONLY golden-vault asset staging ------------------------------------
//
// Stage golden_vault_001 (+ its inputs JSON) from the canonical core/tests/data location
// into the app's DEBUG assets so the runnable demo bundles a vault to open. The destination
// is gitignored: the tracked fixture stays the single source of truth (no committed duplicate
// of a frozen KAT), mirroring :kit's androidTest staging and iOS's bundle staging. `.DS_Store`
// is excluded so a macOS finder artifact never ships in the APK. `Copy` tracks from/into as
// inputs/outputs, so Gradle skips the copy when the fixture is unchanged.
//
// SECURITY (audit SC-2): `golden_vault_001_inputs.json` carries the fixture vault's master
// PASSWORD, its 24-word RECOVERY MNEMONIC, every identity's SECRET KEYS, a device-slot secret
// and sub-floor KDF parameters — all published on GitHub. It used to be staged into
// `src/main/assets` and wired to BOTH `mergeDebugAssets` and `mergeReleaseAssets`, so a release
// APK self-provisioned a vault whose credentials are public. Staging is now confined to the
// `debug` source set and the release asset merge asserts the fixture is ABSENT (see the
// tripwire below) so a shipped build can never contain it.
val stageGoldenVaultForApp by tasks.registering(Copy::class) {
    val fixtureRoot = repoRoot.resolve("core/tests/data")
    from(fixtureRoot.resolve("golden_vault_001")) {
        into("golden_vault_001")
        exclude("**/.DS_Store")
    }
    from(fixtureRoot.resolve("golden_vault_001_inputs.json"))
    into(layout.projectDirectory.dir("src/debug/assets"))
}

// Only the DEBUG asset merge sees the staged fixture.
tasks.matching { it.name == "mergeDebugAssets" }.configureEach {
    dependsOn(stageGoldenVaultForApp)
}

// Release tripwire: fail the build loudly if the fixture (or its secret-bearing inputs JSON)
// is ever present in a source set the release merge consumes. A comment saying "must never
// ship" is not a safeguard; this is.
tasks.matching { it.name == "mergeReleaseAssets" }.configureEach {
    // Resolved at configuration time as plain Files so the execution-time action
    // captures no Project state (configuration-cache safe).
    val forbidden = listOf(
        layout.projectDirectory.dir("src/main/assets/golden_vault_001").asFile,
        layout.projectDirectory.file("src/main/assets/golden_vault_001_inputs.json").asFile,
        layout.projectDirectory.dir("src/release/assets/golden_vault_001").asFile,
        layout.projectDirectory.file("src/release/assets/golden_vault_001_inputs.json").asFile,
    )
    doFirst {
        val present = forbidden.filter { it.exists() }
        check(present.isEmpty()) {
            "SECURITY: golden_vault_001 fixture (public password + recovery mnemonic + secret " +
                "keys) must never be bundled into a RELEASE build; remove: " +
                present.joinToString { it.path }
        }
    }
}
