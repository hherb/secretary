plugins {
    id("com.android.library")
    kotlin("android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.secretary.sync.ui"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Kotlin/JVM 21 bytecode (matches :vault-access jvmToolchain(21) and :kit).
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildFeatures {
        compose = true
    }

    // Host JVM unit tests use JUnit 5 (matches :vault-access / :kit).
    testOptions {
        unitTests.all { it.useJUnitPlatform() }
    }
}

kotlin {
    jvmToolchain(21)
}

// Two distinct pinning mechanisms are in play here — they serve different purposes:
//
// 1. strictly("1.8.0") on the coroutines dependency declarations below is the workspace
//    production pin: it matches the version used by sibling modules :kit and :vault-access
//    and will hard-error if any dependency tries to upgrade it.
//
// 2. force() here is needed ONLY to override a TEST-ONLY transitive demand:
//    androidx.test:core:1.7.0 (pulled by espresso 3.7.0) brings in
//    kotlinx-coroutines-bom:1.8.1 as a constraint, which requests coroutines 1.8.1.
//    Gradle treats a BOM constraint as a hard requirement that strictly("1.8.0") alone
//    cannot satisfy — it would reject the graph with a version-conflict error. The force()
//    overrides that constraint so our 1.8.0 pin wins unconditionally.
//    Without the force(), connectedDebugAndroidTest fails at dependency resolution
//    (verified: removing the force lines causes BUILD FAILED with "Cannot find a version
//    of 'kotlinx-coroutines-core' that satisfies the version constraints").
//
//    The Espresso forces (3.7.0) fix a separate hidden-API issue: Espresso 3.5.x/3.6.x use
//    reflection to call InputManager.getInstance() (@UnsupportedAppUsage) which Android 16
//    (API 36) denies. Espresso 3.7.0 uses getSystemService() on SDK >= 23 instead.
//
// Note: force() is applied via configureEach (all configurations) rather than only
// androidTestRuntimeClasspath because per-configuration force in KTS requires explicit
// iteration; the forces are test-tooling only and conservative — revisit if they ever
// perturb lintClasspath.
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
    // FFI-free: the UI layer depends only on the pure model module, never on :kit.
    api(project(":vault-access"))

    // Compose BOM aligns all Compose artifact versions. If resolution fails, bump to the
    // current stable BOM — the Compose compiler is the Kotlin-bundled plugin (no separate pin).
    // BOM 2025.05.00 → Compose UI 1.8.1, which uses Compose's own idle strategy rather than
    // Espresso's InputManager reflection (removed in API 35+). Required for API 36 emulator.
    val composeBom = platform("androidx.compose:compose-bom:2025.05.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    // material-icons-extended (~10 MB) is intentionally NOT listed here; the sync-ui
    // badge helpers use only the default bundled material-icons-core icons.
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // ViewModel + lifecycle-aware state collection in Compose.
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")
    implementation("androidx.activity:activity-compose")

    // coroutines pinned to match the rest of the workspace.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core") {
        version { strictly("1.8.0") }
    }

    // --- Host JUnit5 unit tests (helpers + ViewModel forwarding) ---
    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test") {
        version { strictly("1.8.0") }
    }
    testImplementation("androidx.lifecycle:lifecycle-viewmodel:2.8.6")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // --- Instrumented Compose UI tests (run on the emulator) ---
    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
