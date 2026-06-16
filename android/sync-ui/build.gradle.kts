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

dependencies {
    // FFI-free: the UI layer depends only on the pure model module, never on :kit.
    api(project(":vault-access"))

    // Compose BOM aligns all Compose artifact versions. If resolution fails, bump to the
    // current stable BOM — the Compose compiler is the Kotlin-bundled plugin (no separate pin).
    val composeBom = platform("androidx.compose:compose-bom:2024.09.00")
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
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
