plugins {
    id("com.android.library")
    kotlin("android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.secretary.browse.ui"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
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

// Test-tooling version forces — identical rationale to :sync-ui (API-36 Espresso + the workspace
// coroutines 1.8.0 production pin must win over espresso's transitive coroutines-bom constraint).
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

    val composeBom = platform("androidx.compose:compose-bom:2025.05.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")
    implementation("androidx.activity:activity-compose")

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

    // --- Instrumented Compose UI tests (none authored this slice; deps kept for parity/future) ---
    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
