import org.gradle.api.tasks.Exec
import org.gradle.nativeplatform.platform.internal.DefaultNativePlatform

plugins {
    id("com.android.library")
    kotlin("android")
}

// Repo root (the cargo workspace) is the parent of the `android/` gradle root project.
val repoRoot: java.io.File = rootProject.projectDir.parentFile
val hostCdylibExt: String = if (DefaultNativePlatform.getCurrentOperatingSystem().isMacOsX) "dylib" else "so"
val generatedBindingsDir = layout.buildDirectory.dir("generated/uniffi")

android {
    namespace = "org.secretary.sync"
    compileSdk = 36
    ndkVersion = "29.0.14206865"

    defaultConfig {
        minSdk = 26
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
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    api(project(":vault-access"))

    // uniffi 0.31 Kotlin bindings load the cdylib through JNA (aar variant for Android).
    // 5.14.0 satisfies uniffi's >=5.12 floor; fetched from mavenCentral (network available).
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core") {
        version { strictly("1.8.0") }
    }

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test") {
        version { strictly("1.8.0") }
    }
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// --- FFI build wiring -------------------------------------------------------

// Generate the uniffi Kotlin bindings from the .udl-derived host cdylib metadata.
// uniffi-bindgen --library reads the built cdylib, so we build the host cdylib first.
val generateUniffiKotlinBindings by tasks.registering(Exec::class) {
    workingDir = repoRoot
    inputs.dir(repoRoot.resolve("ffi/secretary-ffi-uniffi/src"))
    outputs.dir(generatedBindingsDir)
    doFirst {
        exec {
            workingDir = repoRoot
            commandLine("cargo", "build", "--release", "-p", "secretary-ffi-uniffi")
        }
    }
    commandLine(
        "cargo", "run", "--release", "--features", "cli",
        "-p", "secretary-ffi-uniffi", "--bin", "uniffi-bindgen", "--",
        "generate",
        "--library", "target/release/libsecretary_ffi_uniffi.$hostCdylibExt",
        "--language", "kotlin",
        "--out-dir", generatedBindingsDir.get().asFile.absolutePath,
    )
}

// Bindings must exist before Kotlin compiles.
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    dependsOn(generateUniffiKotlinBindings)
}

// Cross-build the cdylib for arm64-v8a and stage it into jniLibs.
val cargoNdkBuildArm64 by tasks.registering(Exec::class) {
    workingDir = repoRoot
    environment("ANDROID_NDK_HOME", "${System.getProperty("user.home")}/Library/Android/sdk/ndk/29.0.14206865")
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-o", layout.projectDirectory.dir("src/main/jniLibs").asFile.absolutePath,
        "build", "--release", "-p", "secretary-ffi-uniffi",
    )
}

// The native lib is required to assemble the AAR, but NOT for host unit tests.
tasks.named("preBuild").configure { dependsOn(cargoNdkBuildArm64) }
