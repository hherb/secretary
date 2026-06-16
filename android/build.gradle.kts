plugins {
    // :vault-access is pure-JVM Kotlin; :kit is an Android library (uniffi adapter + jniLibs).
    kotlin("jvm") version "2.2.10" apply false
    kotlin("android") version "2.2.10" apply false
    id("com.android.library") version "8.13.2" apply false
    // :sync-ui is a Compose Android library; the Compose compiler ships with Kotlin 2.x as a plugin.
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.10" apply false
}
