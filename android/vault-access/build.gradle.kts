plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    // `strictly` (not a soft "1.8.0", which a transitive could silently bump): coroutines is
    // the one runtime dep that ships into later slices, so pin it hard for reproducibility,
    // matching the repo's exact-pin discipline (cf. core's `tempfile = "=3.27.0"`). JUnit is
    // pinned via the BOM platform below — the idiomatic mechanism — so it needs no `strictly`.
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

tasks.test {
    useJUnitPlatform()
}
