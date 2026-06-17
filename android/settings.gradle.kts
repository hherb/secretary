pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        google()
    }
}

rootProject.name = "secretary-android"

include(":vault-access")
include(":kit")
include(":sync-ui")
include(":browse-ui")
include(":app")
