plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "javaguard"

include("javaguard-crypto")
include("javaguard-core")
