plugins {
    id("javaguard.java-library")
}

description = "Configuration for javaguard: wg-quick files and the cross-platform UAPI socket."

dependencies {
    api(project(":javaguard-core"))
}
