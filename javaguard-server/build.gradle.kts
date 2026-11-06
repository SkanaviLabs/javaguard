plugins {
    id("javaguard.java-library")
    id("javaguard.publish")
}

description = "Serve peers from inside a JVM with javaguard: tunnel-only services, no forwarding."

dependencies {
    api(project(":javaguard-netstack"))
    api(project(":javaguard-config"))
    testImplementation(testFixtures(project(":javaguard-core")))
    testImplementation(libs.jetty.server)
    testImplementation(libs.jetty.unixdomain.server)
}

tasks.test {
    testLogging {
        showStandardStreams = true
    }
}
