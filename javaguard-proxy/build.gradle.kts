plugins {
    id("javaguard.java-library")
}

description = "Local SOCKS5 and HTTP proxy for javaguard tunnels, plus java.net integration helpers."

dependencies {
    api(project(":javaguard-netstack"))
    testImplementation(testFixtures(project(":javaguard-core")))
}
