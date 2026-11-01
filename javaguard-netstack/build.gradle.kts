plugins {
    id("javaguard.java-library")
    id("javaguard.publish")
}

description = "Userspace IPv4/IPv6 network stack for javaguard tunnels: ICMP, UDP, DNS."

dependencies {
    api(project(":javaguard-core"))
    testImplementation(testFixtures(project(":javaguard-core")))
}
