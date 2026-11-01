plugins {
    id("javaguard.java-library")
}

description = "WireGuard protocol core for javaguard: messages, Noise IKpsk2 handshake, cookies."

dependencies {
    api(project(":javaguard-crypto"))
}
