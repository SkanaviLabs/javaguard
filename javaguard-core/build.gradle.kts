plugins {
    id("javaguard.java-library")
    id("javaguard.publish")
    `java-test-fixtures`
}

description = "WireGuard protocol core for javaguard: messages, Noise IKpsk2 handshake, cookies."

dependencies {
    api(project(":javaguard-crypto"))
}

// Test fixtures (the Docker interop helpers) are for this build only, not for publication.
val javaComponent = components["java"] as AdhocComponentWithVariants
javaComponent.withVariantsFromConfiguration(configurations["testFixturesApiElements"]) { skip() }
javaComponent.withVariantsFromConfiguration(configurations["testFixturesRuntimeElements"]) { skip() }
