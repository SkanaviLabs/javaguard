plugins {
    id("javaguard.java-library")
    id("javaguard.publish")
}

description = "Local SOCKS5 and HTTP proxy for javaguard tunnels, plus java.net integration helpers."

dependencies {
    api(project(":javaguard-netstack"))
    testImplementation(testFixtures(project(":javaguard-core")))
}

// ./gradlew :javaguard-proxy:remoteTest -PremoteEndpoint=host:port -PremotePublicKey=<base64>
//     -PremoteKeyFile=<client private key file> [-PremoteSsh=user@host] [-PremoteMinutes=N]
// Tests against a real WireGuard peer over the Internet; see RemotePeerTest for the peer setup.
tasks.register<Test>("remoteTest") {
    description = "Runs tests against a real remote WireGuard peer."
    group = "verification"
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform {
        includeTags("remote")
    }
    outputs.upToDateWhen { false }
    for (name in listOf("remoteEndpoint", "remotePublicKey", "remoteKeyFile", "remoteSsh", "remoteMinutes", "remoteLog")) {
        providers.gradleProperty(name).orNull?.let { systemProperty("javaguard.$name", it) }
    }
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
}
