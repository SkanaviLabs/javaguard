plugins {
    id("javaguard.java-library")
    id("javaguard.publish")
    application
}

description = "Command-line runner for javaguard: key tools and `javaguard up <config>`."

dependencies {
    implementation(project(":javaguard-config"))
    implementation(project(":javaguard-proxy"))
    testImplementation(testFixtures(project(":javaguard-core")))
}

application {
    applicationName = "javaguard"
    mainModule = "com.skanavi.javaguard.cli"
    mainClass = "com.skanavi.javaguard.cli.Main"
}

tasks.named<Test>("interopTest") {
    dependsOn(tasks.installDist)
    systemProperty(
        "javaguard.cli.install",
        layout.buildDirectory.dir("install/javaguard").get().asFile.absolutePath,
    )
}
