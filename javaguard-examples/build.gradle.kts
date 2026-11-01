plugins {
    id("javaguard.java-library")
}

description = "Runnable examples of embedding javaguard (compiled with the build, not published)."

dependencies {
    implementation(project(":javaguard-proxy"))
    implementation(project(":javaguard-config"))
}

// ./gradlew :javaguard-examples:run -Pexample=EmbeddedHttpClient --args="wg0.conf http://10.0.0.1/"
tasks.register<JavaExec>("run") {
    description = "Runs an example: -Pexample=<class name> --args=\"...\"."
    group = "application"
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass = providers.gradleProperty("example").map { "com.skanavi.javaguard.examples.$it" }
    javaLauncher = javaToolchains.launcherFor(java.toolchain)
}
