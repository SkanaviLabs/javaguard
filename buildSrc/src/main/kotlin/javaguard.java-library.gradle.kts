// Shared conventions for every javaguard library module.

plugins {
    `java-library`
    id("com.diffplug.spotless")
}

val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

fun lib(alias: String) = libs.findLibrary(alias).get()

group = "com.skanavi.javaguard"
version = "0.1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release = 25
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).addBooleanOption("Xdoclint:all,-missing", true)
}

// ---- Tests: JUnit Jupiter + jqwik; Jazzer fuzz tests and Docker interop tests run separately ----

dependencies {
    testImplementation(platform(lib("junit-bom")))
    testImplementation(lib("junit-jupiter"))
    testImplementation(lib("assertj"))
    testImplementation(lib("jqwik"))
    testImplementation(lib("bouncycastle"))
    testImplementation(lib("jazzer-junit"))
    testRuntimeOnly(lib("junit-platform-launcher"))
}

tasks.test {
    useJUnitPlatform {
        excludeTags("fuzz", "interop", "soak")
    }
}

// ./gradlew interopTest runs tests against real WireGuard implementations in Docker.
tasks.register<Test>("interopTest") {
    description = "Runs interoperability tests against WireGuard in Docker."
    group = "verification"
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform {
        includeTags("interop")
    }
    outputs.upToDateWhen { false }
    // -PlongInterop=true also runs multi-minute tests (rekeying against real peers).
    providers.gradleProperty("longInterop").orNull?.let { systemProperty("javaguard.interop.long", it) }
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
}

// ./gradlew fuzz [-PfuzzTarget=<class pattern>] runs Jazzer @FuzzTest methods in fuzzing mode.
tasks.register<Test>("fuzz") {
    description = "Runs Jazzer fuzz tests in fuzzing mode."
    group = "verification"
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform {
        includeTags("fuzz")
    }
    environment("JAZZER_FUZZ", "1")
    forkEvery = 1 // Jazzer fuzzes only one @FuzzTest per JVM; give each class its own
    providers.gradleProperty("fuzzTarget").orNull?.let { filter.includeTestsMatching(it) }
}

// ---- JMH: src/jmh/java, run with ./gradlew jmh [-Pjmh.include=<regex>] ----

val jmhSourceSet = sourceSets.create("jmh") {
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
}

configurations[jmhSourceSet.implementationConfigurationName].extendsFrom(configurations.implementation.get())

dependencies {
    "jmhImplementation"(lib("jmh-core"))
    "jmhAnnotationProcessor"(lib("jmh-annprocess"))
}

tasks.named<JavaCompile>(jmhSourceSet.compileJavaTaskName) {
    // JMH-generated sources trigger lint warnings we don't control.
    options.compilerArgs.removeAll(listOf("-Werror"))
}

tasks.register<JavaExec>("jmh") {
    description = "Runs JMH benchmarks."
    group = "benchmark"
    classpath = jmhSourceSet.runtimeClasspath
    mainClass = "org.openjdk.jmh.Main"
    javaLauncher = javaToolchains.launcherFor(java.toolchain)
    args(providers.gradleProperty("jmh.include").getOrElse(".*"))
}

// ./gradlew soakTest [-PsoakMinutes=N] runs long stability tests (default 10 minutes).
tasks.register<Test>("soakTest") {
    description = "Runs long-running stability tests."
    group = "verification"
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform {
        includeTags("soak")
    }
    outputs.upToDateWhen { false }
    systemProperty("javaguard.soak.minutes", providers.gradleProperty("soakMinutes").getOrElse("10"))
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
}

// ./gradlew :<module>:throughput [-Pseconds=N] [-Pjfr=true] runs the module's throughput harness.
val throughputMain = mapOf(
    "javaguard-core" to "com.skanavi.javaguard.core.DeviceThroughput",
    "javaguard-netstack" to "com.skanavi.javaguard.netstack.TcpThroughput",
)[project.name]
if (throughputMain != null) {
    tasks.register<JavaExec>("throughput") {
        description = "Runs the end-to-end throughput harness."
        group = "benchmark"
        classpath = jmhSourceSet.runtimeClasspath
        mainClass = throughputMain
        javaLauncher = javaToolchains.launcherFor(java.toolchain)
        args(providers.gradleProperty("seconds").getOrElse("10"))
        if (providers.gradleProperty("jfr").isPresent) {
            jvmArgs("-XX:StartFlightRecording=filename=${layout.buildDirectory.get()}/throughput.jfr,settings=profile")
        }
    }
}

// ---- Formatting ----

spotless {
    java {
        target("src/*/java/**/*.java")
        googleJavaFormat()
        licenseHeader("// SPDX-License-Identifier: MIT\n// Copyright (c) \$YEAR Stanislav Yurin, AI Security Engineering LLC dba Skanavi\n\n")
    }
}
