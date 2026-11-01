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
        excludeTags("fuzz", "interop")
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

// ---- Formatting ----

spotless {
    java {
        target("src/*/java/**/*.java")
        googleJavaFormat()
        licenseHeader("// SPDX-License-Identifier: MIT\n// Copyright (c) \$YEAR Stanislav Yurin, AI Security Engineering LLC dba Skanavi\n\n")
    }
}
