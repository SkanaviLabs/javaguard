// Maven Central publishing for javaguard library modules.
//
// ./gradlew publishAllPublicationsToStagingRepository -PprojectUrl=https://...
// writes signed artifacts to build/staging-deploy (signing needs -PsigningKey/-PsigningPassword,
// an ASCII-armored secret key). See RELEASING.md.

plugins {
    `maven-publish`
    signing
}

val projectUrl = providers.gradleProperty("projectUrl")

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                name = project.name
                description = provider { project.description }
                url = projectUrl
                inceptionYear = "2026"
                licenses {
                    license {
                        name = "MIT License"
                        url = "https://opensource.org/license/mit"
                        distribution = "repo"
                    }
                }
                developers {
                    developer {
                        id = "syurin"
                        name = "Stanislav Yurin"
                        organization = "AI Security Engineering LLC dba Skanavi"
                    }
                }
                scm {
                    url = projectUrl
                    connection = projectUrl.map { "scm:git:$it.git" }
                    developerConnection = projectUrl.map { "scm:git:$it.git" }
                }
            }
        }
    }
    repositories {
        maven {
            name = "staging"
            url = uri(rootProject.layout.buildDirectory.dir("staging-deploy"))
        }
    }
}

signing {
    val key = providers.gradleProperty("signingKey")
    if (key.isPresent) {
        useInMemoryPgpKeys(key.get(), providers.gradleProperty("signingPassword").orNull)
        sign(publishing.publications["maven"])
    } else if (providers.gradleProperty("signing.gnupg.keyName").isPresent) {
        // Sign with the local gpg and its agent; the passphrase, if any, goes to gpg's own prompt.
        useGpgCmd()
        sign(publishing.publications["maven"])
    }
}

tasks.withType<PublishToMavenRepository>().configureEach {
    dependsOn(":cleanStaging")
    val url = projectUrl // a local capture keeps the action configuration-cache compatible
    doFirst {
        check(url.isPresent) {
            "Set -PprojectUrl=<public repository URL>: Maven Central requires url and scm in the POM."
        }
    }
}
