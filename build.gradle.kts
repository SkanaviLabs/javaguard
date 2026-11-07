// Release bundle for the Maven Central Portal (https://central.sonatype.com): a zip of the
// staging repository with POMs, jars, sources, javadoc, checksums and signatures. See RELEASING.md.

import java.util.zip.ZipFile

val staging = layout.buildDirectory.dir("staging-deploy")
val published = listOf("javaguard-crypto", "javaguard-core", "javaguard-netstack", "javaguard-config", "javaguard-server", "javaguard-proxy", "javaguard-tun", "javaguard-cli")

// Staging starts empty on every publish, so files from an earlier run can never reach a bundle.
tasks.register<Delete>("cleanStaging") {
    description = "Deletes the staging repository."
    group = "publishing"
    delete(staging)
}

val verifyCentralBundle = tasks.register("verifyCentralBundle") {
    description = "Checks the staging repository has everything Maven Central requires."
    group = "publishing"
    dependsOn(published.map { ":$it:publishAllPublicationsToStagingRepository" })
    val stagingDir = staging
    val artifacts = published // local captures keep the action configuration-cache compatible
    val version = project.findProperty("version").toString()
    inputs.dir(stagingDir)
    doLast {
        val root = stagingDir.get().asFile
        val problems = mutableListOf<String>()
        var signed = 0
        for (artifact in artifacts) {
            val dir = root.resolve("com/skanavi/javaguard/$artifact/$version")
            for (suffix in listOf(".pom", ".jar", "-sources.jar", "-javadoc.jar")) {
                val file = dir.resolve("$artifact-$version$suffix")
                if (!file.isFile) {
                    problems += "missing ${file.relativeTo(root)}"
                    continue
                }
                for (sum in listOf("md5", "sha1")) {
                    if (!dir.resolve("${file.name}.$sum").isFile) problems += "missing ${file.name}.$sum"
                }
                if (dir.resolve("${file.name}.asc").isFile) signed++ else problems += "missing ${file.name}.asc"
                if (suffix == ".jar") {
                    ZipFile(file).use { zip ->
                        for (entry in listOf("META-INF/LICENSE", "META-INF/THIRD_PARTY_NOTICES.md")) {
                            if (zip.getEntry(entry) == null) problems += "missing $entry in ${file.name}"
                        }
                    }
                }
            }
            val pom = dir.resolve("$artifact-$version.pom")
            if (pom.isFile) {
                val text = pom.readText()
                for (tag in listOf("<name>", "<description>", "<url>", "<licenses>", "<developers>", "<scm>")) {
                    if (!text.contains(tag)) problems += "${pom.name} lacks $tag"
                }
                if (text.contains("testFixtures")) problems += "${pom.name} references test fixtures"
            }
        }
        if (signed == 0) problems += "no signatures (.asc): pass -Psigning.gnupg.keyName, or -PsigningKey and -PsigningPassword"
        if (problems.isNotEmpty()) {
            throw GradleException("Central bundle is not ready:\n  " + problems.joinToString("\n  "))
        }
        logger.lifecycle("Central bundle OK: ${artifacts.size} artifacts, $signed signed files")
    }
}

tasks.register<Zip>("centralBundle") {
    description = "Zips the verified staging repository for upload to the Central Portal."
    group = "publishing"
    dependsOn(verifyCentralBundle)
    from(staging) {
        exclude("**/maven-metadata*")
    }
    archiveFileName = "javaguard-${project.findProperty("version")}-central-bundle.zip"
    destinationDirectory = layout.buildDirectory.dir("distributions")
}
