# Releasing to Maven Central

javaguard publishes eight artifacts under `com.skanavi.javaguard` through the
[Central Portal](https://central.sonatype.com):

- `javaguard-crypto`
- `javaguard-core`
- `javaguard-netstack`
- `javaguard-config`
- `javaguard-server`
- `javaguard-proxy`
- `javaguard-tun`
- `javaguard-cli`

The build creates and checks the upload bundle; uploading and publishing it in the portal are the
manual steps.

## One-time setup

1. **Central Portal account and namespace.** Sign in at <https://central.sonatype.com> and add
   the namespace `com.skanavi`. Verify it with the DNS TXT record the portal shows for
   `skanavi.com`.
2. **Signing key.** Create an OpenPGP key for releases and publish its public half to a
   keyserver that Central checks, for example `keys.openpgp.org`:

   ```bash
   gpg --quick-generate-key "Stanislav Yurin <releases@skanavi.com>" ed25519 sign 3y
   ```

   ```bash
   gpg --keyserver keys.openpgp.org --send-keys <KEY_ID>
   ```

3. **Public repository.** Central requires the POM to name the project URL and SCM. The
   repository is <https://github.com/SkanaviLabs/javaguard>, set as `projectUrl` in
   `gradle.properties`.

## Each release

1. Make sure `main` is green, including Docker interop:

   ```bash
   ./gradlew clean build interopTest
   ```

2. Set the version in `gradle.properties` (for example `version=1.1.1`) and date the entry in
   `CHANGELOG.md`.
3. Build, sign, verify and zip the bundle. The simplest way signs with your local `gpg`, which
   asks for the passphrase itself:

   ```bash
   ./gradlew clean centralBundle -Psigning.gnupg.keyName=<KEY_ID>
   ```

   Or, for CI, pass the key as Gradle properties, never committed:

   ```bash
   export ORG_GRADLE_PROJECT_signingKey="$(gpg --export-secret-keys --armor <KEY_ID>)"
   ```

   ```bash
   export ORG_GRADLE_PROJECT_signingPassword='<passphrase>'
   ```

   ```bash
   ./gradlew clean centralBundle
   ```

   The bundle is written to `build/distributions/javaguard-<version>-central-bundle.zip`.
   `verifyCentralBundle`, which `centralBundle` runs, fails unless every artifact has:
   - its POM, jar, `-sources.jar` and `-javadoc.jar`;
   - MD5 and SHA-1 checksums;
   - an `.asc` signature;
   - the MIT license and third-party notices inside every jar (`META-INF/LICENSE`,
     `META-INF/THIRD_PARTY_NOTICES.md`);
   - the required POM elements.

4. **Upload.** In the Central Portal open *Publish → Upload Deployment*, choose the zip, and
   select *Publish* after validation passes. Publishing cannot be undone: a released version can
   never be replaced.
5. Tag the release and attach the CLI distribution. `centralBundle` does not build it, so run
   `./gradlew :javaguard-cli:distZip` first; the zip is in `javaguard-cli/build/distributions/`.

   ```bash
   git tag -s v1.1.1 -m "javaguard 1.1.1"
   ```

   ```bash
   git push origin v1.1.1
   ```

## Checking a bundle without publishing

The steps above, with a throwaway key, produce a bundle you can inspect but should not upload:

```bash
unzip -l build/distributions/javaguard-*-central-bundle.zip
```

```bash
gpg --verify <file>.asc <file>
```
