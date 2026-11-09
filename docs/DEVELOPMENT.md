# Development

Building from source, code formatting, continuous integration and cutting a release. Usage is in the
[README](../README.md).

## Building

```
mvn package                     # JVM build: target/jfr-redact-<version>.jar
mvn -Pnative package            # Native image: target/jfr-redact
mvn -Pnative,native-jfr package # Native image with JFR support
```

The library requires JDK 25 or later, and the native image GraalVM for JDK 25 or later as `JAVA_HOME`.

## Code formatting

Spotless checks the formatting in the `validate` phase: tabs, 120-column code and 100-column comments, with the
Eclipse profile in `config/formatter/formatting.xml`. Run `mvn spotless:apply` to format the sources.

## Continuous integration

`.github/workflows/build.yml` runs `mvn -B package` on every push and pull request to `main`, and keeps the jar as
a 14-day artifact.

## Cutting a release

Push a `v`-prefixed tag:

```
git tag v0.2.0 && git push origin v0.2.0
```

`.github/workflows/release.yml` sets the Maven version from the tag, builds the jar and native images for
linux-x86_64, linux-aarch64, macos-aarch64 and windows-x86_64, redacts and validates a test recording with each
native image, and publishes everything to a GitHub release with generated notes. `pom.xml` stays at `-SNAPSHOT` on
the branch; the tag is the single source of truth for a release version. Running the workflow from the Actions tab
instead builds everything as workflow artifacts, without signing or publishing.

### Signing

The macOS binary is signed with the Developer ID certificate (hardened runtime, timestamped) and notarized, which
needs the secrets `MACOS_CERTIFICATE` (base64-encoded `.p12`), `MACOS_CERTIFICATE_PWD`, `MACOS_SIGNING_IDENTITY`,
`NOTARIZATION_APPLE_ID`, `NOTARIZATION_PASSWORD` (app-specific) and `NOTARIZATION_TEAM_ID`. A bare executable cannot
be stapled, so Gatekeeper fetches the ticket on first launch.

The Windows binary is signed afterwards, since the Certum certificate needs an interactive SimplySign login. With
SimplySign Desktop logged in and `gh` authenticated:

```
.\scripts\Sign-Release.ps1 -Version 0.2.0   # -NoUpload to inspect target\signed first
```

It reads the certificate thumbprint from `$env:CERTUM_SIGN_THUMBPRINT`, signs and verifies the binary, and replaces
it on the release.
