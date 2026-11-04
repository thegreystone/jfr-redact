# JFR Redact

High performance string redaction for JDK Flight Recorder recordings. JFR Redact replaces strings such as thread
names, class names or personal data everywhere they are stored in a recording, and writes a new recording that JDK
Mission Control (JMC) reads like the original.

Supported formats: JFR 0.9 (JDK 7 and 8, JRockit) and JFR 1.0+ with compressed integers (JDK 9+ and 8u262+).

## Quick start

Build with `mvn package` (JDK 25+). Below, `jfr-redact` stands for `java -jar target/jfr-redact-<version>.jar` or the
native image (see [Building](#building)).

```
jfr-redact redact recording.jfr redacted.jfr
jfr-redact scan --table --top 30 redacted.jfr
```

The first command removes what a recording reveals about the machine and the person who made it, and is the same as

```
jfr-redact redact --redact-secrets --anonymize-user --strip-process-arguments recording.jfr redacted.jfr
```

It replaces secrets, such as the values of environment variables named like `DB_PASSWORD` or `DD_API_KEY` and tokens
with known formats anywhere, replaces the home directories, user names and host names that the recording's own
environment variables name, wherever they occur, and e-mail addresses, and keeps only the executables of the command
lines of the other processes on the machine, which the default JFR settings record. The second command lists the most
frequent strings left, to check the result: no rule finds free text such as a password passed as a plain argument or a
customer name in a log message.

Given any option, `redact` applies only the options given, so a single rule can be tried on its own. To also hide the
code, hash thread names and the class and package names below `com.acme`, and replace strings containing `password`:

```
jfr-redact redact --redact-secrets --anonymize-user --strip-process-arguments --hash-thread-names \
    --hash-class-names 'com\.acme\.(.*)' --match 'password' recording.jfr redacted.jfr
```

The same from Java, plus a rule for a field of the application's own event:

```java
Path input = Path.of("recording.jfr");
StringRedactor redactor = RuleRedactor.builder()
		.redactSecrets()
		.anonymizeUser(UserIdentity.find(input))
		.stripProcessArguments()
		.hashThreadNames()
		.hashClassNames("com\\.acme\\.(.*)")
		.replaceIf(location -> location.getOwner().equals("com.acme.Login") && location.getField().equals("user"),
				user -> "<USER>")
		.replaceMatching("password", "<REDACTED>")
		.build();
RedactionResult result = JfrRedactor.redact(input, Path.of("redacted.jfr"), redactor);
```

More examples are in [`src/test/java/se/hirt/jfr/redact/examples`](src/test/java/se/hirt/jfr/redact/examples).

## Where strings are stored

A string is stored either inline in an event or in a constant pool: in a constant that events refer to, such as a
thread or a class, or in the `java.lang.String` pool. HotSpot writes its own strings directly into events and
constants. The JDK's Java event writer, used for `jdk.jfr.Event` subclasses, moves strings of 17 to 128 characters to
the string pool when it sees them again soon, and longer strings at once from JDK 24, 21.0.6 and 23.0.2 on. JMC's
writer pools every non-empty string. So the same string is often stored in several places.

## Scanning

`scan` lists the strings of a recording, with how often each is stored inline in events and in constant pools.

```
jfr-redact scan [--top <n>] [--table] [--sort <key>] [--references] [--out <file.tsv>] [--validate] <recording.jfr>
```

| Option | Effect |
|---|---|
| `--top <n>` | Number of strings to print (default 20) |
| `--table` | Print a table, with lengths and reference counts (implies `--references`) |
| `--sort <key>` | `occurrences` (default), `references`, `inlined` or `length` |
| `--references` | Also count the references to the constants holding each string (decodes nearly all events, so slower) |
| `--out <file.tsv>` | Write all strings to a tab separated file |
| `--validate` | Check that every event, including those holding the constant pools, decodes to its declared size |

`scripts/demo.sh [recording.jfr|-] [n] [sort key]` (`scripts\demo.bat` on Windows) prints such a table, by default
for the included WebLogic recording.

## Redacting from the command line

```
jfr-redact redact [--redact-secrets] [--anonymize-user] [--strip-process-arguments]
                  [--hash-thread-names] [--hash-class-names <regex>]... [--hash-method-names <regex>]...
                  [--rename-package <package> <new name>]... [--replace <pattern> <replacement>]...
                  [--match <regex>]... [--replacement <text>] <recording.jfr> <redacted.jfr>
```

Without options, `redact` applies the first three. Given any option, it applies only the options given, so a single
rule can be tried on its own; add the first three to keep them.

| Option | Replaces |
|---|---|
| `--redact-secrets` | With `<REDACTED>`: the values of environment variables and system and security properties whose name says they are secret, by its last part, such as `DB_PASSWORD`, `PGPASSWORD`, `*_API_KEY`, `*_TOKEN`, `SENTRY_DSN` or `keyStorePassword`; and in any string, AWS, GitHub, Slack, Google, Stripe and `sk-` keys, JSON web tokens, private keys, bearer tokens and `Authorization` values, passwords in URLs, and the values of `-Dname=`, `--name=`, `--name value`, `NAME=` and `?name=` with secret names |
| `--anonymize-user` | The home directories (`HOME`, `USERPROFILE`, `user.home`), user names (from keys whose last part ends with `USER`, such as `USER`, `USERNAME`, `P4USER` or `user.name`, and `LOGNAME`) and host names (ending with `CLIENT`, `SERVER`, `DOMAIN`, `HOST` or `COMPUTER`, such as `P4CLIENT`, `LOGONSERVER`, `USERDOMAIN`, `HOSTNAME` or `COMPUTERNAME`) found in the recording's environment variables and system properties, wherever they occur, keeping paths (`/Users/alice/app.log` becomes `/Users/user/app.log`), and e-mail addresses, with `<EMAIL>` |
| `--strip-process-arguments` | The arguments of the command lines in `jdk.SystemProcess` and `jdk.ProcessStart`, with `<REDACTED>`, keeping the executable |
| `--hash-thread-names` | Thread names with `Thread-<hash>`, thread group names with `ThreadGroup-<hash>` |
| `--hash-class-names <regex>` | The matched part (first group, if any) of class, package and module names |
| `--hash-method-names <regex>` | The matched part of method names |
| `--rename-package <package> <new name>` | A package and its subpackages |
| `--replace <pattern> <replacement>` | Strings matching a pattern that may start and end with `*`, which stands for the same text in the replacement, as in `'/home/alice/*' '/home/user/*'` |
| `--match <regex>` | Strings containing a match, with `--replacement` (default `<REDACTED>`) |

Rules are tried in the order given, `--match` last, and the first three options after all of them. A `--replace` whose
replacement has a `*` keeps the rest of the string and passes the result on to the following rules; any other rule
that replaces a string decides. Repeated `--hash-class-names` form one rule. Thread dumps and old-object descriptions
go through the rules in order: each name rule rewrites the names it covers, and the first `--replace` without `*` or
`--match` matching the text so far replaces all of it.

The first three options have limits worth knowing:

- `--redact-secrets` judges a variable or property by its name and a string by known formats. A secret in other free
  text, or in a variable with an unremarkable name, stays. A value replaced as a secret is replaced wherever it is
  stored, so a secret value that is also, say, a setting elsewhere is replaced there too; empty values, `true` and
  `false` are never treated as secrets.
- `--anonymize-user` replaces only what the recording names. HotSpot, from JDK 7 to 25, records the environment
  variables, but of the system properties only those the JVM sets and those given with `-D`, so not `user.home` and
  `user.name`. Windows has no `HOME` and `USER` (`USERPROFILE` and `USERNAME` are read instead), macOS does not export
  `HOSTNAME`, and some recordings, such as those of WebLogic's diagnostic framework, hold no environment variables at
  all. It reports how many it found, and warns when it found none. Names shorter than three characters, and generic account names such as `root`, `java`, `oracle` or
  `localhost`, are not replaced, as they name no person and would rename everything sharing them. Names of classes,
  methods, packages and modules are never changed, and in thread dumps only the thread names are: use
  `--hash-class-names` for code named after a person. Full names, IP addresses and Windows short paths such as
  `C:\Users\ALICE~1` are not covered.
- `--strip-process-arguments` takes the executable to end at a closing quote, after `.exe`, after the executable of a
  macOS application bundle, or else at the first space after the last path separator, before the first argument
  starting with `-`, `/` or a quote. An executable with a space in its last path segment, outside an application
  bundle, keeps the part before the space. The JVM's own arguments, in `jdk.JVMInformation`, are kept, for JMC's rules.

`--hash-class-names` keeps the dots, so every class still starts with its package, as JMC requires:

| Expression | Class | Becomes | Its package becomes |
|---|---|---|---|
| `com\.acme\.(.*)` | `com.acme.secret.Foo` | `com.acme.<hash>.<hash>` | `com.acme.<hash>` |
| `(.*)` | `com.acme.secret.Foo` | `<hash>.<hash>.<hash>.<hash>` | `<hash>.<hash>.<hash>` |
| `(.*)Impl$` | `com.acme.secret.FooImpl` | `com.acme.secret.<hash>Impl` | unchanged |

Class names are also replaced in array class names, method descriptors, thread dumps, old-object descriptions,
`jdk.CompilerInlining` events, and the exception and allocation classes of Datadog's events. A package is matched on
its own, followed by a dot, and only the first match counts, so `(secret)$` changes nothing (write `(secret)\.`).
Class names in free text, such as JVM arguments and exception messages, or in the fields of your own events are not
recognized: reach them with `--replace` or `--match`, and check the result with `jfr-redact scan`.

The hashes are not keyed, so guessable names such as `main` or `util` can be found by hashing guesses. The Java API
has keyed variants, such as `hashClassNames(regex, key)`. The Javadoc of `RuleRedactor.Builder` details every rule.

## Redacting from Java

`JfrRedactor.redact(input, output, redactor)` analyzes the whole recording, then calls
`StringRedactor.redact(value, locations)` once per distinct string. Returning `value` keeps the string, and any other
result replaces every copy of it. `RuleRedactor` provides the command line rules (`replaceMatching` for `--match`,
`redactSecrets`, `anonymizeUser` and `stripProcessArguments` for the first three), plus `replaceIf`,
`replaceEachMatch`, which replaces only the matches within a string, and keyed hashes. `UserIdentity.find(path)` reads
the identity to anonymize from a recording, in a pass of its own; an identity can also be given.

`orElse` chains redactors, but only asks the second about the strings the first keeps unchanged. When the first hashes
the thread names in a thread dump, the second never sees the dump, and the rest of it stays as it was. To scrub
everything, put the rules in one `RuleRedactor`, where each rule sees the result of the rules before it.

A location is the type and field that JMC shows the string in (`getOwner()` and `getField()`), however the writer
stored it, and `isPooled()` tells whether this copy is in a constant pool or inline in an event. Predicates such as
`isClassName()` and `isThreadName()` recognize the JDK's own fields. Examples, as `toString()` prints them:

| String | Location |
|---|---|
| Class name, in internal form such as `java/util/List` | `java.lang.Class.name (pooled)` |
| Method name | `jdk.types.Method.name (pooled)` |
| Thread name | `java.lang.Thread.javaName (pooled)` |
| Thread group name | `jdk.types.ThreadGroup.name (pooled) referred to by java.lang.Thread.group` |
| Thread dump | `jdk.ThreadDump.result (inline)` |
| A field of your own event | `com.acme.Sql.sql (inline)` or, if the JDK pooled the value, `com.acme.Sql.sql (pooled)` |
| A GC cause no event refers to | `jdk.types.GCCause.cause (pooled)` |
| The value of an environment variable | `jdk.InitialEnvironmentVariable.value (inline) for key HOME` |
| Class name in JFR 0.9 | `UTFConstant.utf8 (pooled) referred to by Class.name` |

The value of a type with a `key` field, such as an environment variable or a system property, has its key
(`getKey()`), and predicates such as `isEnvironmentVariableValue()` and `isProcessCommandLine()` recognize the JDK's
fields of this kind. A `replaceIf` rule on the owner and field of your own event catches its inline and pooled values. If a writer pools a
nested type of the event, as JMC's writer does, that type is the owner.

## Guarantees and limits

- Every copy of a replaced string is replaced, in events, constant pools and all chunks, except in the metadata (type,
  field and annotation names and values), which is never rewritten. Redacted strings that also occur there are
  reported in `RedactionResult.redactedInMetadata()`.
- A decision applies to every occurrence of a string: hashing the thread name `main` also renames methods named
  `main`.
- Undeclared event types and values that cannot be decoded while collecting strings fail the redaction, rather than
  risk missing a string. Events that can neither hold nor refer to a string are skipped by their size and copied
  verbatim, without being validated; `scan --validate` checks them.
- A recording that cannot be processed, because it is corrupt or in an unsupported format, fails with the checked
  `InvalidRecordingException`, and an incomplete one, such as a copy of a recording still being written, with its
  subclass `TruncatedRecordingException`. Both are `IOException`s; other `IOException`s are failures to read or write
  the files. Exceptions thrown by your `StringRedactor` are passed on unchanged.
- Input and output must be different files. The output is replaced atomically, and an existing output is left
  untouched on failure.
- The redactor sees every string exactly, including unpaired UTF-16 surrogates.

## Monitoring

The library emits JFR events, in the category JFR Redact, when a recording of the JVM running it enables them:

| Event | Emitted for |
|---|---|
| `se.hirt.jfr.redact.Redaction` | Each redaction, with the input size and the counts of `RedactionResult` |
| `se.hirt.jfr.redact.Phase` | Each phase of a redaction: `Collect`, `Locate`, `Decide`, `Rewrite` and `Publish` |
| `se.hirt.jfr.redact.Chunk` | Each chunk parsed or rewritten, with its size and whether it was rewritten |

The events hold sizes, counts and the names of the phases only, never paths or strings of the recording. Without stack
traces, they cost nothing measurable. The default JFR settings, however, also record the command line, which names
the recordings, the environment variables and the system properties. To record a redaction for sharing, use
`config/jfr-redact.jfc`, which enables the events of the library only:

```
java -XX:StartFlightRecording=filename=redact.jfr,settings=config/jfr-redact.jfc -jar target/jfr-redact-<version>.jar \
    redact --hash-thread-names in.jfr out.jfr
```

The native image supports JFR only if built with `mvn -Pnative,native-jfr package`, which adds
`--enable-monitoring=jfr` and about 9 MB to the binary. It takes the same option:

```
target/jfr-redact -XX:StartFlightRecording=filename=redact.jfr,settings=config/jfr-redact.jfc redact ...
```

Without JFR support, the events cost nothing, and the binary rejects `-XX:StartFlightRecording`. With the profiling
settings, the native image samples execution too; on macOS it takes the samples at safepoints, so the sampler's own
frames top each stack, above the frames of the redaction.

## Test recordings

`src/test/resources/recordings` covers every supported JFR version, written by JRockit, HotSpot and JMC's writer:

| Recording | JFR | Content |
|-----------|-----|---------|
| `jrockit-r28-transitions.jfr` | 0.9 | JRockit R28 test application, with environment variables and system properties |
| `jdk8-guimark.jfr` | 0.9 | JDK 8 running the GUIMark JavaFX benchmark on Windows, with environment variables, system properties and the processes of the machine |
| `jdk9-basic.jfr` | 1.0 | JDK 9 running JConsole, with RMI connection threads |
| `jdk9-weblogic-medrec.jfr` | 1.0 | WebLogic running the MedRec patient records demo, with SQL, servlet and EJB events |
| `jdk21-jmc.jfr` | 2.1 | JDK 21 running JMC, with thread dumps containing hidden-class frames |
| `jmc-writer-pooled.jfr` | 2.0 | Written by JMC's `flightrecorder.writer`, which stores every string in the string pool |

Four come from the JMC test resources (see [NOTICE](NOTICE)), with personal data in two of them replaced using
jfr-redact, `jdk8-guimark.jfr` comes from the JMC tutorial, with the identity of its user and machine replaced by
Alice's on HOST01 using jfr-redact, and `jmc-writer-pooled.jfr` was generated for jfr-redact. The tests redact all of
them, verify the results with
`RedactionVerifier`, which also runs on any recording, and load them with JMC's parser.

## How it works

Redaction makes two passes. The first collects every distinct string with its locations. The second re-encodes only
the events and constant pools that store a replaced string, updates the offsets that moved, and copies everything
else verbatim.

The parser reads one chunk at a time into a reusable buffer, so memory is bounded by the largest chunk, the number of
constants in it and the number of distinct strings: a 74 MB recording with two chunks and two million constants
needs a heap of 256 MB. It compiles the metadata into field programs per type, skips the events it does not need by
their size, and hashes strings from the chunk buffer, so that counting a known string allocates nothing.

## Building

```
mvn package                     # JVM build: java -jar target/jfr-redact-<version>.jar
mvn -Pnative package            # Native image: target/jfr-redact
mvn -Pnative,native-jfr package # Native image with JFR support, see Monitoring
```

The library requires JDK 25 or later, and the native image GraalVM for JDK 25 or later as `JAVA_HOME`.

Spotless checks the formatting in the `validate` phase: tabs, 120-column code and 100-column comments, with the
Eclipse profile in `config/formatter/formatting.xml`. Run `mvn spotless:apply` to format the sources.

## License

BSD 3-Clause, see [LICENSE](LICENSE).

## Acknowledgements

The chunk reader and the streaming chunk parser were inspired by `ChunkReader` and `StreamingChunkParser` in the
[OpenJDK JDK Mission Control](https://github.com/openjdk/jmc) project. See [NOTICE](NOTICE).
