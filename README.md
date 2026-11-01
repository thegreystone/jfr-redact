# JFR Redact

High performance string redaction for JDK Flight Recorder recordings.

Strings in a JFR recording do not only live in the constant pools. A string can be written inline in an event, as an
entry in the `java.lang.String` constant pool, or inline in another constant pool entry (for example the
`jdk.types.Symbol` entries that hold method and class names). The JDK event writer also inlines a string the first few
times it is seen and only later moves it to the constant pool, so the same string commonly appears in both places.

## Status

Supported formats are JFR 0.9 (JDK 7 and 8) and JFR 1.0+ with compressed integers (JDK 11+ and 8u262+). In JFR 0.9
there is no string constant pool, so strings are always written in full, in events or in constant pool entries.

The first pass, `scan`, walks a recording and reports every string stored in it, with the number of times it is stored
inline in events and inside constant pools.

```
jfr-redact scan [--top <n>] [--table] [--sort <occurrences|references|inlined|length>] [--references] [--out <file.tsv>] [--validate] <recording.jfr>
```

`--references` also counts the direct references to the constants containing each string, from events and from other
constants (for example a method constant referring to its name). This decodes nearly all events, roughly 1.5-2x the
cost of a plain scan, and is implied by `--table`. Without it, the scan is unaffected.

Strings are sorted in descending order by stored occurrences by default. `--sort` selects the ranking for both the
printed strings and TSV output, with occurrences breaking ties:

- `occurrences`: total stored occurrences (the default).
- `references`: direct references to the constants containing each string; implies `--references`.
- `inlined`: occurrences stored inline in events, matching the table's Inlined column.
- `length`: Unicode code point count, matching the table's Length column; longest first.

For example:

```
jfr-redact scan --table --sort references --top 30 recording.jfr
```

`scripts/demo.sh [recording.jfr|-] [n] [occurrences|references|inlined|length]` shows the top strings as a table. On Windows,
use `scripts\demo.bat` with the same arguments. The scripts use the native image if built, otherwise the jar. If neither
is available, they build the jar with Maven.
With no recording supplied, it uses the included WebLogic (WLDF) MedRec recording,
`src/test/resources/recordings/jdk9-weblogic-medrec.jfr`. The default number of strings is 30.
To sort the included recording by references, start with the row count: `scripts/demo.sh 30 references`, or
`scripts\demo.bat 30 references` on Windows, including PowerShell. You can also use `-` explicitly in place of a
recording path: `scripts\demo.bat - 30 references`.
Replace `references` with `inlined` or `length` to sort by either of those columns.

## Redaction

`JfrRedactor.redact(input, output, redactor)` writes a copy of a recording with strings replaced. The
`StringRedactor` is called once per distinct string, after the whole recording has been analyzed, with every location
the string is stored at: the event or constant pool type, the field, and for constants the fields of other constants
referring to it (a method name is a `jdk.types.Symbol` referred to by `jdk.types.Method.name`). Its decision applies to
every occurrence of the string, inline in events, in constant pools and in all chunks, so no copy of a redacted string
remains. The one exception is the metadata (type, field and annotation names and values), which is not redacted:
redacted strings that also occur there, as whole strings or within longer strings, are reported in the result.

Redaction rejects undeclared event types and payloads it cannot decode when collecting strings. Event types that
cannot contain inline strings are skipped using their declared event sizes and copied verbatim; their payloads are
not validated. Strings in constant pools are processed separately, including those referenced by skipped events.

Input and output must be different files, including through hard links or symbolic links. The result is written to
a temporary file beside the output and atomically replaces it after successful processing. Failed processing leaves
an existing output untouched; the output filesystem must support atomic replacement.

Glob replacements (`--replace`) also apply to whole thread dumps and old-object descriptions. Specialized rules
rewrite embedded names in rule order; the first matching whole-string rule replaces the current value and stops
further processing. The same behavior applies to `RuleRedactor.Builder.replaceIf`.

`--hash-thread-names` replaces thread names with `Thread-<hash>`, as constants, in the headers and lock owners of
thread dumps and in the `Thread Name:` of old-object descriptions, and thread group names with `ThreadGroup-<hash>`,
as constants and in the `Thread Group:` of old-object descriptions, since group names such as
`Thread Group for Queue: 'weblogic.socket.Muxer'` mirror the thread names being hidden. A name that is both is
replaced as a thread name. The groups the JVM creates itself, `system` and `main`, name nothing of the application
and are left alone unless they are also thread names. The empty name of an unnamed virtual thread is not a thread
name and is left to later rules. Names stored through the `java.lang.String` constant pool, as JDK Mission Control's
`flightrecorder.writer` does, are recognized by the thread or thread group field referring to them.

`--hash-class-names` replaces the part of class names matching a regular expression with a hash, segment by segment:
as constants, in array class names and method descriptors, in the frames of thread dumps together with their source
file names and the bare class names HotSpot prints as the location of generated classes, in the lock objects of
thread dumps (`(a X)`, `(object ..., a X)`, `(a java.lang.Class for X)` and `Class initialization monitor for X`), in
the `Class Name:` of old-object descriptions and in the inline class names and descriptors of `jdk.CompilerInlining`
events. Dots are never replaced, and the package of a class is hashed as a package name: the expression is matched
against the package name followed by a dot, as it appears in the class name, and the matched segments are hashed
wherever the package is stored, in the `jdk.types.Package` constants, in the package part of class names and
descriptors, in the `jdk.types.Module` names and in the module segment of thread dump frames (`java.base@21/`). So
every class name still starts with the name of its package, which JDK Mission Control relies on to derive simple
class names. With `com\.acme\.(.*)`, `com.acme.secret.Foo` becomes `com.acme.<hash>.<hash>` and its package
`com.acme.secret` becomes `com.acme.<hash>`; with `(.*)` every segment of every class, package and module name is
hashed; with `(.*)Impl$` only the simple name is hashed, `com.acme.secret.<hash>Impl`, and the package stays, since
the expression does not match it (the recording stored it readably on its own anyway). Prefix expressions such as
`com\.acme\.(.*)` or `(.*)` are the way to hide packages. Only the first match of an expression counts, so a literal
found in the package before the simple name, as `Secret` in `com.acme.Secret.SecretService`, leaves the simple name
alone; an expression anchored to the end of the name, such as `Secret[^.]*$`, hashes the simple name instead. Two kinds
of expression change nothing: one whose group covers package segments only while the rest of it requires the simple
name, as in `(com\.acme)\.secret\.Foo`, since the package is matched on its own, and one anchored to the end of a
package name, as in `(secret)$`, since the package is followed by a dot; end it with the dot instead, as in
`(secret)\.`. Several expressions form one rule, in the place of the first, and for each part of a name, the package or
the simple name, the first expression covering a piece of it decides, so that the package part of a class, the constant
of its package and the name of its module always agree: with `com\.acme\.(.*)` followed by `(.*)`, `com.acme.secret.Foo`
becomes `com.acme.<hash>.<hash>` and `org.other.Bar` becomes `<hash>.<hash>.<hash>`. Since segments are hashed one by
one, a
short and common segment such as `impl` or `util` is easy to guess from its unkeyed hash, which is the same in every
package it occurs in; the library's `hashClassNames(regex, key)` hashes with a secret key, which the command line does
not offer yet. Primitive arrays are unchanged. A hidden class such as
`com.acme.Foo$$Lambda/0x00007fb87c2252f8` is hashed by its host class, `com.acme.Foo$$Lambda`, and keeps the address
or identity hash the JVM appends in each run, so its frames and its class constant get the same hash, and from JDK 21
on the same hash in every run (JDK 8 to 20 number their lambda proxy classes per run, as in `Foo$$Lambda$269` and
`Foo$$Lambda$14`). Module locations (`jrt:/jdk.jfr`), JVM arguments, exception messages and other free text naming
classes or packages are not touched. `--hash-method-names` also rewrites the frames of thread dumps and the inline
method names of `jdk.CompilerInlining` events.

Strings are decoded according to their recording encoding, preserving UTF-16 code units, including unpaired
surrogates in char-array values. Replacements containing unpaired surrogates use JFR's char-array encoding where
available. Fixed UTF-8 fields in JFR 0.9 reject replacements they cannot represent. TSV output escapes unpaired
surrogates as `\uXXXX` to preserve them in UTF-8 text.

```
jfr-redact redact --match <regex> [--match <regex>]... [--replacement <text>] <recording.jfr> <redacted.jfr>
```

`RedactionVerifier` in the test sources redacts any recording aggressively and verifies the result independently. Its
`checkClassPackageInvariant` checks that every class name of a recording starts with the name of its package, which
`--hash-class-names` keeps and the aggressive redaction does not; `FixtureTest` runs it on the redacted test
recordings, and `JmcCompatibilityTest` loads them with JDK Mission Control's parser (`org.openjdk.jmc:flightrecorder`,
a test dependency), which relies on that.

## Test recordings

`src/test/resources/recordings` has one recording per supported JFR version, and one from a writer other than
HotSpot, used by the tests and examples:

| Recording | JFR | Content |
|-----------|-----|---------|
| `jrockit-r28-transitions.jfr` | 0.9 | JRockit R28 test application, with environment variables and system properties |
| `jdk9-basic.jfr` | 1.0 | JDK 9 running JConsole, with RMI connection threads |
| `jdk9-weblogic-medrec.jfr` | 1.0 | WebLogic running the MedRec patient records demo, with SQL, servlet and EJB events |
| `jdk21-jmc.jfr` | 2.1 | JDK 21 running JDK Mission Control, with thread dumps containing hidden-class frames |
| `jmc-writer-pooled.jfr` | 2.0 | Written by JMC's pure-Java `flightrecorder.writer`, storing thread, class and thread group names through the `java.lang.String` constant pool |

The first four come from the JDK Mission Control test resources, see [NOTICE](NOTICE). Personal data in two of them
was replaced with jfr-redact itself, using the `ScrubPersonalData` example. The last one was generated for jfr-redact
with the writer library of the same project. `RedactPatientData` shows a redaction of the MedRec recording:

```java
StringRedactor redactor = RuleRedactor.builder()
		.hashThreadNames()
		.hashClassNames("com\\.bea\\.medrec\\.(.*)")
		.build()
		.orElse((value, locations) -> EMAIL.matcher(value).replaceAll("<EMAIL>"));
JfrRedactor.redact(Path.of("jdk9-weblogic-medrec.jfr"), Path.of("redacted.jfr"), redactor);
```

## How it works

The parser is a streaming chunk parser that decodes checkpoints and event fields:

- One chunk at a time is read into a reusable buffer, so memory is bounded by the largest chunk, not the recording.
- The chunk metadata is compiled into int-encoded field programs per type; types that cannot reach an inline string
  are skipped in one jump using the event size.
- Strings are hashed directly from the chunk buffer into an open addressing map keyed on UTF-8 bytes. Latin-1 and char
  array encoded strings are transcoded so that all encodings of the same string count as one. Counting a known string
  allocates nothing.

`--validate` decodes every event and verifies that each event and checkpoint decodes to exactly its declared size.

## Building

```
mvn package                 # JVM build: java -jar target/jfr-redact-<version>.jar
mvn -Pnative package        # Native image: target/jfr-redact (requires GraalVM as JAVA_HOME)
```

Spotless checks Java formatting during Maven's `validate` phase, so normal builds enforce it. Run
`mvn spotless:apply` to format the sources or `mvn spotless:check` to check them. It uses the same Eclipse formatter
profile as `jmc-jev-mcp`, copied unchanged into `config/formatter/jmc-jev-mcp-formatting.xml`: one tab per indentation
level, 120-column code and 100-column comments.

## License

BSD 3-Clause, see [LICENSE](LICENSE).

## Acknowledgements

The streaming chunk parser was inspired by the one in the [OpenJDK JDK Mission Control](https://github.com/openjdk/jmc)
project. See [NOTICE](NOTICE).
