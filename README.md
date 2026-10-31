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

Redaction refuses recordings it cannot fully decode, such as ones with events of undeclared types, rather than risk
leaving strings it could not see.

Input and output must be different files, including through hard links or symbolic links. The result is written to
a temporary file beside the output and atomically replaces it after successful processing. Failed processing leaves
an existing output untouched; the output filesystem must support atomic replacement.

Glob replacements (`--replace`) also apply to whole thread dumps and old-object descriptions. Specialized rules
rewrite embedded names in rule order; the first matching whole-string rule replaces the current value and stops
further processing. The same behavior applies to `RuleRedactor.Builder.replaceIf`.

Strings are decoded according to their recording encoding, preserving UTF-16 code units, including unpaired
surrogates in char-array values. Replacements containing unpaired surrogates use JFR's char-array encoding where
available. Fixed UTF-8 fields in JFR 0.9 reject replacements they cannot represent. TSV output escapes unpaired
surrogates as `\uXXXX` to preserve them in UTF-8 text.

```
jfr-redact redact --match <regex> [--match <regex>]... [--replacement <text>] <recording.jfr> <redacted.jfr>
```

`RedactionVerifier` in the test sources redacts any recording aggressively and verifies the result independently.

## Test recordings

`src/test/resources/recordings` has one recording per supported JFR version, used by the tests and examples:

| Recording | JFR | Content |
|-----------|-----|---------|
| `jrockit-r28-transitions.jfr` | 0.9 | JRockit R28 test application, with environment variables and system properties |
| `jdk9-basic.jfr` | 1.0 | JDK 9 running JConsole, with RMI connection threads |
| `jdk9-weblogic-medrec.jfr` | 1.0 | WebLogic running the MedRec patient records demo, with SQL, servlet and EJB events |
| `jdk21-jmc.jfr` | 2.1 | JDK 21 running JDK Mission Control, with thread dumps |

They come from the JDK Mission Control test resources, see [NOTICE](NOTICE). Personal data in two of them was
replaced with jfr-redact itself, using the `ScrubPersonalData` example. `RedactPatientData` shows a redaction of the
MedRec recording:

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
