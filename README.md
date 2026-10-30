# JFR Redact

Low-cost string redaction for JDK Flight Recorder recordings.

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
jfr-redact scan [--top <n>] [--table] [--out <file.tsv>] [--validate] <recording.jfr>
```

`scripts/demo.sh <recording.jfr> [n]` shows the top strings as a table, using the native image if built, otherwise
the jar.

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

## License

BSD 3-Clause, see [LICENSE](LICENSE).

## Acknowledgements

The streaming chunk parser was inspired by the one in the [OpenJDK JDK Mission Control](https://github.com/openjdk/jmc)
project. See [NOTICE](NOTICE).
