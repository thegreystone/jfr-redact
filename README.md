# JFR Redact

High performance string redaction for JDK Flight Recorder recordings. JFR Redact replaces strings such as thread
names, class names or personal data everywhere they are stored in a recording, and writes a new recording that JDK
Mission Control (JMC) reads like the original.

Supported formats: JFR 0.9 (JDK 7 and 8, JRockit) and JFR 1.0+ with compressed integers (JDK 9+ and 8u262+).

## Quick start

Build with `mvn package` (JDK 21+). Below, `jfr-redact` stands for `java -jar target/jfr-redact-<version>.jar` or the
native image (see [Building](#building)).

```
jfr-redact scan --table --top 30 recording.jfr
jfr-redact redact --hash-thread-names --hash-class-names 'com\.acme\.(.*)' --match 'password' recording.jfr out.jfr
```

The first command lists the most frequent strings. The second hashes thread names and the class and package names
below `com.acme`, and replaces strings containing `password` with `<REDACTED>`. The same from Java, plus a rule for a
field of the application's own event:

```java
StringRedactor redactor = RuleRedactor.builder()
		.hashThreadNames()
		.hashClassNames("com\\.acme\\.(.*)")
		.replaceIf(location -> location.getOwner().equals("com.acme.Login") && location.getField().equals("user"),
				user -> "<USER>")
		.replaceMatching("password", "<REDACTED>")
		.build();
RedactionResult result = JfrRedactor.redact(Path.of("recording.jfr"), Path.of("out.jfr"), redactor);
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
jfr-redact redact [--hash-thread-names] [--hash-class-names <regex>]... [--hash-method-names <regex>]...
                  [--rename-package <package> <new name>]... [--replace <pattern> <replacement>]...
                  [--match <regex>]... [--replacement <text>] <recording.jfr> <redacted.jfr>
```

| Option | Replaces |
|---|---|
| `--hash-thread-names` | Thread names with `Thread-<hash>`, thread group names with `ThreadGroup-<hash>` |
| `--hash-class-names <regex>` | The matched part (first group, if any) of class, package and module names |
| `--hash-method-names <regex>` | The matched part of method names |
| `--rename-package <package> <new name>` | A package and its subpackages |
| `--replace <pattern> <replacement>` | Strings matching a pattern that may start and end with `*`, which stands for the same text in the replacement, as in `'/home/alice/*' '/home/user/*'` |
| `--match <regex>` | Strings containing a match, with `--replacement` (default `<REDACTED>`) |

Rules are tried in the order given, `--match` last, and the first one that replaces a string decides; repeated
`--hash-class-names` form one rule. Thread dumps and old-object descriptions go through the rules in order: each name
rule rewrites the names it covers, and the first `--replace` or `--match` matching the text so far replaces all of it.

`--hash-class-names` keeps the dots, so every class still starts with its package, as JMC requires:

| Expression | Class | Becomes | Its package becomes |
|---|---|---|---|
| `com\.acme\.(.*)` | `com.acme.secret.Foo` | `com.acme.<hash>.<hash>` | `com.acme.<hash>` |
| `(.*)` | `com.acme.secret.Foo` | `<hash>.<hash>.<hash>.<hash>` | `<hash>.<hash>.<hash>` |
| `(.*)Impl$` | `com.acme.secret.FooImpl` | `com.acme.secret.<hash>Impl` | unchanged |

Class names are also replaced in array class names, method descriptors, thread dumps, old-object descriptions and
`jdk.CompilerInlining` events. A package is matched on its own, followed by a dot, and only the first match counts, so
`(secret)$` changes nothing (write `(secret)\.`). Class names in free text, such as JVM arguments and exception
messages, or in the fields of your own events are not recognized: reach them with `--replace` or `--match`, and check
the result with `jfr-redact scan`.

The hashes are not keyed, so guessable names such as `main` or `util` can be found by hashing guesses. The Java API
has keyed variants, such as `hashClassNames(regex, key)`. The Javadoc of `RuleRedactor.Builder` details every rule.

## Redacting from Java

`JfrRedactor.redact(input, output, redactor)` analyzes the whole recording, then calls
`StringRedactor.redact(value, locations)` once per distinct string. Returning `value` keeps the string, and any other
result replaces every copy of it. `RuleRedactor` provides the command line rules (`replaceMatching` for `--match`),
plus `replaceIf` and keyed hashes, and `orElse` chains redactors.

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
| Class name in JFR 0.9 | `UTFConstant.utf8 (pooled) referred to by Class.name` |

A `replaceIf` rule on the owner and field of your own event catches its inline and pooled values. If a writer pools a
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
- Input and output must be different files. The output is replaced atomically, and an existing output is left
  untouched on failure.
- The redactor sees every string exactly, including unpaired UTF-16 surrogates.

## Test recordings

`src/test/resources/recordings` covers every supported JFR version, written by JRockit, HotSpot and JMC's writer:

| Recording | JFR | Content |
|-----------|-----|---------|
| `jrockit-r28-transitions.jfr` | 0.9 | JRockit R28 test application, with environment variables and system properties |
| `jdk9-basic.jfr` | 1.0 | JDK 9 running JConsole, with RMI connection threads |
| `jdk9-weblogic-medrec.jfr` | 1.0 | WebLogic running the MedRec patient records demo, with SQL, servlet and EJB events |
| `jdk21-jmc.jfr` | 2.1 | JDK 21 running JMC, with thread dumps containing hidden-class frames |
| `jmc-writer-pooled.jfr` | 2.0 | Written by JMC's `flightrecorder.writer`, which stores every string in the string pool |

The first four come from the JMC test resources (see [NOTICE](NOTICE)), with personal data in two of them replaced
using jfr-redact; the last was generated for jfr-redact. The tests redact all of them, verify the results with
`RedactionVerifier`, which also runs on any recording, and load them with JMC's parser.

## How it works

Redaction makes two passes. The first collects every distinct string with its locations. The second re-encodes only
the events and constant pools that store a replaced string, updates the offsets that moved, and copies everything
else verbatim.

The parser reads one chunk at a time into a reusable buffer, so memory is bounded by the largest chunk and the number
of distinct strings. It compiles the metadata into field programs per type, skips the events it does not need by
their size, and hashes strings from the chunk buffer, so that counting a known string allocates nothing.

## Building

```
mvn package                 # JVM build: java -jar target/jfr-redact-<version>.jar
mvn -Pnative package        # Native image: target/jfr-redact (requires GraalVM as JAVA_HOME)
```

Spotless checks the formatting in the `validate` phase: tabs, 120-column code and 100-column comments, with the
Eclipse profile in `config/formatter/jmc-jev-mcp-formatting.xml`. Run `mvn spotless:apply` to format the sources.

## License

BSD 3-Clause, see [LICENSE](LICENSE).

## Acknowledgements

The chunk reader and the streaming chunk parser were inspired by `ChunkReader` and `StreamingChunkParser` in the
[OpenJDK JDK Mission Control](https://github.com/openjdk/jmc) project. See [NOTICE](NOTICE).
