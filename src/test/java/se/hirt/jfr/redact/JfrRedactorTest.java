/*
 * Copyright (C) 2026 Marcus Hirt
 *
 * This software is free:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESSED OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package se.hirt.jfr.redact;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jdk.jfr.Configuration;
import jdk.jfr.Event;
import jdk.jfr.Name;
import jdk.jfr.Recording;
import jdk.jfr.StackTrace;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import se.hirt.jfr.redact.parser.StreamingChunkParser;
import se.hirt.jfr.redact.scan.StringCountMap;
import se.hirt.jfr.redact.scan.StringScanner;

class JfrRedactorTest {
	private static final String SECRET = "jdbc:secret://db.internal.example.com:5432/patients";
	private static final String UNIQUE_SECRET = "a unique secret that only occurs once in the recording";

	@Name("test.Query")
	@StackTrace(true)
	static class QueryEvent extends Event {
		String sql;
		String url;
	}

	@Test
	void redactsEverywhereAndKeepsEverythingElse(@TempDir
	Path dir) throws Exception {
		Path input = record(dir.resolve("input.jfr"));
		Path output = dir.resolve("output.jfr");
		Map<String, String> replacements = new LinkedHashMap<>();
		replacements.put(SECRET, "<URL>");
		replacements.put(UNIQUE_SECRET, "<A MUCH LONGER REPLACEMENT THAN THE ORIGINAL STRING, TO MAKE SIZES GROW>");
		replacements.put("executeQueries", "m1");

		RedactionResult result = JfrRedactor.redact(input, output,
				(value, locations) -> replacements.getOrDefault(value, value));
		assertEquals(3, result.redactedStringCount());

		List<String> expected = new ArrayList<>();
		for (RecordedEvent event : RecordingFile.readAllEvents(input)) {
			String text = event.toString();
			for (Map.Entry<String, String> r : replacements.entrySet()) {
				text = text.replace(r.getKey(), r.getValue());
			}
			expected.add(text);
		}
		List<String> actual = new ArrayList<>();
		for (RecordedEvent event : RecordingFile.readAllEvents(output)) {
			actual.add(event.toString());
		}
		assertEquals(expected, actual, "the JDK reads the same events, with only the strings replaced");

		byte[] bytes = Files.readAllBytes(output);
		String raw = new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
		assertTrue(!raw.contains(SECRET) && !raw.contains(UNIQUE_SECRET) && !raw.contains("executeQueries"),
				"no copy of a redacted string remains");
	}

	@Test
	void passesVerification(@TempDir
	Path dir) throws Exception {
		Path input = record(dir.resolve("input.jfr"));
		List<String> problems = RedactionVerifier.verify(input, dir.resolve("output.jfr"),
				RedactionVerifier.aggressive(4), true);
		assertEquals(List.of(), problems);
	}

	@Test
	void identifiesMethodNamesByReferrer(@TempDir
	Path dir) throws Exception {
		Path input = record(dir.resolve("input.jfr"));
		List<String> methodNames = new ArrayList<>();
		JfrRedactor.redact(input, dir.resolve("output.jfr"), (value, locations) -> {
			for (StringLocation location : locations) {
				if (location.isMethodName()) {
					methodNames.add(value);
				}
			}
			return value;
		});
		assertTrue(methodNames.contains("executeQueries"), methodNames.toString());
		assertTrue(!methodNames.contains(SECRET));
	}

	@Test
	void reportsStringsAlsoInMetadata(@TempDir
	Path dir) throws Exception {
		Path input = record(dir.resolve("input.jfr"));
		RedactionResult result = JfrRedactor.redact(input, dir.resolve("output.jfr"),
				(value, locations) -> locations.contains(StringLocation.METADATA) ? "<M>" : value);
		assertTrue(result.redactedStringCount() > 0);
		assertEquals(result.redactedStringCount(), result.redactedInMetadata().size());
	}

	@Test
	void keepingEverythingCopiesTheRecording(@TempDir
	Path dir) throws Exception {
		Path input = record(dir.resolve("input.jfr"));
		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output, (value, locations) -> value);
		assertEquals(0, result.redactedStringCount());
		assertArrayEquals(Files.readAllBytes(input), Files.readAllBytes(output));
	}

	@Test
	void preservesExactJavaStringsWhenRedactingSurrogates(@TempDir
	Path dir) throws Exception {
		String prefix = "exact-string-secret-";
		List<String> secrets = List.of(prefix + "middle-\uD800-tail", prefix + "middle-\uDC00-tail",
				prefix + "end-\uD800", prefix + "end-\uDC00", "\uD800" + prefix + "start", "\uDC00" + prefix + "start");
		List<String> values = new ArrayList<>(secrets);
		values.addAll(List.of(prefix + "middle-\uFFFD-tail", prefix + "middle-?-tail",
				prefix + "middle-\uD800\uDC00-tail", prefix + "middle-\u0000-tail"));
		Path input = dir.resolve("surrogates-input.jfr");
		List<String> emitted = new ArrayList<>();
		try (Recording recording = new Recording()) {
			recording.enable(ExactStringEvent.class);
			recording.start();
			for (String value : values) {
				for (int i = 0; i < 100; i++) {
					ExactStringEvent event = new ExactStringEvent();
					event.value = value;
					event.commit();
					emitted.add(value);
				}
			}
			recording.stop();
			recording.dump(input);
		}
		List<String> read = exactStringValues(input);
		assertEquals(emitted.size(), read.size());
		Map<String, Integer> expectedCounts = new LinkedHashMap<>();
		Map<String, Integer> recordedCounts = new LinkedHashMap<>();
		for (String value : emitted) {
			expectedCounts.merge(codeUnits(value), 1, Integer::sum);
		}
		for (String value : read) {
			recordedCounts.merge(codeUnits(value), 1, Integer::sum);
		}
		assertEquals(expectedCounts, recordedCounts, "the JDK must preserve every exact value and occurrence count");
		StringScanner scanner = new StringScanner(true, true);
		new StreamingChunkParser().parse(input, scanner);
		StringCountMap strings = scanner.getStrings();
		assertEquals(0, scanner.getMisalignedCount());
		for (int i = 0; i < values.size(); i++) {
			String value = values.get(i);
			int entry = strings.indexOf(value);
			assertTrue(entry >= 0, "missing original value " + i);
			assertEquals(codeUnits(value), codeUnits(strings.getString(entry)), "exact original value " + i);
			assertTrue(strings.getCount(entry, StringScanner.INLINE) > 0, "inlined original value " + i);
			assertTrue(strings.getCount(entry, StringScanner.CONSTANT_POOL) > 0, "pooled original value " + i);
			assertEquals(100, strings.getCount(entry, StringScanner.INLINE) + strings.getReferenceCount(entry),
					"every event must store or reference original value " + i);
		}
		Map<String, String> replacements = new LinkedHashMap<>();
		for (String secret : secrets) {
			replacements.put(secret, secret.replace(prefix, "redacted-value-"));
		}
		Map<String, Integer> calls = new LinkedHashMap<>();
		Path output = dir.resolve("surrogates-output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output, (value, locations) -> {
			if (values.contains(value)) {
				calls.merge(value, 1, Integer::sum);
			}
			return replacements.getOrDefault(value, value);
		});
		assertEquals(secrets.size(), result.redactedStringCount());
		assertEquals(values.size(), calls.size());
		for (int i = 0; i < values.size(); i++) {
			assertEquals(1, calls.getOrDefault(values.get(i), 0).intValue(), "one callback for original value " + i);
		}
		assertEquals(
				read.stream().map(value -> replacements.getOrDefault(value, value)).map(JfrRedactorTest::codeUnits)
						.toList(),
				exactStringValues(output).stream().map(JfrRedactorTest::codeUnits).toList(),
				"lone-surrogate replacements must round-trip and controls must remain exact");
	}

	@Name("test.ExactString")
	@StackTrace(false)
	static class ExactStringEvent extends Event {
		String value;
	}

	private static List<String> exactStringValues(Path file) throws Exception {
		return RecordingFile.readAllEvents(file).stream()
				.filter(event -> event.getEventType().getName().equals("test.ExactString"))
				.map(event -> event.getString("value")).toList();
	}

	private static String codeUnits(String value) {
		return value.chars().mapToObj(c -> String.format("%04X", c)).reduce((left, right) -> left + " " + right)
				.orElse("");
	}

	@ParameterizedTest
	@ValueSource(booleans = {false, true})
	void rejectsSameInputAndOutputWithoutChangingIt(boolean changed, @TempDir
	Path dir) throws Exception {
		Path input = Files.copy(fixture("jdk9-basic.jfr"), dir.resolve("input.jfr"));
		assertAliasRejected(input, input, changed, dir);
	}

	@ParameterizedTest
	@ValueSource(booleans = {false, true})
	void rejectsHardLinkToInputWithoutChangingIt(boolean changed, @TempDir
	Path dir) throws Exception {
		Path input = Files.copy(fixture("jdk9-basic.jfr"), dir.resolve("input.jfr"));
		Path output = dir.resolve("hard-link.jfr");
		try {
			Files.createLink(output, input);
		} catch (UnsupportedOperationException | FileSystemException | SecurityException e) {
			assumeTrue(false, "Hard links are unavailable: " + e);
		}
		assertAliasRejected(input, output, changed, dir);
	}

	@ParameterizedTest
	@ValueSource(booleans = {false, true})
	void rejectsSymbolicLinkToInputWithoutChangingIt(boolean changed, @TempDir
	Path dir) throws Exception {
		Path input = Files.copy(fixture("jdk9-basic.jfr"), dir.resolve("input.jfr"));
		Path output = dir.resolve("symbolic-link.jfr");
		try {
			Files.createSymbolicLink(output, input.getFileName());
		} catch (UnsupportedOperationException | FileSystemException | SecurityException e) {
			assumeTrue(false, "Symbolic links are unavailable: " + e);
		}
		assertAliasRejected(input, output, changed, dir);
	}

	@ParameterizedTest
	@ValueSource(booleans = {false, true})
	void failedRewritePreservesOutputAndCleansTemporaryFiles(boolean existingOutput, @TempDir
	Path dir) throws Exception {
		Path input = Files.copy(fixture("jrockit-r28-transitions.jfr"), dir.resolve("input.jfr"));
		Path output = dir.resolve("output.jfr");
		byte[] original = Files.readAllBytes(input);
		byte[] previousOutput = {1, 2, 3, 4};
		if (existingOutput) {
			Files.write(output, previousOutput);
		}
		List<String> before = fileNames(dir);
		String oversized = "X".repeat(65536);
		IOException failure = assertThrows(IOException.class,
				() -> JfrRedactor.redact(input, output, (value, locations) -> oversized));
		assertTrue(failure.getMessage().contains("Replacement too long for a JFR 0.9 string"));
		assertArrayEquals(original, Files.readAllBytes(input));
		if (existingOutput) {
			assertArrayEquals(previousOutput, Files.readAllBytes(output));
		} else {
			assertFalse(Files.exists(output));
		}
		assertEquals(before, fileNames(dir), "failed redaction must leave no temporary files");
	}

	@Test
	void rejectsUnpairedSurrogatesInLegacyUtf8WithoutChangingOutput(@TempDir
	Path dir) throws Exception {
		Path input = Files.copy(fixture("jrockit-r28-transitions.jfr"), dir.resolve("input.jfr"));
		Path output = dir.resolve("output.jfr");
		byte[] original = Files.readAllBytes(input);
		byte[] previousOutput = {1, 2, 3, 4};
		Files.write(output, previousOutput);
		List<String> before = fileNames(dir);
		IOException failure = assertThrows(IOException.class,
				() -> JfrRedactor.redact(input, output, (value, locations) -> "replacement\uD800"));
		assertTrue(failure.getMessage().contains("surrogate"), failure.getMessage());
		assertArrayEquals(original, Files.readAllBytes(input));
		assertArrayEquals(previousOutput, Files.readAllBytes(output));
		assertEquals(before, fileNames(dir), "unsupported legacy encoding must leave no temporary files");
	}

	@ParameterizedTest
	@ValueSource(booleans = {false, true})
	void replacesExistingOutputOnlyAfterSuccess(boolean changed, @TempDir
	Path dir) throws Exception {
		Path input = Files.copy(fixture("jdk9-basic.jfr"), dir.resolve("input.jfr"));
		Path output = dir.resolve("output.jfr");
		byte[] original = Files.readAllBytes(input);
		Files.write(output, new byte[] {1, 2, 3, 4});
		List<String> before = fileNames(dir);
		RedactionResult result = JfrRedactor.redact(input, output, replacement(changed));
		assertArrayEquals(original, Files.readAllBytes(input));
		if (changed) {
			assertTrue(result.redactedStringCount() > 0);
			assertFalse(Arrays.equals(original, Files.readAllBytes(output)));
			assertEquals(RecordingFile.readAllEvents(input).size(), RecordingFile.readAllEvents(output).size());
		} else {
			assertEquals(0, result.redactedStringCount());
			assertArrayEquals(original, Files.readAllBytes(output));
		}
		assertEquals(before, fileNames(dir), "successful redaction must leave no temporary files");
	}

	@ParameterizedTest
	@ValueSource(booleans = {false, true})
	void failedPublicationPreservesDestinationAndCleansTemporaryFiles(boolean changed, @TempDir
	Path dir) throws Exception {
		Path input = Files.copy(fixture("jdk9-basic.jfr"), dir.resolve("input.jfr"));
		byte[] original = Files.readAllBytes(input);
		Path output = Files.createDirectory(dir.resolve("output.jfr"));
		byte[] previous = {1, 2, 3, 4};
		Path existing = Files.write(output.resolve("keep"), previous);
		List<String> before = fileNames(dir);
		assertThrows(IOException.class, () -> JfrRedactor.redact(input, output, replacement(changed)));
		assertArrayEquals(original, Files.readAllBytes(input));
		assertArrayEquals(previous, Files.readAllBytes(existing));
		assertEquals(before, fileNames(dir), "failed publication must leave no temporary files");
	}

	private static void assertAliasRejected(Path input, Path output, boolean changed, Path dir) throws Exception {
		byte[] original = Files.readAllBytes(input);
		List<String> before = fileNames(dir);
		assertThrows(IOException.class, () -> JfrRedactor.redact(input, output, replacement(changed)));
		assertArrayEquals(original, Files.readAllBytes(input));
		assertArrayEquals(original, Files.readAllBytes(output));
		assertTrue(Files.isSameFile(input, output), "rejection must preserve the alias itself");
		assertEquals(before, fileNames(dir));
	}

	private static StringRedactor replacement(boolean changed) {
		return (value, locations) -> changed ? "<REDACTED>" : value;
	}

	private static Path fixture(String name) throws Exception {
		return Path.of(JfrRedactorTest.class.getResource("/recordings/" + name).toURI());
	}

	private static List<String> fileNames(Path dir) throws IOException {
		try (var files = Files.list(dir)) {
			return files.map(path -> path.getFileName().toString()).sorted().toList();
		}
	}

	private static Path record(Path file) throws Exception {
		try (Recording recording = new Recording(Configuration.getConfiguration("default"))) {
			recording.enable(QueryEvent.class);
			recording.start();
			executeQueries();
			recording.stop();
			recording.dump(file);
		}
		return file;
	}

	private static void executeQueries() {
		for (int i = 0; i < 500; i++) {
			QueryEvent event = new QueryEvent();
			event.sql = "SELECT * FROM patients WHERE id = " + (i % 10);
			event.url = SECRET;
			event.commit();
		}
		QueryEvent unique = new QueryEvent();
		unique.sql = UNIQUE_SECRET;
		unique.commit();
	}
}
