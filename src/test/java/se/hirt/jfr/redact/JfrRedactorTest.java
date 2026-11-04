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
import java.nio.channels.FileChannel;
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
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import jdk.jfr.Configuration;
import jdk.jfr.Description;
import jdk.jfr.Event;
import jdk.jfr.Name;
import jdk.jfr.Recording;
import jdk.jfr.StackTrace;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import se.hirt.jfr.redact.parser.ChunkReader;
import se.hirt.jfr.redact.parser.ChunkTypes;
import se.hirt.jfr.redact.parser.RecordingStream;
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

	/** A method name is the value of {@code jdk.types.Method.name}, through its symbol */
	@Test
	void identifiesMethodNamesByTheirField(@TempDir
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
	void reportsRedactedSubstringsInsideLongerMetadataStrings(@TempDir
	Path dir) throws Exception {
		String secret = "recording-secret-abc";
		String differentCase = "RECORDING-SECRET-ABC";
		String absent = "unmentioned-recording-secret";
		List<String> values = List.of(secret, secret, differentCase, absent, "");
		Path input = dir.resolve("metadata-substring-input.jfr");
		try (Recording recording = new Recording()) {
			recording.enable(MetadataSubstringEvent.class);
			recording.start();
			for (String value : values) {
				MetadataSubstringEvent event = new MetadataSubstringEvent();
				event.value = value;
				event.commit();
			}
			recording.stop();
			recording.dump(input);
		}
		List<String> metadata = metadataStrings(input);
		assertFalse(metadata.contains(secret), "the secret must occur only inside a longer metadata string");
		assertTrue(metadata.contains("prefix " + secret + " suffix"));
		Map<String, Integer> calls = new LinkedHashMap<>();
		Map<String, Boolean> metadataLocations = new LinkedHashMap<>();
		Path output = dir.resolve("metadata-substring-output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output, (value, locations) -> {
			if (!values.contains(value)) {
				return value;
			}
			calls.merge(value, 1, Integer::sum);
			metadataLocations.put(value, locations.contains(StringLocation.METADATA));
			return "<REDACTED>";
		});
		assertEquals(Map.of(secret, 1, differentCase, 1, absent, 1, "", 1), calls);
		assertEquals(Map.of(secret, true, differentCase, false, absent, false, "", metadata.contains("")),
				metadataLocations, "empty values match only an actual empty metadata string");
		assertEquals(4, result.redactedStringCount());
		List<String> warnings = new ArrayList<>(List.of(secret));
		if (metadata.contains("")) {
			warnings.add("");
		}
		assertEquals(warnings.stream().sorted().toList(), result.redactedInMetadata().stream().sorted().toList(),
				"repeated values must be reported only once");
		List<RecordedEvent> events = RecordingFile.readAllEvents(output).stream()
				.filter(event -> event.getEventType().getName().equals("test.MetadataSubstring")).toList();
		assertEquals(values.size(), events.size());
		for (RecordedEvent event : events) {
			assertEquals("<REDACTED>", event.getString("value"));
			assertEquals("prefix " + secret + " suffix", event.getEventType().getDescription(),
					"metadata stays unchanged and the leftover substring must be reported");
		}
	}

	@Name("test.MetadataSubstring")
	@Description("prefix recording-secret-abc suffix")
	@StackTrace(false)
	static class MetadataSubstringEvent extends Event {
		String value;
	}

	private static List<String> metadataStrings(Path file) throws IOException {
		List<String> strings = new ArrayList<>();
		try (FileChannel channel = FileChannel.open(file)) {
			ChunkReader reader = new ChunkReader();
			reader.reset(channel);
			while (reader.next()) {
				strings.addAll(Arrays.asList(reader.types().getMetadataStrings()));
			}
		}
		return strings;
	}

	@ParameterizedTest
	@CsvSource({"jdk9-basic.jfr, 1, false", "jdk9-basic.jfr, 1, true", "jdk9-weblogic-medrec.jfr, 2, false",
			"jdk9-weblogic-medrec.jfr, 2, true", "jdk8-guimark.jfr, 1, false"})
	void keepingEverythingCopiesTheRecording(String name, int chunks, boolean equalNewString, @TempDir
	Path dir) throws Exception {
		Path input = fixture(name);
		byte[] original = Files.readAllBytes(input);
		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output,
				(value, locations) -> equalNewString ? new String(value) : value);
		assertEquals(chunks, result.chunkCount());
		assertTrue(result.stringCount() > 0);
		assertEquals(0, result.redactedStringCount());
		assertEquals(0, result.rewrittenChunkCount());
		assertEquals(0, result.rewrittenEventCount());
		assertEquals(0, result.rewrittenCheckpointCount());
		assertEquals(0, result.replacedOccurrenceCount());
		assertEquals(List.of(), result.redactedInMetadata());
		assertArrayEquals(original, Files.readAllBytes(input));
		assertArrayEquals(original, Files.readAllBytes(output));
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
	void copiesUnrelatedPrimitivePayloadWithoutDecodingIt(boolean changed, @TempDir
	Path dir) throws Exception {
		Path input = dir.resolve("primitive-input.jfr");
		String secret = "redaction-payload-secret";
		try (Recording recording = new Recording()) {
			recording.enable(PrimitivePayloadEvent.class);
			recording.enable(ExactStringEvent.class);
			recording.start();
			PrimitivePayloadEvent primitive = new PrimitivePayloadEvent();
			primitive.value = 128;
			primitive.commit();
			ExactStringEvent string = new ExactStringEvent();
			string.value = secret;
			string.commit();
			recording.stop();
			recording.dump(input);
		}
		List<RecordedEvent> primitives = RecordingFile.readAllEvents(input).stream()
				.filter(event -> event.getEventType().getName().equals("test.PrimitivePayload")).toList();
		assertEquals(1, primitives.size());
		assertEquals(128, primitives.getFirst().getInt("value"));
		assertEquals(List.of(secret), exactStringValues(input));
		int valueOffset = primitiveEvent(input, true).valueOffset();
		byte[] malformed = Files.readAllBytes(input);
		assertEquals(0x80, malformed[valueOffset] & 0xFF);
		malformed[valueOffset] &= 0x7F;
		Files.write(input, malformed);
		byte[] primitiveBytes = primitiveEvent(input, false).bytes();
		Path output = dir.resolve("output.jfr");
		Files.write(output, new byte[] {1, 2, 3, 4});
		List<String> before = fileNames(dir);
		RedactionResult result = JfrRedactor.redact(input, output,
				(value, locations) -> changed && value.equals(secret) ? "<REDACTED>" : value);
		assertArrayEquals(malformed, Files.readAllBytes(input));
		if (changed) {
			assertEquals(1, result.redactedStringCount());
			assertEquals(List.of("<REDACTED>"), exactStringValues(output));
		} else {
			assertEquals(0, result.redactedStringCount());
			assertArrayEquals(malformed, Files.readAllBytes(output));
		}
		assertArrayEquals(primitiveBytes, primitiveEvent(output, false).bytes(),
				"the unrelated event frame and its deliberately opaque payload must be copied verbatim");
		assertEquals(before, fileNames(dir), "redaction must leave no temporary files");
	}

	@Name("test.PrimitivePayload")
	@StackTrace(false)
	static class PrimitivePayloadEvent extends Event {
		int value;
	}

	private record PrimitiveFrame(int valueOffset, byte[] bytes) {
	}

	private static PrimitiveFrame primitiveEvent(Path input, boolean locateValue) throws IOException {
		try (FileChannel channel = FileChannel.open(input)) {
			ChunkReader reader = new ChunkReader();
			reader.reset(channel);
			long chunkStart = 0;
			while (reader.next()) {
				RecordingStream stream = reader.stream();
				for (int start = reader.headerSize(); start < reader.size();) {
					stream.position(start);
					int end = start + (int) stream.readVarint();
					ChunkTypes.Type type = reader.types().getEventType(stream.readVarint());
					if (type != null && type.name.equals("test.PrimitivePayload")) {
						assertFalse(type.containsStrings, "the event must take the no-inline-string path");
						byte[] bytes = Arrays.copyOfRange(stream.array(), start, end);
						if (!locateValue) {
							return new PrimitiveFrame(-1, bytes);
						}
						for (int field = 0; field < type.fields.length; field++) {
							int op = type.fields[field];
							assertEquals(0, op & ChunkTypes.ARRAY_FLAG);
							int position = stream.position();
							if (type.fieldNames[field].equals("value")) {
								assertEquals(ChunkTypes.KIND_VARINT, op & ChunkTypes.KIND_MASK);
								assertEquals(128, stream.readVarint());
								assertEquals(2, stream.position() - position);
								return new PrimitiveFrame(Math.toIntExact(chunkStart + position), bytes);
							}
							switch (op & ChunkTypes.KIND_MASK) {
							case ChunkTypes.KIND_VARINT -> stream.skipVarint();
							case ChunkTypes.KIND_FIXED1 -> stream.skip(1);
							case ChunkTypes.KIND_FIXED4 -> stream.skip(4);
							case ChunkTypes.KIND_FIXED8 -> stream.skip(8);
							default -> throw new AssertionError("Unexpected primitive field kind " + op);
							}
						}
					}
					start = end;
				}
				chunkStart += reader.size();
			}
		}
		throw new AssertionError("The primitive event value was not found");
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

	/**
	 * Each offset is a byte in the metadata of the fixture which, set to 0x7F, makes decoding fail
	 * with an unchecked exception or a stack overflow, which are reported as the cause of a checked
	 * exception
	 */
	@ParameterizedTest
	@ValueSource(ints = {101006, 101560, 110258, 121289, 129611})
	void reportsCorruptRecordingsAsInvalid(int offset, @TempDir
	Path dir) throws Exception {
		byte[] bytes = Files.readAllBytes(fixture("jdk9-basic.jfr"));
		bytes[offset] = 0x7F;
		Path input = Files.write(dir.resolve("corrupt.jfr"), bytes);
		Path output = dir.resolve("output.jfr");
		InvalidRecordingException failure = assertThrows(InvalidRecordingException.class,
				() -> JfrRedactor.redact(input, output, (value, locations) -> "X"));
		assertFalse(failure instanceof TruncatedRecordingException, failure.toString());
		assertTrue(failure.getCause() instanceof RuntimeException || failure.getCause() instanceof StackOverflowError,
				String.valueOf(failure.getCause()));
		assertFalse(Files.exists(output));
	}

	@Test
	void reportsTruncatedRecordings(@TempDir
	Path dir) throws Exception {
		byte[] bytes = Files.readAllBytes(fixture("jdk21-jmc.jfr"));
		Path truncated = Files.write(dir.resolve("truncated.jfr"), Arrays.copyOf(bytes, bytes.length - 1));
		assertThrows(TruncatedRecordingException.class,
				() -> JfrRedactor.redact(truncated, dir.resolve("output.jfr"), (value, locations) -> value));
		// The JVM writes the size of a chunk when it finishes it
		Arrays.fill(bytes, 8, 16, (byte) 0);
		Path inProgress = Files.write(dir.resolve("in-progress.jfr"), bytes);
		assertThrows(TruncatedRecordingException.class,
				() -> JfrRedactor.redact(inProgress, dir.resolve("output.jfr"), (value, locations) -> value));
	}

	@Test
	void reportsFilesThatAreNoRecordingsAsInvalid(@TempDir
	Path dir) throws Exception {
		Path text = Files.writeString(dir.resolve("text.jfr"), "This is not a recording at all");
		assertThrows(InvalidRecordingException.class,
				() -> JfrRedactor.redact(text, dir.resolve("output.jfr"), (value, locations) -> value));
	}

	/** A failing redactor is a failure of the caller's code, not of the recording */
	@Test
	void passesOnExceptionsOfTheRedactor(@TempDir
	Path dir) throws Exception {
		IllegalStateException thrown = new IllegalStateException("redactor bug");
		IllegalStateException failure = assertThrows(IllegalStateException.class,
				() -> JfrRedactor.redact(fixture("jdk9-basic.jfr"), dir.resolve("output.jfr"), (value, locations) -> {
					throw thrown;
				}));
		assertEquals(thrown, failure);
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
		assertFalse(failure instanceof InvalidRecordingException, "the recording is valid, the replacement is not");
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
