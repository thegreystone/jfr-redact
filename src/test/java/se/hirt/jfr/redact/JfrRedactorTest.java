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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import jdk.jfr.Configuration;
import jdk.jfr.Event;
import jdk.jfr.Name;
import jdk.jfr.Recording;
import jdk.jfr.StackTrace;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

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
	void redactsEverywhereAndKeepsEverythingElse(@TempDir Path dir) throws Exception {
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
	void passesVerification(@TempDir Path dir) throws Exception {
		Path input = record(dir.resolve("input.jfr"));
		List<String> problems = RedactionVerifier.verify(input, dir.resolve("output.jfr"),
				RedactionVerifier.aggressive(4), true);
		assertEquals(List.of(), problems);
	}

	@Test
	void identifiesMethodNamesByReferrer(@TempDir Path dir) throws Exception {
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
	void reportsStringsAlsoInMetadata(@TempDir Path dir) throws Exception {
		Path input = record(dir.resolve("input.jfr"));
		RedactionResult result = JfrRedactor.redact(input, dir.resolve("output.jfr"),
				(value, locations) -> locations.contains(StringLocation.METADATA) ? "<M>" : value);
		assertTrue(result.redactedStringCount() > 0);
		assertEquals(result.redactedStringCount(), result.redactedInMetadata().size());
	}

	@Test
	void keepingEverythingCopiesTheRecording(@TempDir Path dir) throws Exception {
		Path input = record(dir.resolve("input.jfr"));
		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output, (value, locations) -> value);
		assertEquals(0, result.redactedStringCount());
		assertArrayEquals(Files.readAllBytes(input), Files.readAllBytes(output));
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
