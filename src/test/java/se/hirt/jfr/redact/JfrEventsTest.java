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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import jdk.jfr.consumer.RecordedObject;

/**
 * The JFR events of the library describe a redaction with sizes, counts and its own constants only
 */
class JfrEventsTest {
	@Test
	void describesTheRedaction(@TempDir
	Path dir) throws Exception {
		Path input = Path.of(JfrEventsTest.class.getResource("/recordings/jdk21-jmc.jfr").toURI());
		Path output = dir.resolve("redacted.jfr");
		Path events = dir.resolve("events.jfr");
		RedactionResult result;
		try (Recording recording = new Recording()) {
			recording.enable("se.hirt.jfr.redact.Redaction");
			recording.enable("se.hirt.jfr.redact.Phase");
			recording.enable("se.hirt.jfr.redact.Chunk");
			recording.start();
			result = JfrRedactor.redact(input, output, RuleRedactor.builder().hashThreadNames().build());
			recording.stop();
			recording.dump(events);
		}
		List<RecordedEvent> recorded = RecordingFile.readAllEvents(events).stream()
				.filter(e -> e.getEventType().getName().startsWith("se.hirt.jfr.redact.")).toList();

		List<RecordedEvent> redactions = ofType(recorded, "Redaction");
		assertEquals(1, redactions.size());
		RecordedEvent redaction = redactions.getFirst();
		assertEquals(Files.size(input), redaction.getLong("inputSize"));
		assertEquals(result.chunkCount(), redaction.getLong("chunks"));
		assertEquals(result.rewrittenChunkCount(), redaction.getLong("rewrittenChunks"));
		assertEquals(result.stringCount(), redaction.getLong("strings"));
		assertEquals(result.redactedStringCount(), redaction.getLong("redactedStrings"));
		assertEquals(result.replacedOccurrenceCount(), redaction.getLong("replacedOccurrences"));
		assertTrue(result.redactedStringCount() > 0);

		assertEquals(List.of("Collect", "Locate", "Decide", "Rewrite", "Publish"),
				ofType(recorded, "Phase").stream().map(e -> e.getString("phase")).toList());

		List<RecordedEvent> chunks = ofType(recorded, "Chunk");
		for (String operation : List.of("Parse", "Rewrite")) {
			List<RecordedEvent> ofOperation = chunks.stream().filter(e -> e.getString("operation").equals(operation))
					.toList();
			assertEquals(result.chunkCount(), ofOperation.size(), operation);
			assertEquals(Files.size(input), ofOperation.stream().mapToLong(e -> e.getLong("size")).sum(), operation);
		}
		assertEquals(result.rewrittenChunkCount(), chunks.stream().filter(e -> e.getBoolean("rewritten")).count());

		for (RecordedEvent event : recorded) {
			for (var field : event.getFields()) {
				if (field.getTypeName().equals("java.lang.String")) {
					String value = ((RecordedObject) event).getValue(field.getName());
					assertFalse(value.contains("/") || value.contains("jfr"), event.toString());
				}
			}
		}
	}

	private static List<RecordedEvent> ofType(List<RecordedEvent> events, String name) {
		return events.stream().filter(e -> e.getEventType().getName().equals("se.hirt.jfr.redact." + name)).toList();
	}
}
