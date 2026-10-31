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
package se.hirt.jfr.redact.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import jdk.jfr.Configuration;
import jdk.jfr.Event;
import jdk.jfr.Name;
import jdk.jfr.Recording;
import jdk.jfr.StackTrace;
import se.hirt.jfr.redact.parser.StreamingChunkParser;

class StringScannerTest {
	private static final String SHORT = "short-string";
	private static final String UNIQUE = "a unique string that is only emitted once";
	private static final String REPEATED = "a repeated string that should end up in the constant pool";
	private static final String NON_ASCII = "Küssnacht am Rigi, åäö and 😀 emoji";
	private static final String LONG_LATIN1 = "\u00fc".repeat(3000);
	private static final String LONG_UTF16 = "\u20ac".repeat(3000);

	@Name("test.Message")
	@StackTrace(true)
	static class MessageEvent extends Event {
		String message;
	}

	@Test
	void countsInlineAndPooledStrings(@TempDir
	Path dir) throws Exception {
		Path file = dir.resolve("strings.jfr");
		try (Recording recording = new Recording()) {
			recording.enable(MessageEvent.class);
			recording.start();
			emitMessages();
			recording.stop();
			recording.dump(file);
		}

		StringScanner scanner = scan(file, true);
		StringCountMap strings = scanner.getStrings();
		assertEquals(0, scanner.getMisalignedCount());

		int shortEntry = strings.indexOf(SHORT);
		assertTrue(shortEntry >= 0);
		assertEquals(100, strings.getCount(shortEntry, StringScanner.INLINE));
		assertEquals(0, strings.getCount(shortEntry, StringScanner.CONSTANT_POOL));

		int uniqueEntry = strings.indexOf(UNIQUE);
		assertTrue(uniqueEntry >= 0);
		assertEquals(1, strings.getTotalCount(uniqueEntry));

		int repeatedEntry = strings.indexOf(REPEATED);
		assertTrue(repeatedEntry >= 0);
		assertTrue(strings.getCount(repeatedEntry, StringScanner.INLINE) >= 1, "first occurrence inlined");
		assertTrue(strings.getCount(repeatedEntry, StringScanner.CONSTANT_POOL) >= 1, "later moved to the pool");
		assertTrue(strings.getTotalCount(repeatedEntry) < 1000, "most occurrences are pool references");

		assertTrue(strings.indexOf(NON_ASCII) >= 0);
		assertEquals(1, strings.getTotalCount(strings.indexOf(LONG_LATIN1)));
		assertEquals(1, strings.getTotalCount(strings.indexOf(LONG_UTF16)));

		int methodEntry = strings.indexOf("emitMessages");
		assertTrue(methodEntry >= 0, "method name from the stack traces");
		assertEquals(0, strings.getCount(methodEntry, StringScanner.INLINE));
		assertTrue(strings.getCount(methodEntry, StringScanner.CONSTANT_POOL) >= 1);
	}

	@Test
	void countsReferences(@TempDir
	Path dir) throws Exception {
		Path file = dir.resolve("references.jfr");
		try (Recording recording = new Recording()) {
			recording.enable(MessageEvent.class);
			recording.start();
			emitMessages();
			recording.stop();
			recording.dump(file);
		}

		StringScanner scanner = new StringScanner(true, true);
		new StreamingChunkParser().parse(file, scanner);
		StringCountMap strings = scanner.getStrings();
		assertEquals(0, scanner.getMisalignedCount());
		assertEquals(0, scanner.getUnresolvedReferenceCount());
		assertEquals(1, scanner.getChunkCount());

		int repeatedEntry = strings.indexOf(REPEATED);
		assertEquals(1000,
				strings.getCount(repeatedEntry, StringScanner.INLINE) + strings.getReferenceCount(repeatedEntry),
				"every event either inlines or references it");

		int shortEntry = strings.indexOf(SHORT);
		assertEquals(0, strings.getReferenceCount(shortEntry), "short strings are never pooled");

		int methodEntry = strings.indexOf("emitMessages");
		assertTrue(strings.getReferenceCount(methodEntry) >= 1, "referenced by the method constant");

		StringScanner plain = scan(file, true);
		assertEquals(plain.getStrings().size(), strings.size());
		assertEquals(plain.getOccurrenceCount(StringScanner.INLINE), scanner.getOccurrenceCount(StringScanner.INLINE));
		assertEquals(plain.getOccurrenceCount(StringScanner.CONSTANT_POOL),
				scanner.getOccurrenceCount(StringScanner.CONSTANT_POOL));
		assertEquals(0, plain.getStrings().getReferenceCount(plain.getStrings().indexOf(REPEATED)));
	}

	@Test
	void decodesAllEventsOfDefaultRecording(@TempDir
	Path dir) throws Exception {
		Path file = dir.resolve("default.jfr");
		try (Recording recording = new Recording(Configuration.getConfiguration("profile"))) {
			recording.start();
			List<String> garbage = new ArrayList<>();
			long end = System.currentTimeMillis() + 1500;
			while (System.currentTimeMillis() < end) {
				garbage.add(String.valueOf(System.nanoTime()));
				if (garbage.size() > 100_000) {
					garbage.clear();
				}
			}
			recording.stop();
			recording.dump(file);
		}

		StringScanner validating = scan(file, true);
		assertEquals(0, validating.getMisalignedCount());
		assertEquals(0, validating.getUnknownEventCount());
		assertEquals(validating.getEventCount(), validating.getDecodedEventCount());
		assertTrue(validating.getEventCount() > 100);

		StringScanner fast = scan(file, false);
		assertTrue(fast.getDecodedEventCount() < fast.getEventCount());
		assertEquals(validating.getStrings().size(), fast.getStrings().size());
		assertEquals(validating.getOccurrenceCount(StringScanner.INLINE),
				fast.getOccurrenceCount(StringScanner.INLINE));
		assertEquals(validating.getOccurrenceCount(StringScanner.CONSTANT_POOL),
				fast.getOccurrenceCount(StringScanner.CONSTANT_POOL));
		assertTrue(fast.getStrings().indexOf("java.lang.Thread") >= 0
				|| fast.getStrings().indexOf("java/lang/Thread") >= 0);
	}

	private static void emitMessages() {
		for (int i = 0; i < 100; i++) {
			MessageEvent event = new MessageEvent();
			event.message = SHORT;
			event.commit();
		}
		MessageEvent unique = new MessageEvent();
		unique.message = UNIQUE;
		unique.commit();
		for (int i = 0; i < 1000; i++) {
			MessageEvent event = new MessageEvent();
			event.message = REPEATED;
			event.commit();
		}
		MessageEvent nonAscii = new MessageEvent();
		nonAscii.message = NON_ASCII;
		nonAscii.commit();
		for (String s : new String[] {LONG_LATIN1, LONG_UTF16}) {
			MessageEvent event = new MessageEvent();
			event.message = s;
			event.commit();
		}
	}

	private static StringScanner scan(Path file, boolean decodeAll) throws Exception {
		StringScanner scanner = new StringScanner(decodeAll);
		new StreamingChunkParser().parse(file, scanner);
		return scanner;
	}
}
