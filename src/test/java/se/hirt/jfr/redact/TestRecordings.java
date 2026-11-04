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

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

/** Reads recordings the way the tests compare them: through the JDK's parser, and as raw bytes */
final class TestRecordings {
	private TestRecordings() {
	}

	/**
	 * Asserts that no copy of the values remains in the file, in any of the encodings a recording
	 * stores strings in: UTF-8, UTF-16 and Latin-1
	 */
	static void assertAbsent(Path file, String ... values) throws IOException {
		byte[] bytes = Files.readAllBytes(file);
		for (String value : values) {
			for (Charset charset : List.of(StandardCharsets.UTF_8, StandardCharsets.UTF_16BE,
					StandardCharsets.ISO_8859_1)) {
				assertTrue(indexOf(bytes, value.getBytes(charset)) < 0, value + " remains, as " + charset);
			}
		}
	}

	private static int indexOf(byte[] haystack, byte[] needle) {
		for (int i = 0, last = haystack.length - needle.length; i <= last; i++) {
			if (haystack[i] == needle[0] && Arrays.equals(haystack, i, i + needle.length, needle, 0, needle.length)) {
				return i;
			}
		}
		return -1;
	}

	/** @return the texts of the thread dump events of the recording, in order */
	static List<String> threadDumps(Path file) throws IOException {
		List<String> dumps = new ArrayList<>();
		try (RecordingFile recording = new RecordingFile(file)) {
			while (recording.hasMoreEvents()) {
				RecordedEvent event = recording.readEvent();
				if (event.getEventType().getName().equals("jdk.ThreadDump")) {
					dumps.add(event.getString("result"));
				}
			}
		}
		return dumps;
	}
}
