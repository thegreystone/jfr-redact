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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static se.hirt.jfr.redact.HandWrittenRecording.constant;
import static se.hirt.jfr.redact.HandWrittenRecording.pool;
import static se.hirt.jfr.redact.HandWrittenRecording.reference;
import static se.hirt.jfr.redact.HandWrittenRecording.string;
import static se.hirt.jfr.redact.HandWrittenRecording.varint;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import jdk.jfr.Recording;

/**
 * The value of a type with a {@code key} field, such as an environment variable, is located at its
 * field for its key, whether key and value are inline or pooled
 */
class KeyedLocationTest {
	private static final long ENVIRONMENT = 200;

	@Test
	void locatesInlineValuesForTheirInlineKeys(@TempDir
	Path dir) throws Exception {
		HandWrittenRecording recording = environmentRecording();
		recording.event(ENVIRONMENT, string("API_TOKEN"), string("token value"));
		Map<String, List<String>> locations = locationsOf(recording.write(dir.resolve("in.jfr")), dir);
		assertEquals(List.of("jdk.InitialEnvironmentVariable.value (inline) for key API_TOKEN"),
				locations.get("token value"));
		assertEquals(List.of("jdk.InitialEnvironmentVariable.key (inline)"), locations.get("API_TOKEN"));
	}

	/** The string pool comes after the events, as HotSpot writes it at the end of the chunk */
	@Test
	void locatesValuesForKeysStoredInTheStringPool(@TempDir
	Path dir) throws Exception {
		HandWrittenRecording recording = environmentRecording();
		recording.event(ENVIRONMENT, reference(1), string("inline value"));
		recording.event(ENVIRONMENT, reference(2), reference(3));
		recording.event(ENVIRONMENT, string("INLINE_KEY"), reference(4));
		recording.checkpoint(
				pool(HandWrittenRecording.STRING, constant(1, string("POOLED_KEY")), constant(2, string("OTHER_KEY")),
						constant(3, string("pooled value")), constant(4, string("pooled value of inline key"))));
		Map<String, List<String>> locations = locationsOf(recording.write(dir.resolve("in.jfr")), dir);
		assertEquals(List.of("jdk.InitialEnvironmentVariable.value (inline) for key POOLED_KEY"),
				locations.get("inline value"));
		assertEquals(List.of("jdk.InitialEnvironmentVariable.value (pooled) for key OTHER_KEY"),
				locations.get("pooled value"));
		assertEquals(List.of("jdk.InitialEnvironmentVariable.value (pooled) for key INLINE_KEY"),
				locations.get("pooled value of inline key"));
		assertEquals(List.of("jdk.InitialEnvironmentVariable.key (pooled)"), locations.get("POOLED_KEY"));
	}

	/** A key missing from its chunk's string pool cannot be read, so the value has no key */
	@Test
	void locatesTheValueOfAKeyMissingFromThePoolWithoutAKey(@TempDir
	Path dir) throws Exception {
		HandWrittenRecording recording = environmentRecording();
		recording.event(ENVIRONMENT, reference(7), string("value of an unknown key"));
		Path input = recording.write(dir.resolve("in.jfr"));
		Map<String, List<StringLocation>> locations = rawLocationsOf(input, dir);
		StringLocation location = locations.get("value of an unknown key").getFirst();
		assertTrue(location.isEnvironmentVariableValue() && location.getKey() == null, location.toString());
	}

	/** JRockit stores its environment as an array of key and value structs in one event */
	@Test
	void locatesValuesInArraysOfKeyAndValueStructs(@TempDir
	Path dir) throws Exception {
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declare(300, "test.Variable", "key:" + HandWrittenRecording.STRING,
				"value:" + HandWrittenRecording.STRING);
		recording.declareEvent(301, "os/environment", "variables:300:array");
		recording.event(301, varint(2), string("HOME"), string("/home/alice"), string("SECRET"), string("hunter2"));
		Map<String, List<StringLocation>> locations = rawLocationsOf(recording.write(dir.resolve("in.jfr")), dir);
		StringLocation home = locations.get("/home/alice").getFirst();
		assertEquals("os/environment.variables.value (inline) for key HOME", home.toString());
		assertTrue(home.isEnvironmentVariableValue());
		assertEquals("SECRET", locations.get("hunter2").getFirst().getKey());
	}

	@Test
	void locatesAValueUnderEachOfItsKeys(@TempDir
	Path dir) throws Exception {
		HandWrittenRecording recording = environmentRecording();
		recording.event(ENVIRONMENT, string("FIRST"), string("shared"));
		recording.event(ENVIRONMENT, string("SECOND"), string("shared"));
		Map<String, List<String>> locations = locationsOf(recording.write(dir.resolve("in.jfr")), dir);
		assertEquals(List.of("jdk.InitialEnvironmentVariable.value (inline) for key FIRST",
				"jdk.InitialEnvironmentVariable.value (inline) for key SECOND"), locations.get("shared"));
	}

	@Test
	void locatesTheSystemPropertiesOfARecordingOfThisJvm(@TempDir
	Path dir) throws Exception {
		Path file = dir.resolve("jvm.jfr");
		try (Recording recording = new Recording()) {
			recording.enable("jdk.InitialSystemProperty");
			recording.start();
			recording.stop();
			recording.dump(file);
		}
		// HotSpot records the properties the JVM sets itself, not those of the class library, such as
		// user.home
		Map<String, List<StringLocation>> locations = rawLocationsOf(file, dir);
		String javaHome = System.getProperty("java.home");
		assertTrue(
				locations.get(javaHome).stream()
						.anyMatch(l -> l.isSystemPropertyValue() && "java.home".equals(l.getKey())),
				"the Java home is located as the value of java.home");
	}

	private static HandWrittenRecording environmentRecording() {
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declareEvent(ENVIRONMENT, "jdk.InitialEnvironmentVariable", "key:" + HandWrittenRecording.STRING,
				"value:" + HandWrittenRecording.STRING);
		return recording;
	}

	private static Map<String, List<StringLocation>> rawLocationsOf(Path input, Path dir) throws IOException {
		Map<String, List<StringLocation>> found = new HashMap<>();
		JfrRedactor.redact(input, dir.resolve("out.jfr"), (value, locations) -> {
			found.put(value, locations);
			return value;
		});
		return found;
	}

	private static Map<String, List<String>> locationsOf(Path input, Path dir) throws IOException {
		Map<String, List<String>> found = new HashMap<>();
		rawLocationsOf(input, dir).forEach((value, locations) -> found.put(value,
				new ArrayList<>(new TreeSet<>(locations.stream().map(StringLocation::toString).toList()))));
		return found;
	}

}
