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

import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import se.hirt.jfr.redact.examples.RedactPatientData;
import se.hirt.jfr.redact.parser.StreamingChunkParser;
import se.hirt.jfr.redact.scan.StringCountMap;
import se.hirt.jfr.redact.scan.StringScanner;

/**
 * Tests on the recordings in {@code src/test/resources/recordings}, one per supported JFR version.
 */
class FixtureTest {
	@ParameterizedTest
	@ValueSource(strings = {"jrockit-r28-transitions.jfr", "jdk9-basic.jfr", "jdk9-weblogic-medrec.jfr",
			"jdk21-jmc.jfr"})
	void redactsEveryStringCorrectly(String name, @TempDir
	Path dir) throws Exception {
		boolean jdkCanParse = !name.startsWith("jrockit");
		List<String> problems = RedactionVerifier.verify(recording(name), dir.resolve(name),
				RedactionVerifier.aggressive(4), jdkCanParse);
		assertEquals(List.of(), problems);
	}

	@Test
	void redactsPatientData(@TempDir
	Path dir) throws Exception {
		Path output = dir.resolve("redacted.jfr");
		JfrRedactor.redact(recording("jdk9-weblogic-medrec.jfr"), output, RedactPatientData.redactor());

		StringScanner scanner = new StringScanner(true);
		new StreamingChunkParser().parse(output, scanner);
		assertEquals(0, scanner.getMisalignedCount());
		StringCountMap strings = scanner.getStrings();
		int[] hashedClasses = new int[1];
		// An identity redaction of the output, to see the locations of its strings
		JfrRedactor.redact(output, dir.resolve("unchanged.jfr"), (value, locations) -> {
			assertTrue(!value.contains("@star.com"), value);
			for (StringLocation location : locations) {
				if (location.isClassName() && value.startsWith("com/bea/medrec/")) {
					assertTrue(value.matches("com/bea/medrec/[A-Za-z0-9_$]{12,13}"), value);
					hashedClasses[0]++;
				}
				if (location.isMethodDescriptor()) {
					for (int at = value.indexOf("Lcom/bea/medrec/"); at >= 0; at = value.indexOf("Lcom/bea/medrec/",
							at + 1)) {
						assertTrue(value.substring(at).matches("Lcom/bea/medrec/[A-Za-z0-9_$]{12,13};.*"), value);
					}
				}
			}
			return value;
		});
		assertTrue(hashedClasses[0] > 0, "the application classes are hashed");
		assertTrue(strings.indexOf("UPDATE PATIENTS SET STATUS='REGISTERED' WHERE EMAIL='<EMAIL>'") >= 0);
	}

	static Path recording(String name) throws URISyntaxException {
		return Path.of(FixtureTest.class.getResource("/recordings/" + name).toURI());
	}
}
