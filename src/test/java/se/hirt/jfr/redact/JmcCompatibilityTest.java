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

import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import se.hirt.jfr.redact.examples.RedactPatientData;

/**
 * Loads redacted recordings with JDK Mission Control's parser, which derives the simple name of a
 * class from the name of its package and so requires every class name to start with the name of its
 * package, see {@link JmcModel}. Every fixture is checked: the JRockit recording too, which JMC
 * reads as well, although JFR 0.9 stores no package names, and the recording of JMC's own writer,
 * whose class and package names are stored through {@code jdk.types.Symbol} constants and the
 * {@code java.lang.String} pool, both read as the value of the field referring to them, and hashed
 * all the same.
 */
class JmcCompatibilityTest {
	@ParameterizedTest
	@ValueSource(strings = {"jdk9-basic.jfr", "jdk9-weblogic-medrec.jfr", "jdk21-jmc.jfr", "jmc-writer-pooled.jfr",
			"jrockit-r28-transitions.jfr"})
	void readsTheFixturesThemselves(String name) throws Exception {
		JmcModel control = JmcModel.load(FixtureTest.recording(name));
		assertEquals(List.of(), control.problems(), "the control: the fixture itself");
		assertTrue(control.items() > 0 && control.classes() > 0,
				"events and classes: " + control.items() + ", " + control.classes());
	}

	@ParameterizedTest
	@ValueSource(strings = {"jdk9-basic.jfr", "jdk9-weblogic-medrec.jfr", "jdk21-jmc.jfr", "jmc-writer-pooled.jfr",
			"jrockit-r28-transitions.jfr"})
	void readsRecordingsWithEveryNameHashed(String name, @TempDir
	Path dir) throws Exception {
		assertReadsLikeTheFixture(name, dir.resolve("hashed.jfr"),
				RuleRedactor.builder().hashClassNames("(.*)").hashMethodNames("(.*)").hashThreadNames().build());
	}

	@ParameterizedTest
	@ValueSource(strings = {"jdk9-basic.jfr", "jdk9-weblogic-medrec.jfr", "jdk21-jmc.jfr", "jmc-writer-pooled.jfr",
			"jrockit-r28-transitions.jfr"})
	void readsRecordingsRedactedLikeThePatientData(String name, @TempDir
	Path dir) throws Exception {
		assertReadsLikeTheFixture(name, dir.resolve("patients.jfr"), RedactPatientData.redactor());
	}

	/**
	 * Several class name expressions, keyed and unkeyed, decide the package part of a class and the
	 * constant of its package alike, see {@link #severalClassNameExpressions()}
	 */
	@ParameterizedTest
	@ValueSource(strings = {"jdk9-basic.jfr", "jdk9-weblogic-medrec.jfr", "jdk21-jmc.jfr", "jmc-writer-pooled.jfr",
			"jrockit-r28-transitions.jfr"})
	void readsRecordingsRedactedWithSeveralClassNameExpressions(String name, @TempDir
	Path dir) throws Exception {
		assertReadsLikeTheFixture(name, dir.resolve("several.jfr"), severalClassNameExpressions());
	}

	/**
	 * Hashes the classes of the medrec application and of JMC with a key below their prefixes, the
	 * {@code Impl} classes by their simple names, and every other class, package and module without
	 * a key, as a configuration hashing an application's classes and the libraries alike would
	 */
	static StringRedactor severalClassNameExpressions() {
		byte[] key = {1, 2, 3};
		return RuleRedactor.builder().hashClassNames("com\\.bea\\.medrec\\.(.*)", key)
				.hashClassNames("org\\.openjdk\\.jmc\\.(.*)", key).hashClassNames("(.*)Impl$").hashClassNames("(.*)")
				.build();
	}

	/**
	 * Redacts the fixture and asserts that JMC reads the output without problems, reaching every
	 * event, class and frame it reaches in the fixture itself, so that nothing disappears silently.
	 * It may reach more: JMC's parser leaves out the {@code jdk.JavaExceptionThrow} events of the
	 * constructors of errors, which it tells by the class name, so hashing {@code java.lang.Error}
	 * lets them through, with their stack traces.
	 */
	private static void assertReadsLikeTheFixture(String name, Path output, StringRedactor redactor) throws Exception {
		Path input = FixtureTest.recording(name);
		JmcModel control = JmcModel.load(input);
		assertTrue(control.classes() > 0, "the fixture has classes");
		JfrRedactor.redact(input, output, redactor);
		JmcModel redacted = JmcModel.load(output);
		assertEquals(List.of(), redacted.problems(), name);
		assertTrue(redacted.items() >= control.items(), "events read: " + redacted.items() + " of " + control.items());
		assertTrue(redacted.classes() >= control.classes(),
				"classes reached: " + redacted.classes() + " of " + control.classes());
		assertTrue(redacted.frames() >= control.frames(),
				"frames reached: " + redacted.frames() + " of " + control.frames());
	}
}
