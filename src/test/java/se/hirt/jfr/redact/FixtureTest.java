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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedThread;
import jdk.jfr.consumer.RecordingFile;
import se.hirt.jfr.redact.examples.RedactPatientData;
import se.hirt.jfr.redact.parser.StreamingChunkParser;
import se.hirt.jfr.redact.scan.StringCountMap;
import se.hirt.jfr.redact.scan.StringScanner;

/**
 * Tests on the recordings in {@code src/test/resources/recordings}, one per supported JFR version
 * and one written by JMC's pure-Java writer, which stores names through the string pool.
 */
class FixtureTest {
	/**
	 * A thread dump frame of a hidden class, such as {@code Foo$$Lambda/0x00007fb87c2252f8.run(}
	 */
	private static final Pattern HIDDEN_CLASS_FRAME = Pattern.compile("^\\s*at [^(]*/0x[0-9a-f]+\\.[^(]+\\(");

	@ParameterizedTest
	@ValueSource(strings = {"jrockit-r28-transitions.jfr", "jdk9-basic.jfr", "jdk9-weblogic-medrec.jfr",
			"jdk21-jmc.jfr", "jmc-writer-pooled.jfr"})
	void redactsEveryStringCorrectly(String name, @TempDir
	Path dir) throws Exception {
		boolean jdkCanParse = !name.startsWith("jrockit");
		List<String> problems = RedactionVerifier.verify(recording(name), dir.resolve(name),
				RedactionVerifier.aggressive(4), jdkCanParse);
		assertEquals(List.of(), problems);
	}

	@Test
	void hashesHiddenClassFramesInBundledThreadDumps(@TempDir
	Path dir) throws Exception {
		Path input = recording("jdk21-jmc.jfr");
		List<String> inputDumps = TestRecordings.threadDumps(input);
		String inputText = String.join("\n", inputDumps);
		assertTrue(inputText.contains("at org.eclipse.ui.internal.Workbench$$Lambda/0x"),
				"the fixture must contain hidden-class frames of application classes");
		Set<String> packages = new TreeSet<>();
		Matcher m = Pattern.compile("org\\.eclipse\\.[a-z0-9]+\\.").matcher(inputText);
		while (m.find()) {
			packages.add(m.group());
		}
		assertTrue(packages.size() > 3, packages.toString());
		long hiddenFrames = inputText.lines().filter(line -> HIDDEN_CLASS_FRAME.matcher(line).find()).count();
		assertTrue(hiddenFrames > 3, "hidden-class frames: " + hiddenFrames);

		Path classes = dir.resolve("classes.jfr");
		JfrRedactor.redact(input, classes, RuleRedactor.builder().hashClassNames("org\\.eclipse\\.(.*)").build());
		List<String> dumps = TestRecordings.threadDumps(classes);
		assertEquals(inputDumps.size(), dumps.size());
		String text = String.join("\n", dumps);
		for (String line : text.split("\n")) {
			for (String pkg : packages) {
				assertTrue(!line.contains(pkg), line);
			}
			assertTrue(!line.matches(".*org\\.eclipse\\..*\\$\\$Lambda/0x.*"), line);
		}
		assertEquals(hiddenFrames, text.lines().filter(line -> HIDDEN_CLASS_FRAME.matcher(line).find()).count(),
				"the hidden-class frames remain, with hashed hosts");
		int[] hashed = new int[2];
		String[] dialogLambda = new String[1];
		// An identity redaction of the output, to see the locations of its strings
		JfrRedactor.redact(classes, dir.resolve("unchanged.jfr"), (value, locations) -> {
			for (StringLocation location : locations) {
				if (!location.isClassName()) {
					continue;
				}
				// An array class constant, [Lorg/eclipse/...;, is classified by its component class
				String component = value.startsWith("[") ? value.replaceFirst("^\\[+L", "").replaceFirst(";$", "")
						: value;
				if (component.startsWith("org/eclipse/")) {
					assertTrue(component.matches("org/eclipse/[A-Za-z0-9_$]{12,13}"), value);
					hashed[0]++;
				} else if (component.startsWith("org.eclipse.")) {
					assertTrue(component.matches("org\\.eclipse\\.[A-Za-z0-9_$]{12,13}\\+0x[0-9a-f]+/\\d+"), value);
					hashed[1]++;
					if (component.contains("+0x00007fb87c5e2678/")) {
						dialogLambda[0] = component.substring(0, component.indexOf('+'));
					}
				} else {
					assertTrue(!value.contains("org/eclipse/") && !value.contains("org.eclipse."), value);
				}
			}
			return value;
		});
		assertTrue(hashed[0] > 0 && hashed[1] > 0, "classes and hidden classes: " + hashed[0] + ", " + hashed[1]);
		// The frames of a hidden class carry the hash of its constant, the Dialog lambda once and the
		// Workbench lambda once per dump
		assertTrue(dialogLambda[0] != null, "the constant of the Dialog lambda");
		String dialogFrame = "\tat " + dialogLambda[0] + "/0x00007fb87c5e2678.accept(Unknown Source)";
		assertEquals(1, text.lines().filter(dialogFrame::equals).count(), dialogFrame);
		Pattern workbenchFrame = Pattern
				.compile("\tat org\\.eclipse\\.[A-Za-z0-9_$]{12,13}/0x00007fb87c2252f8\\.run\\(Unknown Source\\)");
		assertEquals(inputDumps.size(), text.lines().filter(line -> workbenchFrame.matcher(line).matches()).count());
	}

	@Test
	void hashesMethodsOfHiddenClassFramesInBundledThreadDumps(@TempDir
	Path dir) throws Exception {
		Path input = recording("jdk21-jmc.jfr");
		String dialogLambda = "org.eclipse.jface.dialogs.Dialog$$Lambda/0x00007fb87c5e2678";
		String workbenchLambda = "org.eclipse.ui.internal.Workbench$$Lambda/0x00007fb87c2252f8";
		List<String> inputDumps = TestRecordings.threadDumps(input);
		assertTrue(
				inputDumps.stream().anyMatch(dump -> dump.contains("\tat " + dialogLambda + ".accept(Unknown Source)")),
				"the fixture has the Dialog lambda frame");
		RuleRedactor redactor = RuleRedactor.builder().hashMethodNames("^(run|accept)$").build();
		StringLocation methodName = new StringLocation("jdk.types.Symbol", "string", true,
				List.of("jdk.types.Method.name"));
		String accept = redactor.redact("accept", List.of(methodName));
		String run = redactor.redact("run", List.of(methodName));
		assertTrue(!accept.equals("accept") && !run.equals("run"), accept + " " + run);

		Path output = dir.resolve("methods.jfr");
		JfrRedactor.redact(input, output, redactor);
		String text = String.join("\n", TestRecordings.threadDumps(output));
		for (String line : text.split("\n")) {
			assertTrue(!line.matches(".*/0x[0-9a-f]+\\.(run|accept)\\(.*"), line);
		}
		String dialogFrame = "\tat " + dialogLambda + "." + accept + "(Unknown Source)";
		String workbenchFrame = "\tat " + workbenchLambda + "." + run + "(Unknown Source)";
		assertEquals(1, text.lines().filter(dialogFrame::equals).count(), dialogFrame);
		assertEquals(inputDumps.size(), text.lines().filter(workbenchFrame::equals).count(), workbenchFrame);
	}

	@Test
	void hashesPooledThreadAndThreadGroupNames(@TempDir
	Path dir) throws Exception {
		Path output = dir.resolve("redacted.jfr");
		RuleRedactor redactor = RuleRedactor.builder().hashThreadNames().build();
		RedactionResult result = JfrRedactor.redact(recording("jmc-writer-pooled.jfr"), output, redactor);
		assertEquals(11, result.redactedStringCount(), "SecretWorker-0..4, SecretOs-0..4 and SecretGroup");

		StringScanner scanner = new StringScanner(true);
		new StreamingChunkParser().parse(output, scanner);
		assertEquals(0, scanner.getMisalignedCount());
		StringCountMap strings = scanner.getStrings();
		StringLocation threadName = new StringLocation("java.lang.Thread", "javaName", true, List.of());
		StringLocation groupName = new StringLocation("jdk.types.ThreadGroup", "name", true, List.of());
		String group = redactor.redact("SecretGroup", List.of(groupName));
		for (int i = 0; i < 5; i++) {
			for (String name : List.of("SecretWorker-" + i, "SecretOs-" + i)) {
				assertTrue(strings.indexOf(name) < 0, name);
				assertTrue(strings.indexOf(redactor.redact(name, List.of(threadName))) >= 0, name);
			}
		}
		assertTrue(strings.indexOf("SecretGroup") < 0);
		assertTrue(strings.indexOf(group) >= 0, group);
		String raw = new String(Files.readAllBytes(output), StandardCharsets.ISO_8859_1);
		assertTrue(!raw.contains("SecretWorker") && !raw.contains("SecretOs") && !raw.contains("SecretGroup"));

		Set<String> javaNames = new TreeSet<>();
		Set<String> groupNames = new TreeSet<>();
		for (RecordedEvent event : RecordingFile.readAllEvents(output)) {
			RecordedThread thread = event.getThread();
			javaNames.add(thread.getJavaName());
			groupNames.add(thread.getThreadGroup().getName());
		}
		assertEquals(5, javaNames.size(), javaNames.toString());
		assertTrue(javaNames.stream().allMatch(name -> name.matches("Thread-[0-9a-f]{8}")), javaNames.toString());
		assertEquals(Set.of(group), groupNames);
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
