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

import java.io.IOException;
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
	/** The shape of the base64 hash of a class, package or method name segment */
	private static final String HASH = "[A-Za-z0-9_$]{12,13}";
	/**
	 * A thread dump frame, with its class, including the suffix of a hidden class, as group 1 and
	 * its location after the module, if any, as group 2
	 */
	private static final Pattern FRAME = Pattern.compile("^\\s*at ([^(]+)\\.[^.(]+\\((?:[^()/]*/)?([^()]*)\\)$");

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
		int[] hashed = new int[3];
		String[] dialogLambda = new String[1];
		// An identity redaction of the output, to see the locations of its strings. The classes and
		// packages of org.eclipse are hashed segment by segment, so that every class name still
		// starts with the name of its package
		JfrRedactor.redact(classes, dir.resolve("unchanged.jfr"), (value, locations) -> {
			for (StringLocation location : locations) {
				if (location.isPackageName()) {
					assertTrue(
							!value.startsWith("org/eclipse/") || value.matches("org/eclipse/(" + HASH + "/)*" + HASH),
							value);
					hashed[2] += value.startsWith("org/eclipse/") ? 1 : 0;
				}
				if (!location.isClassName()) {
					continue;
				}
				// An array class constant, [Lorg/eclipse/...;, is classified by its component class
				String component = value.startsWith("[") ? value.replaceFirst("^\\[+L", "").replaceFirst(";$", "")
						: value;
				if (component.startsWith("org/eclipse/")) {
					assertTrue(component.matches("org/eclipse/(" + HASH + "/)*" + HASH), value);
					hashed[0]++;
				} else if (component.startsWith("org.eclipse.")) {
					assertTrue(component.matches("org\\.eclipse\\.(" + HASH + "\\.)*" + HASH + "\\+0x[0-9a-f]+/\\d+"),
							value);
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
		assertTrue(hashed[0] > 0 && hashed[1] > 0 && hashed[2] > 0,
				"classes, hidden classes and packages: " + hashed[0] + ", " + hashed[1] + ", " + hashed[2]);
		// The frames of a hidden class carry the hash of its constant, the Dialog lambda once and the
		// Workbench lambda once per dump
		assertTrue(dialogLambda[0] != null, "the constant of the Dialog lambda");
		String dialogFrame = "\tat " + dialogLambda[0] + "/0x00007fb87c5e2678.accept(Unknown Source)";
		assertEquals(1, text.lines().filter(dialogFrame::equals).count(), dialogFrame);
		Pattern workbenchFrame = Pattern.compile(
				"\tat org\\.eclipse\\.(" + HASH + "\\.)*" + HASH + "/0x00007fb87c2252f8\\.run\\(Unknown Source\\)");
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
		Path input = recording("jdk9-weblogic-medrec.jfr");
		// The application's class and package names and their segments, which must all disappear
		Set<String> originalNames = new TreeSet<>();
		Set<String> originalSegments = new TreeSet<>();
		JfrRedactor.redact(input, dir.resolve("input-unchanged.jfr"), (value, locations) -> {
			for (StringLocation location : locations) {
				if (location.isClassName() || location.isPackageName()) {
					List<String> segments = medrecSegments(value);
					if (segments != null) {
						originalNames.add(value);
						originalSegments.addAll(segments);
					}
				}
			}
			return value;
		});
		assertTrue(originalNames.contains("com/bea/medrec/web/controller/ViewingPatientController")
				&& originalNames.contains("com/bea/medrec/web/controller"), originalNames.toString());
		assertTrue(originalSegments.containsAll(List.of("web", "controller", "ViewingPatientController")),
				originalSegments.toString());
		// The model classes of the README's example occur in descriptors only
		String patientDescriptor = "(Lcom/bea/medrec/model/Patient;)Lcom/bea/medrec/model/Patient;";
		assertTrue(scanStrings(input).indexOf(patientDescriptor) >= 0, "the fixture has " + patientDescriptor);

		Path output = dir.resolve("redacted.jfr");
		JfrRedactor.redact(input, output, RedactPatientData.redactor());

		StringCountMap strings = scanStrings(output);
		int[] hashed = new int[2];
		// An identity redaction of the output, to see the locations of its strings: the classes and
		// the packages of com.bea.medrec are hashed segment by segment, and the package constant of
		// com/bea/medrec itself stays, as the expression matches nothing of it
		JfrRedactor.redact(output, dir.resolve("unchanged.jfr"), (value, locations) -> {
			assertTrue(!value.contains("@star.com"), value);
			for (StringLocation location : locations) {
				if (location.isClassName() || location.isPackageName()) {
					List<String> segments = medrecSegments(value);
					if (segments != null) {
						// Slashed constants of classes, arrays and packages, dotted ones of hidden classes
						assertTrue(value.matches("com/bea/medrec(/" + HASH + ")+")
								|| value.matches("\\[+Lcom/bea/medrec(/" + HASH + ")+;")
								|| value.matches(
										"com\\.bea\\.medrec(\\." + HASH + ")+(\\+0x[0-9a-f]+)?(/\\d+|/0x[0-9a-f]+)?"),
								value);
						assertNoOriginalSegment(segments, originalSegments, value);
						hashed[location.isClassName() ? 0 : 1]++;
					}
				}
				if (location.isMethodDescriptor()) {
					for (int at = value.indexOf("Lcom/bea/medrec/"); at >= 0; at = value.indexOf("Lcom/bea/medrec/",
							at + 1)) {
						String rest = value.substring(at + "Lcom/bea/medrec/".length());
						String name = rest.substring(0, rest.indexOf(';'));
						assertTrue(name.matches("(" + HASH + "/)*" + HASH), value);
						assertNoOriginalSegment(List.of(name.split("/")), originalSegments, value);
					}
				}
			}
			return value;
		});
		assertTrue(hashed[0] > 0 && hashed[1] > 0, "classes and packages: " + hashed[0] + ", " + hashed[1]);
		for (String name : originalNames) {
			assertTrue(strings.indexOf(name) < 0, name + " survives");
		}
		for (int i = 0; i < strings.size(); i++) {
			assertTrue(!strings.getString(i).contains("com/bea/medrec/model"), strings.getString(i) + " survives");
		}
		assertTrue(strings.indexOf("UPDATE PATIENTS SET STATUS='REGISTERED' WHERE EMAIL='<EMAIL>'") >= 0);
	}

	/**
	 * The segments of a class or package name below {@code com.bea.medrec}, in either form, or
	 * {@code null} for other names. Hidden classes are stored in source form with a per-run suffix.
	 */
	private static List<String> medrecSegments(String value) {
		List<String> segments = classNameSegments(value);
		if (segments.size() <= 3 || !segments.subList(0, 3).equals(List.of("com", "bea", "medrec"))) {
			return null;
		}
		return segments.subList(3, segments.size());
	}

	private static void assertNoOriginalSegment(List<String> segments, Set<String> originalSegments, String value) {
		for (String segment : segments) {
			assertTrue(!originalSegments.contains(segment), segment + " survives in " + value);
		}
	}

	/** The strings of the recording, whose events and checkpoints must all be aligned */
	private static StringCountMap scanStrings(Path recording) throws IOException {
		StringScanner scanner = new StringScanner(true);
		new StreamingChunkParser().parse(recording, scanner);
		assertEquals(0, scanner.getMisalignedCount());
		return scanner.getStrings();
	}

	@Test
	void hashesSourceNamesOfBundledThreadDumpFramesWithTheirClasses(@TempDir
	Path dir) throws Exception {
		Path input = recording("jdk21-jmc.jfr");
		String inputText = String.join("\n", TestRecordings.threadDumps(input));
		// HotSpot names the source of a generated class like the class, without an extension, and
		// prints it as the location of the frame: the convention the redactor relies on
		assertTrue(
				inputText.contains("(java.base@21.0.1/LambdaForm$MH)")
						&& inputText.contains("(java.base@21.0.1/DirectMethodHandle$Holder)"),
				"the fixture has frames of generated classes");
		int bare = 0;
		for (String line : inputText.split("\n")) {
			Matcher m = FRAME.matcher(line);
			if (m.matches() && !m.group(2).contains(".") && !m.group(2).contains(" ")) {
				assertEquals(simpleHostName(m.group(1)), m.group(2), line);
				bare++;
			}
		}
		assertTrue(bare > 10, "frames of generated classes: " + bare);
		Path output = dir.resolve("everything.jfr");
		JfrRedactor.redact(input, output, RuleRedactor.builder().hashClassNames("(.*)").build());
		int[] counts = new int[2]; // Frames, and frames with a bare source name
		for (String line : String.join("\n", TestRecordings.threadDumps(output)).split("\n")) {
			Matcher m = FRAME.matcher(line);
			if (!m.matches()) {
				continue;
			}
			String location = m.group(2);
			assertTrue(location.equals("Native Method") || location.equals("Unknown Source")
					|| location.matches(HASH + "(\\.java(:\\d+)?)?"), line);
			counts[0]++;
			if (location.matches(HASH)) {
				// The bare name is still the simple name of the class, hashed with it
				assertEquals(simpleHostName(m.group(1)), location, line);
				counts[1]++;
			}
		}
		assertTrue(counts[0] > 100 && counts[1] > 10, "frames and bare source names: " + counts[0] + ", " + counts[1]);
	}

	/** The simple name of the host of the class of a frame, without the suffix of a hidden class */
	private static String simpleHostName(String frameClass) {
		String host = frameClass.replaceFirst("/(0x[0-9a-f]+|\\d+)$", "");
		return host.substring(host.lastIndexOf('.') + 1);
	}

	/**
	 * The redactions whose output parsers must still read: with every name hashed, like the
	 * README's example, and with several class name expressions, the application's classes keyed
	 * below a prefix and everything else unkeyed, which must decide the package of a class and the
	 * constant of the package alike
	 */
	private static List<StringRedactor> packageAwareRedactors() {
		return List.of(RuleRedactor.builder().hashClassNames("(.*)").hashMethodNames("(.*)").hashThreadNames().build(),
				RedactPatientData.redactor(), JmcCompatibilityTest.severalClassNameExpressions());
	}

	@ParameterizedTest
	@ValueSource(strings = {"jdk9-basic.jfr", "jdk9-weblogic-medrec.jfr", "jdk21-jmc.jfr", "jmc-writer-pooled.jfr"})
	void keepsClassNamesStartingWithTheirPackages(String name, @TempDir
	Path dir) throws Exception {
		Path input = recording(name);
		assertEquals(List.of(), RedactionVerifier.checkClassPackageInvariant(input), "the control: the fixture itself");
		int i = 0;
		for (StringRedactor redactor : packageAwareRedactors()) {
			Path output = dir.resolve("redacted-" + i++ + ".jfr");
			JfrRedactor.redact(input, output, redactor);
			assertEquals(List.of(), RedactionVerifier.checkClassPackageInvariant(output), name + " with redactor " + i);
		}
	}

	/**
	 * The HotSpot recordings: the names the JMC writer stores through the string pool are not
	 * classified as class names, as their constants carry no referrer
	 */
	@ParameterizedTest
	@ValueSource(strings = {"jdk9-basic.jfr", "jdk9-weblogic-medrec.jfr", "jdk21-jmc.jfr"})
	void hashesEveryPackageModuleAndClassNameWhenEveryClassNameMatches(String name, @TempDir
	Path dir) throws Exception {
		Path input = recording(name);
		Set<String> packagesAndModules = new TreeSet<>();
		Set<String> classSegments = new TreeSet<>();
		JfrRedactor.redact(input, dir.resolve("input-unchanged.jfr"), (value, locations) -> {
			for (StringLocation location : locations) {
				if (location.isPackageName() || location.isModuleName()) {
					packagesAndModules.add(value);
				}
				if (location.isClassName()) {
					classSegments.addAll(classNameSegments(value));
				}
			}
			return value;
		});
		packagesAndModules.remove("");
		assertTrue(classSegments.size() > 10 && classSegments.contains("java"),
				"the fixture has class names: " + classSegments.size());
		assertTrue(packagesAndModules.size() > 10,
				"the fixture has package and module names: " + packagesAndModules.size());

		Path output = dir.resolve("redacted.jfr");
		JfrRedactor.redact(input, output, RuleRedactor.builder().hashClassNames("(.*)").build());
		int[] checked = new int[2];
		JfrRedactor.redact(output, dir.resolve("unchanged.jfr"), (value, locations) -> {
			// No name in internal form survives anywhere, the inline strings of events included
			assertTrue(!value.matches("(java|jdk|sun|org|com)/.*"), value + " survives at " + locations);
			for (StringLocation location : locations) {
				if (location.isPackageName() || location.isModuleName()) {
					assertTrue(value.isEmpty() || !packagesAndModules.contains(value),
							value + " survives at " + location);
					if (!value.isEmpty()) {
						assertTrue(value.matches("(" + HASH + "[/.])*" + HASH), value);
						checked[0]++;
					}
				}
				if (location.isClassName()) {
					List<String> segments = classNameSegments(value);
					for (String segment : segments) {
						assertTrue(segment.matches(HASH) && !classSegments.contains(segment), segment + " of " + value);
					}
					checked[1] += segments.isEmpty() ? 0 : 1;
				}
			}
			return value;
		});
		assertTrue(checked[1] > 10, "class names: " + checked[1]);
		assertTrue(checked[0] > 10, "package and module names: " + checked[0]);
	}

	/**
	 * The class name, method name and descriptor of the inlined method of a
	 * {@code jdk.CompilerInlining} event are written inline, and are classified and hashed like the
	 * constants, while the message of the event is free text and stays
	 */
	@Test
	void hashesCompilerInliningStringsOfTheBundledRecording(@TempDir
	Path dir) throws Exception {
		Path input = recording("jdk21-jmc.jfr");
		Set<String> types = new TreeSet<>();
		Set<String> methods = new TreeSet<>();
		Set<String> descriptors = new TreeSet<>();
		Set<String> messages = new TreeSet<>();
		JfrRedactor.redact(input, dir.resolve("input-unchanged.jfr"), (value, locations) -> {
			for (StringLocation location : locations) {
				if (!location.getOwner().equals("jdk.CompilerInlining") || location.isConstant()) {
					continue;
				}
				boolean type = location.getField().equals("callee.type");
				boolean method = location.getField().equals("callee.name");
				boolean descriptor = location.getField().equals("callee.descriptor");
				assertEquals(type, location.isClassName(), location.toString());
				assertEquals(method, location.isMethodName(), location.toString());
				assertEquals(descriptor, location.isMethodDescriptor(), location.toString());
				(type ? types : method ? methods : descriptor ? descriptors : messages).add(value);
			}
			return value;
		});
		assertTrue(types.size() > 10 && types.contains("java/lang/Object"), "inlined classes: " + types);
		assertTrue(methods.size() > 10 && methods.contains("<init>"), "inlined methods: " + methods);
		assertTrue(descriptors.size() > 10 && descriptors.contains("()V"), "inlined descriptors: " + descriptors);
		assertTrue(messages.size() > 1, "messages: " + messages);
		Set<String> segments = new TreeSet<>();
		types.forEach(type -> segments.addAll(classNameSegments(type)));

		Path output = dir.resolve("redacted.jfr");
		JfrRedactor.redact(input, output,
				RuleRedactor.builder().hashClassNames("(.*)").hashMethodNames("(.*)").build());
		int[] checked = new int[3];
		JfrRedactor.redact(output, dir.resolve("unchanged.jfr"), (value, locations) -> {
			for (StringLocation location : locations) {
				if (!location.getOwner().equals("jdk.CompilerInlining") || location.isConstant()) {
					continue;
				}
				switch (location.getField()) {
				case "callee.type" -> {
					assertTrue(value.matches("(" + HASH + "/)*" + HASH + "(\\+0x[0-9a-f]+)?"), value);
					assertNoOriginalSegment(classNameSegments(value), segments, value);
					checked[0]++;
				}
				case "callee.name" -> {
					assertTrue(value.matches(HASH) && !methods.contains(value), value);
					checked[1]++;
				}
				case "callee.descriptor" -> {
					for (int at = value.indexOf('L'); at >= 0; at = value.indexOf('L', value.indexOf(';', at))) {
						String name = value.substring(at + 1, value.indexOf(';', at));
						assertNoOriginalSegment(classNameSegments(name), segments, value);
					}
					checked[2]++;
				}
				default -> assertTrue(messages.contains(value), "the message is free text: " + value);
				}
			}
			return value;
		});
		assertTrue(checked[0] > 10 && checked[1] > 10 && checked[2] > 10,
				"classes, methods and descriptors: " + checked[0] + ", " + checked[1] + ", " + checked[2]);
	}

	@Test
	void findsClassesNamedOutsideTheirPackages(@TempDir
	Path dir) throws Exception {
		// A redaction that renames the classes but not their packages
		Path output = dir.resolve("broken.jfr");
		JfrRedactor.redact(recording("jdk9-basic.jfr"), output, RuleRedactor.builder()
				.replaceIf(StringLocation::isClassName, value -> value.replace('/', '_')).build());
		List<String> problems = RedactionVerifier.checkClassPackageInvariant(output);
		assertTrue(problems.size() > 2, problems.toString());
		for (String problem : problems.subList(0, problems.size() - 1)) {
			assertTrue(problem.matches("class \\S+_\\S+ is not named within its package \\S+"), problem);
		}
		assertTrue(problems.get(problems.size() - 1).matches("\\.\\.\\. and \\d+ more classes outside their packages"),
				problems.toString());
	}

	/**
	 * JMC's writer stores class and package names through the {@code java.lang.String} pool, whose
	 * constants carry no referrer that classifies them, and writes no package or module constants,
	 * so hashing every class name changes nothing of its recording: the limitation that keeps the
	 * fixture out of {@link #hashesEveryPackageModuleAndClassNameWhenEveryClassNameMatches}
	 */
	@Test
	void changesNothingOfTheJmcWriterRecordingWhenEveryClassNameMatches(@TempDir
	Path dir) throws Exception {
		Path input = recording("jmc-writer-pooled.jfr");
		int[] classified = new int[1];
		JfrRedactor.redact(input, dir.resolve("input-unchanged.jfr"), (value, locations) -> {
			for (StringLocation location : locations) {
				if (location.isClassName() || location.isPackageName() || location.isModuleName()) {
					classified[0]++;
				}
			}
			return value;
		});
		assertEquals(0, classified[0], "class, package and module names classified");
		RedactionResult result = JfrRedactor.redact(input, dir.resolve("redacted.jfr"),
				RuleRedactor.builder().hashClassNames("(.*)").build());
		assertTrue(result.stringCount() > 100 && result.redactedStringCount() == 0, result.toString());
	}

	/**
	 * The segments of a class name constant in any form: the component of an array class, without
	 * the per-run suffix of a hidden class, which in source form is also a lone identity hash
	 * ({@code Foo$$Lambda$14/1234567}, JDK 8 to 14), split at dots and slashes; empty for a
	 * primitive array
	 */
	private static List<String> classNameSegments(String value) {
		String component = value.replaceFirst("^\\[+", "");
		if (component.length() < value.length()) {
			if (!component.startsWith("L") || !component.endsWith(";")) {
				return List.of();
			}
			component = component.substring(1, component.length() - 1);
		}
		String host = component.replaceFirst("\\+0x[0-9a-fA-F]+(/\\d+)?$", "").replaceFirst("/0x[0-9a-fA-F]+$", "");
		if (host.indexOf('.') >= 0) {
			host = host.replaceFirst("/\\d+$", "");
		}
		return List.of(host.split("[./]"));
	}

	static Path recording(String name) throws URISyntaxException {
		return Path.of(FixtureTest.class.getResource("/recordings/" + name).toURI());
	}
}
