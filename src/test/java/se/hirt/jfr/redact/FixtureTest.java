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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

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
 * and one written by JMC's pure-Java writer, which stores every string, the names of threads,
 * classes and methods included, through the {@code java.lang.String} constant pool.
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
	@ValueSource(strings = {"jrockit-r28-transitions.jfr", "jdk8-guimark.jfr", "jdk9-basic.jfr",
			"jdk9-weblogic-medrec.jfr", "jdk21-jmc.jfr", "jmc-writer-pooled.jfr"})
	void redactsEveryStringCorrectly(String name, @TempDir
	Path dir) throws Exception {
		// The JDK's parser reads JFR 1.0+, not the JFR 0.9 of JRockit and JDK 7 and 8
		boolean jdkCanParse = Files.readAllBytes(recording(name))[5] != 0;
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
		StringLocation methodName = new StringLocation("jdk.types.Method", "name", true, List.of());
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
	 * The HotSpot recordings, which have the many classes, packages and modules the thresholds
	 * expect; the JMC writer's recording, with one package and no modules, is checked by
	 * {@link #hashesEveryNameOfTheJmcWriterRecording}
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
				if (!location.getOwner().equals("jdk.CompilerInlining") || location.isPooled()) {
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
				if (!location.getOwner().equals("jdk.CompilerInlining") || location.isPooled()) {
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
	 * JMC's writer stores every string through the {@code java.lang.String} pool: the class,
	 * method, descriptor and package symbols, the thread and thread group names, the strings of its
	 * events and those of its own constant types. Each is located at the field whose value it is,
	 * as in HotSpot's inline layout, so that the predicates classify the names: a class name is the
	 * value of {@code java.lang.Class.name} through two simple types, the {@code jdk.types.Symbol}
	 * the class refers to and the pool entry the symbol refers to, and the writer stores the frames
	 * of a stack trace as constants of their own, so a frame type is the value of
	 * {@code jdk.types.StackFrame.type}. Neither a class, a method, a package nor a frame stores a
	 * string itself, so none of them has referrers, see {@link StringLocation#getReferrers()}; the
	 * thread group, which does, is referred to by the thread. The pool is a location of its own
	 * only for the entries no field refers to: the annotation texts the writer pools, and the empty
	 * string, which it pools as well while writing empty values with the empty encoding, inline.
	 */
	@Test
	void locatesTheStringsOfTheJmcWriterRecordingAtTheirFields(@TempDir
	Path dir) throws Exception {
		Map<String, List<StringLocation>> locations = allLocations(recording("jmc-writer-pooled.jfr"),
				dir.resolve("unchanged.jfr"));
		for (int i = 0; i < 3; i++) {
			assertLocatedAt(locations, "se/hirt/wm/secretpkg/Workload$SecretCustomer" + i, StringLocation::isClassName,
					"java.lang.Class.name (pooled)");
		}
		assertLocatedAt(locations, "computeSecretTotal", StringLocation::isMethodName,
				"jdk.types.Method.name (pooled)");
		assertLocatedAt(locations, "(I)J", StringLocation::isMethodDescriptor, "jdk.types.Method.descriptor (pooled)");
		assertLocatedAt(locations, "se/hirt/wm/secretpkg", StringLocation::isPackageName,
				"jdk.types.Package.name (pooled)");
		assertLocatedAt(locations, "Interpreted", location -> location.getField().equals("type"),
				"jdk.types.StackFrame.type (pooled)");
		assertEquals(Map.of("java.lang.String", 12),
				unreferencedSimpleConstants(locations, "jdk.types.Symbol", "jdk.types.FrameType", "java.lang.String"),
				"no symbol or frame type is unreferenced; the pool holds the 11 annotation texts and the empty string");
		assertLocatedAt(locations, "SecretWorker-0", StringLocation::isThreadName,
				"java.lang.Thread.javaName (pooled)");
		assertLocatedAt(locations, "SecretOs-0", StringLocation::isThreadName, "java.lang.Thread.osName (pooled)");
		assertLocatedAt(locations, "SecretGroup", StringLocation::isThreadGroupName,
				"jdk.types.ThreadGroup.name (pooled) referred to by java.lang.Thread.group");
		// The strings of the events, and of the nested and info structs, which the writer stores as
		// constants of their own types, referred to by the events and by the info constants
		Predicate<StringLocation> eventValue = location -> location.getOwner().startsWith("se.hirt.wm.")
				&& location.isPooled();
		assertLocatedAt(locations, "secret message number 0 for account 4711", eventValue,
				"se.hirt.wm.JmcEvent.message (pooled)");
		assertLocatedAt(locations, "Café ÿ Ångström 0", eventValue, "se.hirt.wm.JmcEvent.latin1 (pooled)");
		assertLocatedAt(locations, "漢字Ω 😀 0", eventValue, "se.hirt.wm.JmcEvent.unicode (pooled)");
		assertLocatedAt(locations, "nested secret 0", eventValue, "se.hirt.wm.Nested.secret (pooled)");
		assertLocatedAt(locations, "nested-tag-0", eventValue, "se.hirt.wm.Nested.tags (pooled)");
		assertLocatedAt(locations, "hunter2", eventValue, "se.hirt.wm.Nested.tags (pooled)");
		assertLocatedAt(locations, "pooled label 0", eventValue, "se.hirt.wm.PooledInfo.label (pooled)");
		assertLocatedAt(locations, "pooled nested secret 0", eventValue,
				"se.hirt.wm.Nested.secret (pooled) referred to by se.hirt.wm.PooledInfo.inner");
		assertLocatedAt(locations, "p0", eventValue,
				"se.hirt.wm.Nested.tags (pooled) referred to by se.hirt.wm.PooledInfo.inner");
		// The entries no field refers to, and nothing else, are located at the pool, without referrers
		Predicate<StringLocation> unreferenced = location -> location.getOwner().equals("java.lang.String")
				&& location.getField().equals("value") && location.isPooled() && location.getReferrers().isEmpty();
		int unreferencedCount = 0;
		for (Map.Entry<String, List<StringLocation>> entry : locations.entrySet()) {
			for (StringLocation location : entry.getValue()) {
				if (location.getOwner().equals("java.lang.String")) {
					assertTrue(unreferenced.test(location), entry.getKey() + " at " + location);
					unreferencedCount++;
				}
			}
		}
		assertEquals(12, unreferencedCount, "unreferenced pool entries: the 11 annotation texts and the empty string");
		for (String annotation : List.of("jdk.jfr.Timestamp", "A point in time", "Unsigned value")) {
			assertLocatedAt(locations, annotation, unreferenced, "java.lang.String.value (pooled)",
					StringLocation.METADATA.toString());
		}
		assertLocatedAt(locations, "", unreferenced, "java.lang.String.value (pooled)",
				"se.hirt.wm.JmcEvent.empty (inline)", "se.hirt.wm.Nested.tags (pooled)");
	}

	/**
	 * The constant types HotSpot's metadata declares simple, {@code jdk.types.Symbol},
	 * {@code FrameType}, {@code ThreadState}, {@code GCWhen}, {@code GCCause} and the other types
	 * with one string field, are read by every reader as that value, so each of their strings is
	 * located at the fields referring to it, and never at the simple type: a class name at
	 * {@code java.lang.Class.name}, a method name at {@code jdk.types.Method.name}, a frame type at
	 * {@code jdk.types.StackTrace.frames.type}, the state of a sample at
	 * {@code jdk.ExecutionSample.state}, the moment of a heap summary at
	 * {@code jdk.GCHeapSummary.when}, and a symbol only an event refers to, the code source of a
	 * finalizer statistic, at the event's field. A class, a method, a package or a module stores no
	 * string itself, its names being symbols, so none of them has referrers, however many methods
	 * refer to a class or frames to a method, see {@link StringLocation#getReferrers()}. The inline
	 * copies of the {@code jdk.CompilerInlining} events stay where they are. HotSpot writes every
	 * value of its enumerations, so the values nothing refers to, {@code STATE_NEW} among the
	 * thread states and {@code System.gc()} among the GC causes of this recording, are located at
	 * their own field, and only those: 8 thread states, 33 GC causes and 9 GC names, none of the
	 * symbols, frame types and pool entries.
	 */
	@Test
	void locatesTheValuesOfTheJdk21SimpleTypesAtTheFieldsReferringToThem(@TempDir
	Path dir) throws Exception {
		Path input = recording("jdk21-jmc.jfr");
		Map<String, List<StringLocation>> locations = allLocations(input, dir.resolve("unchanged.jfr"));
		assertLocatedAt(locations, "java/util/HashMap", StringLocation::isClassName, "java.lang.Class.name (pooled)",
				"jdk.CompilerInlining.callee.type (inline)");
		assertLocatedAt(locations, "java/lang/Object", StringLocation::isClassName, "java.lang.Class.name (pooled)",
				"jdk.CompilerInlining.callee.type (inline)");
		assertLocatedAt(locations, "<init>", StringLocation::isMethodName, "jdk.types.Method.name (pooled)",
				"jdk.CompilerInlining.callee.name (inline)");
		assertLocatedAt(locations, "()V", StringLocation::isMethodDescriptor, "jdk.types.Method.descriptor (pooled)",
				"jdk.CompilerInlining.callee.descriptor (inline)");
		assertLocatedAt(locations, "java/util", StringLocation::isPackageName, "jdk.types.Package.name (pooled)");
		assertLocatedAt(locations, "java.base", StringLocation::isModuleName, "jdk.types.Module.name (pooled)");
		assertNoReferrers(locations, "java.lang.Class", "jdk.types.Method", "jdk.types.Package", "jdk.types.Module",
				"jdk.types.StackTrace");
		assertLocatedAt(locations, "JIT compiled", StringLocation::isPooled,
				"jdk.types.StackTrace.frames.type (pooled)");
		assertLocatedAt(locations, "Interpreted", StringLocation::isPooled, "jdk.types.StackTrace.frames.type (pooled)",
				StringLocation.METADATA.toString());
		assertLocatedAt(locations, "STATE_RUNNABLE", StringLocation::isPooled, "jdk.ExecutionSample.state (pooled)",
				"jdk.NativeMethodSample.state (pooled)");
		for (String when : List.of("Before GC", "After GC")) {
			assertLocatedAt(locations, when, StringLocation::isPooled, "jdk.GCHeapSummary.when (pooled)",
					"jdk.G1HeapSummary.when (pooled)", "jdk.MetaspaceSummary.when (pooled)",
					"jdk.MetaspaceChunkFreeListSummary.when (pooled)");
		}
		assertLocatedAt(locations, "Heap Inspection Initiated GC", StringLocation::isPooled,
				"jdk.GarbageCollection.cause (pooled)");
		assertLocatedAt(locations, "G1New", StringLocation::isPooled, "jdk.GCConfiguration.youngCollector (pooled)");
		assertLocatedAt(locations, "file:///usr/lib/jmc/plugins/org.openjdk.jmc.rjmx_8.3.0.jar",
				StringLocation::isPooled, "jdk.FinalizerStatistics.codeSource (pooled)");
		assertLocatedAt(locations, "STATE_NEW", StringLocation::isPooled, "jdk.types.ThreadState.name (pooled)");
		assertLocatedAt(locations, "System.gc()", StringLocation::isPooled, "jdk.types.GCCause.cause (pooled)",
				StringLocation.METADATA.toString());
		assertLocatedAt(locations, "Allocation Failure", StringLocation::isPooled, "jdk.types.GCCause.cause (pooled)",
				StringLocation.METADATA.toString());
		assertEquals(Map.of("jdk.types.ThreadState", 8, "jdk.types.GCCause", 33, "jdk.types.GCName", 9),
				unreferencedSimpleConstants(locations, "jdk.types.Symbol", "jdk.types.FrameType", "java.lang.String",
						"jdk.types.ThreadState", "jdk.types.GCWhen", "jdk.types.GCCause", "jdk.types.GCName"));
		assertOwnedOnlyWhenUnreferenced(locations, input, "jdk.types.ThreadState", "jdk.types.GCWhen",
				"jdk.types.GCCause", "jdk.types.GCName");
	}

	/**
	 * The JDK 9 recording names the types {@code com.oracle.jfr.types} and the events
	 * {@code com.oracle.jdk}, and has neither samples nor collections, so its 9 thread states, 2 GC
	 * moments, 28 GC causes, 9 GC names and the {@code Inlined} frame type are referred to by
	 * nothing and located at their own field
	 */
	@Test
	void locatesTheValuesOfTheJdk9SimpleTypesAtTheFieldsReferringToThem(@TempDir
	Path dir) throws Exception {
		Path input = recording("jdk9-basic.jfr");
		Map<String, List<StringLocation>> locations = allLocations(input, dir.resolve("unchanged.jfr"));
		assertLocatedAt(locations, "java/lang/Object", StringLocation::isClassName, "java.lang.Class.name (pooled)");
		assertLocatedAt(locations, "<init>", StringLocation::isMethodName, "com.oracle.jfr.types.Method.name (pooled)");
		assertLocatedAt(locations, "()V", StringLocation::isMethodDescriptor,
				"com.oracle.jfr.types.Method.descriptor (pooled)");
		assertLocatedAt(locations, "java/util", StringLocation::isPackageName,
				"com.oracle.jfr.types.Package.name (pooled)");
		assertLocatedAt(locations, "java.base", StringLocation::isModuleName,
				"com.oracle.jfr.types.Module.name (pooled)");
		assertNoReferrers(locations, "java.lang.Class", "com.oracle.jfr.types.Method", "com.oracle.jfr.types.Package",
				"com.oracle.jfr.types.Module", "com.oracle.jfr.types.StackTrace");
		assertLocatedAt(locations, "JIT compiled", StringLocation::isPooled,
				"com.oracle.jfr.types.StackTrace.frames.type (pooled)");
		assertLocatedAt(locations, "Interpreted", StringLocation::isPooled,
				"com.oracle.jfr.types.StackTrace.frames.type (pooled)");
		assertLocatedAt(locations, "Inlined", StringLocation::isPooled,
				"com.oracle.jfr.types.FrameType.description (pooled)", StringLocation.METADATA.toString());
		assertLocatedAt(locations, "STATE_RUNNABLE", StringLocation::isPooled,
				"com.oracle.jfr.types.ThreadState.name (pooled)");
		assertLocatedAt(locations, "Before GC", StringLocation::isPooled, "com.oracle.jfr.types.GCWhen.when (pooled)");
		assertEquals(Map.of("com.oracle.jfr.types.FrameType", 1, "com.oracle.jfr.types.ThreadState", 9,
				"com.oracle.jfr.types.GCWhen", 2, "com.oracle.jfr.types.GCCause", 28, "com.oracle.jfr.types.GCName", 9),
				unreferencedSimpleConstants(locations, "com.oracle.jfr.types.Symbol", "java.lang.String",
						"com.oracle.jfr.types.FrameType", "com.oracle.jfr.types.ThreadState",
						"com.oracle.jfr.types.GCWhen", "com.oracle.jfr.types.GCCause", "com.oracle.jfr.types.GCName"));
		assertOwnedOnlyWhenUnreferenced(locations, input, "com.oracle.jfr.types.FrameType",
				"com.oracle.jfr.types.ThreadState", "com.oracle.jfr.types.GCWhen", "com.oracle.jfr.types.GCCause",
				"com.oracle.jfr.types.GCName");
	}

	/**
	 * JFR 0.9 declares no simple types, so JRockit's interned strings keep their storage as the
	 * location, {@code UTFConstant.utf8} with the referring field, and its enumerations, such as
	 * {@code ThreadState}, are located at their own field; the predicates know the referring fields
	 */
	@Test
	void locatesTheJRockitStringsAtTheConstantsStoringThem(@TempDir
	Path dir) throws Exception {
		Map<String, List<StringLocation>> locations = allLocations(recording("jrockit-r28-transitions.jfr"),
				dir.resolve("unchanged.jfr"));
		assertLocatedAt(locations, "java/lang/Object", StringLocation::isClassName,
				"UTFConstant.utf8 (pooled) referred to by Class.name");
		assertLocatedAt(locations, "()V", StringLocation::isMethodDescriptor,
				"UTFConstant.utf8 (pooled) referred to by Method.signature");
		assertLocatedAt(locations, "main", StringLocation::isMethodName,
				"UTFConstant.utf8 (pooled) referred to by Method.name",
				"ThreadGroup.name (pooled) referred to by JavaThread.group");
		assertLocatedAt(locations, "STATE_RUNNABLE", StringLocation::isPooled, "ThreadState.name (pooled)");
		assertLocatedAt(locations, "Main Thread", StringLocation::isThreadName,
				"Thread.name (pooled) referred to by JavaThread.thread, VMThread.thread");
	}

	/**
	 * Asserts that no location with one of the owners, entities storing no string themselves, has
	 * referrers, and that the recording has locations of each: the fields referring to such an
	 * entity are not tracked, see {@link StringLocation#getReferrers()}
	 */
	private static void assertNoReferrers(Map<String, List<StringLocation>> locations, String ... owners) {
		Set<String> ownerSet = Set.of(owners);
		Set<String> seen = new TreeSet<>();
		for (Map.Entry<String, List<StringLocation>> entry : locations.entrySet()) {
			for (StringLocation location : entry.getValue()) {
				if (ownerSet.contains(location.getOwner())) {
					assertEquals(List.of(), location.getReferrers(), entry.getKey() + " at " + location);
					seen.add(location.getOwner());
				}
			}
		}
		assertEquals(new TreeSet<>(ownerSet), seen, "the recording locates strings at every owner");
	}

	/** The locations of every string of the recording, by an identity redaction */
	private static Map<String, List<StringLocation>> allLocations(Path input, Path output) throws IOException {
		Map<String, List<StringLocation>> locations = new TreeMap<>();
		JfrRedactor.redact(input, output, (value, list) -> {
			locations.put(value, list);
			return value;
		});
		return locations;
	}

	/**
	 * Asserts that every location with one of the owners, simple types whose constants are located
	 * at the fields referring to them, is the own field of a constant nothing refers to, as a
	 * constant without referrers
	 *
	 * @return per owner, the number of strings located so, which pins how many constants of each
	 *         type the recording leaves unreferenced
	 */
	private static Map<String, Integer> unreferencedSimpleConstants(
		Map<String, List<StringLocation>> locations, String ... owners) {
		Set<String> ownerSet = Set.of(owners);
		Map<String, Integer> counts = new TreeMap<>();
		for (Map.Entry<String, List<StringLocation>> entry : locations.entrySet()) {
			for (StringLocation location : entry.getValue()) {
				if (ownerSet.contains(location.getOwner())) {
					assertTrue(location.isPooled() && location.getReferrers().isEmpty(),
							entry.getKey() + " at " + location);
					counts.merge(location.getOwner(), 1, Integer::sum);
				}
			}
		}
		return counts;
	}

	/**
	 * Asserts that the simple types own a location only for the constants nothing refers to, which
	 * the scanner's reference counting tells independently, and then without referrers. The scanner
	 * takes key 0 as null in every pool, so for the first constant of an enumeration, such as
	 * {@code Interpreted} or {@code Before GC}, it counts no references, and the check is vacuous:
	 * the exact counts of {@link #unreferencedSimpleConstants} cover those.
	 */
	private static void assertOwnedOnlyWhenUnreferenced(
		Map<String, List<StringLocation>> locations, Path input, String ... owners) throws IOException {
		StringScanner scanner = new StringScanner(true, true);
		new StreamingChunkParser().parse(input, scanner);
		StringCountMap strings = scanner.getStrings();
		Set<String> ownerSet = Set.of(owners);
		int unreferenced = 0;
		for (Map.Entry<String, List<StringLocation>> entry : locations.entrySet()) {
			for (StringLocation location : entry.getValue()) {
				if (ownerSet.contains(location.getOwner())) {
					assertTrue(location.getReferrers().isEmpty(), entry.getKey() + " at " + location);
					assertEquals(0, strings.getReferenceCount(strings.indexOf(entry.getKey())),
							entry.getKey() + " at " + location + " is referred to");
					unreferenced++;
				}
			}
		}
		assertTrue(unreferenced > 0, "the fixture has unreferenced values of " + ownerSet);
	}

	/**
	 * Hashing every class, method and thread name and replacing the application's strings leaves no
	 * name of the JMC writer's recording behind, since the strings it stores through the pool are
	 * reached like inline ones, and JMC reads the result like the original. The application's
	 * strings are matched by the prefix of their owners: the writer stores the nested and info
	 * structs of its events as constants of their own types, {@code se.hirt.wm.Nested} and
	 * {@code se.hirt.wm.PooledInfo}, so a rule on the event type alone would leave their values
	 * behind. With one package and no modules the recording is below the thresholds of
	 * {@link #hashesEveryPackageModuleAndClassNameWhenEveryClassNameMatches}, so the hashing of
	 * every name is checked here.
	 */
	@Test
	void hashesEveryNameOfTheJmcWriterRecording(@TempDir
	Path dir) throws Exception {
		Path input = recording("jmc-writer-pooled.jfr");
		JmcModel control = JmcModel.load(input);
		Path output = dir.resolve("redacted.jfr");
		RedactionResult result = JfrRedactor.redact(input, output,
				RuleRedactor.builder().hashClassNames("(.*)").hashMethodNames("(.*)").hashThreadNames()
						.replaceIf(location -> location.getOwner().startsWith("se.hirt.wm."),
								value -> value.isEmpty() ? value : "<X>")
						.build());
		assertTrue(result.redactedStringCount() > 100, result.toString());
		TestRecordings.assertAbsent(output, "secretpkg", "SecretCustomer", "computeSecretTotal", "SecretWorker",
				"SecretOs", "SecretGroup", "secret message", "nested secret", "pooled");
		assertEquals(List.of(), RedactionVerifier.checkClassPackageInvariant(output));
		JmcModel redacted = JmcModel.load(output);
		assertEquals(List.of(), redacted.problems());
		assertEquals(control.items(), redacted.items(), "events read");
		assertEquals(control.classes(), redacted.classes(), "classes reached");
		assertEquals(control.frames(), redacted.frames(), "frames reached");
		// The three class names and the package name are hashed segment by segment, and no name in
		// internal form survives anywhere
		int[] hashed = new int[2];
		JfrRedactor.redact(output, dir.resolve("unchanged.jfr"), (value, list) -> {
			assertTrue(!value.contains("se/hirt/wm"), value + " survives at " + list);
			for (StringLocation location : list) {
				if (location.isClassName() || location.isPackageName()) {
					assertTrue(value.matches("(" + HASH + "/)*" + HASH), value);
					hashed[location.isClassName() ? 0 : 1]++;
				}
			}
			return value;
		});
		assertEquals(3, hashed[0], "class names");
		assertEquals(1, hashed[1], "package names");
	}

	/**
	 * HotSpot's Java event writer pools a string of 17 to 128 characters once it has seen it twice,
	 * remembering what it pooled beyond the chunk it first saw it in, and pools longer strings on
	 * first sight from JDK 24 on and in the updates JDK-8338389 was backported to, so a value can
	 * have no inline copy at all: the bundled JDK 21 recording, a single chunk of a JVM that had
	 * pooled them before the chunk began, stores the exception messages and security properties
	 * below in the pool only. Each is located at the event field whose value it is, as a constant,
	 * so a rule on those fields reaches it. The chunk's events refer to every entry of its pool, so
	 * none is located at the pool; the first entry JDK 11 ever pools, which it never refers to, or
	 * a chunk holding an entry that only a later chunk refers to, would leave an entry located
	 * there.
	 */
	@Test
	void locatesTheValuesHotSpotPooledOnlyAtTheirEventFields(@TempDir
	Path dir) throws Exception {
		Path input = recording("jdk21-jmc.jfr");
		Map<String, String> fields = Map.of("Malformed IPv4 address", "jdk.JavaExceptionThrow.message",
				"org.eclipse.swt.widgets.Tree.cut()", "jdk.JavaExceptionThrow.message",
				"org.eclipse.swt.widgets.Tree.copy()", "jdk.JavaExceptionThrow.message",
				"org.eclipse.swt.widgets.Tree.paste()", "jdk.JavaExceptionThrow.message", "jceks.key.serialFilter",
				"jdk.InitialSecurityProperty.key", "sun.misc.,sun.reflect.", "jdk.InitialSecurityProperty.value");
		StringCountMap strings = scanStrings(input);
		for (String value : fields.keySet()) {
			int entry = strings.indexOf(value);
			assertTrue(entry >= 0, "the fixture stores " + value);
			assertEquals(0, strings.getCount(entry, StringScanner.INLINE), value + " has an inline copy");
			assertEquals(1, strings.getCount(entry, StringScanner.CONSTANT_POOL), value + " is pooled");
		}
		Map<String, List<StringLocation>> locations = new TreeMap<>();
		JfrRedactor.redact(input, dir.resolve("input-unchanged.jfr"), (value, list) -> {
			if (fields.containsKey(value)) {
				locations.put(value, list);
			}
			for (StringLocation location : list) {
				assertTrue(!location.getOwner().equals("java.lang.String"),
						"every entry of this chunk's pool is referred to by a field of the chunk: " + value + " at "
								+ list);
			}
			return value;
		});
		// The values of security properties are located per key, see KeyedLocationTest
		fields.forEach((value, field) -> assertEquals(List.of(field + " (pooled)"),
				locations.get(value).stream()
						.map(l -> l.getOwner() + "." + l.getField() + (l.isPooled() ? " (pooled)" : " (inline)"))
						.distinct().toList(),
				value));

		Path output = dir.resolve("redacted.jfr");
		RedactionResult result = JfrRedactor.redact(input, output,
				RuleRedactor.builder()
						.replaceIf(location -> fields.containsValue(location.getOwner() + "." + location.getField()),
								value -> "<X>")
						.build());
		assertTrue(result.redactedStringCount() >= fields.size(), result.toString());
		TestRecordings.assertAbsent(output, fields.keySet().toArray(new String[0]));
		assertEquals(RecordingFile.readAllEvents(input).size(), RecordingFile.readAllEvents(output).size());
		JmcModel control = JmcModel.load(input);
		JmcModel redacted = JmcModel.load(output);
		assertEquals(List.of(), redacted.problems());
		assertEquals(control.items(), redacted.items(), "events read");
	}

	/**
	 * Asserts the locations of the value, exactly, by their descriptions, one of them satisfying
	 * the predicate
	 */
	private static void assertLocatedAt(
		Map<String, List<StringLocation>> locations, String value, Predicate<StringLocation> predicate,
		String ... expected) {
		List<StringLocation> actual = locations.get(value);
		assertNotNull(actual, "the recording stores " + value);
		assertEquals(new TreeSet<>(Arrays.asList(expected)),
				actual.stream().map(StringLocation::toString).collect(Collectors.toCollection(TreeSet::new)), value);
		assertTrue(actual.stream().anyMatch(predicate), value + " at " + actual);
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
