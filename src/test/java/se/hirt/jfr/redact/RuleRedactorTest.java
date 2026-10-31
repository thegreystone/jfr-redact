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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import jdk.jfr.Event;
import jdk.jfr.Name;
import jdk.jfr.Recording;
import jdk.jfr.StackTrace;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedFrame;
import jdk.jfr.consumer.RecordingFile;
import se.hirt.jfr.redact.examples.RenameJavaUtil;
import se.hirt.jfr.redact.scan.StringCountMap;
import se.hirt.jfr.redact.scan.StringScanner;
import se.hirt.jfr.redact.parser.StreamingChunkParser;

class RuleRedactorTest {
	@Test
	void matching() {
		RuleRedactor redactor = RuleRedactor.builder().replace("exact", "E").replace("java.util.*", "utilz.*")
				.replace("com.acme.*", "REDACTED").replace("*.secret", "*.hidden").replace("*password*", "\\*\\*\\*")
				.replace("*java/util/*", "*utilz/*").build();
		assertEquals("E", redactor.redact("exact"));
		assertEquals("exactly", redactor.redact("exactly"));
		assertEquals("utilz.HashMap", redactor.redact("java.util.HashMap"));
		assertEquals("utilz.", redactor.redact("java.util."));
		assertEquals("java.utility", redactor.redact("java.utility"));
		assertEquals("REDACTED", redactor.redact("com.acme.Foo"));
		assertEquals("db.hidden", redactor.redact("db.secret"));
		assertEquals("***", redactor.redact("my password is 1234"));
		assertEquals("(Lutilz/List;Lutilz/Map;)V", redactor.redact("(Ljava/util/List;Ljava/util/Map;)V"));
		assertEquals("unrelated", redactor.redact("unrelated"));
	}

	@Test
	void renamesPackages() {
		RuleRedactor redactor = RuleRedactor.builder().renamePackage("java.util", "utilz").build();
		assertEquals("utilz", redactor.redact("java.util"));
		assertEquals("utilz.HashMap", redactor.redact("java.util.HashMap"));
		assertEquals("utilz.concurrent.Future", redactor.redact("java.util.concurrent.Future"));
		assertEquals("utilz", redactor.redact("java/util"));
		assertEquals("utilz/HashMap", redactor.redact("java/util/HashMap"));
		assertEquals("utilz/stream/ReferencePipeline$$Lambda/0x0000000801001234",
				redactor.redact("java/util/stream/ReferencePipeline$$Lambda/0x0000000801001234"));
		assertEquals("(ILutilz/List;Lutilz/Map;)V", redactor.redact("(ILjava/util/List;Ljava/util/Map;)V"));
		assertEquals("(Ljava/lang/String;)Lutilz/Optional;",
				redactor.redact("(Ljava/lang/String;)Ljava/util/Optional;"));
		assertEquals("[[Lutilz/HashMap;", redactor.redact("[[Ljava/util/HashMap;"));
		assertEquals("Lutilz/List;", redactor.redact("Ljava/util/List;"));
		// Not the package, or not at a package boundary
		assertEquals("java.utility", redactor.redact("java.utility"));
		assertEquals("java/utility/Foo", redactor.redact("java/utility/Foo"));
		assertEquals("org/example/java/util/Foo", redactor.redact("org/example/java/util/Foo"));
		assertEquals("(Lorg/example/java/util/Foo;)V", redactor.redact("(Lorg/example/java/util/Foo;)V"));
		assertEquals("([Ljava/utility/X;)V", redactor.redact("([Ljava/utility/X;)V"));
		assertEquals("", redactor.redact(""));
	}

	@Test
	void rejectsInvalidPackageNames() {
		assertThrows(IllegalArgumentException.class, () -> RuleRedactor.builder().renamePackage("java/util", "x"));
		assertThrows(IllegalArgumentException.class, () -> RuleRedactor.builder().renamePackage("java.", "x"));
		assertThrows(IllegalArgumentException.class, () -> RuleRedactor.builder().renamePackage("java.util", ""));
	}

	@Test
	void replacesAtLocations() {
		StringLocation threadName = new StringLocation("java.lang.Thread", "javaName", true, List.of());
		StringLocation eventField = new StringLocation("test.Work", "description", false, List.of());
		RuleRedactor redactor = RuleRedactor.builder().replaceIf(StringLocation::isThreadName, n -> "T").build();
		assertEquals("T", redactor.redact("worker", List.of(eventField, threadName)));
		assertEquals("worker", redactor.redact("worker", List.of(eventField)));
		assertEquals("worker", redactor.redact("worker"));
	}

	@Test
	void replacesCompositeStringsWithGlobs() {
		RuleRedactor all = RuleRedactor.builder().replace("*", "X").build();
		RuleRedactor matching = RuleRedactor.builder().replace("*secret*", "<REDACTED>").build();
		RuleRedactor preserving = RuleRedactor.builder().replace("*secret*", "*hidden*").build();
		RuleRedactor nonmatching = RuleRedactor.builder().replace("*not-present*", "X").build();
		for (StringLocation location : compositeLocations()) {
			String text = compositeText(location);
			List<StringLocation> locations = List.of(location);
			assertEquals("X", all.redact(text, locations), location.toString());
			assertEquals("X", all.redact("", locations), location.toString());
			assertEquals("<REDACTED>", matching.redact(text, locations), location.toString());
			assertEquals(text.replace("secret", "hidden"), preserving.redact(text, locations), location.toString());
			assertEquals(text, nonmatching.redact(text, locations), location.toString());
			assertEquals("<EXACT>", RuleRedactor.builder().replace(text, "<EXACT>").build().redact(text, locations));
		}
	}

	@Test
	void replacesCompositeStringsAtMatchingLocations() {
		RuleRedactor matching = RuleRedactor.builder()
				.replaceIf(StringLocation::isComposite, text -> text.replace("secret", "hidden")).build();
		RuleRedactor nonmatching = RuleRedactor.builder()
				.replaceIf(location -> location.getOwner().equals("absent"), text -> "X").build();
		for (StringLocation location : compositeLocations()) {
			String text = compositeText(location);
			assertEquals(text.replace("secret", "hidden"), matching.redact(text, List.of(location)),
					location.toString());
			assertEquals(text, nonmatching.redact(text, List.of(location)), location.toString());
		}
	}

	@Test
	void compositeStringsRetainEveryLocationForPredicates() {
		StringLocation ordinary = new StringLocation("test.Work", "description", false, List.of());
		RuleRedactor redactor = RuleRedactor.builder().replaceIf(location -> location == ordinary, text -> "X").build();
		for (StringLocation composite : compositeLocations()) {
			String text = compositeText(composite);
			assertEquals("X", redactor.redact(text, List.of(composite, ordinary)));
			assertEquals("X", redactor.redact(text, List.of(ordinary, composite)));
			assertEquals(text, redactor.redact(text, List.of(composite)));
		}
	}

	@Test
	void nonmatchingGenericRulesPreserveSpecializedCompositeRewrites() {
		RuleRedactor specialized = RuleRedactor.builder().hashThreadNames().renamePackage("java.util", "utilz").build();
		RuleRedactor combined = RuleRedactor.builder().replace("*not-present*", "X").hashThreadNames()
				.renamePackage("java.util", "utilz")
				.replaceIf(location -> location.getOwner().equals("absent"), text -> "X").build();
		for (StringLocation location : compositeLocations()) {
			String text = compositeText(location);
			String expected = specialized.redact(text, List.of(location));
			assertTrue(expected.contains("Thread-"), expected);
			assertTrue(!expected.contains("secret"), expected);
			if (location.isThreadDump()) {
				assertTrue(expected.contains("utilz.ArrayList"), expected);
			}
			assertEquals(expected, combined.redact(text, List.of(location)), location.toString());
		}
	}

	@Test
	void firstMatchingWholeCompositeRuleWinsEvenWhenItKeepsTheValue() {
		RuleRedactor first = RuleRedactor.builder().replace("*secret*", "first").replace("*", "second").build();
		RuleRedactor identityPredicate = RuleRedactor.builder().replaceIf(StringLocation::isComposite, text -> text)
				.replace("*", "second").build();
		for (StringLocation location : compositeLocations()) {
			String text = compositeText(location);
			List<StringLocation> locations = List.of(location);
			assertEquals("first", first.redact(text, locations), location.toString());
			assertEquals(text, identityPredicate.redact(text, locations), location.toString());
			RuleRedactor identityGlob = RuleRedactor.builder().replace(text, text).replace("*", "second").build();
			assertEquals(text, identityGlob.redact(text, locations), location.toString());
		}
	}

	@Test
	void wholeCompositeRulesSeePrecedingSpecializedRewrites() {
		RuleRedactor hashes = RuleRedactor.builder().hashThreadNames().build();
		String hashed = hashes.redact("secret",
				List.of(new StringLocation("java.lang.Thread", "javaName", true, List.of())));
		RuleRedactor matchingHash = RuleRedactor.builder().hashThreadNames().replace("*" + hashed + "*", "X").build();
		RuleRedactor matchingOriginal = RuleRedactor.builder().hashThreadNames().replace("*secret*", "X").build();
		for (StringLocation location : compositeLocations()) {
			String text = compositeText(location);
			List<StringLocation> locations = List.of(location);
			assertEquals("X", matchingHash.redact(text, locations), location.toString());
			assertEquals(hashes.redact(text, locations), matchingOriginal.redact(text, locations), location.toString());
		}
	}

	@Test
	void packageRulesRewriteEveryCompositeOccurrenceEvenAtTheStart() {
		RuleRedactor redactor = RuleRedactor.builder().renamePackage("java.util", "utilz").build();
		for (StringLocation location : compositeLocations()) {
			if (location.isOldObjectDescription()) {
				assertEquals("utilz.List and utilz.Set",
						redactor.redact("java.util.List and java.util.Set", List.of(location)), location.toString());
			}
		}
	}

	@Test
	void blanketReplacementRemovesBundledThreadDumps(@TempDir
	Path dir) throws Exception {
		Path input = Path.of(RuleRedactorTest.class.getResource("/recordings/jdk21-jmc.jfr").toURI());
		Path output = dir.resolve("redacted.jfr");
		List<String> before = threadDumps(input);
		assertEquals(2, before.size(), "the bundled fixture must exercise both thread dumps");
		assertTrue(before.stream().allMatch(text -> text.contains("Full thread dump")));
		JfrRedactor.redact(input, output, RuleRedactor.builder().replace("*", "X").build());
		assertEquals(List.of("X", "X"), threadDumps(output), "the JDK reader must see only the replacements");
	}

	private static List<StringLocation> compositeLocations() {
		return List.of(new StringLocation("jdk.ThreadDump", "result", false, List.of()),
				new StringLocation("vm/runtime/thread_dump", "result", false, List.of()),
				new StringLocation("jdk.types.OldObject", "description", true, List.of()),
				new StringLocation("jdk.types.OldObjectGcRoot", "description", true, List.of()));
	}

	private static String compositeText(StringLocation location) {
		return location.isThreadDump() ? "\"secret\" #1 prio=5\n\tat java.util.ArrayList.run(ArrayList.java:1)\n"
				: "Thread Name: secret";
	}

	private static List<String> threadDumps(Path file) throws Exception {
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

	@Test
	void hashesThreadNamesStably() {
		StringLocation legacyThreadName = new StringLocation("Thread", "name", true, List.of());
		List<StringLocation> locations = List.of(legacyThreadName);
		String hashed = RuleRedactor.builder().hashThreadNames().build().redact("worker-1", locations);
		assertTrue(hashed.matches("Thread-[0-9a-f]{8}"), hashed);
		assertEquals(hashed, RuleRedactor.builder().hashThreadNames().build().redact("worker-1", locations));
		assertTrue(!hashed.equals(RuleRedactor.builder().hashThreadNames().build().redact("worker-2", locations)));
		String keyed = RuleRedactor.builder().hashThreadNames(new byte[] {1, 2, 3}).build().redact("worker-1",
				locations);
		assertTrue(keyed.matches("Thread-[0-9a-f]{8}") && !keyed.equals(hashed), keyed);
	}

	@Test
	void hashesThreadNamesInRecording(@TempDir
	Path dir) throws Exception {
		Path input = dir.resolve("input.jfr");
		String secretName = "payroll-batch-worker-42";
		try (Recording recording = new Recording()) {
			recording.enable(WorkEvent.class);
			recording.start();
			Thread thread = new Thread(() -> {
				WorkEvent event = new WorkEvent();
				event.description = "work";
				event.commit();
			}, secretName);
			thread.start();
			thread.join();
			recording.stop();
			recording.dump(input);
		}
		Path output = dir.resolve("output.jfr");
		RuleRedactor redactor = RuleRedactor.builder().hashThreadNames().build();
		JfrRedactor.redact(input, output, redactor);
		String expected = redactor.redact(secretName,
				List.of(new StringLocation("java.lang.Thread", "javaName", true, List.of())));

		boolean found = false;
		for (RecordedEvent event : RecordingFile.readAllEvents(output)) {
			if (event.getEventType().getName().equals("test.Work")) {
				assertEquals(expected, event.getThread().getJavaName());
				assertEquals(expected, event.getThread().getOSName());
				found = true;
			}
		}
		assertTrue(found);
		String raw = new String(java.nio.file.Files.readAllBytes(output), java.nio.charset.StandardCharsets.ISO_8859_1);
		assertTrue(!raw.contains(secretName));
	}

	@Test
	void rewritesThreadDumps() {
		String dump = """
				2026-06-04 22:20:00
				Full thread dump OpenJDK 64-Bit Server VM (25.0.2 mixed mode, sharing):

				"main" #3 [6147] prio=5 os_prio=31 cpu=273.14ms tid=0x00000001009e0810 nid=6147 waiting
				   java.lang.Thread.State: WAITING (parking)
					at java.util.concurrent.locks.LockSupport.park(java.base@25.0.2/LockSupport.java:223)
					- parking to wait for  <0x00000070008009a0> (a java.util.concurrent.CountDownLatch$Sync)
					at java.utility.Other.run(Other.java:1)

				"worker" daemon prio=6 tid=0x000000000ebd4000 nid=0x1578 waiting on condition
				"worker-2" daemon prio=6 tid=0x000000000ebd4000 nid=0x1579 waiting on condition

				Found one Java-level deadlock:
				"worker":
				  waiting to lock monitor 0x00007f (object 0x00000007, a java.lang.Object),
				  which is held by "worker-2"
				""";
		RuleRedactor redactor = RuleRedactor.builder().hashThreadNames().renamePackage("java.util", "utilz").build();
		StringLocation threadName = new StringLocation("java.lang.Thread", "javaName", true, List.of());
		String main = redactor.redact("main", List.of(threadName));
		String worker = redactor.redact("worker", List.of(threadName));
		String worker2 = redactor.redact("worker-2", List.of(threadName));

		String result = redactor.redact(dump,
				List.of(new StringLocation("jdk.ThreadDump", "result", false, List.of())));
		assertTrue(result.contains('"' + main + "\" #3"), result);
		assertTrue(result.contains('"' + worker + "\" daemon") && result.contains('"' + worker + "\":"), result);
		assertTrue(result.contains("which is held by \"" + worker2 + '"'), result);
		assertTrue(!result.contains("\"main\"") && !result.contains("\"worker"), result);
		assertTrue(result.contains("at utilz.concurrent.locks.LockSupport.park(java.base@25.0.2/LockSupport.java:223)"),
				result);
		assertTrue(result.contains("(a utilz.concurrent.CountDownLatch$Sync)"), result);
		assertTrue(result.contains("java.utility.Other") && result.contains("java.lang.Thread.State"), result);
	}

	@Test
	void hashesThreadNamesInOldObjectDescriptions() {
		RuleRedactor redactor = RuleRedactor.builder().hashThreadNames().build();
		String hashed = redactor.redact("RMI TCP Connection(2)-10.50.202.221",
				List.of(new StringLocation("java.lang.Thread", "javaName", true, List.of())));
		StringLocation description = new StringLocation("jdk.types.OldObjectGcRoot", "description", true, List.of());
		assertEquals("Thread Name: " + hashed,
				redactor.redact("Thread Name: RMI TCP Connection(2)-10.50.202.221", List.of(description)));
		assertEquals("Size: 10", redactor.redact("Size: 10", List.of(description)));
	}

	@Test
	void hashesThreadNamesInThreadDumpEvents(@TempDir
	Path dir) throws Exception {
		Path input = dir.resolve("input.jfr");
		String secretName = "patient-records-exporter";
		java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(1);
		Thread thread = new Thread(() -> {
			try {
				done.await();
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}, secretName);
		thread.start();
		try (Recording recording = new Recording()) {
			recording.enable("jdk.ThreadDump").withPeriod(java.time.Duration.ofMillis(100));
			recording.start();
			Thread.sleep(400);
			recording.stop();
			recording.dump(input);
		} finally {
			done.countDown();
			thread.join();
		}
		Path output = dir.resolve("output.jfr");
		RuleRedactor redactor = RuleRedactor.builder().hashThreadNames().build();
		JfrRedactor.redact(input, output, redactor);
		String expected = redactor.redact(secretName,
				List.of(new StringLocation("java.lang.Thread", "javaName", true, List.of())));

		int dumps = 0;
		for (RecordedEvent event : RecordingFile.readAllEvents(output)) {
			if (event.getEventType().getName().equals("jdk.ThreadDump")) {
				String text = event.getString("result");
				assertTrue(text.contains('"' + expected + '"'), "hashed name in the dump");
				assertTrue(!text.contains(secretName));
				dumps++;
			}
		}
		assertTrue(dumps > 0, "the recording contains thread dumps");
		String raw = new String(java.nio.file.Files.readAllBytes(output), java.nio.charset.StandardCharsets.ISO_8859_1);
		assertTrue(!raw.contains(secretName));
	}

	@Test
	void hashesClassNames() {
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)").build();
		StringLocation className = new StringLocation("jdk.types.Symbol", "string", true,
				List.of("java.lang.Class.name"));
		StringLocation descriptor = new StringLocation("jdk.types.Symbol", "string", true,
				List.of("jdk.types.Method.descriptor"));
		String hashed = redactor.redact("com/acme/secret/Foo", List.of(className));
		assertTrue(hashed.matches("com/acme/[A-Za-z0-9_$]{12,13}"), hashed);
		assertEquals(hashed, redactor.redact("com/acme/secret/Foo", List.of(className)), "stable");
		assertTrue(!hashed.equals(redactor.redact("com/acme/secret/Bar", List.of(className))));
		String hash = hashed.substring("com/acme/".length());
		assertEquals("(ILcom/acme/" + hash + ";[Ljava/lang/String;)Lcom/acme/" + hash + ";", redactor
				.redact("(ILcom/acme/secret/Foo;[Ljava/lang/String;)Lcom/acme/secret/Foo;", List.of(descriptor)));
		assertEquals("org/other/Foo", redactor.redact("org/other/Foo", List.of(className)));
		assertEquals("com/acme/secret/Foo", redactor.redact("com/acme/secret/Foo"), "only at class name locations");

		String dump = """
				"main" #1 prio=5 tid=0x1 nid=0x2 waiting
				\tat com.acme.secret.Foo.run(Foo.java:12)
				\t- locked <0x00000007> (a com.acme.secret.Foo)
				\tat java.lang.Thread.run(java.base@25/Thread.java:1583)
				""";
		String rewritten = redactor.redact(dump,
				List.of(new StringLocation("jdk.ThreadDump", "result", false, List.of())));
		assertTrue(rewritten.matches("(?s).*at com\\.acme\\." + java.util.regex.Pattern.quote(hash)
				+ "\\.run\\([A-Za-z0-9_$]{12,13}\\.java:12\\).*"), rewritten);
		assertTrue(!rewritten.contains("Foo.java") && !rewritten.contains("secret"), rewritten);
		assertTrue(rewritten.contains("(a com.acme." + hash + ")"), rewritten);
		assertTrue(rewritten.contains("at java.lang.Thread.run("), rewritten);
	}

	@Test
	void hashesObjectArrayClassesLikeComponentsAndDescriptors() {
		List<RuleRedactor> redactors = List.of(
				RuleRedactor.builder().hashClassNames("^com\\.acme\\.SecretService$").build(),
				RuleRedactor.builder().hashClassNames("com\\.acme\\.(Secret)").build(),
				RuleRedactor.builder().hashClassNames("^com\\.acme\\.(SecretService)$", new byte[] {1, 2, 3}).build());
		List<StringLocation> classLocations = List.of(
				new StringLocation("jdk.types.Symbol", "string", true, List.of("java.lang.Class.name")),
				new StringLocation("Symbol", "string", true, List.of("Class.name")));
		StringLocation descriptor = new StringLocation("jdk.types.Symbol", "string", true,
				List.of("jdk.types.Method.descriptor"));
		String component = "com/acme/SecretService";
		for (RuleRedactor redactor : redactors) {
			for (StringLocation location : classLocations) {
				String hashed = redactor.redact(component, List.of(location));
				assertTrue(!hashed.equals(component));
				for (String prefix : List.of("[L", "[[L", "[[[L")) {
					String array = prefix + component + ";";
					assertEquals(prefix + hashed + ";", redactor.redact(array, List.of(location)));
					assertEquals("(" + prefix + hashed + ";)L" + hashed + ";",
							redactor.redact("(" + array + ")L" + component + ";", List.of(descriptor)));
					assertEquals(array, redactor.redact(array), "unclassified strings must remain unchanged");
				}
				assertEquals("[[Lorg/other/Plain;", redactor.redact("[[Lorg/other/Plain;", List.of(location)));
			}
		}
	}

	@Test
	void keepsPrimitiveArrayClassesEvenWhenEveryClassNameMatches() {
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("(.*)").build();
		StringLocation className = new StringLocation("jdk.types.Symbol", "string", true,
				List.of("java.lang.Class.name"));
		for (String type : List.of("B", "C", "D", "F", "I", "J", "S", "Z")) {
			for (String dimensions : List.of("[", "[[")) {
				String array = dimensions + type;
				assertEquals(array, redactor.redact(array, List.of(className)));
			}
		}
	}

	@Test
	void hashesRecordedObjectArrayClassNamesWithoutChangingTheirDescriptors(@TempDir
	Path dir) throws Exception {
		Path input = dir.resolve("array-input.jfr");
		List<Class<?>> types = List.of(RuleRedactorTest.class, RuleRedactorTest[].class, RuleRedactorTest[][].class,
				int[].class, boolean[][].class, String[].class);
		try (Recording recording = new Recording()) {
			recording.enable(UnicodeClassEvent.class);
			recording.start();
			for (Class<?> type : types) {
				UnicodeClassEvent event = new UnicodeClassEvent();
				event.value = type;
				event.commit();
			}
			recording.stop();
			recording.dump(input);
		}
		assertEquals(types.stream().map(Class::getName).toList(), recordedClassValues(input),
				"the input must contain the component and every tested array class");
		RuleRedactor redactor = RuleRedactor.builder()
				.hashClassNames("^" + Pattern.quote(RuleRedactorTest.class.getName()) + "$").build();
		String component = redactor
				.redact(RuleRedactorTest.class.getName().replace('.', '/'), List
						.of(new StringLocation("jdk.types.Symbol", "string", true, List.of("java.lang.Class.name"))))
				.replace('/', '.');
		assertTrue(!component.equals(RuleRedactorTest.class.getName()));
		Path output = dir.resolve("array-output.jfr");
		JfrRedactor.redact(input, output, redactor);
		assertEquals(
				List.of(component, "[L" + component + ";", "[[L" + component + ";", "[I", "[[Z", "[Ljava.lang.String;"),
				recordedClassValues(output),
				"the JDK reader must see matching hashes with array dimensions and semicolons preserved");
	}

	private static List<String> recordedClassValues(Path file) throws Exception {
		return RecordingFile.readAllEvents(file).stream()
				.filter(event -> event.getEventType().getName().equals("test.UnicodeClass"))
				.map(event -> event.getClass("value").getName()).toList();
	}

	@Test
	void hashesMethodNames() {
		RuleRedactor redactor = RuleRedactor.builder().hashMethodNames("(processRecord)").build();
		StringLocation methodName = new StringLocation("jdk.types.Symbol", "string", true,
				List.of("jdk.types.Method.name"));
		String hashed = redactor.redact("processRecord", List.of(methodName));
		assertTrue(hashed.matches("[A-Za-z0-9_$]{12,13}"), hashed);
		assertEquals("lambda$" + hashed + "$0", redactor.redact("lambda$processRecord$0", List.of(methodName)));
		assertEquals("run", redactor.redact("run", List.of(methodName)));
		assertEquals("processRecord", redactor.redact("processRecord"), "only at method name locations");
	}

	@Test
	void hashesClassAndMethodNamesInThreadDumps() {
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)")
				.hashMethodNames("(processRecord)").build();
		String method = redactor.redact("processRecord",
				List.of(new StringLocation("Symbol", "string", true, List.of("Method.name"))));
		String dump = "\tat com.acme.secret.RecordService.processRecord(RecordService.java:42)\n"
				+ "\tat java.util.ArrayList.forEach(java.base@25/ArrayList.java:1596)\n";
		String rewritten = redactor.redact(dump,
				List.of(new StringLocation("vm/runtime/thread_dump", "result", false, List.of())));
		assertTrue(rewritten.contains("." + method + "("), rewritten);
		assertTrue(!rewritten.contains("processRecord") && !rewritten.contains("RecordService"), rewritten);
		assertTrue(rewritten.contains("at java.util.ArrayList.forEach(java.base@25/ArrayList.java:1596)"), rewritten);
	}

	@Test
	void hashesUnicodeFrameIdentifiersFilesAndLockClasses() {
		String[][] identifiers = {{"秘密", "処理", "秘密"}, {"Outer$秘密", "lambda$処理$0", "秘密"}, {"€Secret", "€処理", "€Secret"},
				{"Cafe\u0301", "me\u0301thod", "Cafe\u0301"},
				{"\uD801\uDC00Secret", "\uD801\uDC01run", "\uD801\uDC00Secret"}};
		StringLocation className = new StringLocation("jdk.types.Symbol", "string", true,
				List.of("java.lang.Class.name"));
		StringLocation methodName = new StringLocation("jdk.types.Symbol", "string", true,
				List.of("jdk.types.Method.name"));
		for (String[] names : identifiers) {
			RuleRedactor redactor = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)")
					.hashMethodNames(Pattern.quote(names[1])).build();
			String type = "com.acme." + names[0];
			String hashedType = redactor.redact(type.replace('.', '/'), List.of(className)).replace('/', '.');
			String hashedMethod = redactor.redact(names[1], List.of(methodName));
			String hashedFile = redactor.redact("com/acme/" + names[2], List.of(className))
					.substring("com/acme/".length());
			String dump = "\tat " + type + "." + names[1] + "(demo@1/" + names[2] + ".java:42)\n" + "\tat " + type
					+ ".<init>(" + names[2] + ".java:43)\n" + "\tat " + type + ".<clinit>(" + names[2] + ".java:44)\n"
					+ "\t- locked <0x00000007> (a " + type + ")\n" + "\tat java.lang.Thread.run(Thread.java:1)\n";
			String expected = "\tat " + hashedType + "." + hashedMethod + "(demo@1/" + hashedFile + ".java:42)\n"
					+ "\tat " + hashedType + ".<init>(" + hashedFile + ".java:43)\n" + "\tat " + hashedType
					+ ".<clinit>(" + hashedFile + ".java:44)\n" + "\t- locked <0x00000007> (a " + hashedType + ")\n"
					+ "\tat java.lang.Thread.run(Thread.java:1)\n";
			for (StringLocation location : compositeLocations()) {
				if (location.isThreadDump()) {
					assertEquals(expected, redactor.redact(dump, List.of(location)), location + ": " + type);
				}
			}
		}
	}

	@Test
	void hashesUnicodeClassAndMethodFramesInRealThreadDumps(@TempDir
	Path dir) throws Exception {
		Path input = dir.resolve("unicode-input.jfr");
		CountDownLatch entered = new CountDownLatch(1);
		CountDownLatch done = new CountDownLatch(1);
		Thread worker = new Thread(() -> 秘密.待機(entered, done), "unicode-dump-worker");
		try (Recording recording = new Recording()) {
			recording.enable("jdk.ThreadDump").withPeriod(Duration.ofMillis(20));
			recording.enable(WorkEvent.class);
			recording.enable(UnicodeClassEvent.class);
			recording.start();
			worker.start();
			assertTrue(entered.await(5, TimeUnit.SECONDS), "the Unicode method must be on the worker's stack");
			UnicodeClassEvent event = new UnicodeClassEvent();
			event.value = 秘密.class;
			event.commit();
			Thread.sleep(300);
			recording.stop();
			recording.dump(input);
		} finally {
			done.countDown();
			worker.join();
		}
		String originalClass = 秘密.class.getName();
		String originalMethod = "待機";
		List<String> inputDumps = threadDumps(input);
		assertTrue(inputDumps.stream().anyMatch(text -> text.contains(originalClass + "." + originalMethod + "(")),
				"the input must genuinely contain the Unicode frame");
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames(Pattern.quote(originalClass))
				.hashMethodNames(Pattern.quote(originalMethod)).build();
		String expectedClass = redactor
				.redact(originalClass.replace('.', '/'), List
						.of(new StringLocation("jdk.types.Symbol", "string", true, List.of("java.lang.Class.name"))))
				.replace('/', '.');
		String expectedMethod = redactor.redact(originalMethod,
				List.of(new StringLocation("jdk.types.Symbol", "string", true, List.of("jdk.types.Method.name"))));
		Path output = dir.resolve("unicode-output.jfr");
		JfrRedactor.redact(input, output, redactor);
		boolean sawHashedDumpFrame = false;
		boolean sawHashedClass = false;
		boolean sawHashedMethod = false;
		int dumps = 0;
		for (RecordedEvent event : RecordingFile.readAllEvents(output)) {
			switch (event.getEventType().getName()) {
			case "jdk.ThreadDump" -> {
				String text = event.getString("result");
				assertTrue(!text.contains(originalClass) && !text.contains(originalMethod + "("), text);
				sawHashedDumpFrame |= text.contains(expectedClass + "." + expectedMethod + "(");
				dumps++;
			}
			case "test.UnicodeClass" -> {
				assertEquals(expectedClass, event.getClass("value").getName());
				sawHashedClass = true;
			}
			case "test.Work" -> {
				for (RecordedFrame frame : event.getStackTrace().getFrames()) {
					if (frame.getMethod().getType().getName().equals(expectedClass)) {
						assertEquals(expectedMethod, frame.getMethod().getName());
						sawHashedMethod = true;
					}
				}
			}
			default -> {
			}
			}
		}
		assertEquals(inputDumps.size(), dumps);
		assertTrue(sawHashedDumpFrame && sawHashedClass && sawHashedMethod,
				"the dump and the independent class/method constants must contain the same hashes");
	}

	@Name("test.UnicodeClass")
	@StackTrace(false)
	static class UnicodeClassEvent extends Event {
		Class<?> value;
	}

	static class 秘密 {
		static void 待機(CountDownLatch entered, CountDownLatch done) {
			WorkEvent event = new WorkEvent();
			event.description = "Unicode frame";
			event.commit();
			entered.countDown();
			try {
				done.await();
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
	}

	@Test
	void hashesMethodNamesInRecording(@TempDir
	Path dir) throws Exception {
		Path input = dir.resolve("input.jfr");
		try (Recording recording = new Recording()) {
			recording.enable(WorkEvent.class);
			recording.start();
			commitFromSecretlyNamedMethod();
			recording.stop();
			recording.dump(input);
		}
		Path output = dir.resolve("output.jfr");
		JfrRedactor.redact(input, output, RuleRedactor.builder().hashMethodNames("(SecretlyNamed)").build());

		boolean found = false;
		for (RecordedEvent recorded : RecordingFile.readAllEvents(output)) {
			if (recorded.getEventType().getName().equals("test.Work")) {
				for (RecordedFrame frame : recorded.getStackTrace().getFrames()) {
					String name = frame.getMethod().getName();
					assertTrue(!name.contains("SecretlyNamed"), name);
					found |= name.matches("commitFrom[A-Za-z0-9_$]{12,13}Method");
				}
			}
		}
		assertTrue(found, "the frame of the renamed method");
		String raw = new String(java.nio.file.Files.readAllBytes(output), java.nio.charset.StandardCharsets.ISO_8859_1);
		assertTrue(!raw.contains("SecretlyNamed"));
	}

	private static void commitFromSecretlyNamedMethod() {
		WorkEvent event = new WorkEvent();
		event.description = "work";
		event.commit();
	}

	@Test
	void hashesWholeMatchWithoutGroup() {
		StringLocation className = new StringLocation("Symbol", "string", true, List.of("Class.name"));
		String hashed = RuleRedactor.builder().hashClassNames("Secret[A-Za-z]*").build()
				.redact("com/acme/SecretService$Inner", List.of(className));
		assertTrue(hashed.matches("com/acme/[A-Za-z0-9_$]{12,13}\\$Inner"), hashed);
	}

	@Test
	void hashesClassNamesInRecording(@TempDir
	Path dir) throws Exception {
		Path input = dir.resolve("input.jfr");
		try (Recording recording = new Recording()) {
			recording.enable(WorkEvent.class);
			recording.start();
			WorkEvent event = new WorkEvent();
			event.description = "work";
			event.commit();
			recording.stop();
			recording.dump(input);
		}
		Path output = dir.resolve("output.jfr");
		JfrRedactor.redact(input, output,
				RuleRedactor.builder().hashClassNames("se\\.hirt\\.jfr\\.redact\\.(.*)").build());

		boolean found = false;
		for (RecordedEvent recorded : RecordingFile.readAllEvents(output)) {
			if (recorded.getEventType().getName().equals("test.Work")) {
				for (RecordedFrame frame : recorded.getStackTrace().getFrames()) {
					String typeName = frame.getMethod().getType().getName();
					if (typeName.startsWith("se.hirt.jfr.redact.")) {
						assertTrue(typeName.matches("se\\.hirt\\.jfr\\.redact\\.[A-Za-z0-9_$]{12,13}"), typeName);
						found = true;
					}
				}
			}
		}
		assertTrue(found, "frames of the test class, with hashed names");
		String raw = new String(java.nio.file.Files.readAllBytes(output), java.nio.charset.StandardCharsets.ISO_8859_1);
		assertTrue(!raw.contains("RuleRedactorTest"));
	}

	@Test
	void firstMatchingRuleWins() {
		RuleRedactor redactor = RuleRedactor.builder().replace("java.*", "first").replace("java.util.*", "second")
				.build();
		assertEquals("first", redactor.redact("java.util.List"));
	}

	@Test
	void everything() {
		assertEquals("X", RuleRedactor.builder().replace("*", "X").build().redact("anything"));
		assertEquals("X", RuleRedactor.builder().replace("*", "X").build().redact(""));
	}

	@Test
	void rejectsUnsupportedPatterns() {
		assertThrows(IllegalArgumentException.class, () -> RuleRedactor.builder().replace("a*b", "x"));
		assertThrows(IllegalArgumentException.class, () -> RuleRedactor.builder().replace("exact", "x*"));
		assertThrows(IllegalArgumentException.class, () -> RuleRedactor.builder().replace("a*", "*x*"));
		assertThrows(IllegalArgumentException.class, () -> RuleRedactor.builder().replace("*a*", "x*"));
		assertThrows(IllegalArgumentException.class, () -> RuleRedactor.builder().replace("*password*", "***"));
	}

	@Test
	void escapedStars() {
		RuleRedactor redactor = RuleRedactor.builder().replace("a\\*b", "c").replace("x*", "\\**").build();
		assertEquals("c", redactor.redact("a*b"));
		assertEquals("ab", redactor.redact("ab"));
		assertEquals("*yz", redactor.redact("xyz"));
	}

	@Test
	void orElse() {
		StringRedactor redactor = RuleRedactor.builder().replace("a*", "A").build()
				.orElse((value, locations) -> value.startsWith("b") ? "B" : value);
		assertEquals("A", redactor.redact("apple", List.of()));
		assertEquals("B", redactor.redact("banana", List.of()));
		assertEquals("cherry", redactor.redact("cherry", List.of()));
	}

	@Name("test.Work")
	@StackTrace(true)
	static class WorkEvent extends Event {
		String description;
	}

	@Test
	void renamesJavaUtilEverywhere(@TempDir
	Path dir) throws Exception {
		Path input = dir.resolve("input.jfr");
		try (Recording recording = new Recording()) {
			recording.enable(WorkEvent.class);
			recording.start();
			// Commit from inside java.util, so that the stack traces contain java.util frames
			new ArrayList<>(List.of(1, 2, 3)).forEach(i -> {
				WorkEvent event = new WorkEvent();
				event.description = "uses java.util.ArrayList";
				event.commit();
			});
			recording.stop();
			recording.dump(input);
		}
		Path output = dir.resolve("output.jfr");
		RenameJavaUtil.main(new String[] {input.toString(), output.toString()});

		StringScanner scanner = new StringScanner(true);
		new StreamingChunkParser().parse(output, scanner);
		StringCountMap strings = scanner.getStrings();
		for (int i = 0; i < strings.size(); i++) {
			String s = strings.getString(i);
			assertTrue(!s.equals("java.util") && !s.startsWith("java.util.") && !s.equals("java/util")
					&& !s.startsWith("java/util/") && !s.contains("Ljava/util/"), s);
		}

		boolean sawUtilzFrame = false;
		for (RecordedEvent event : RecordingFile.readAllEvents(output)) {
			if (event.getEventType().getName().equals("test.Work")) {
				for (RecordedFrame frame : event.getStackTrace().getFrames()) {
					String typeName = frame.getMethod().getType().getName();
					assertTrue(!typeName.startsWith("java.util."), typeName);
					sawUtilzFrame |= typeName.startsWith("utilz.");
				}
			}
		}
		assertTrue(sawUtilzFrame, "the JDK reads the renamed java.util frames");
	}
}
