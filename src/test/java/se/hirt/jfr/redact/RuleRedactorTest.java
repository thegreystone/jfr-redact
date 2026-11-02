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
import java.util.function.UnaryOperator;
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
	/**
	 * The names as HotSpot's recordings locate them: at the field whose value they are, without
	 * referrers, since a class, a method, a package or a module stores no string itself, see
	 * {@link StringLocation#getReferrers()}
	 */
	private static final StringLocation CLASS_NAME = new StringLocation("java.lang.Class", "name", true, List.of());
	private static final StringLocation METHOD_NAME = new StringLocation("jdk.types.Method", "name", true, List.of());
	private static final StringLocation DESCRIPTOR = new StringLocation("jdk.types.Method", "descriptor", true,
			List.of());
	private static final StringLocation THREAD_NAME = new StringLocation("java.lang.Thread", "javaName", true,
			List.of());
	private static final StringLocation THREAD_DUMP = new StringLocation("jdk.ThreadDump", "result", false, List.of());
	private static final StringLocation PACKAGE_NAME = new StringLocation("jdk.types.Package", "name", true, List.of());
	private static final StringLocation MODULE_NAME = new StringLocation("jdk.types.Module", "name", true, List.of());
	/**
	 * The JFR 0.9 names: JRockit's interned strings, located at the storing constant with the
	 * referring field, since its metadata declares no simple types
	 */
	private static final StringLocation LEGACY_CLASS_NAME = new StringLocation("UTFConstant", "utf8", true,
			List.of("Class.name"));
	private static final StringLocation LEGACY_METHOD_NAME = new StringLocation("UTFConstant", "utf8", true,
			List.of("Method.name"));
	private static final StringLocation LEGACY_DESCRIPTOR = new StringLocation("UTFConstant", "utf8", true,
			List.of("Method.signature"));
	/** The shape of the base64 hash of a class, package or method name segment */
	private static final String HASH = "[A-Za-z0-9_$]{12,13}";
	/** Hashes every segment of every class, package and module name */
	private static final RuleRedactor EVERYTHING = RuleRedactor.builder().hashClassNames("(.*)").build();

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
		List<String> before = TestRecordings.threadDumps(input);
		assertEquals(2, before.size(), "the bundled fixture must exercise both thread dumps");
		assertTrue(before.stream().allMatch(text -> text.contains("Full thread dump")));
		JfrRedactor.redact(input, output, RuleRedactor.builder().replace("*", "X").build());
		assertEquals(List.of("X", "X"), TestRecordings.threadDumps(output),
				"the JDK reader must see only the replacements");
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
	void hashesDistinctLoneSurrogatesWithoutCollapsingToReplacementCharacters() {
		List<String> names = List.of("\uD800", "\uD801", "\uDC00", "?", "\uFFFD");
		List<StringLocation> locations = List.of(new StringLocation("java.lang.Thread", "javaName", true, List.of()));
		for (boolean keyed : List.of(false, true)) {
			RuleRedactor first = keyed ? RuleRedactor.builder().hashThreadNames(new byte[] {1, 2, 3}).build()
					: RuleRedactor.builder().hashThreadNames().build();
			RuleRedactor second = keyed ? RuleRedactor.builder().hashThreadNames(new byte[] {1, 2, 3}).build()
					: RuleRedactor.builder().hashThreadNames().build();
			List<String> hashes = new ArrayList<>();
			for (String name : names) {
				String hashed = first.redact(name, locations);
				assertEquals(hashed, first.redact(name, locations));
				assertEquals(hashed, second.redact(name, locations));
				hashes.add(hashed);
			}
			assertEquals(names.size(), hashes.stream().distinct().count(), "distinct hashes, HMAC=" + keyed);
		}
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
		StringLocation className = CLASS_NAME;
		StringLocation descriptor = DESCRIPTOR;
		// The matched part is hashed segment by segment, so the class keeps starting with its package
		String hashed = redactor.redact("com/acme/secret/Foo", List.of(className));
		assertTrue(hashed.matches("com/acme/" + HASH + "/" + HASH), hashed);
		assertEquals(hashed, redactor.redact("com/acme/secret/Foo", List.of(className)), "stable");
		String secret = hashed.substring("com/acme/".length(), hashed.lastIndexOf('/'));
		String foo = hashed.substring(hashed.lastIndexOf('/') + 1);
		String bar = redactor.redact("com/acme/secret/Bar", List.of(className));
		assertTrue(bar.startsWith("com/acme/" + secret + "/") && !bar.equals(hashed), bar);
		assertEquals("com/acme/" + secret, redactor.redact("com/acme/secret", List.of(PACKAGE_NAME)),
				"the package constant gets the package part of its classes");
		assertEquals("com/acme", redactor.redact("com/acme", List.of(PACKAGE_NAME)), "an empty group is no match");
		assertEquals("com.acme." + secret, redactor.redact("com.acme.secret", List.of(MODULE_NAME)),
				"a module named like the package");
		assertEquals("(ILcom/acme/" + secret + "/" + foo + ";[Ljava/lang/String;)Lcom/acme/" + secret + "/" + foo + ";",
				redactor.redact("(ILcom/acme/secret/Foo;[Ljava/lang/String;)Lcom/acme/secret/Foo;",
						List.of(descriptor)));
		assertEquals("org/other/Foo", redactor.redact("org/other/Foo", List.of(className)));
		assertEquals("com/acme/secret/Foo", redactor.redact("com/acme/secret/Foo"), "only at class name locations");
		assertEquals("com/acme/secret", redactor.redact("com/acme/secret"), "only at package name locations");

		String dump = """
				"main" #1 prio=5 tid=0x1 nid=0x2 waiting
				\tat com.acme.secret.Foo.run(Foo.java:12)
				\t- locked <0x00000007> (a com.acme.secret.Foo)
				\tat java.lang.Thread.run(java.base@25/Thread.java:1583)
				""";
		String rewritten = redactor.redact(dump,
				List.of(new StringLocation("jdk.ThreadDump", "result", false, List.of())));
		// The file name gets the hash of the simple class name, which it is in the common case
		assertTrue(rewritten.contains("\tat com.acme." + secret + "." + foo + ".run(" + foo + ".java:12)\n"),
				rewritten);
		assertTrue(!rewritten.contains("Foo.java") && !rewritten.contains("secret"), rewritten);
		assertTrue(rewritten.contains("(a com.acme." + secret + "." + foo + ")"), rewritten);
		assertTrue(rewritten.contains("at java.lang.Thread.run(java.base@25/Thread.java:1583)"), rewritten);
	}

	/**
	 * A name is classified by the field whose value it is, as a constant: the name of a class, a
	 * method, a package or a module at the field of its own constant, wherever the writer stored
	 * the value, inline in that constant, through a simple type such as {@code jdk.types.Symbol},
	 * or through the string pool, since every reader reads a simple type as the value of the field
	 * referring to it. JRockit declares no simple types, so its JFR 0.9 names keep their storing
	 * constant, {@code UTFConstant}, with the referring field. Referrers play no part: HotSpot's
	 * classes have none, a class storing its name inline, which other constants refer to, has them,
	 * and both are class names. Other fields of the same types, an inline value, and the simple
	 * types themselves, whatever refers to them, are not names.
	 */
	@Test
	void classifiesNamesByTheFieldWhoseValueTheyAre() {
		for (String types : List.of("jdk.types.", "com.oracle.jfr.types.")) {
			assertOnlyClassName(new StringLocation("java.lang.Class", "name", true, List.of(types + "Method.type")));
			assertOnlyClassName(new StringLocation("java.lang.Class", "name", true, List.of()));
			assertOnlyMethodName(new StringLocation(types + "Method", "name", true, List.of()));
			assertOnlyDescriptor(new StringLocation(types + "Method", "descriptor", true, List.of()));
			StringLocation packageName = new StringLocation(types + "Package", "name", true,
					List.of("java.lang.Class.package"));
			assertTrue(
					packageName.isPackageName() && !packageName.isClassName() && !packageName.isModuleName()
							&& !packageName.isMethodName() && !packageName.isMethodDescriptor(),
					packageName.toString());
			StringLocation moduleName = new StringLocation(types + "Module", "name", true, List.of());
			assertTrue(moduleName.isModuleName() && !moduleName.isPackageName() && !moduleName.isClassName()
					&& !moduleName.isMethodName() && !moduleName.isMethodDescriptor(), moduleName.toString());
		}
		for (String callee : List.of("jdk.CompilerInlining", "com.oracle.jdk.CompilerInlining")) {
			assertOnlyClassName(new StringLocation(callee, "callee.type", false, List.of()));
			assertOnlyMethodName(new StringLocation(callee, "callee.name", false, List.of()));
			assertOnlyDescriptor(new StringLocation(callee, "callee.descriptor", false, List.of()));
			StringLocation message = new StringLocation(callee, "message", false, List.of());
			assertTrue(!message.isClassName() && !message.isMethodName() && !message.isMethodDescriptor(),
					message.toString());
		}
		assertOnlyClassName(LEGACY_CLASS_NAME);
		assertOnlyMethodName(LEGACY_METHOD_NAME);
		assertOnlyDescriptor(LEGACY_DESCRIPTOR);
		for (StringLocation other : List.of(new StringLocation("java.lang.Class", "package", true, List.of()),
				new StringLocation("java.lang.Class", "name", false, List.of()),
				new StringLocation("jdk.types.Method", "name", false, List.of()),
				new StringLocation("jdk.types.Method", "type", true, List.of()),
				new StringLocation("jdk.types.Package", "module", true, List.of()),
				new StringLocation("jdk.types.Module", "version", true, List.of()),
				new StringLocation("jdk.types.Symbol", "string", true, List.of("java.lang.Class.name")),
				new StringLocation("jdk.types.Symbol", "string", true,
						List.of("jdk.types.Method.descriptor", "jdk.types.Method.name", "jdk.types.Module.name",
								"jdk.types.Package.name")),
				new StringLocation("jdk.types.Symbol", "string", true, List.of()),
				new StringLocation("java.lang.String", "value", true, List.of("java.lang.Class.name")),
				new StringLocation("UTFConstant", "utf8", true, List.of()))) {
			assertTrue(!other.isClassName() && !other.isMethodName() && !other.isMethodDescriptor()
					&& !other.isPackageName() && !other.isModuleName(), other.toString());
		}
	}

	private static void assertOnlyClassName(StringLocation location) {
		assertTrue(location.isClassName() && !location.isMethodName() && !location.isMethodDescriptor()
				&& !location.isPackageName() && !location.isModuleName(), location.toString());
	}

	private static void assertOnlyMethodName(StringLocation location) {
		assertTrue(location.isMethodName() && !location.isClassName() && !location.isMethodDescriptor()
				&& !location.isPackageName() && !location.isModuleName(), location.toString());
	}

	private static void assertOnlyDescriptor(StringLocation location) {
		assertTrue(location.isMethodDescriptor() && !location.isClassName() && !location.isMethodName()
				&& !location.isPackageName() && !location.isModuleName(), location.toString());
	}

	/**
	 * The hash of a segment, which is the replacement of a class in the default package when every
	 * class name matches
	 */
	private static String hash(String segment) {
		String hashed = EVERYTHING.redact(segment, List.of(CLASS_NAME));
		assertTrue(hashed.matches(HASH) && !hashed.equals(segment), hashed);
		return hashed;
	}

	@Test
	void hashesPackageSegmentsOnlyWhereTheExpressionMatchesThePackage() {
		// A prefix expression hashes the segments after the prefix, of classes and of packages
		RuleRedactor acme = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)").build();
		assertEquals("com/acme/" + hash("secret") + "/" + hash("Foo"),
				acme.redact("com/acme/secret/Foo", List.of(CLASS_NAME)));
		assertEquals("com/acme/" + hash("secret") + "/" + hash("db") + "/" + hash("Foo"),
				acme.redact("com/acme/secret/db/Foo", List.of(CLASS_NAME)));
		assertEquals("com/acme/" + hash("Foo"), acme.redact("com/acme/Foo", List.of(CLASS_NAME)));
		assertEquals("com/acme/" + hash("secret"), acme.redact("com/acme/secret", List.of(PACKAGE_NAME)));
		assertEquals("com/acme/" + hash("secret") + "/" + hash("db"),
				acme.redact("com/acme/secret/db", List.of(PACKAGE_NAME)));
		assertEquals("com/acme", acme.redact("com/acme", List.of(PACKAGE_NAME)));
		assertEquals("com.acme." + hash("secret"), acme.redact("com.acme.secret", List.of(MODULE_NAME)));
		assertEquals("org/other/Foo", acme.redact("org/other/Foo", List.of(CLASS_NAME)));
		assertEquals("org/other", acme.redact("org/other", List.of(PACKAGE_NAME)));
		assertEquals("Foo", acme.redact("Foo", List.of(CLASS_NAME)), "default package");
		// Every class name: every segment
		RuleRedactor everything = RuleRedactor.builder().hashClassNames("(.*)").build();
		assertEquals(hash("com") + "/" + hash("acme") + "/" + hash("secret") + "/" + hash("Foo"),
				everything.redact("com/acme/secret/Foo", List.of(CLASS_NAME)));
		assertEquals(hash("com") + "/" + hash("acme") + "/" + hash("secret"),
				everything.redact("com/acme/secret", List.of(PACKAGE_NAME)));
		assertEquals(hash("java") + "." + hash("base"), everything.redact("java.base", List.of(MODULE_NAME)));
		assertEquals(hash("Foo"), everything.redact("Foo", List.of(CLASS_NAME)), "default package");
		// A deeper prefix keeps the segments before it
		RuleRedactor secret = RuleRedactor.builder().hashClassNames("com\\.acme\\.secret\\.(.*)").build();
		assertEquals("com/acme/secret/" + hash("Foo"), secret.redact("com/acme/secret/Foo", List.of(CLASS_NAME)));
		assertEquals("com/acme/secret/" + hash("db") + "/" + hash("Foo"),
				secret.redact("com/acme/secret/db/Foo", List.of(CLASS_NAME)));
		assertEquals("com/acme/secret/" + hash("db"), secret.redact("com/acme/secret/db", List.of(PACKAGE_NAME)));
		assertEquals("com/acme/secret", secret.redact("com/acme/secret", List.of(PACKAGE_NAME)));
		assertEquals("com/acme/Foo", secret.redact("com/acme/Foo", List.of(CLASS_NAME)));
		// A suffix expression matches no package followed by a dot, so only the simple name is hashed,
		// and the package stays, as the recording stored it readably on its own anyway
		RuleRedactor impl = RuleRedactor.builder().hashClassNames("(.*)Impl$").build();
		assertEquals("com/acme/secret/" + hash("Foo") + "Impl",
				impl.redact("com/acme/secret/FooImpl", List.of(CLASS_NAME)));
		assertEquals("com/acme/secret", impl.redact("com/acme/secret", List.of(PACKAGE_NAME)));
		assertEquals("com/acme/secretImpl", impl.redact("com/acme/secretImpl", List.of(PACKAGE_NAME)),
				"the package is matched followed by a dot");
		assertEquals("com/acme/secretImpl/" + hash("Foo") + "Impl",
				impl.redact("com/acme/secretImpl/FooImpl", List.of(CLASS_NAME)));
		assertEquals("com/acme/secret/Foo", impl.redact("com/acme/secret/Foo", List.of(CLASS_NAME)));
		assertEquals(hash("Foo") + "Impl", impl.redact("FooImpl", List.of(CLASS_NAME)), "default package");
		// A whole match without a group, which is hashed where it lies
		RuleRedactor literal = RuleRedactor.builder().hashClassNames("Secret").build();
		assertEquals("com/acme/" + hash("Secret") + "Service",
				literal.redact("com/acme/SecretService", List.of(CLASS_NAME)));
		assertEquals("com/acme/" + hash("Secret"), literal.redact("com/acme/Secret", List.of(PACKAGE_NAME)));
		assertEquals("com/acme/" + hash("Secret") + "/SecretService",
				literal.redact("com/acme/Secret/SecretService", List.of(CLASS_NAME)),
				"the first match decides for the simple name, as before");
		assertEquals("com/acme/Top" + hash("Secret"), literal.redact("com/acme/TopSecret", List.of(PACKAGE_NAME)));
		// A match covering part of a segment hashes that part
		RuleRedactor partial = RuleRedactor.builder().hashClassNames("com\\.ac(.*)").build();
		assertEquals("com/ac" + hash("me") + "/" + hash("secret") + "/" + hash("Foo"),
				partial.redact("com/acme/secret/Foo", List.of(CLASS_NAME)));
		assertEquals("com/ac" + hash("me") + "/" + hash("secret"),
				partial.redact("com/acme/secret", List.of(PACKAGE_NAME)));
		assertEquals("com/ac" + hash("me"), partial.redact("com/acme", List.of(PACKAGE_NAME)));
		// A match that only covers dots changes nothing
		RuleRedactor dots = RuleRedactor.builder().hashClassNames("\\.").build();
		assertEquals("com/acme/secret/Foo", dots.redact("com/acme/secret/Foo", List.of(CLASS_NAME)));
		assertEquals("com/acme/secret", dots.redact("com/acme/secret", List.of(PACKAGE_NAME)));
		// A group matching the package of the class hashes the package, not the simple name
		RuleRedactor packageOnly = RuleRedactor.builder().hashClassNames("com\\.acme\\.(secret)").build();
		assertEquals("com/acme/" + hash("secret") + "/Foo",
				packageOnly.redact("com/acme/secret/Foo", List.of(CLASS_NAME)));
		assertEquals("com/acme/" + hash("secret"), packageOnly.redact("com/acme/secret", List.of(PACKAGE_NAME)));
		// Nested classes and the host of a hidden class are one segment
		assertEquals("com/acme/" + hash("Outer$Inner"), acme.redact("com/acme/Outer$Inner", List.of(CLASS_NAME)));
		assertEquals(hash("com") + "/" + hash("acme") + "/" + hash("Outer$Inner"),
				everything.redact("com/acme/Outer$Inner", List.of(CLASS_NAME)));
		assertEquals("com.acme." + hash("secret") + "." + hash("Host$$Lambda") + "/0x00007fb87c2252f8",
				acme.redact("com.acme.secret.Host$$Lambda/0x00007fb87c2252f8", List.of(CLASS_NAME)));
		assertEquals("com.acme." + hash("secret") + "." + hash("Host$$Lambda") + "+0x00007fb87c2252f8/262911569",
				acme.redact("com.acme.secret.Host$$Lambda+0x00007fb87c2252f8/262911569", List.of(CLASS_NAME)));
		assertEquals("[Lcom/acme/" + hash("secret") + "/" + hash("Host$$Lambda") + "+0x00007fb87c2252f8;",
				acme.redact("[Lcom/acme/secret/Host$$Lambda+0x00007fb87c2252f8;", List.of(CLASS_NAME)));
		// Arrays and descriptors, with several classes
		assertEquals("[[Lcom/acme/" + hash("secret") + "/" + hash("Foo") + ";",
				acme.redact("[[Lcom/acme/secret/Foo;", List.of(CLASS_NAME)));
		assertEquals(
				"(Lcom/acme/" + hash("secret") + "/" + hash("Foo") + ";Lorg/other/Bar;[Lcom/acme/" + hash("Baz")
						+ ";J)Lcom/acme/" + hash("secret") + "/" + hash("db") + "/" + hash("Qux") + ";",
				acme.redact("(Lcom/acme/secret/Foo;Lorg/other/Bar;[Lcom/acme/Baz;J)Lcom/acme/secret/db/Qux;",
						List.of(DESCRIPTOR)));
		assertEquals("(Lorg/other/Bar;)V", acme.redact("(Lorg/other/Bar;)V", List.of(DESCRIPTOR)));
	}

	@Test
	void hashesPackageNameConstants() {
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)").replace("*", "X").build();
		List<StringLocation> packages = List.of(PACKAGE_NAME,
				new StringLocation("com.oracle.jfr.types.Package", "name", true, List.of()));
		for (StringLocation location : packages) {
			assertTrue(location.isPackageName() && !location.isClassName() && !location.isModuleName(),
					location.toString());
			assertEquals("com/acme/" + hash("secret") + "/" + hash("db"),
					redactor.redact("com/acme/secret/db", List.of(location)), location.toString());
			assertEquals("com.acme." + hash("secret") + "." + hash("db"),
					redactor.redact("com.acme.secret.db", List.of(location)), "a dotted name keeps its form");
			assertEquals("X", redactor.redact("org/other", List.of(location)), "an unmatched package: later rules");
			assertEquals("X", redactor.redact("com/acme", List.of(location)), "an empty match: later rules");
			assertEquals("X", redactor.redact("", List.of(location)), "the default package: later rules");
		}
		RuleRedactor everything = RuleRedactor.builder().hashClassNames("(.*)").build();
		assertEquals("", everything.redact("", List.of(PACKAGE_NAME)), "the empty name of the default package");
		RuleRedactor chained = RuleRedactor.builder().hashClassNames("(.*)").replace("", "<EMPTY>").build();
		assertEquals("<EMPTY>", chained.redact("", List.of(PACKAGE_NAME)), "later rules still apply to it");
		assertEquals(hash("java") + "/" + hash("util"), everything.redact("java/util", List.of(PACKAGE_NAME)));
		for (StringLocation other : List.of(new StringLocation("jdk.types.Package", "name", false, List.of()),
				new StringLocation("jdk.types.Package", "module", true, List.of()),
				new StringLocation("jdk.types.Symbol", "string", true, List.of("jdk.types.Package.name")), CLASS_NAME,
				MODULE_NAME)) {
			assertTrue(!other.isPackageName(), other.toString());
		}
		assertEquals("java/util", everything.redact("java/util", List.of(METHOD_NAME)), "not a package name");
	}

	@Test
	void hashesModuleNameConstants() {
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)").build();
		RuleRedactor everything = RuleRedactor.builder().hashClassNames("(.*)").build();
		RuleRedactor chained = RuleRedactor.builder().hashClassNames("(.*)").replace("", "<EMPTY>").build();
		List<StringLocation> modules = List.of(MODULE_NAME,
				new StringLocation("com.oracle.jfr.types.Module", "name", true, List.of()));
		for (StringLocation location : modules) {
			assertTrue(location.isModuleName() && !location.isPackageName() && !location.isClassName(),
					location.toString());
			assertEquals("com.acme." + hash("secret"), redactor.redact("com.acme.secret", List.of(location)),
					location.toString());
			assertEquals("com/acme/" + hash("secret"), redactor.redact("com/acme/secret", List.of(location)),
					"a slashed name keeps its form");
			assertEquals("java.base", redactor.redact("java.base", List.of(location)));
			assertEquals(hash("java") + "." + hash("base"), everything.redact("java.base", List.of(location)));
			assertEquals(hash("jdk") + "." + hash("jfr"), everything.redact("jdk.jfr", List.of(location)));
			assertEquals("", everything.redact("", List.of(location)), "the empty name of the unnamed module");
			assertEquals("<EMPTY>", chained.redact("", List.of(location)), "later rules still apply to it");
		}
		// The version and location of a module are other strings, and untouched
		for (StringLocation other : List.of(new StringLocation("jdk.types.Module", "version", true, List.of()),
				new StringLocation("jdk.types.Module", "location", true, List.of()),
				new StringLocation("com.oracle.jfr.types.Module", "version", true, List.of()),
				new StringLocation("com.oracle.jfr.types.Module", "location", true, List.of()))) {
			assertTrue(!other.isModuleName(), other.toString());
			assertEquals("21.0.1", everything.redact("21.0.1", List.of(other)), other.toString());
			assertEquals("jrt:/jdk.jfr", everything.redact("jrt:/jdk.jfr", List.of(other)), other.toString());
		}
		assertTrue(!new StringLocation("jdk.types.Module", "name", false, List.of()).isModuleName(), "inline");
		assertTrue(!CLASS_NAME.isModuleName() && !PACKAGE_NAME.isModuleName() && !THREAD_NAME.isModuleName());
	}

	@Test
	void hashesModuleSegmentsOfThreadDumpFrames() {
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)").build();
		String secret = hash("secret");
		String dump = """
				"main" #1 prio=5 tid=0x1 nid=0x2 waiting
				\tat java.lang.Thread.run(java.base@21.0.1/Thread.java:1583)
				\tat com.acme.secret.Foo.run(com.acme.secret@1.0/Foo.java:12)
				\tat com.acme.secret.Bar.run(com.acme.secret/Bar.java:3)
				\tat com.acme.secret.Baz.run(Baz.java:1)
				\tat org.other.Qux.run(com.acme.secret/Qux.java:1)
				\tat com.acme.secret.Foo.run(com.acme.secret@1.0/Native Method)
				\tat com.acme.secret.Foo.run(Unknown Source)
				\tat org.other.Qux.run(org.other@2/Qux.java:1)
				""";
		String expected = """
				"main" #1 prio=5 tid=0x1 nid=0x2 waiting
				\tat java.lang.Thread.run(java.base@21.0.1/Thread.java:1583)
				\tat com.acme.%1$s.%2$s.run(com.acme.%1$s@1.0/%2$s.java:12)
				\tat com.acme.%1$s.%3$s.run(com.acme.%1$s/%3$s.java:3)
				\tat com.acme.%1$s.%4$s.run(%4$s.java:1)
				\tat org.other.Qux.run(com.acme.%1$s/Qux.java:1)
				\tat com.acme.%1$s.%2$s.run(com.acme.%1$s@1.0/Native Method)
				\tat com.acme.%1$s.%2$s.run(Unknown Source)
				\tat org.other.Qux.run(org.other@2/Qux.java:1)
				""".formatted(secret, hash("Foo"), hash("Bar"), hash("Baz"));
		for (StringLocation location : compositeLocations()) {
			if (location.isThreadDump()) {
				assertEquals(expected, redactor.redact(dump, List.of(location)), location.toString());
			}
		}
		assertEquals("com.acme." + secret, redactor.redact("com.acme.secret", List.of(MODULE_NAME)),
				"the module constant gets the same name as the frames");
		RuleRedactor everything = RuleRedactor.builder().hashClassNames("(.*)").hashMethodNames("(.*)").build();
		String frame = "\tat java.lang.Thread.run(java.base@21.0.1/Thread.java:1583)\n";
		assertEquals(
				"\tat " + hash("java") + "." + hash("lang") + "." + hash("Thread") + "." + hash("run") + "("
						+ hash("java") + "." + hash("base") + "@21.0.1/" + hash("Thread") + ".java:1583)\n",
				everything.redact(frame, List.of(THREAD_DUMP)));
		assertEquals(hash("java") + "." + hash("base"), everything.redact("java.base", List.of(MODULE_NAME)));
		// The module is renamed although the class of the frame is not
		RuleRedactor base = RuleRedactor.builder().hashClassNames("java\\.(base)").build();
		assertEquals("\tat java.lang.Thread.run(java." + hash("base") + "@21.0.1/Thread.java:1583)\n",
				base.redact(frame, List.of(THREAD_DUMP)));
		assertEquals("java." + hash("base"), base.redact("java.base", List.of(MODULE_NAME)));
		assertEquals("java/lang/Thread", base.redact("java/lang/Thread", List.of(CLASS_NAME)));
		assertEquals("java/lang", base.redact("java/lang", List.of(PACKAGE_NAME)));
	}

	@Test
	void hashesBareSourceNamesOfFramesWithTheirClasses() {
		// HotSpot prints the location of a frame as Foo.java:12, Foo.java, Native Method, Unknown
		// Source, Redefined or, for a generated class, whose source is named like the class without
		// an extension, the bare name of the class, which would reveal the hashed class. Of the bare
		// texts only the class's own name is hashed, with the class; the others are left as they are
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)").build();
		String dump = """
				\tat com.acme.secret.Gen.run(com.acme.secret@1/Gen)
				\tat com.acme.secret.Gen.run(Gen)
				\tat com.acme.secret.Gen$$Lambda/0x00007fb87c2252f8.run(Gen$$Lambda)
				\tat com.acme.secret.Outer$Inner.run(Outer$Inner)
				\tat com.acme.secret.Foo.run(Foo.java)
				\tat com.acme.secret.Foo.run(Native Method)
				\tat com.acme.secret.Foo.run(com.acme.secret@1/Unknown Source)
				\tat com.acme.secret.Foo.run(Redefined)
				\tat com.acme.secret.Foo.run(com.acme.secret@1/Redefined)
				\tat com.acme.secret.Foo.run(Gen)
				\tat com.acme.secret.Foo.run(my-file)
				\tat org.other.Gen.run(org.other@1/Gen)
				\tat java.lang.invoke.LambdaForm$MH/0x00007fb87c0c4800.invoke(java.base@21.0.1/LambdaForm$MH)
				""";
		String expected = """
				\tat com.acme.%1$s.%2$s.run(com.acme.%1$s@1/%2$s)
				\tat com.acme.%1$s.%2$s.run(%2$s)
				\tat com.acme.%1$s.%3$s/0x00007fb87c2252f8.run(%3$s)
				\tat com.acme.%1$s.%5$s.run(%5$s)
				\tat com.acme.%1$s.%4$s.run(%4$s.java)
				\tat com.acme.%1$s.%4$s.run(Native Method)
				\tat com.acme.%1$s.%4$s.run(com.acme.%1$s@1/Unknown Source)
				\tat com.acme.%1$s.%4$s.run(Redefined)
				\tat com.acme.%1$s.%4$s.run(com.acme.%1$s@1/Redefined)
				\tat com.acme.%1$s.%4$s.run(Gen)
				\tat com.acme.%1$s.%4$s.run(my-file)
				\tat org.other.Gen.run(org.other@1/Gen)
				\tat java.lang.invoke.LambdaForm$MH/0x00007fb87c0c4800.invoke(java.base@21.0.1/LambdaForm$MH)
				""".formatted(hash("secret"), hash("Gen"), hash("Gen$$Lambda"), hash("Foo"), hash("Outer$Inner"));
		assertEquals(expected, redactor.redact(dump, List.of(THREAD_DUMP)));
		// Only the bare name of the class is hashed, so the marker of a redefined class stays
		String redefined = "\tat com.acme.secret.Foo.run(Redefined)\n\tat com.acme.secret.Foo.run(Foo.java:12)\n";
		assertEquals(
				"\tat %1$s.%2$s.%3$s.run(Redefined)\n\tat %1$s.%2$s.%3$s.run(%3$s.java:12)\n"
						.formatted(hash("com") + "." + hash("acme"), hash("secret"), hash("Foo")),
				EVERYTHING.redact(redefined, List.of(THREAD_DUMP)));
		// When every class name is hashed, so are the names of the JDK's generated classes
		String frame = "\tat java.lang.invoke.LambdaForm$MH/0x00007fb87c0c4800.invoke("
				+ "java.base@21.0.1/LambdaForm$MH)\n";
		assertEquals("\tat " + hash("java") + "." + hash("lang") + "." + hash("invoke") + "." + hash("LambdaForm$MH")
				+ "/0x00007fb87c0c4800.invoke(" + hash("java") + "." + hash("base") + "@21.0.1/" + hash("LambdaForm$MH")
				+ ")\n", EVERYTHING.redact(frame, List.of(THREAD_DUMP)));
	}

	@Test
	void hashesCompilerInliningStrings() {
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)").hashMethodNames("^(run)$")
				.build();
		for (String owner : List.of("jdk.CompilerInlining", "com.oracle.jdk.CompilerInlining")) {
			StringLocation type = new StringLocation(owner, "callee.type", false, List.of());
			StringLocation name = new StringLocation(owner, "callee.name", false, List.of());
			StringLocation descriptor = new StringLocation(owner, "callee.descriptor", false, List.of());
			StringLocation message = new StringLocation(owner, "message", false, List.of());
			assertTrue(type.isClassName() && !type.isMethodName() && !type.isMethodDescriptor(), type.toString());
			assertTrue(name.isMethodName() && !name.isClassName() && !name.isMethodDescriptor(), name.toString());
			assertTrue(descriptor.isMethodDescriptor() && !descriptor.isClassName() && !descriptor.isMethodName(),
					descriptor.toString());
			assertTrue(!message.isClassName() && !message.isMethodName() && !message.isMethodDescriptor(),
					message.toString());
			assertEquals("com/acme/" + hash("secret") + "/" + hash("Foo"),
					redactor.redact("com/acme/secret/Foo", List.of(type)), owner);
			assertEquals(redactor.redact("com/acme/secret/Foo", List.of(CLASS_NAME)),
					redactor.redact("com/acme/secret/Foo", List.of(type)), "the same hash as the constant");
			assertEquals("java/lang/Object", redactor.redact("java/lang/Object", List.of(type)));
			assertEquals(redactor.redact("run", List.of(METHOD_NAME)), redactor.redact("run", List.of(name)));
			assertEquals("(Lcom/acme/" + hash("secret") + "/" + hash("Foo") + ";)V",
					redactor.redact("(Lcom/acme/secret/Foo;)V", List.of(descriptor)));
			assertEquals("com.acme.secret.Foo::run", redactor.redact("com.acme.secret.Foo::run", List.of(message)),
					"the message is free text");
		}
		StringLocation constant = new StringLocation("jdk.CompilerInlining", "callee.type", true, List.of());
		assertTrue(!constant.isClassName(), "only the inline strings of the event");
	}

	@Test
	void keepsClassNamesStartingWithTheirPackagesInEveryForm() {
		List<String> patterns = List.of("com\\.acme\\.(.*)", "(.*)", "(.*)Impl$", "Secret", "com\\.ac(.*)",
				"com\\.acme\\.(secret)", "^com\\.acme\\.secret\\.FooImpl$", "com\\.acme\\.secret\\.(.*)", "秘密");
		List<String> classes = List.of("com.acme.secret.FooImpl", "com.acme.secret.Secret", "com.acme.Secret",
				"com.acme.secret.db.Outer$Inner", "org.other.FooImpl", "com.acme.secret.Foo$$Lambda", "FooImpl",
				"se.hirt.秘密.秘密Impl");
		byte[] key = {1, 2, 3};
		// The hash of a segment with the key: the replacement of a class in the default package when
		// everything matches
		RuleRedactor everythingKeyed = RuleRedactor.builder().hashClassNames("(.*)", key).build();
		UnaryOperator<String> keyedHash = text -> everythingKeyed.redact(text, List.of(CLASS_NAME));
		for (String pattern : patterns) {
			RuleRedactor unkeyed = RuleRedactor.builder().hashClassNames(pattern).build();
			RuleRedactor keyed = RuleRedactor.builder().hashClassNames(pattern, key).build();
			boolean renamed = false;
			for (String dotted : classes) {
				String slashed = dotted.replace('.', '/');
				String constant = assertConsistentForms(unkeyed, RuleRedactorTest::hash, dotted);
				String keyedConstant = assertConsistentForms(keyed, keyedHash, dotted);
				if (constant.equals(slashed)) {
					assertEquals(slashed, keyedConstant, pattern + " with a key");
				} else {
					assertTrue(!keyedConstant.equals(constant) && !keyedConstant.equals(slashed),
							pattern + " on " + dotted + ": the key changes the hashes, " + keyedConstant);
					renamed = true;
				}
			}
			assertTrue(renamed, pattern + " renames one of the classes");
		}
		// Keyed hashes differ from those of another key, and are stable
		RuleRedactor keyed = RuleRedactor.builder().hashClassNames("(.*)", key).build();
		String hashed = keyed.redact("com/acme/secret/Foo", List.of(CLASS_NAME));
		String otherKey = RuleRedactor.builder().hashClassNames("(.*)", new byte[] {4, 5, 6}).build()
				.redact("com/acme/secret/Foo", List.of(CLASS_NAME));
		assertTrue(hashed.matches(HASH + "/" + HASH + "/" + HASH + "/" + HASH), hashed);
		assertTrue(!hashed.equals(EVERYTHING.redact("com/acme/secret/Foo", List.of(CLASS_NAME)))
				&& !hashed.equals(otherKey), hashed);
		assertEquals(hashed, keyed.redact("com/acme/secret/Foo", List.of(CLASS_NAME)));
		assertEquals(hashed.substring(0, hashed.lastIndexOf('/')),
				keyed.redact("com/acme/secret", List.of(PACKAGE_NAME)));
	}

	/**
	 * Asserts that every form of the class gets the same replacement, which starts with the
	 * replacement of its package, as the package and module constants get it. The file name of a
	 * frame is hashed when the class is renamed, as before. A class in the default package has no
	 * package and no module to check.
	 *
	 * @param h
	 *            the hash of a segment, with the key of the redactor
	 * @return the replacement of the class name constant, in internal form
	 */
	private static String assertConsistentForms(RuleRedactor redactor, UnaryOperator<String> h, String dotted) {
		int dot = dotted.lastIndexOf('.');
		String packageDotted = dot < 0 ? "" : dotted.substring(0, dot);
		String packageSlashed = packageDotted.replace('.', '/');
		String slashed = dotted.replace('.', '/');
		String newPackageSlashed = redactor.redact(packageSlashed, List.of(PACKAGE_NAME));
		String newPackageDotted = newPackageSlashed.replace('/', '.');
		assertEquals(newPackageDotted, redactor.redact(packageDotted, List.of(MODULE_NAME)), dotted);
		assertTrue(dot >= 0 || newPackageSlashed.isEmpty(), "the default package stays unnamed");
		String constant = redactor.redact(slashed, List.of(CLASS_NAME));
		String prefix = dot < 0 ? "" : newPackageSlashed + "/";
		assertTrue(constant.startsWith(prefix), constant + " for " + dotted);
		String simple = constant.substring(prefix.length());
		assertTrue(!simple.isEmpty() && simple.indexOf('/') < 0, constant);
		boolean renamed = !constant.equals(slashed);
		String newDotted = (dot < 0 ? "" : newPackageDotted + ".") + simple;
		assertEquals("[[L" + constant + ";", redactor.redact("[[L" + slashed + ";", List.of(CLASS_NAME)), dotted);
		assertEquals("(L" + constant + ";[L" + constant + ";)L" + constant + ";",
				redactor.redact("(L" + slashed + ";[L" + slashed + ";)L" + slashed + ";", List.of(DESCRIPTOR)), dotted);
		String file = renamed ? h.apply("Foo") : "Foo";
		// A class in the default package is in the unnamed module, which the frames do not show
		String module = dot < 0 ? "" : packageDotted + "@1/";
		String newModule = dot < 0 ? "" : newPackageDotted + "@1/";
		String unversioned = dot < 0 ? "" : packageDotted + "/";
		String newUnversioned = dot < 0 ? "" : newPackageDotted + "/";
		String dump = "\tat " + dotted + ".run(" + module + "Foo.java:1)\n" + "\tat " + dotted
				+ "/0x00007fb87c2252f8.run(" + unversioned + "Foo.java:2)\n" + "\t- locked <0x1> (a " + dotted + ")\n"
				+ "\t- locked <0x2> (a [L" + dotted + ";)\n";
		String expected = "\tat " + newDotted + ".run(" + newModule + file + ".java:1)\n" + "\tat " + newDotted
				+ "/0x00007fb87c2252f8.run(" + newUnversioned + file + ".java:2)\n" + "\t- locked <0x1> (a " + newDotted
				+ ")\n" + "\t- locked <0x2> (a [L" + newDotted + ";)\n";
		assertEquals(expected, redactor.redact(dump, List.of(THREAD_DUMP)), dotted);
		for (StringLocation description : descriptionLocations()) {
			assertEquals("Class Name: " + newDotted, redactor.redact("Class Name: " + dotted, List.of(description)),
					dotted);
			assertEquals("Class Name: [L" + newDotted + ";",
					redactor.redact("Class Name: [L" + dotted + ";", List.of(description)), dotted);
		}
		return constant;
	}

	/**
	 * Several expressions form one rule, which decides each part of a name, the package or the
	 * simple name, by the first expression covering a piece of it, so that the classes stay within
	 * their packages whichever expression hashed their simple names, as in the common configuration
	 * hashing the application's classes below a prefix and everything else with {@code (.*)}
	 */
	@Test
	void combinesSeveralClassNameExpressionsIntoOneRuleDecidingEachPartOnce() {
		RuleRedactor acmeThenEverything = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)")
				.hashClassNames("(.*)").build();
		// The simple names and the packages below com.acme by the first expression
		assertEquals("com/acme/" + hash("secret") + "/" + hash("Foo"),
				acmeThenEverything.redact("com/acme/secret/Foo", List.of(CLASS_NAME)));
		assertEquals("com/acme/" + hash("secret"), acmeThenEverything.redact("com/acme/secret", List.of(PACKAGE_NAME)));
		assertEquals("com.acme." + hash("secret"), acmeThenEverything.redact("com.acme.secret", List.of(MODULE_NAME)));
		// Other packages, and com.acme itself, of which the first expression covers nothing, by the second
		assertEquals(hash("org") + "/" + hash("other") + "/" + hash("Bar"),
				acmeThenEverything.redact("org/other/Bar", List.of(CLASS_NAME)));
		assertEquals(hash("org") + "/" + hash("other"), acmeThenEverything.redact("org/other", List.of(PACKAGE_NAME)));
		assertEquals(hash("com") + "/" + hash("acme") + "/" + hash("Baz"),
				acmeThenEverything.redact("com/acme/Baz", List.of(CLASS_NAME)));
		assertEquals(hash("com") + "/" + hash("acme"), acmeThenEverything.redact("com/acme", List.of(PACKAGE_NAME)));
		assertEquals(hash("com") + "." + hash("acme"), acmeThenEverything.redact("com.acme", List.of(MODULE_NAME)));
		assertEquals(hash("Foo"), acmeThenEverything.redact("Foo", List.of(CLASS_NAME)), "the default package");
		// In the other order, the first expression decides everything
		RuleRedactor everythingThenAcme = RuleRedactor.builder().hashClassNames("(.*)")
				.hashClassNames("com\\.acme\\.(.*)").build();
		for (String name : List.of("com/acme/secret/Foo", "com/acme/Baz", "org/other/Bar", "Foo")) {
			assertEquals(EVERYTHING.redact(name, List.of(CLASS_NAME)),
					everythingThenAcme.redact(name, List.of(CLASS_NAME)), name);
		}
		// A literal and a prefix: the simple name by the literal, the package by the prefix
		RuleRedactor secretThenOrg = RuleRedactor.builder().hashClassNames("Secret").hashClassNames("org\\.(.*)")
				.build();
		assertEquals("org/" + hash("other") + "/" + hash("Secret") + "Service",
				secretThenOrg.redact("org/other/SecretService", List.of(CLASS_NAME)));
		assertEquals("org/" + hash("other"), secretThenOrg.redact("org/other", List.of(PACKAGE_NAME)));
		// A suffix and everything: the simple name keeps its suffix, and the second expression decides
		// the packages, and the simple names the first does not reach
		RuleRedactor implThenEverything = RuleRedactor.builder().hashClassNames("(.*)Impl$").hashClassNames("(.*)")
				.build();
		assertEquals(hash("com") + "/" + hash("acme") + "/" + hash("Foo") + "Impl",
				implThenEverything.redact("com/acme/FooImpl", List.of(CLASS_NAME)));
		assertEquals(hash("com") + "/" + hash("acme") + "/" + hash("Bar"),
				implThenEverything.redact("com/acme/Bar", List.of(CLASS_NAME)));
		assertEquals(hash("com") + "/" + hash("acme"), implThenEverything.redact("com/acme", List.of(PACKAGE_NAME)));
		// The expressions are one rule, in the place of the first, so a rule added between them comes
		// after both, and gets what no expression covers
		RuleRedactor between = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)")
				.replaceIf(StringLocation::isPackageName, value -> "X").hashClassNames("(.*)").build();
		assertEquals(hash("org") + "/" + hash("other"), between.redact("org/other", List.of(PACKAGE_NAME)));
		assertEquals("X", between.redact("", List.of(PACKAGE_NAME)), "the default package");
		// A builder goes on without changing what it built
		RuleRedactor.Builder builder = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)");
		RuleRedactor acme = builder.build();
		RuleRedactor more = builder.hashClassNames("(.*)").build();
		assertEquals("org/other/Bar", acme.redact("org/other/Bar", List.of(CLASS_NAME)));
		assertEquals(hash("org") + "/" + hash("other") + "/" + hash("Bar"),
				more.redact("org/other/Bar", List.of(CLASS_NAME)));
	}

	/**
	 * Keyed and unkeyed expressions combine like any others: each part of a name is hashed by the
	 * expression deciding it, in every form, and the file names of frames with the simple names
	 */
	@Test
	void combinesKeyedAndUnkeyedClassNameExpressionsConsistentlyInEveryForm() {
		byte[] key = {1, 2, 3};
		RuleRedactor everythingKeyed = RuleRedactor.builder().hashClassNames("(.*)", key).build();
		UnaryOperator<String> k = text -> everythingKeyed.redact(text, List.of(CLASS_NAME));
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)", key).hashClassNames("(.*)")
				.build();
		// Below com.acme the keyed expression decides the simple names and the packages
		assertEquals("com/acme/" + k.apply("secret") + "/" + k.apply("Foo"),
				assertConsistentForms(redactor, k, "com.acme.secret.Foo"));
		assertEquals("com/acme/" + k.apply("secret") + "/" + k.apply("Foo$$Lambda"),
				assertConsistentForms(redactor, k, "com.acme.secret.Foo$$Lambda"));
		assertEquals("com/acme/" + k.apply("secret") + "/" + k.apply("db") + "/" + k.apply("Outer$Inner"),
				assertConsistentForms(redactor, k, "com.acme.secret.db.Outer$Inner"));
		// The simple name of a class in com.acme itself too, while the unkeyed expression decides the
		// package, of which the keyed one covers nothing
		assertEquals(hash("com") + "/" + hash("acme") + "/" + k.apply("Baz"),
				assertConsistentForms(redactor, k, "com.acme.Baz"));
		// Elsewhere the unkeyed expression decides everything
		assertEquals(hash("org") + "/" + hash("other") + "/" + hash("Bar"),
				assertConsistentForms(redactor, RuleRedactorTest::hash, "org.other.Bar"));
		assertEquals(hash("Foo"), assertConsistentForms(redactor, RuleRedactorTest::hash, "Foo"));
		assertTrue(!k.apply("Foo").equals(hash("Foo")), "the key changes the hashes");
	}

	/**
	 * A name stored both as a class and as a package, which javac forbids and the JVM allows, is
	 * renamed as the package whichever location comes first, so that the classes of the package
	 * stay within it; a prefix expression maps both alike anyway
	 */
	@Test
	void renamesANameThatIsBothAClassAndAPackageAsThePackage() {
		RuleRedactor literal = RuleRedactor.builder().hashClassNames("com\\.acme\\.secret").build();
		String asPackage = literal.redact("com/acme/secret", List.of(PACKAGE_NAME));
		String asClass = literal.redact("com/acme/secret", List.of(CLASS_NAME));
		assertEquals(hash("com") + "/" + hash("acme") + "/" + hash("secret"), asPackage);
		assertEquals("com/acme/" + hash("secret"), asClass);
		assertEquals(asPackage, literal.redact("com/acme/secret", List.of(CLASS_NAME, PACKAGE_NAME)));
		assertEquals(asPackage, literal.redact("com/acme/secret", List.of(PACKAGE_NAME, CLASS_NAME)));
		assertEquals(asPackage, literal.redact("com/acme/secret", List.of(CLASS_NAME, DESCRIPTOR, MODULE_NAME)));
		assertTrue(literal.redact("com/acme/secret/Foo", List.of(CLASS_NAME)).startsWith(asPackage + "/"),
				"the classes of the package stay within it");
		RuleRedactor prefix = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)").build();
		assertEquals(prefix.redact("com/acme/secret", List.of(PACKAGE_NAME)),
				prefix.redact("com/acme/secret", List.of(CLASS_NAME)), "a prefix expression maps both alike");
	}

	@Test
	void hashesObjectArrayClassesLikeComponentsAndDescriptors() {
		List<RuleRedactor> redactors = List.of(
				RuleRedactor.builder().hashClassNames("^com\\.acme\\.SecretService$").build(),
				RuleRedactor.builder().hashClassNames("com\\.acme\\.(Secret)").build(),
				RuleRedactor.builder().hashClassNames("^com\\.acme\\.(SecretService)$", new byte[] {1, 2, 3}).build());
		List<StringLocation> classLocations = List.of(CLASS_NAME, LEGACY_CLASS_NAME);
		StringLocation descriptor = DESCRIPTOR;
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
		// Every segment of the component class, when every class name matches
		RuleRedactor everything = RuleRedactor.builder().hashClassNames("(.*)").build();
		String hashed = everything.redact(component, List.of(classLocations.get(0)));
		assertEquals(hash("com") + "/" + hash("acme") + "/" + hash("SecretService"), hashed);
		assertEquals("[[L" + hashed + ";", everything.redact("[[L" + component + ";", List.of(classLocations.get(0))));
		assertEquals("([L" + hashed + ";)L" + hashed + ";",
				everything.redact("([L" + component + ";)L" + component + ";", List.of(descriptor)));
	}

	@Test
	void keepsPrimitiveArrayClassesEvenWhenEveryClassNameMatches() {
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("(.*)").build();
		StringLocation className = CLASS_NAME;
		for (String type : List.of("B", "C", "D", "F", "I", "J", "S", "Z")) {
			for (String dimensions : List.of("[", "[[")) {
				String array = dimensions + type;
				assertEquals(array, redactor.redact(array, List.of(className)));
			}
		}
		assertEquals("[L" + hash("java") + "/" + hash("lang") + "/" + hash("String") + ";",
				redactor.redact("[Ljava/lang/String;", List.of(className)), "while object arrays are hashed");
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
		String component = redactor.redact(RuleRedactorTest.class.getName().replace('.', '/'), List.of(CLASS_NAME))
				.replace('/', '.');
		assertTrue(!component.equals(RuleRedactorTest.class.getName()));
		assertTrue(component.startsWith(RuleRedactorTest.class.getPackageName() + "."),
				"the anchored name does not match the package followed by a dot: " + component);
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
		StringLocation methodName = METHOD_NAME;
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
		String method = redactor.redact("processRecord", List.of(LEGACY_METHOD_NAME));
		String dump = "\tat com.acme.secret.RecordService.processRecord(RecordService.java:42)\n"
				+ "\tat java.util.ArrayList.forEach(java.base@25/ArrayList.java:1596)\n";
		String rewritten = redactor.redact(dump,
				List.of(new StringLocation("vm/runtime/thread_dump", "result", false, List.of())));
		assertTrue(rewritten.contains("." + method + "("), rewritten);
		assertTrue(!rewritten.contains("processRecord") && !rewritten.contains("RecordService"), rewritten);
		assertTrue(!rewritten.contains("secret"), rewritten);
		String service = hash("RecordService");
		assertTrue(rewritten.startsWith(
				"\tat com.acme." + hash("secret") + "." + service + "." + method + "(" + service + ".java:42)\n"),
				rewritten);
		assertTrue(rewritten.contains("at java.util.ArrayList.forEach(java.base@25/ArrayList.java:1596)"), rewritten);
	}

	@Test
	void hashesUnicodeFrameIdentifiersFilesAndLockClasses() {
		String[][] identifiers = {{"秘密", "処理", "秘密"}, {"Outer$秘密", "lambda$処理$0", "秘密"}, {"€Secret", "€処理", "€Secret"},
				{"Cafe\u0301", "me\u0301thod", "Cafe\u0301"},
				{"\uD801\uDC00Secret", "\uD801\uDC01run", "\uD801\uDC00Secret"}};
		StringLocation className = CLASS_NAME;
		StringLocation methodName = METHOD_NAME;
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
		List<String> inputDumps = TestRecordings.threadDumps(input);
		assertTrue(inputDumps.stream().anyMatch(text -> text.contains(originalClass + "." + originalMethod + "(")),
				"the input must genuinely contain the Unicode frame");
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames(Pattern.quote(originalClass))
				.hashMethodNames(Pattern.quote(originalMethod)).build();
		String expectedClass = redactor.redact(originalClass.replace('.', '/'), List.of(CLASS_NAME)).replace('/', '.');
		String expectedMethod = redactor.redact(originalMethod, List.of(METHOD_NAME));
		assertTrue(expectedClass.startsWith(秘密.class.getPackageName() + ".") && !expectedClass.equals(originalClass),
				"the quoted name does not match the package followed by a dot, so only the simple name is hashed: "
						+ expectedClass);
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
		StringLocation className = LEGACY_CLASS_NAME;
		String hashed = RuleRedactor.builder().hashClassNames("Secret[A-Za-z]*").build()
				.redact("com/acme/SecretService$Inner", List.of(className));
		assertTrue(hashed.matches("com/acme/[A-Za-z0-9_$]{12,13}\\$Inner"), hashed);
		assertEquals("com/acme/" + hash("SecretService") + "$Inner", hashed);
		// A match reaching into the package hashes the simple name only, since the package is matched
		// on its own, followed by a dot
		RuleRedactor acrossDot = RuleRedactor.builder().hashClassNames("acme\\.Secret").build();
		assertEquals("com/acme/" + hash("Secret") + "Service$Inner",
				acrossDot.redact("com/acme/SecretService$Inner", List.of(className)));
		assertEquals("com/acme", acrossDot.redact("com/acme", List.of(PACKAGE_NAME)));
		assertEquals("com/" + hash("acme") + "/SecretService",
				RuleRedactor.builder().hashClassNames("acme\\.?").build().redact("com/acme/SecretService",
						List.of(className)),
				"the package is hashed where the expression matches it followed by a dot, the dot never");
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
						// The expression matches nothing of the package followed by a dot, so only the
						// simple name is hashed
						assertTrue(typeName.matches("se\\.hirt\\.jfr\\.redact\\." + HASH), typeName);
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
	void hashesHiddenClassesByTheirHostClassKeepingThePerRunSuffix() {
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("(?:com\\.acme|java\\.lang\\.invoke)\\.(.*)")
				.hashMethodNames("^(run)$").build();
		String host = hashedSource(redactor, "com.acme.Host");
		String lambda = hashedSource(redactor, "com.acme.Host$$Lambda");
		String lambda14 = hashedSource(redactor, "com.acme.Host$$Lambda$14");
		String lambda269 = hashedSource(redactor, "com.acme.Host$$Lambda$269");
		String form = hashedSource(redactor, "java.lang.invoke.LambdaForm$MH");
		String run = redactor.redact("run", List.of(METHOD_NAME));
		assertTrue(!lambda.contains("Lambda") && !lambda.equals(lambda14) && !run.equals("run"), lambda + " " + run);
		// JDK 8 to 20 number lambda proxy classes per run, and the counter is part of the hashed host
		assertTrue(!lambda14.equals(hashedSource(redactor, "com.acme.Host$$Lambda$15")),
				"the hash follows the counter");

		// Constants of every JDK generation: the host is hashed, the suffix and the separators are kept
		assertEquals(lambda269 + "/286774984",
				redactor.redact("com.acme.Host$$Lambda$269/286774984", List.of(CLASS_NAME)), "JDK 8-14");
		assertEquals(lambda14 + "+0x0000000800c02a00/1052195003",
				redactor.redact("com.acme.Host$$Lambda$14+0x0000000800c02a00/1052195003", List.of(CLASS_NAME)),
				"JDK 15-20");
		assertEquals(lambda + "+0x00007fb87c2252f8/262911569",
				redactor.redact("com.acme.Host$$Lambda+0x00007fb87c2252f8/262911569", List.of(CLASS_NAME)),
				"JDK 21-22");
		assertEquals(lambda + "/0x000000002e045c38",
				redactor.redact("com.acme.Host$$Lambda/0x000000002e045c38", List.of(CLASS_NAME)), "JDK 23+");
		assertEquals(lambda + "/0x000000002f0a0000",
				redactor.redact("com.acme.Host$$Lambda/0x000000002f0a0000", List.of(CLASS_NAME)), "another run");
		assertEquals(host.replace('.', '/'), redactor.redact("com/acme/Host", List.of(CLASS_NAME)));
		String internal = lambda.replace('.', '/');
		assertEquals("[L" + internal + "+0x00007fb87c2252f8;",
				redactor.redact("[Lcom/acme/Host$$Lambda+0x00007fb87c2252f8;", List.of(CLASS_NAME)));
		assertEquals("(L" + internal + "+0x00007fb87c2252f8;)L" + internal + ";", redactor
				.redact("(Lcom/acme/Host$$Lambda+0x00007fb87c2252f8;)Lcom/acme/Host$$Lambda;", List.of(DESCRIPTOR)));
		assertEquals("([[L" + internal + "+0x00007fb87c2252f8;I)V",
				redactor.redact("([[Lcom/acme/Host$$Lambda+0x00007fb87c2252f8;I)V", List.of(DESCRIPTOR)));
		// In internal form only the address is a suffix, so a last segment of digits is a class name
		String digits = redactor.redact("com/acme/123", List.of(CLASS_NAME));
		assertTrue(digits.matches("com/acme/[A-Za-z0-9_$]{12,13}"), digits);
		assertEquals("(L" + digits + ";)V", redactor.redact("(Lcom/acme/123;)V", List.of(DESCRIPTOR)));
		String hex = redactor.redact("com/acme/0x1F", List.of(CLASS_NAME));
		assertTrue(hex.matches("com/acme/[A-Za-z0-9_$]{12,13}"), hex);
		// A dotted name may end in a slash segment that is no suffix, and stays dotted
		String fooXyz = redactor.redact("com.acme.Foo/xyz", List.of(CLASS_NAME));
		assertTrue(fooXyz.matches("com\\.acme\\.[A-Za-z0-9_$]{12,13}"), fooXyz);
		RuleRedactor everything = RuleRedactor.builder().hashClassNames("(.*)").build();
		assertEquals(everything.redact("Gen$$Lambda", List.of(CLASS_NAME)) + "/0x000000002e045c38",
				everything.redact("Gen$$Lambda/0x000000002e045c38", List.of(CLASS_NAME)), "default package");
		assertEquals(everything.redact("Gen$$Lambda$5", List.of(CLASS_NAME)) + "/286774984",
				everything.redact("Gen$$Lambda$5/286774984", List.of(CLASS_NAME)), "default package, JDK 8-14");
		// A hidden class defined in the default package without a $ in its name, as by
		// Lookup.defineHiddenClass, keeps its address too, so its hash is the same in every run
		String hidden = everything.redact("GenHidden", List.of(CLASS_NAME));
		assertEquals(hidden + "/0x000000002e045c38",
				everything.redact("GenHidden/0x000000002e045c38", List.of(CLASS_NAME)), "default package, no $");
		assertEquals(hidden + "/0x000000002e0a0000",
				everything.redact("GenHidden/0x000000002e0a0000", List.of(CLASS_NAME)), "another run");
		assertEquals("[L" + hidden + "/0x000000002e045c38;",
				everything.redact("[LGenHidden/0x000000002e045c38;", List.of(CLASS_NAME)));
		// The only slash of a class in a single-segment package is no suffix when it starts a decimal
		// segment after a host without a $, unlike the identity hash of a JDK 8 to 14 class in the
		// default package, while an address names a hidden class whatever the host
		RuleRedactor acme = RuleRedactor.builder().hashClassNames("acme\\.(.*)").build();
		String digitsClass = acme.redact("acme/123", List.of(CLASS_NAME));
		assertTrue(digitsClass.matches("acme/[A-Za-z0-9_$]{12,13}"), digitsClass);
		assertEquals("[L" + digitsClass + ";", acme.redact("[Lacme/123;", List.of(CLASS_NAME)));
		assertEquals("(L" + digitsClass + ";)V", acme.redact("(Lacme/123;)V", List.of(DESCRIPTOR)));
		assertEquals(hash("acme") + "/" + hash("123"), everything.redact("acme/123", List.of(CLASS_NAME)),
				"segment by segment");
		assertEquals("acme/0x1F", acme.redact("acme/0x1F", List.of(CLASS_NAME)), "the hidden class acme, unmatched");
		assertEquals(everything.redact("acme", List.of(CLASS_NAME)) + "/0x1F",
				everything.redact("acme/0x1F", List.of(CLASS_NAME)));
		// In a descriptor, where a hidden class carries its address after a plus, the segment is a class
		String hexClass = acme.redact("(Lacme/0x1F;)V", List.of(DESCRIPTOR));
		assertTrue(hexClass.matches("\\(Lacme/[A-Za-z0-9_$]{12,13};\\)V"), hexClass);
		// The pattern decides for the names of primitive types, as before
		assertTrue(!everything.redact("int", List.of(CLASS_NAME)).equals("int"));
		assertEquals("int", redactor.redact("int", List.of(CLASS_NAME)));

		// The bare source name HotSpot prints for the generated LambdaForm is hashed like a file name
		String dump = """
				"main" #1 prio=5 tid=0x1 nid=0x2 waiting
				\tat com.acme.Host$$Lambda$269/286774984.run(Unknown Source)
				\tat com.acme.Host$$Lambda$14/0x0000000800c02a00.run(Unknown Source)
				\tat com.acme.Host$$Lambda/0x00007fb87c2252f8.run(Unknown Source)
				\tat java.lang.invoke.LambdaForm$MH/0x00007fb87c0c4800.invoke(java.base@21.0.1/LambdaForm$MH)
				\tat com.acme.Host.lambda$run$0(Host.java:12)
				\tat java.lang.Thread.run(java.base@21.0.1/Thread.java:1583)
				""";
		String expected = """
				"main" #1 prio=5 tid=0x1 nid=0x2 waiting
				\tat %1$s/286774984.%6$s(Unknown Source)
				\tat %2$s/0x0000000800c02a00.%6$s(Unknown Source)
				\tat %3$s/0x00007fb87c2252f8.%6$s(Unknown Source)
				\tat %4$s/0x00007fb87c0c4800.invoke(java.base@21.0.1/%8$s)
				\tat %5$s.lambda$run$0(%7$s.java:12)
				\tat java.lang.Thread.%6$s(java.base@21.0.1/Thread.java:1583)
				""".formatted(lambda269, lambda14, lambda, form, host, run, host.substring("com.acme.".length()),
				form.substring("java.lang.invoke.".length()));
		assertEquals(expected, redactor.redact(dump, List.of(THREAD_DUMP)));
	}

	@Test
	void takesOnlyAddressesAndIdentityHashesAsHiddenClassSuffixesOfFrames() {
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("(.*)").hashMethodNames("(.*)").build();
		// JRockit prints frames in internal form, whose slashes are no hidden-class suffixes
		StringLocation legacyDump = new StringLocation("vm/runtime/thread_dump", "result", false, List.of());
		String slashed = "\tat acme/Foo.run()V(Foo.java:12)\n\tat com/acme/Bar.run()V(Bar.java:3)\n";
		assertEquals(slashed, redactor.redact(slashed, List.of(legacyDump)));
		// In the default package, the suffix tells a hidden class, with or without a $ in its name,
		// in frames and lock objects alike
		String lambda = redactor.redact("Gen$$Lambda", List.of(CLASS_NAME));
		String lambda5 = redactor.redact("Gen$$Lambda$5", List.of(CLASS_NAME));
		String hidden = redactor.redact("GenHidden", List.of(CLASS_NAME));
		String run = redactor.redact("run", List.of(METHOD_NAME));
		assertTrue(!hidden.equals("GenHidden") && !run.equals("run"), hidden + " " + run);
		String dump = """
				\tat Gen$$Lambda/0x000000002e045c38.run(Unknown Source)
				\tat Gen$$Lambda$5/286774984.run(Unknown Source)
				\tat GenHidden/0x000000002e045c38.run(Unknown Source)
				\t- locked <0x00000004336b8a38> (a GenHidden/0x000000002e045c38)
				""";
		String expected = """
				\tat %1$s/0x000000002e045c38.%4$s(Unknown Source)
				\tat %2$s/286774984.%4$s(Unknown Source)
				\tat %3$s/0x000000002e045c38.%4$s(Unknown Source)
				\t- locked <0x00000004336b8a38> (a %3$s/0x000000002e045c38)
				""".formatted(lambda, lambda5, hidden, run);
		assertEquals(expected, redactor.redact(dump, List.of(THREAD_DUMP)));
	}

	@Test
	void leavesFramesInsideQuotedThreadNamesToTheThreadRule() {
		String threadName = "look at com.acme.Foo.bar(Foo.java:1) now";
		String header = '"' + threadName + "\" #14 prio=5 tid=0x1 nid=0x2 waiting\n";
		String frame = "\tat com.acme.Foo.bar(Foo.java:1)\n";
		RuleRedactor classes = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)").hashMethodNames("^(bar)$")
				.build();
		String foo = hashedSource(classes, "com.acme.Foo");
		String bar = classes.redact("bar", List.of(METHOD_NAME));
		assertEquals(header + "\tat " + foo + "." + bar + "(" + foo.substring("com.acme.".length()) + ".java:1)\n",
				classes.redact(header + frame, List.of(THREAD_DUMP)));
		// So the header gets the hash of the name as recorded, whichever rule comes first
		RuleRedactor threadsFirst = RuleRedactor.builder().hashThreadNames().hashClassNames("com\\.acme\\.(.*)")
				.hashMethodNames("^(bar)$").build();
		RuleRedactor threadsLast = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)").hashMethodNames("^(bar)$")
				.hashThreadNames().build();
		String expectedHeader = '"' + threadsFirst.redact(threadName, List.of(THREAD_NAME))
				+ "\" #14 prio=5 tid=0x1 nid=0x2 waiting\n";
		assertTrue(expectedHeader.startsWith("\"Thread-"), expectedHeader);
		for (RuleRedactor redactor : List.of(threadsFirst, threadsLast)) {
			String dump = redactor.redact(header + frame, List.of(THREAD_DUMP));
			assertTrue(dump.startsWith(expectedHeader), dump);
			assertTrue(!dump.contains("Foo") && !dump.contains(".bar("), dump);
		}
	}

	@Test
	void hashesLockObjectClassesInEveryThreadDumpTemplate() {
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)").build();
		String foo = hashedSource(redactor, "com.acme.Foo");
		String inner = hashedSource(redactor, "com.acme.Foo$Inner");
		String sync = hashedSource(redactor, "com.acme.Foo$Sync");
		String lambda = hashedSource(redactor, "com.acme.Foo$$Lambda");
		String dump = """
				"worker (a com.acme.Foo)" #12 prio=5 tid=0x1 nid=0x2 waiting for monitor entry
				\t- locked <0x00000004336b8a38> (a com.acme.Foo)
				\t- waiting to lock <0x00000004336b8a39> (a com.acme.Foo$Inner)
				\t- waiting on <0x00000004336b8a3a> (a [Lcom.acme.Foo;)
				\t- parking to wait for  <0x00000004336b8a3b> (a [[Lcom.acme.Foo;)
				\t- waiting to re-lock in wait() <0x00000004336b8a3c> (a [I)
				\t- eliminated <owner is scalar replaced> (a java.lang.Class for com.acme.Foo)
				\t- locked <0x00000004336b8a3d> (a java.lang.Class for [Lcom.acme.Foo;)
				\t- waiting on the Class initialization monitor for com.acme.Foo
				\t- locked <0x00000004336b8a3e> (a com.acme.Foo$$Lambda/0x00007fb87c2252f8)

				Found one Java-level deadlock:
				"worker (a com.acme.Foo)":
				  waiting to lock monitor 0x00007f8b1c004e00 (object 0x000000076b4d8f88, a com.acme.Foo),
				  which is held by "other (a com.acme.Foo)"
				"other (a com.acme.Foo)":
				  waiting for ownable synchronizer 0x000000076b4d8f90, (a com.acme.Foo$Sync),
				  which is held by "worker (a com.acme.Foo)"
				""";
		String expected = """
				"worker (a com.acme.Foo)" #12 prio=5 tid=0x1 nid=0x2 waiting for monitor entry
				\t- locked <0x00000004336b8a38> (a %1$s)
				\t- waiting to lock <0x00000004336b8a39> (a %2$s)
				\t- waiting on <0x00000004336b8a3a> (a [L%1$s;)
				\t- parking to wait for  <0x00000004336b8a3b> (a [[L%1$s;)
				\t- waiting to re-lock in wait() <0x00000004336b8a3c> (a [I)
				\t- eliminated <owner is scalar replaced> (a java.lang.Class for %1$s)
				\t- locked <0x00000004336b8a3d> (a java.lang.Class for [L%1$s;)
				\t- waiting on the Class initialization monitor for %1$s
				\t- locked <0x00000004336b8a3e> (a %4$s/0x00007fb87c2252f8)

				Found one Java-level deadlock:
				"worker (a com.acme.Foo)":
				  waiting to lock monitor 0x00007f8b1c004e00 (object 0x000000076b4d8f88, a %1$s),
				  which is held by "other (a com.acme.Foo)"
				"other (a com.acme.Foo)":
				  waiting for ownable synchronizer 0x000000076b4d8f90, (a %3$s),
				  which is held by "worker (a com.acme.Foo)"
				""".formatted(foo, inner, sync, lambda);
		for (StringLocation location : compositeLocations()) {
			if (location.isThreadDump()) {
				assertEquals(expected, redactor.redact(dump, List.of(location)), location.toString());
			}
		}
		RuleRedactor everything = RuleRedactor.builder().hashClassNames("(.*)").build();
		// The pattern decides for the class of a mirror, as it does for the class name constant, also
		// for a primitive type; primitive arrays have no class name
		String mirrors = "\t- locked <0x00000004336b8a38> (a java.lang.Class for int)\n"
				+ "\t- eliminated <owner is scalar replaced> (a java.lang.Class for java.lang.String)\n"
				+ "\t- waiting on <0x00000004336b8a39> (a [[J)\n";
		String string = everything.redact("java/lang/String", List.of(CLASS_NAME));
		assertEquals(hash("java") + "/" + hash("lang") + "/" + hash("String"), string);
		String expectedMirrors = "\t- locked <0x00000004336b8a38> (a java.lang.Class for "
				+ everything.redact("int", List.of(CLASS_NAME)) + ")\n"
				+ "\t- eliminated <owner is scalar replaced> (a java.lang.Class for " + string.replace('/', '.') + ")\n"
				+ "\t- waiting on <0x00000004336b8a39> (a [[J)\n";
		assertEquals(expectedMirrors, everything.redact(mirrors, List.of(THREAD_DUMP)));
		assertTrue(!expectedMirrors.contains("for int)"), "the constant int is hashed, so is the mirror");
	}

	@Test
	void hashesClassNamesInOldObjectDescriptions() {
		RuleRedactor redactor = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)").build();
		RuleRedactor everything = RuleRedactor.builder().hashClassNames("(.*)").build();
		String foo = hashedSource(redactor, "com.acme.Foo");
		String lambda = hashedSource(redactor, "com.acme.Foo$$Lambda");
		for (StringLocation description : descriptionLocations()) {
			List<StringLocation> locations = List.of(description);
			assertEquals("Class Name: " + foo, redactor.redact("Class Name: com.acme.Foo", locations));
			assertEquals("Class Name: com.acme." + hash("secret") + "." + hash("Foo"),
					redactor.redact("Class Name: com.acme.secret.Foo", locations), "segment by segment");
			assertEquals("Class Name: [[L" + foo + ";", redactor.redact("Class Name: [[Lcom.acme.Foo;", locations));
			assertEquals("Class Name: " + lambda + "/0x00007fb87c2252f8",
					redactor.redact("Class Name: com.acme.Foo$$Lambda/0x00007fb87c2252f8", locations));
			assertEquals("Class Name: [L" + lambda + "/0x00007fb87c2252f8;",
					redactor.redact("Class Name: [Lcom.acme.Foo$$Lambda/0x00007fb87c2252f8;", locations));
			assertEquals("Class Name: [I", redactor.redact("Class Name: [I", locations));
			assertEquals("Class Name: java.lang.String", redactor.redact("Class Name: java.lang.String", locations));
			assertEquals("Class Name: ", redactor.redact("Class Name: ", locations), "an empty remainder");
			assertEquals("Class Name: " + everything.redact("int", List.of(CLASS_NAME)),
					everything.redact("Class Name: int", locations), "the pattern decides for a primitive mirror");
			assertTrue(!everything.redact("Class Name: java.lang.String", locations)
					.equals("Class Name: java.lang.String"));
			assertEquals("Thread Name: com.acme.Foo", redactor.redact("Thread Name: com.acme.Foo", locations),
					"a thread named like a class");
			assertEquals("Size: 10", redactor.redact("Size: 10", locations));
		}
	}

	@Test
	void leavesEmptyThreadAndThreadGroupNamesAlone() {
		RuleRedactor redactor = RuleRedactor.builder().hashThreadNames().build();
		StringLocation flag = new StringLocation("jdk.StringFlag", "value", false, List.of());
		StringLocation group = new StringLocation("jdk.types.ThreadGroup", "name", true, List.of());
		assertEquals("", redactor.redact("", List.of(THREAD_NAME)), "unnamed virtual threads");
		assertEquals("", redactor.redact("", List.of(flag, THREAD_NAME)));
		assertEquals("", redactor.redact("", List.of(group)));
		for (StringLocation description : descriptionLocations()) {
			assertEquals("Thread Name: ", redactor.redact("Thread Name: ", List.of(description)));
			assertEquals("Thread Group: ", redactor.redact("Thread Group: ", List.of(description)));
		}
		RuleRedactor chained = RuleRedactor.builder().hashThreadNames().replace("", "<EMPTY>").build();
		assertEquals("<EMPTY>", chained.redact("", List.of(THREAD_NAME)), "later rules still apply");
	}

	@Test
	void keepsEmptyStringsWhenHashingNamesOfUnnamedVirtualThreads(@TempDir
	Path dir) throws Exception {
		Path input = dir.resolve("input.jfr");
		try (Recording recording = new Recording()) {
			recording.enable(WorkEvent.class);
			recording.start();
			Thread thread = Thread.ofVirtual().unstarted(() -> {
				WorkEvent event = new WorkEvent();
				event.description = "work";
				event.commit();
			});
			thread.start();
			thread.join();
			recording.stop();
			recording.dump(input);
		}
		assertTrue(emptyStringCount(input) > 0, "the recording must store the empty name of the thread");
		boolean[] emptyThreadName = new boolean[1];
		// An identity redaction of the input, to see the locations of the empty string
		JfrRedactor.redact(input, dir.resolve("unchanged.jfr"), (value, locations) -> {
			if (value.isEmpty()) {
				emptyThreadName[0] |= locations.stream().anyMatch(StringLocation::isThreadName);
			}
			return value;
		});
		assertTrue(emptyThreadName[0], "the unnamed virtual thread must be recorded with the empty name");
		Path output = dir.resolve("output.jfr");
		JfrRedactor.redact(input, output, RuleRedactor.builder().hashThreadNames().build());

		boolean found = false;
		for (RecordedEvent event : RecordingFile.readAllEvents(output)) {
			if (event.getEventType().getName().equals("test.Work")) {
				assertTrue(event.getThread().isVirtual());
				assertEquals("", event.getThread().getJavaName(), "the unnamed thread stays unnamed");
				found = true;
			}
		}
		assertTrue(found);
		assertEquals(emptyStringCount(input), emptyStringCount(output), "no empty string is replaced");
		// The SHA-256 of the empty string starts with e3b0c442
		assertTrue(scan(output).indexOf("Thread-e3b0c442") < 0);
	}

	@Test
	void hashesThreadGroupNames() {
		RuleRedactor redactor = RuleRedactor.builder().hashThreadNames().build();
		List<StringLocation> groups = List.of(new StringLocation("jdk.types.ThreadGroup", "name", true, List.of()),
				new StringLocation("com.oracle.jfr.types.ThreadGroup", "name", true, List.of()),
				new StringLocation("ThreadGroup", "name", true, List.of()),
				new StringLocation("jdk.types.ThreadGroup", "name", true, List.of("java.lang.Thread.group")));
		String name = "Thread Group for Queue: 'weblogic.socket.Muxer'";
		String hashed = redactor.redact(name, List.of(groups.get(0)));
		assertTrue(hashed.matches("ThreadGroup-[0-9a-f]{8}"), hashed);
		String thread = redactor.redact(name, List.of(THREAD_NAME));
		assertEquals(thread.substring("Thread-".length()), hashed.substring("ThreadGroup-".length()), "same digest");
		for (StringLocation group : groups) {
			assertTrue(group.isThreadGroupName() && !group.isThreadName(), group.toString());
			assertEquals(hashed, redactor.redact(name, List.of(group)), group.toString());
			assertEquals(thread, redactor.redact(name, List.of(group, THREAD_NAME)), "a thread name wins");
			assertEquals(thread, redactor.redact(name, List.of(THREAD_NAME, group)), "a thread name wins");
		}
		// A location in the string pool names nothing: the pool is the location only of entries no
		// field refers to, so one with referrers, as a name stored through the pool had before it
		// was located at its field, is not a group name either
		for (StringLocation other : List.of(new StringLocation("jdk.types.ThreadGroup", "name", false, List.of()),
				new StringLocation("jdk.types.ThreadGroup", "parent", true, List.of()),
				new StringLocation("java.lang.String", "value", true, List.of()),
				new StringLocation("java.lang.String", "value", true, List.of("jdk.types.ThreadGroup.name")),
				new StringLocation("java.lang.String", "value", true, List.of("jdk.types.ThreadGroup.parent")),
				CLASS_NAME)) {
			assertTrue(!other.isThreadGroupName(), other.toString());
			assertEquals(name, redactor.redact(name, List.of(other)), other.toString());
		}
		assertTrue(!THREAD_NAME.isThreadGroupName());
		for (StringLocation description : descriptionLocations()) {
			assertEquals("Thread Group: " + hashed, redactor.redact("Thread Group: " + name, List.of(description)));
		}
		// The groups the JVM creates itself name nothing of the application, unless they are also thread names
		for (String jvmGroup : List.of("system", "main")) {
			assertEquals(jvmGroup, redactor.redact(jvmGroup, List.of(groups.get(0))), jvmGroup);
			assertEquals(jvmGroup, redactor.redact(jvmGroup, List.of(groups.get(3))), jvmGroup);
			assertTrue(redactor.redact(jvmGroup, List.of(groups.get(0), THREAD_NAME)).startsWith("Thread-"), jvmGroup);
			for (StringLocation description : descriptionLocations()) {
				assertEquals("Thread Group: " + jvmGroup,
						redactor.redact("Thread Group: " + jvmGroup, List.of(description)));
			}
		}
		String keyed = RuleRedactor.builder().hashThreadNames(new byte[] {1, 2, 3}).build().redact(name,
				List.of(groups.get(0)));
		assertTrue(keyed.matches("ThreadGroup-[0-9a-f]{8}") && !keyed.equals(hashed), keyed);
	}

	/**
	 * A name the writer stored through the string pool is located at the thread or thread group
	 * field like an inline one, so the rule needs no notion of the pool, and a location in the pool
	 * itself, which only entries no field refers to have, names nothing, whatever referrers it
	 * carries
	 */
	@Test
	void hashesThreadNamesWhereverTheWriterStoredThem() {
		RuleRedactor redactor = RuleRedactor.builder().hashThreadNames().build();
		String expected = redactor.redact("SecretWorker-0", List.of(THREAD_NAME));
		for (StringLocation name : List.of(new StringLocation("java.lang.Thread", "osName", true, List.of()),
				new StringLocation("Thread", "name", true, List.of()))) {
			assertTrue(name.isThreadName(), name.toString());
			assertEquals(expected, redactor.redact("SecretWorker-0", List.of(name)), name.toString());
		}
		for (List<String> referrers : List.of(List.<String> of(), List.of("java.lang.Thread.javaName"),
				List.of("java.lang.Thread.osName"), List.of("Thread.name"), List.of("jdk.types.ThreadGroup.name"),
				List.of("com.oracle.jfr.types.ThreadGroup.name"))) {
			StringLocation pool = new StringLocation("java.lang.String", "value", true, referrers);
			assertTrue(!pool.isThreadName() && !pool.isThreadGroupName(), pool.toString());
			assertEquals("SecretWorker-0", redactor.redact("SecretWorker-0", List.of(pool)), pool.toString());
		}
		assertTrue(!new StringLocation("java.lang.Thread", "javaName", false, List.of()).isThreadName(), "inline");
	}

	/**
	 * A dump is identified by its owner and field wherever the writer stored it, inline in the
	 * event as HotSpot does or through the string pool as JMC's writer would, and is rewritten the
	 * same way; a location in the pool itself is not a dump
	 */
	@Test
	void identifiesThreadDumpsWhereverTheWriterStoredThem() {
		String dump = "\"worker\" daemon prio=6 tid=0x000000000ebd4000 nid=0x1578 waiting on condition\n";
		RuleRedactor redactor = RuleRedactor.builder().hashThreadNames().build();
		String inline = redactor.redact(dump, List.of(THREAD_DUMP));
		assertTrue(!inline.contains("\"worker\""), inline);
		for (boolean constant : new boolean[] {false, true}) {
			for (String owner : List.of("jdk.ThreadDump", "vm/runtime/thread_dump")) {
				StringLocation result = new StringLocation(owner, "result", constant, List.of());
				assertTrue(result.isThreadDump() && result.isComposite(), result.toString());
				assertEquals(inline, redactor.redact(dump, List.of(result)), result.toString());
			}
			assertTrue(!new StringLocation("jdk.ThreadDump", "startTime", constant, List.of()).isThreadDump());
		}
		StringLocation pool = new StringLocation("java.lang.String", "value", true, List.of("jdk.ThreadDump.result"));
		assertTrue(!pool.isThreadDump() && !pool.isComposite(), pool.toString());
	}

	/** The class name hashed by the redactor, in source form as it appears in thread dumps */
	private static String hashedSource(RuleRedactor redactor, String className) {
		String hashed = redactor.redact(className.replace('.', '/'), List.of(CLASS_NAME));
		assertTrue(!hashed.equals(className.replace('.', '/')), className);
		return hashed.replace('/', '.');
	}

	private static List<StringLocation> descriptionLocations() {
		return compositeLocations().stream().filter(StringLocation::isOldObjectDescription).toList();
	}

	private static long emptyStringCount(Path file) throws Exception {
		StringCountMap strings = scan(file);
		int entry = strings.indexOf("");
		return entry < 0 ? 0 : strings.getTotalCount(entry);
	}

	private static StringCountMap scan(Path file) throws Exception {
		StringScanner scanner = new StringScanner(true);
		new StreamingChunkParser().parse(file, scanner);
		return scanner.getStrings();
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
