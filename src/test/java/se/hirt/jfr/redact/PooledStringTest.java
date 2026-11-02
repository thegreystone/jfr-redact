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
import static se.hirt.jfr.redact.HandWrittenRecording.assertReadsBack;
import static se.hirt.jfr.redact.HandWrittenRecording.constant;
import static se.hirt.jfr.redact.HandWrittenRecording.pool;
import static se.hirt.jfr.redact.HandWrittenRecording.reference;
import static se.hirt.jfr.redact.HandWrittenRecording.string;
import static se.hirt.jfr.redact.HandWrittenRecording.varint;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openjdk.jmc.flightrecorder.writer.api.Type;
import org.openjdk.jmc.flightrecorder.writer.api.TypedValue;
import org.openjdk.jmc.flightrecorder.writer.api.Types;

import jdk.jfr.Event;
import jdk.jfr.Name;
import jdk.jfr.Recording;
import jdk.jfr.StackTrace;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import se.hirt.jfr.redact.parser.ChunkReader;
import se.hirt.jfr.redact.parser.ChunkTypes;
import se.hirt.jfr.redact.parser.RecordingStream;
import se.hirt.jfr.redact.parser.StreamingChunkParser;
import se.hirt.jfr.redact.scan.StringCountMap;
import se.hirt.jfr.redact.scan.StringScanner;

/**
 * The locations of strings stored in the {@code java.lang.String} constant pool: a pooled value is
 * located at the field whose value it is, as a constant, like an inline value is located at its
 * field, and only an entry no field of its chunk refers to is located at the pool itself. The pool
 * is the simple type without a field, read as its value like {@code jdk.types.Symbol} and the other
 * types the metadata declares simple, whose locations {@link SimpleTypeTest} covers.
 * <p>
 * The live recordings rely on HotSpot's Java event writer, which writes the events of
 * {@code jdk.jfr.Event} subclasses: it inlines strings of up to 16 characters, inlines a string of
 * 17 to 128 characters the first time and pools it when it is seen again while still among the four
 * most recent candidates, which is why the repeats are committed in a row (JDK 11 does the same,
 * except that the first string it ever pools, which it numbers 0, is written inline while its entry
 * sits unreferenced in the pool), and pools longer strings, up to 131071 characters, on first sight
 * from JDK 24 on and in the updates JDK-8338389 was backported to, OpenJDK 21.0.6 and 23.0.2 among
 * them, while JDKs without the fix, such as 22.0.1, inline them: the tests read off the recording
 * which the build JDK did, and hold a JDK known to have the fix to it. The layouts HotSpot never
 * writes, references from constants, dangling references, entries no field refers to, string fields
 * declared with a constant pool, a pool written before the events referring to it, a reference to
 * key 0, entries that are aliases of other entries, and names declared as String fields, are
 * written into the temporary directory with JDK Mission Control's {@code flightrecorder.writer},
 * which stores every non-empty string through the pool, by patching a live recording, or by hand;
 * the hand-written ones are read back with the JDK's parser, see
 * {@link HandWrittenRecording#readValues}, so that each is known to be valid JFR resolving to the
 * same values.
 */
class PooledStringTest {
	/**
	 * Numbers the values of the recordings: the JVM's string pool remembers what it has pooled for
	 * the life of the JVM, so a value another recording pooled is pooled from its first commit
	 */
	private static final AtomicInteger RECORDINGS = new AtomicInteger();

	@Name("test.Sql")
	@StackTrace(false)
	static class SqlEvent extends Event {
		String sql;
	}

	/**
	 * The value stored both inline and in the pool has one location for each copy, differing in
	 * {@link StringLocation#isConstant()}, and the value stored in the pool only has the constant
	 * one; neither is located at the pool, and a rule on the event's field reaches both
	 */
	@Test
	void locatesPooledEventValuesAtTheirField(@TempDir
	Path dir) throws Exception {
		// 40 characters, inlined the first time and pooled from the second sighting on, and 300
		// characters, pooled on first sight by the JDKs with JDK-8338389 and inlined by the others:
		// the recording tells which the build JDK did, and a JDK known to have the fix must have pooled
		String repeated = unique("select ssn from patients where id = ", 40);
		String longValue = unique("select diagnosis from patients where ssn = ", 300);
		Path input = record(dir.resolve("input.jfr"), repeated, longValue);
		// What the writer did, counted independently of the locations
		StringCountMap strings = scan(input).getStrings();
		int entry = strings.indexOf(repeated);
		assertTrue(entry >= 0, "the recording stores the repeated value");
		assertEquals(1, strings.getCount(entry, StringScanner.INLINE), "the first sighting is inlined");
		assertEquals(1, strings.getCount(entry, StringScanner.CONSTANT_POOL), "the second sighting pools the value");
		assertEquals(4, strings.getReferenceCount(entry), "the later sightings refer to the pool");
		int longEntry = strings.indexOf(longValue);
		assertTrue(longEntry >= 0, "the recording stores the long value");
		long pooledLong = strings.getCount(longEntry, StringScanner.CONSTANT_POOL);
		assertEquals(1, pooledLong + strings.getCount(longEntry, StringScanner.INLINE),
				"the long value is stored once, in the pool or inline");
		boolean poolsOnFirstSight = pooledLong == 1;
		if (poolsLongStringsOnFirstSight(Runtime.version())) {
			assertTrue(poolsOnFirstSight, "JDK " + Runtime.version() + " pools a long string on first sight");
		}
		List<Long> referenceKeys = stringFieldReferenceKeys(input, "test.Sql", "sql");
		assertEquals(6, referenceKeys.size(), "one storage choice per event");

		Map<String, List<StringLocation>> locations = locationsOf(input, dir.resolve("unchanged.jfr"),
				Set.of(repeated, longValue));
		assertEquals(List.of("test.Sql.sql (constant)", "test.Sql.sql (inline)"), sorted(locations.get(repeated)),
				"one location per copy, none at the pool");
		assertEquals(List.of(poolsOnFirstSight ? "test.Sql.sql (constant)" : "test.Sql.sql (inline)"),
				sorted(locations.get(longValue)));

		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output,
				RuleRedactor.builder()
						.replaceIf(
								location -> location.getOwner().equals("test.Sql") && location.getField().equals("sql"),
								value -> "<SQL>")
						.build());
		assertEquals(2, result.redactedStringCount(), "the repeated and the long value");
		StringCountMap after = scan(output).getStrings();
		int replacement = after.indexOf("<SQL>");
		assertTrue(replacement >= 0, "the recording stores the replacement");
		for (int category : new int[] {StringScanner.INLINE, StringScanner.CONSTANT_POOL}) {
			assertEquals(strings.getCount(entry, category) + strings.getCount(longEntry, category),
					after.getCount(replacement, category),
					"the replacement retains stored occurrences in category " + category);
		}
		assertEquals(strings.getReferenceCount(entry) + strings.getReferenceCount(longEntry),
				after.getReferenceCount(replacement),
				"pool references retain their counts when replacement values merge");
		assertEquals(referenceKeys, stringFieldReferenceKeys(output, "test.Sql", "sql"),
				"each event retains its inline value or reference to the same pool key");
		List<RecordedEvent> events = RecordingFile.readAllEvents(output).stream()
				.filter(event -> event.getEventType().getName().equals("test.Sql")).toList();
		assertEquals(6, events.size());
		for (RecordedEvent event : events) {
			assertEquals("<SQL>", event.getString("sql"));
		}
		TestRecordings.assertAbsent(output, repeated, longValue);
	}

	/**
	 * A reference to an entry the chunk does not hold, as a lost buffer leaves behind, locates
	 * nothing and breaks nothing, and the entry it pointed to, located at the event's field while
	 * the references held, is located at the pool once nothing refers to it, beside the inline copy
	 * at its field. HotSpot writes no dangling references, so the entry of the live recording is
	 * given a key nothing refers to.
	 */
	@Test
	void locatesAnEntryWhoseReferencesDangleAtThePool(@TempDir
	Path dir) throws Exception {
		String repeated = unique("select ssn from patients where id = ", 40);
		Path input = record(dir.resolve("input.jfr"), repeated, null);
		assertEquals(List.of("test.Sql.sql (constant)", "test.Sql.sql (inline)"),
				sorted(locationsOf(input, dir.resolve("intact.jfr"), Set.of(repeated)).get(repeated)),
				"while the references hold, the entry is located at the field");
		renameStringPoolEntry(input, repeated);
		assertEquals(4, scan(input).getUnresolvedReferenceCount(), "the references to the renamed entry dangle");
		Map<String, List<StringLocation>> locations = locationsOf(input, dir.resolve("unchanged.jfr"),
				Set.of(repeated));
		assertEquals(List.of("java.lang.String.value (constant)", "test.Sql.sql (inline)"),
				sorted(locations.get(repeated)));

		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output, RuleRedactor.builder()
				.replaceIf(location -> location.getOwner().equals("java.lang.String"), value -> "<POOLED>").build());
		assertEquals(1, result.redactedStringCount());
		TestRecordings.assertAbsent(output, repeated);
		StringScanner after = scan(output);
		assertTrue(after.getStrings().indexOf("<POOLED>") >= 0);
		assertEquals(4, after.getUnresolvedReferenceCount(), "the dangling references are copied as they are");
	}

	/**
	 * One entry of the pool referred to by the fields of two event types and by the field of a
	 * constant has the three locations, each as an inline value of the field would, and a rule on
	 * any of them replaces the value wherever it is read from
	 */
	@Test
	void locatesAPooledStringAtEveryFieldWhoseValueItIs(@TempDir
	Path dir) throws Exception {
		String shared = "shared pooled value for account 4711";
		Path input = JmcWriterRecording.write(dir.resolve("input.jfr"), recording -> {
			Type first = recording.registerEventType("test.First", b -> b.addField("value", Types.Builtin.STRING));
			Type second = recording.registerEventType("test.Second", b -> b.addField("value", Types.Builtin.STRING));
			TypedValue thread = JmcWriterRecording.thread(recording, shared);
			recording.writeEvent(first.asValue(
					b -> b.putField("startTime", 1L).putField("eventThread", thread).putField("value", shared)));
			recording.writeEvent(second.asValue(
					b -> b.putField("startTime", 2L).putField("eventThread", thread).putField("value", shared)));
		});
		StringCountMap strings = scan(input).getStrings();
		int entry = strings.indexOf(shared);
		assertTrue(entry >= 0, "the recording stores the value");
		assertEquals(0, strings.getCount(entry, StringScanner.INLINE), "the writer stores nothing inline");
		assertEquals(1, strings.getCount(entry, StringScanner.CONSTANT_POOL), "one entry holds the value");
		assertEquals(3, strings.getReferenceCount(entry), "the two events and the thread's constant refer to it");

		List<StringLocation> locations = locationsOf(input, dir.resolve("unchanged.jfr"), Set.of(shared)).get(shared);
		assertEquals(List.of("java.lang.Thread.javaName (constant)", "test.First.value (constant)",
				"test.Second.value (constant)"), sorted(locations));
		assertTrue(locations.stream().anyMatch(StringLocation::isThreadName), locations.toString());

		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output, RuleRedactor.builder()
				.replaceIf(location -> location.getOwner().equals("test.Second"), value -> "<X>").build());
		assertEquals(1, result.redactedStringCount());
		TestRecordings.assertAbsent(output, shared);
		List<RecordedEvent> events = RecordingFile.readAllEvents(output);
		assertEquals(2, events.size());
		for (RecordedEvent event : events) {
			assertEquals("<X>", event.getString("value"), event.getEventType().getName());
			assertEquals("<X>", event.getThread().getJavaName(), "the decision applies to every copy");
		}
		assertEquals(List.of(), JmcModel.load(output).problems());
	}

	/**
	 * A reference to a key no entry of the chunk has locates nothing and breaks nothing, while the
	 * entry it pointed to, referred to by nothing else, is located at the pool. The writer's
	 * reference is pointed at an unused key.
	 */
	@Test
	void dropsDanglingReferences(@TempDir
	Path dir) throws Exception {
		String dangled = "value whose reference will dangle";
		String intact = "value whose reference stays intact";
		Path input = JmcWriterRecording.write(dir.resolve("input.jfr"), recording -> {
			Type type = recording.registerEventType("test.Dangling", b -> b.addField("value", Types.Builtin.STRING));
			recording.writeEvent(type.asValue(b -> b.putField("startTime", 1L).putField("value", dangled)));
			recording.writeEvent(type.asValue(b -> b.putField("startTime", 2L).putField("value", intact)));
		});
		List<Integer> offsets = stringFieldOffsets(input, "test.Dangling", "value");
		assertEquals(2, offsets.size());
		byte[] bytes = Files.readAllBytes(input);
		assertEquals(2, bytes[offsets.get(0)], "the writer stores the value through the pool");
		// Point the first reference to a key no entry has, in as many bytes as the original key
		int keyStart = offsets.get(0) + 1;
		int width = varintWidth(bytes, keyStart);
		long unresolvedBefore = scan(input).getUnresolvedReferenceCount();
		Path dangling = dir.resolve("dangling.jfr");
		long candidate = (1L << (7 * width)) - 1;
		for (int attempt = 0;; attempt++, candidate--) {
			assertTrue(attempt < 100, "no unused key of " + width + " bytes");
			byte[] patched = bytes.clone();
			writeVarint(patched, keyStart, candidate, width);
			Files.write(dangling, patched);
			StringScanner after = scan(dangling);
			if (after.getUnresolvedReferenceCount() == unresolvedBefore + 1) {
				break;
			}
		}

		Map<String, List<StringLocation>> locations = locationsOf(dangling, dir.resolve("unchanged.jfr"),
				Set.of(dangled, intact));
		assertEquals(List.of("test.Dangling.value (constant)"), sorted(locations.get(intact)));
		assertEquals(List.of("java.lang.String.value (constant)"), sorted(locations.get(dangled)),
				"referred to by nothing, the entry is located at the pool");

		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(dangling, output,
				RuleRedactor.builder().replaceIf(location -> location.getOwner().equals("java.lang.String"),
						value -> value.equals(dangled) ? "<X>" : value).build());
		assertEquals(1, result.redactedStringCount());
		TestRecordings.assertAbsent(output, dangled);
		assertEquals(unresolvedBefore + 1, scan(output).getUnresolvedReferenceCount(),
				"the reference is left as it is");
	}

	/**
	 * An entry no field refers to is located at the pool, with no referrers, and nowhere else. The
	 * links are resolved per chunk: appended to a recording in which it is a value of a field, the
	 * recording is a second chunk, and the string is located wherever any chunk stores it.
	 */
	@Test
	void locatesAnEntryNoFieldRefersToAtThePool(@TempDir
	Path dir) throws Exception {
		String orphan = "orphan pooled value for account 4711";
		String referenced = "referenced pooled value for account 4711";
		Path first = JmcWriterRecording.write(dir.resolve("first.jfr"), recording -> {
			Type type = recording.registerEventType("test.First", b -> b.addField("value", Types.Builtin.STRING));
			recording.getTypes().getType(Types.Builtin.STRING).asValue(orphan);
			recording.writeEvent(type.asValue(b -> b.putField("startTime", 1L).putField("value", referenced)));
		});
		StringCountMap strings = scan(first).getStrings();
		int entry = strings.indexOf(orphan);
		assertTrue(entry >= 0, "the writer stores the orphan");
		assertEquals(1, strings.getCount(entry, StringScanner.CONSTANT_POOL));
		assertEquals(0, strings.getReferenceCount(entry), "nothing refers to the orphan");
		Map<String, List<StringLocation>> locations = locationsOf(first, dir.resolve("unchanged.jfr"),
				Set.of(orphan, referenced));
		assertEquals(List.of("java.lang.String.value (constant)"), sorted(locations.get(orphan)));
		assertEquals(List.of("test.First.value (constant)"), sorted(locations.get(referenced)));

		Path second = JmcWriterRecording.write(dir.resolve("second.jfr"), recording -> {
			Type type = recording.registerEventType("test.Second", b -> b.addField("value", Types.Builtin.STRING));
			recording.getTypes().getType(Types.Builtin.STRING).asValue(referenced);
			recording.writeEvent(type.asValue(b -> b.putField("startTime", 1L).putField("value", orphan)));
		});
		Path both = JmcWriterRecording.concatenate(dir.resolve("both.jfr"), first, second);
		locations = locationsOf(both, dir.resolve("both-unchanged.jfr"), Set.of(orphan, referenced));
		assertEquals(List.of("java.lang.String.value (constant)", "test.Second.value (constant)"),
				sorted(locations.get(orphan)));
		assertEquals(List.of("java.lang.String.value (constant)", "test.First.value (constant)"),
				sorted(locations.get(referenced)));

		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(both, output,
				RuleRedactor.builder().replaceIf(location -> location.getOwner().equals("java.lang.String"),
						value -> value.equals(orphan) ? "<X>" : value).build());
		assertEquals(1, result.redactedStringCount());
		assertEquals(2, result.chunkCount());
		assertEquals(2, result.rewrittenChunkCount(), "the entry is replaced in both chunks");
		TestRecordings.assertAbsent(output, orphan);
		// Counted rather than read: the JDK's parser resolves the pooled values of the second chunk
		// through the first chunk's entries when the keys repeat, as the writer's do and HotSpot's
		// never do
		strings = scan(output).getStrings();
		assertEquals(2, strings.getCount(strings.indexOf("<X>"), StringScanner.CONSTANT_POOL),
				"the replacement is in the pool of both chunks");
		assertEquals(2, RecordingFile.readAllEvents(output).size());
	}

	/**
	 * A string field declared with a constant pool stores keys into the string pool rather than
	 * strings with the reference encoding: a layout no known writer produces, but one the metadata
	 * allows and the JDK's parser reads. Its values are located at the field all the same, in
	 * events and in constants alike, with the referrers of the constant holding it, and never at
	 * the pool; an event whose only string field is declared so holds no string inline and is
	 * walked for its keys. The constant of a type holding nothing but a key, which the metadata
	 * does not declare simple, is an entity nothing refers to, so its value is located without
	 * referrers.
	 */
	@Test
	void locatesTheValuesOfStringFieldsDeclaredWithAConstantPoolAtTheField(@TempDir
	Path dir) throws Exception {
		String label = "label stored as a key into the string pool";
		String note = "note stored inline in the same constant";
		String keyed = "value of a constant storing no string inline";
		String text = "value of an event stored with the reference encoding";
		String tag = "value of an event stored as a key into the string pool";
		String only = "value of an event whose only string field is declared with a constant pool";
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declare(100, "test.Pooled", "label:20:pool", "note:20");
		recording.declare(101, "test.Outer", "inner:100:pool");
		recording.declare(102, "test.Keyed", "key:20:pool");
		recording.declareEvent(103, "test.Evt", "outer:101:pool", "keyed:102:pool", "text:20", "tag:20:pool");
		recording.declareEvent(104, "test.KeyedOnly", "tag:20:pool");
		recording.event(103, varint(1), varint(1), reference(3), varint(4));
		recording.event(104, varint(5));
		recording.checkpoint(
				pool(20, constant(1, string(label)), constant(2, string(keyed)), constant(3, string(text)),
						constant(4, string(tag)), constant(5, string(only))),
				pool(100, constant(1, varint(1), string(note))), pool(101, constant(1, varint(1))),
				pool(102, constant(1, varint(2))));
		Path input = recording.write(dir.resolve("input.jfr"));
		assertReadsBack(input, "test.Evt", "outer.inner.label", label);
		assertReadsBack(input, "test.Evt", "outer.inner.note", note);
		assertReadsBack(input, "test.Evt", "keyed.key", keyed);
		assertReadsBack(input, "test.Evt", "text", text);
		assertReadsBack(input, "test.Evt", "tag", tag);
		assertReadsBack(input, "test.KeyedOnly", "tag", only);
		StringCountMap strings = scan(input).getStrings();
		assertEquals(1, strings.getReferenceCount(strings.indexOf(label)), "the constant refers to the label");
		assertEquals(1, strings.getReferenceCount(strings.indexOf(text)), "the event refers to the text");
		assertEquals(1, strings.getReferenceCount(strings.indexOf(tag)), "the event refers to the tag by its key");
		assertEquals(1, strings.getReferenceCount(strings.indexOf(only)), "the keyed event refers to its value");

		Map<String, List<StringLocation>> locations = locationsOf(input, dir.resolve("unchanged.jfr"),
				Set.of(label, note, keyed, text, tag, only));
		assertEquals(List.of("test.Pooled.label (constant) referred to by test.Outer.inner"),
				sorted(locations.get(label)), "a key into the string pool, like a reference");
		assertEquals(List.of("test.Pooled.note (constant) referred to by test.Outer.inner"),
				sorted(locations.get(note)), "inline in the same constant");
		assertEquals(List.of("test.Keyed.key (constant)"), sorted(locations.get(keyed)),
				"a constant of a type storing no string inline, which nothing refers to");
		assertEquals(List.of("test.Evt.text (constant)"), sorted(locations.get(text)));
		assertEquals(List.of("test.Evt.tag (constant)"), sorted(locations.get(tag)),
				"a key in an event, like a reference");
		assertEquals(List.of("test.KeyedOnly.tag (constant)"), sorted(locations.get(only)),
				"an event storing no string inline, walked for its keys");

		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output, RuleRedactor.builder()
				.replaceIf(location -> location.getOwner().startsWith("test."), value -> "<X>").build());
		assertEquals(6, result.redactedStringCount());
		TestRecordings.assertAbsent(output, label, note, keyed, text, tag, only);
		strings = scan(output).getStrings();
		assertEquals(6, strings.getCount(strings.indexOf("<X>"), StringScanner.CONSTANT_POOL),
				"the five entries of the string pool and the inline note");
		assertReadsBack(output, "test.Evt", "outer.inner.label", "<X>");
		assertReadsBack(output, "test.Evt", "tag", "<X>");
		assertReadsBack(output, "test.KeyedOnly", "tag", "<X>");
	}

	/**
	 * The entry and the fields referring to it arrive in either order: the entry after them, in the
	 * checkpoint ending the chunk, as HotSpot writes it, or before them, in a chunk with flushes.
	 * The links are resolved at chunk end, so the locations are the same, with the referrers of the
	 * constants, which arrive last as well, and the entry is replaced wherever its checkpoint is.
	 * The JDK's parser reads the checkpoints from the last one back through their deltas, so it
	 * resolves the value in both orders too.
	 */
	@Test
	void locatesPooledValuesWhicheverOrderTheEntryAndItsReferencesArriveIn(@TempDir
	Path dir) throws Exception {
		String pooled = "value referred to by an event and by a constant";
		List<String> expected = List.of("test.Evt.text (constant)",
				"test.Holder.name (constant) referred to by test.Outer.inner");
		for (boolean entryFirst : new boolean[] {false, true}) {
			String order = entryFirst ? "entry-first" : "entry-last";
			HandWrittenRecording recording = new HandWrittenRecording();
			recording.declareEvent(100, "test.Evt", "text:20");
			recording.declare(101, "test.Holder", "name:20");
			recording.declare(102, "test.Outer", "inner:101:pool");
			recording.declareEvent(103, "test.Evt2", "outer:102:pool");
			byte[] entry = pool(20, constant(1, string(pooled)));
			if (entryFirst) {
				recording.checkpoint(entry);
			}
			recording.event(100, reference(1));
			recording.event(103, varint(1));
			recording.checkpoint(pool(101, constant(1, reference(1))), pool(102, constant(1, varint(1))));
			if (!entryFirst) {
				recording.checkpoint(entry);
			}
			Path input = recording.write(dir.resolve(order + ".jfr"));
			assertReadsBack(input, "test.Evt", "text", pooled);
			assertReadsBack(input, "test.Evt2", "outer.inner.name", pooled);
			assertEquals(expected,
					sorted(locationsOf(input, dir.resolve(order + "-unchanged.jfr"), Set.of(pooled)).get(pooled)),
					order);

			Path output = dir.resolve(order + "-output.jfr");
			RedactionResult result = JfrRedactor.redact(input, output, RuleRedactor.builder()
					.replaceIf(location -> location.getOwner().equals("test.Holder"), value -> "<X>").build());
			assertEquals(1, result.redactedStringCount(), order);
			assertEquals(entryFirst ? 2 : 1, result.rewrittenCheckpointCount(), order
					+ ": the checkpoint holding the entry, and the one after it, whose delta to the resized one is patched");
			TestRecordings.assertAbsent(output, pooled);
			StringCountMap strings = scan(output).getStrings();
			assertEquals(1, strings.getCount(strings.indexOf("<X>"), StringScanner.CONSTANT_POOL), order);
			assertReadsBack(output, "test.Evt", "text", "<X>");
			assertReadsBack(output, "test.Evt2", "outer.inner.name", "<X>");
		}
	}

	/**
	 * A reference to key 0 is taken as null, as the scanner takes it, since no known writer refers
	 * to key 0: HotSpot numbers the entries of its string pool from 1 and inlines a string whose
	 * number is not positive, and JMC's writer numbers from 1 as well. An entry with key 0, which
	 * the JDK 11 writer emits without referring to it, is located at the pool. The JDK's parser,
	 * for its part, resolves a reference to key 0 like any other when the pool has such an entry,
	 * as the read-back shows.
	 */
	@Test
	void takesAReferenceToKeyZeroAsNull(@TempDir
	Path dir) throws Exception {
		String zero = "value of the entry with key zero";
		String one = "value of the entry with key one";
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declareEvent(100, "test.Evt", "text:20");
		recording.declare(101, "test.Holder", "name:20");
		recording.event(100, reference(0));
		recording.event(100, reference(1));
		recording.checkpoint(pool(20, constant(0, string(zero)), constant(1, string(one))),
				pool(101, constant(1, reference(0))));
		Path input = recording.write(dir.resolve("input.jfr"));
		assertReadsBack(input, "test.Evt", "text", zero, one);
		StringCountMap strings = scan(input).getStrings();
		assertEquals(0, strings.getReferenceCount(strings.indexOf(zero)), "the scanner counts no reference to key 0");
		assertEquals(1, strings.getReferenceCount(strings.indexOf(one)));
		Map<String, List<StringLocation>> locations = locationsOf(input, dir.resolve("unchanged.jfr"),
				Set.of(zero, one));
		assertEquals(List.of("java.lang.String.value (constant)"), sorted(locations.get(zero)),
				"referred to by key 0 only, the entry is located at the pool");
		assertEquals(List.of("test.Evt.text (constant)"), sorted(locations.get(one)));
	}

	/**
	 * A holder storing nothing but keys into the string pool stores no string itself, so its values
	 * are located at its fields without referrers, like the name of a class, whose string is a
	 * symbol's, although another constant refers to the holder; a holder storing a string inline as
	 * well has the referrer for both its values, the inline and the keyed one, see
	 * {@link StringLocation#getReferrers()}. The JDK reads both holders alike, through the constant
	 * referring to them.
	 */
	@Test
	void givesReferrersOnlyToTheHoldersStoringStringsThemselves(@TempDir
	Path dir) throws Exception {
		String keyedOnly = "value of a holder storing nothing but keys";
		String mixedKey = "keyed value of a holder storing a string inline too";
		String mixedNote = "inline value of the same holder";
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declare(100, "test.KeyedHolder", "tag:20:pool");
		recording.declare(101, "test.MixedHolder", "tag:20:pool", "note:20");
		recording.declare(102, "test.Outer", "keyed:100:pool", "mixed:101:pool");
		recording.declareEvent(103, "test.Evt", "outer:102:pool");
		recording.event(103, varint(1));
		recording.checkpoint(pool(20, constant(1, string(keyedOnly)), constant(2, string(mixedKey))),
				pool(100, constant(1, varint(1))), pool(101, constant(1, varint(2), string(mixedNote))),
				pool(102, constant(1, varint(1), varint(1))));
		Path input = recording.write(dir.resolve("input.jfr"));
		assertReadsBack(input, "test.Evt", "outer.keyed.tag", keyedOnly);
		assertReadsBack(input, "test.Evt", "outer.mixed.tag", mixedKey);
		assertReadsBack(input, "test.Evt", "outer.mixed.note", mixedNote);
		Map<String, List<StringLocation>> locations = locationsOf(input, dir.resolve("unchanged.jfr"),
				Set.of(keyedOnly, mixedKey, mixedNote));
		assertEquals(List.of("test.KeyedHolder.tag (constant)"), sorted(locations.get(keyedOnly)),
				"the holder stores no string itself: no referrers, although the outer constant refers to it");
		assertEquals(List.of("test.MixedHolder.tag (constant) referred to by test.Outer.mixed"),
				sorted(locations.get(mixedKey)),
				"the holder stores a string inline, so both its values have the referrer");
		assertEquals(List.of("test.MixedHolder.note (constant) referred to by test.Outer.mixed"),
				sorted(locations.get(mixedNote)));

		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output, RuleRedactor.builder()
				.replaceIf(location -> location.getOwner().equals("test.KeyedHolder"), value -> "<X>").build());
		assertEquals(1, result.redactedStringCount());
		TestRecordings.assertAbsent(output, keyedOnly);
		assertReadsBack(output, "test.Evt", "outer.keyed.tag", "<X>");
		assertReadsBack(output, "test.Evt", "outer.mixed.tag", mixedKey);
	}

	/**
	 * An entry of the pool may itself refer to another entry, with the reference encoding, an alias
	 * the JDK's parser resolves: the string at the end of a chain of aliases, of any length, is a
	 * value of the field referring to the first alias, from an event or from a constant, with the
	 * constant's referrers, and is located there. Aliases referring to each other in a cycle, an
	 * alias referring to itself and an alias referring to a key no entry has hold no string, so
	 * they locate nothing, and the JDK resolves them to nothing as well.
	 */
	@Test
	void locatesTheStringBehindAliasesOfThePoolAtTheReferringField(@TempDir
	Path dir) throws Exception {
		String secret = "Secret behind two aliases of the pool";
		String deep = "Secret behind twenty aliases of the pool";
		String held = "Secret behind an alias, held by a constant";
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declareEvent(100, "test.Evt", "text:20", "deep:20", "cyclic:20", "dangling:20");
		recording.declare(101, "test.Holder", "name:20");
		recording.declare(102, "test.Outer", "inner:101:pool");
		recording.declareEvent(103, "test.Evt2", "outer:102:pool");
		recording.event(100, reference(3), reference(30), reference(40), reference(50));
		recording.event(103, varint(1));
		List<byte[]> entries = new ArrayList<>(
				List.of(constant(1, string(secret)), constant(2, reference(1)), constant(3, reference(2)),
						constant(4, string(held)), constant(5, reference(4)), constant(10, string(deep))));
		for (int key = 11; key <= 30; key++) {
			entries.add(constant(key, reference(key - 1)));
		}
		entries.addAll(List.of(constant(40, reference(41)), constant(41, reference(40)), constant(42, reference(42)),
				constant(50, reference(99))));
		recording.checkpoint(pool(20, entries.toArray(new byte[0][])), pool(101, constant(1, reference(5))),
				pool(102, constant(1, varint(1))));
		Path input = recording.write(dir.resolve("input.jfr"));
		assertReadsBack(input, "test.Evt", "text", secret);
		assertReadsBack(input, "test.Evt", "deep", deep);
		assertReadsBack(input, "test.Evt", "cyclic", (String) null);
		assertReadsBack(input, "test.Evt", "dangling", (String) null);
		assertReadsBack(input, "test.Evt2", "outer.inner.name", held);
		Map<String, List<StringLocation>> all = new TreeMap<>();
		JfrRedactor.redact(input, dir.resolve("unchanged.jfr"), (value, locations) -> {
			all.put(value, locations);
			return value;
		});
		assertEquals(Set.of(secret, deep, held), all.keySet(), "the aliases hold no strings of their own");
		assertEquals(List.of("test.Evt.text (constant)"), sorted(all.get(secret)), "through two aliases");
		assertEquals(List.of("test.Evt.deep (constant)"), sorted(all.get(deep)), "through twenty aliases");
		assertEquals(List.of("test.Holder.name (constant) referred to by test.Outer.inner"), sorted(all.get(held)),
				"through an alias, from a constant storing strings, with its referrers");

		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output, RuleRedactor.builder()
				.replaceIf(location -> location.getOwner().equals("test.Evt"), value -> "<X>").build());
		assertEquals(2, result.redactedStringCount());
		TestRecordings.assertAbsent(output, secret, deep);
		assertReadsBack(output, "test.Evt", "text", "<X>");
		assertReadsBack(output, "test.Evt", "deep", "<X>");
		assertReadsBack(output, "test.Evt2", "outer.inner.name", held);
	}

	/**
	 * A writer may declare the name of a class, a method, a package or a module as a String field
	 * rather than as a reference to a symbol, and store the value inline in the constant or through
	 * the string pool: both are the value of the same field, located there with the referrers of
	 * the constant, which stores strings itself, so the predicates classify both and the rules on
	 * class, method and package names reach both copies. JMC's writer predefines
	 * {@code java.lang.Class} with a symbol, so the layout is written by hand.
	 */
	@Test
	void classifiesTheNamesOfStringTypedFieldsInlineAndThroughThePool(@TempDir
	Path dir) throws Exception {
		String inlineClass = "com/acme/SecretService";
		String pooledClass = "com/acme/pooled/PooledService";
		String inlineMethod = "processRecord";
		String pooledMethod = "pooledRecord";
		String inlineDescriptor = "(Ljava/lang/String;)V";
		String pooledDescriptor = "(Lcom/acme/pooled/PooledService;)V";
		String inlinePackage = "com/acme";
		String pooledPackage = "com/acme/pooled";
		String inlineModule = "acme.module";
		String pooledModule = "acme.pooled";
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declare(100, "jdk.types.Module", "name:20", "version:20");
		recording.declare(101, "jdk.types.Package", "name:20", "module:100:pool");
		recording.declare(102, "java.lang.Class", "package:101:pool", "name:20", "modifiers:1");
		recording.declare(103, "jdk.types.Method", "type:102:pool", "name:20", "descriptor:20");
		recording.declareEvent(104, "test.Load", "clazz:102:pool", "method:103:pool");
		recording.event(104, varint(1), varint(1));
		recording.event(104, varint(2), varint(2));
		recording.checkpoint(
				pool(20, constant(1, string(pooledClass)), constant(2, string(pooledMethod)),
						constant(3, string(pooledDescriptor)), constant(4, string(pooledPackage)),
						constant(5, string(pooledModule))),
				pool(100, constant(1, string(inlineModule), string("1.0")), constant(2, reference(5), string("2.0"))),
				pool(101, constant(1, string(inlinePackage), varint(1)), constant(2, reference(4), varint(2))),
				pool(102, constant(1, varint(1), string(inlineClass), varint(1)),
						constant(2, varint(2), reference(1), varint(1))),
				pool(103, constant(1, varint(1), string(inlineMethod), string(inlineDescriptor)),
						constant(2, varint(2), reference(2), reference(3))));
		Path input = recording.write(dir.resolve("input.jfr"));
		assertReadsBack(input, "test.Load", "clazz.name", inlineClass, pooledClass);
		assertReadsBack(input, "test.Load", "method.name", inlineMethod, pooledMethod);
		assertReadsBack(input, "test.Load", "method.descriptor", inlineDescriptor, pooledDescriptor);
		assertReadsBack(input, "test.Load", "clazz.package.name", inlinePackage, pooledPackage);
		assertReadsBack(input, "test.Load", "clazz.package.module.name", inlineModule, pooledModule);
		Map<String, List<StringLocation>> locations = locationsOf(input, dir.resolve("unchanged.jfr"),
				Set.of(inlineClass, pooledClass, inlineMethod, pooledMethod, inlineDescriptor, pooledDescriptor,
						inlinePackage, pooledPackage, inlineModule, pooledModule, "1.0", "2.0"));
		for (String name : List.of(inlineClass, pooledClass)) {
			assertEquals(List.of("java.lang.Class.name (constant) referred to by jdk.types.Method.type"),
					sorted(locations.get(name)), name);
			assertClassified(locations.get(name), "class", name);
		}
		for (String name : List.of(inlineMethod, pooledMethod)) {
			assertEquals(List.of("jdk.types.Method.name (constant)"), sorted(locations.get(name)), name);
			assertClassified(locations.get(name), "method", name);
		}
		for (String name : List.of(inlineDescriptor, pooledDescriptor)) {
			assertEquals(List.of("jdk.types.Method.descriptor (constant)"), sorted(locations.get(name)), name);
			assertClassified(locations.get(name), "descriptor", name);
		}
		for (String name : List.of(inlinePackage, pooledPackage)) {
			assertEquals(List.of("jdk.types.Package.name (constant) referred to by java.lang.Class.package"),
					sorted(locations.get(name)), name);
			assertClassified(locations.get(name), "package", name);
		}
		for (String name : List.of(inlineModule, pooledModule)) {
			assertEquals(List.of("jdk.types.Module.name (constant) referred to by jdk.types.Package.module"),
					sorted(locations.get(name)), name);
			assertClassified(locations.get(name), "module", name);
		}
		for (String version : List.of("1.0", "2.0")) {
			assertEquals(List.of("jdk.types.Module.version (constant) referred to by jdk.types.Package.module"),
					sorted(locations.get(version)), version);
			assertClassified(locations.get(version), "", version);
		}

		Path hashed = dir.resolve("hashed.jfr");
		RuleRedactor hashing = RuleRedactor.builder().hashClassNames("com\\.acme\\.(.*)").hashMethodNames("(.*)")
				.build();
		JfrRedactor.redact(input, hashed, hashing);
		TestRecordings.assertAbsent(hashed, "SecretService", "PooledService", inlineMethod, pooledMethod);
		assertReadsBack(hashed, "test.Load", "clazz.name", hashing.redact(inlineClass, locations.get(inlineClass)),
				hashing.redact(pooledClass, locations.get(pooledClass)));
		assertReadsBack(hashed, "test.Load", "method.name", hashing.redact(inlineMethod, locations.get(inlineMethod)),
				hashing.redact(pooledMethod, locations.get(pooledMethod)));
		assertReadsBack(hashed, "test.Load", "method.descriptor", inlineDescriptor,
				hashing.redact(pooledDescriptor, locations.get(pooledDescriptor)));
		assertReadsBack(hashed, "test.Load", "clazz.package.name", inlinePackage,
				hashing.redact(pooledPackage, locations.get(pooledPackage)));
		assertEquals(List.of(), RedactionVerifier.checkClassPackageInvariant(hashed),
				"every hashed class keeps starting with its hashed package");

		Path renamed = dir.resolve("renamed.jfr");
		JfrRedactor.redact(input, renamed, RuleRedactor.builder().renamePackage("com.acme", "org.example").build());
		assertReadsBack(renamed, "test.Load", "clazz.name", "org/example/SecretService",
				"org/example/pooled/PooledService");
		assertReadsBack(renamed, "test.Load", "method.descriptor", inlineDescriptor,
				"(Lorg/example/pooled/PooledService;)V");
		assertReadsBack(renamed, "test.Load", "clazz.package.name", "org/example", "org/example/pooled");
		assertReadsBack(renamed, "test.Load", "clazz.package.module.name", inlineModule, pooledModule);
	}

	/**
	 * Asserts that every location of the string is classified as the kind of name given, one of
	 * class, method, descriptor, package and module, and as no other, or as none for an empty kind
	 */
	private static void assertClassified(List<StringLocation> locations, String kind, String value) {
		for (StringLocation location : locations) {
			Set<String> kinds = new TreeSet<>();
			if (location.isClassName()) {
				kinds.add("class");
			}
			if (location.isMethodName()) {
				kinds.add("method");
			}
			if (location.isMethodDescriptor()) {
				kinds.add("descriptor");
			}
			if (location.isPackageName()) {
				kinds.add("package");
			}
			if (location.isModuleName()) {
				kinds.add("module");
			}
			assertEquals(kind.isEmpty() ? Set.of() : Set.of(kind), kinds, value + " at " + location);
		}
	}

	/**
	 * Whether the JDK pools strings of more than 128 characters on first sight: JDK 24 and later,
	 * and the OpenJDK updates JDK-8338389 was backported to, 21.0.6 and 23.0.2
	 */
	private static boolean poolsLongStringsOnFirstSight(Runtime.Version version) {
		return version.feature() >= 24 || (version.feature() == 21 && version.update() >= 6)
				|| (version.feature() == 23 && version.update() >= 2);
	}

	/** Records the repeated value five times in a row, then the other value once, if any */
	private static Path record(Path file, String repeated, String once) throws IOException {
		try (Recording recording = new Recording()) {
			recording.enable(SqlEvent.class);
			recording.start();
			for (int i = 0; i < 5; i++) {
				commit(repeated);
			}
			if (once != null) {
				commit(once);
			}
			recording.stop();
			recording.dump(file);
		}
		return file;
	}

	private static void commit(String sql) {
		SqlEvent event = new SqlEvent();
		event.sql = sql;
		event.commit();
	}

	/**
	 * A value of the length, starting with the prefix, that no other recording of this JVM commits
	 */
	private static String unique(String prefix, int length) {
		StringBuilder value = new StringBuilder(prefix).append(RECORDINGS.incrementAndGet());
		assertTrue(value.length() <= length, "the prefix leaves room for the number");
		while (value.length() < length) {
			value.append('x');
		}
		return value.toString();
	}

	/** The locations of the values, which the recording must all store */
	private static Map<String, List<StringLocation>> locationsOf(Path input, Path output, Set<String> values)
			throws IOException {
		Map<String, List<StringLocation>> found = new TreeMap<>();
		JfrRedactor.redact(input, output, (value, locations) -> {
			if (values.contains(value)) {
				found.put(value, locations);
			}
			return value;
		});
		for (String value : values) {
			assertNotNull(found.get(value), "the recording stores " + value);
		}
		return found;
	}

	private static List<String> sorted(List<StringLocation> locations) {
		return new ArrayList<>(new TreeSet<>(locations.stream().map(StringLocation::toString).toList()));
	}

	/**
	 * Scans the recording, counting references, whose events and checkpoints must all be aligned
	 */
	private static StringScanner scan(Path file) throws IOException {
		StringScanner scanner = new StringScanner(true, true);
		new StreamingChunkParser().parse(file, scanner);
		assertEquals(0, scanner.getMisalignedCount());
		return scanner;
	}

	/**
	 * Gives the string pool entry holding the value a key no field refers to, encoded in as many
	 * bytes as the old one, so that the references to the entry dangle and the entry is
	 * unreferenced
	 */
	private static void renameStringPoolEntry(Path file, String value) throws IOException {
		byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
		long keyOffset = -1;
		int keyWidth = 0;
		Set<Long> keys = new HashSet<>();
		StringDecoder decoder = new StringDecoder();
		try (FileChannel channel = FileChannel.open(file)) {
			ChunkReader reader = new ChunkReader();
			reader.reset(channel);
			long chunkStart = 0;
			while (reader.next()) {
				ChunkTypes types = reader.types();
				RecordingStream stream = reader.stream();
				for (int position = reader.headerSize(); position < reader.size();) {
					stream.position(position);
					int end = position + (int) stream.readVarint();
					if (stream.readVarint() == 1) { // A checkpoint
						stream.skipVarint(); // start time
						stream.skipVarint(); // duration
						stream.skipVarint(); // delta to previous checkpoint
						stream.skip(1); // checkpoint type
						int poolCount = (int) stream.readVarint();
						for (int p = 0; p < poolCount; p++) {
							ChunkTypes.Type type = types.getPoolType(stream.readVarint());
							int count = (int) stream.readVarint();
							for (int i = 0; i < count; i++) {
								int keyStart = stream.position();
								long key = stream.readVarint();
								int width = stream.position() - keyStart;
								if (!type.isString) {
									skipValue(stream, types, type, decoder);
									continue;
								}
								keys.add(key);
								if (decoder.read(stream, ChunkTypes.KIND_STRING) == StringDecoder.STRING
										&& Arrays.equals(decoder.array, decoder.offset, decoder.offset + decoder.length,
												utf8, 0, utf8.length)) {
									assertEquals(-1, keyOffset, "one entry holds the value");
									keyOffset = chunkStart + keyStart;
									keyWidth = width;
								}
							}
						}
					}
					position = end;
				}
				chunkStart += reader.size();
			}
		}
		assertTrue(keyOffset >= 0, "the value is in the string pool");
		long smallest = keyWidth == 1 ? 0 : 1L << (7 * (keyWidth - 1));
		long unused = (1L << (7 * keyWidth)) - 1;
		while (keys.contains(unused)) {
			unused--;
		}
		assertTrue(unused >= smallest, "an unused key encoded in " + keyWidth + " bytes");
		byte[] bytes = Files.readAllBytes(file);
		writeVarint(bytes, (int) keyOffset, unused, keyWidth);
		Files.write(file, bytes);
	}

	/** Skips the value of a constant, its strings in whichever encoding */
	private static void skipValue(RecordingStream stream, ChunkTypes types, ChunkTypes.Type type, StringDecoder decoder)
			throws IOException {
		for (int op : type.fields) {
			int kind = op & ChunkTypes.KIND_MASK;
			int count = (op & ChunkTypes.ARRAY_FLAG) == 0 ? 1 : (int) stream.readVarint();
			for (int i = 0; i < count; i++) {
				switch (kind) {
				case ChunkTypes.KIND_FIXED1, ChunkTypes.KIND_FIXED2, ChunkTypes.KIND_FIXED4, ChunkTypes.KIND_FIXED8 ->
					stream.skip(ChunkTypes.fixedSize(kind));
				case ChunkTypes.KIND_VARINT -> stream.skipVarint();
				case ChunkTypes.KIND_STRING -> decoder.read(stream, kind);
				case ChunkTypes.KIND_STRUCT ->
					skipValue(stream, types, types.getByIndex(op >>> ChunkTypes.TYPE_SHIFT), decoder);
				default -> throw new IOException("Unexpected field kind " + kind);
				}
			}
		}
	}

	/**
	 * The offsets of the string field in the events of the type in the first chunk, which the
	 * fields before it must make reachable without decoding arrays or structs
	 */
	private static List<Integer> stringFieldOffsets(Path file, String typeName, String fieldName) throws IOException {
		List<Integer> offsets = new ArrayList<>();
		try (FileChannel channel = FileChannel.open(file)) {
			ChunkReader reader = new ChunkReader();
			reader.reset(channel);
			assertTrue(reader.next(), "a chunk");
			RecordingStream stream = reader.stream();
			for (int start = reader.headerSize(); start < reader.size();) {
				stream.position(start);
				int end = start + (int) stream.readVarint();
				ChunkTypes.Type type = reader.types().getEventType(stream.readVarint());
				if (type != null && type.name.equals(typeName)) {
					for (int field = 0;; field++) {
						int op = type.fields[field];
						assertEquals(0, op & ChunkTypes.ARRAY_FLAG, "an array before the string field");
						if (type.fieldNames[field].equals(fieldName)) {
							assertEquals(ChunkTypes.KIND_STRING, op & ChunkTypes.KIND_MASK);
							offsets.add(stream.position());
							break;
						}
						switch (op & ChunkTypes.KIND_MASK) {
						case ChunkTypes.KIND_VARINT -> stream.skipVarint();
						case ChunkTypes.KIND_FIXED1 -> stream.skip(1);
						case ChunkTypes.KIND_FIXED4 -> stream.skip(4);
						case ChunkTypes.KIND_FIXED8 -> stream.skip(8);
						default -> throw new AssertionError("Unexpected field kind before the string field: " + op);
						}
					}
				}
				start = end;
			}
		}
		return offsets;
	}

	/** Null denotes an inline value; otherwise the value is the event field's string-pool key. */
	private static List<Long> stringFieldReferenceKeys(Path file, String typeName, String fieldName)
			throws IOException {
		byte[] bytes = Files.readAllBytes(file);
		List<Long> keys = new ArrayList<>();
		for (int offset : stringFieldOffsets(file, typeName, fieldName)) {
			if (bytes[offset] != 2) {
				keys.add(null);
				continue;
			}
			long key = 0;
			for (int i = 0; i < 9; i++) {
				int b = bytes[offset + 1 + i] & 0xFF;
				key |= (long) (b & (i == 8 ? 0xFF : 0x7F)) << (7 * i);
				if (b < 0x80 || i == 8) {
					break;
				}
			}
			keys.add(key);
		}
		return keys;
	}

	private static int varintWidth(byte[] bytes, int start) {
		int width = 1;
		while ((bytes[start + width - 1] & 0x80) != 0) {
			width++;
		}
		return width;
	}

	/** Writes the value as a varint of exactly the width, which must fit it */
	private static void writeVarint(byte[] bytes, int start, long value, int width) {
		for (int i = 0; i < width; i++) {
			bytes[start + i] = (byte) ((value & 0x7F) | (i < width - 1 ? 0x80 : 0));
			value >>>= 7;
		}
	}
}
