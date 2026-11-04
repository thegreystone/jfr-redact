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
import static se.hirt.jfr.redact.HandWrittenRecording.assertReadsBack;
import static se.hirt.jfr.redact.HandWrittenRecording.constant;
import static se.hirt.jfr.redact.HandWrittenRecording.pool;
import static se.hirt.jfr.redact.HandWrittenRecording.reference;
import static se.hirt.jfr.redact.HandWrittenRecording.string;
import static se.hirt.jfr.redact.HandWrittenRecording.varint;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openjdk.jmc.flightrecorder.writer.api.Type;
import org.openjdk.jmc.flightrecorder.writer.api.Types;

import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import se.hirt.jfr.redact.parser.StreamingChunkParser;
import se.hirt.jfr.redact.scan.StringCountMap;
import se.hirt.jfr.redact.scan.StringScanner;

/**
 * The locations of strings stored in the constants of simple types. The metadata declares a type
 * {@code simpleType} when it has one field and no supertype, as the JDK does for
 * {@code jdk.types.Symbol} and its enumerations and as JMC's writer does for a user-registered
 * one-field type, and every reader reads such a constant as that one value: the value belongs to
 * the field referring to the constant and is located there, with the referrers of the constant
 * holding that field, through chains of simple types and the string pool, which is the simple type
 * without a field. A declared simple type whose field is not a scalar string or a reference to
 * another simple type, an array, a struct, a number, or a member of a cycle, is an entity like any
 * other constant type, and a simple constant nothing refers to in its chunk is located at its own
 * field. Referrers are recorded only for the constants storing strings themselves, so a value
 * reached through a constant that stores none, a class or a method of HotSpot's, a holder of
 * nothing but simple constants here, is located without them, see
 * {@link StringLocation#getReferrers()}. The layouts the JDK never writes, a chain of simple types,
 * a simple type declared over an array, a struct or a number, a cycle and a simple type inlined in
 * a field, are written by hand, since JMC's writer declares only a one-field type over a builtin
 * simple, and read back with the JDK's parser, which reads each simple constant as its value, to
 * show they are valid JFR. The tests assert the locations; the flags of the parser behind them are
 * the subject of {@link ChunkTypesTest}.
 */
class SimpleTypeTest {
	/**
	 * A one-field type JMC's writer declares simple is the value of the event field and of the
	 * constant field referring to it, and a constant both refer to is the value of both; a
	 * two-field type is an entity holding its own string; a simple constant nothing refers to is
	 * located at its own field. The holder stores nothing but the simple constant, so it has no
	 * referrers, although another constant refers to it. A rule on the event's field, which knows
	 * nothing of the simple type, replaces the value the JDK reads from the event, and the decision
	 * applies to the shared constant wherever it is read from.
	 */
	@Test
	void locatesTheValuesOfAWritersSimpleTypeAtTheFieldsReferringToIt(@TempDir
	Path dir) throws Exception {
		String queried = "select ssn from patients where id = 4711";
		String shared = "select diagnosis from patients where id = 4711";
		String held = "label interned for the holder";
		String paired = "value of a two-field type, an entity";
		String orphan = "value of a simple constant nothing refers to";
		Path input = JmcWriterRecording.write(dir.resolve("input.jfr"), recording -> {
			Type interned = recording.registerType("acme.Interned", b -> b.addField("text", Types.Builtin.STRING));
			Type pair = recording.registerType("acme.Pair",
					b -> b.addField("text", Types.Builtin.STRING).addField("count", Types.Builtin.INT));
			Type holder = recording.registerType("acme.Holder",
					b -> b.addField("sql", interned).addField("count", Types.Builtin.INT));
			Type outer = recording.registerType("acme.Outer", b -> b.addField("inner", holder));
			Type query = recording.registerEventType("acme.Query",
					b -> b.addField("sql", interned).addField("pair", pair).addField("outer", outer));
			interned.asValue(b -> b.putField("text", orphan));
			String[][] values = {{queried, held}, {shared, shared}};
			for (String[] value : values) {
				recording
						.writeEvent(
								query.asValue(
										b -> b.putField("startTime", 1L)
												.putField("sql",
														s -> s.putField("text", value[0]))
												.putField("pair",
														p -> p.putField("text", paired).putField("count", 1))
												.putField(
														"outer", o -> o
																.putField(
																		"inner", h -> h
																				.putField("sql",
																						s -> s.putField("text",
																								value[1]))
																				.putField("count", 7)))));
			}
		});
		Map<String, List<StringLocation>> locations = locationsOf(input, dir.resolve("unchanged.jfr"),
				Set.of(queried, shared, held, paired, orphan));
		assertEquals(List.of("acme.Query.sql (pooled)"), sorted(locations.get(queried)),
				"the value of the simple constant is the value of the event's field");
		assertEquals(List.of("acme.Holder.sql (pooled)"), sorted(locations.get(held)),
				"and of the constant's field, without referrers, as the holder stores no string itself");
		assertEquals(List.of("acme.Holder.sql (pooled)", "acme.Query.sql (pooled)"), sorted(locations.get(shared)),
				"one constant referred to from both");
		assertEquals(List.of("acme.Pair.text (pooled)"), sorted(locations.get(paired)),
				"a two-field type is an entity");
		assertEquals(List.of("acme.Interned.text (pooled)"), sorted(locations.get(orphan)),
				"a constant nothing refers to is located at its own field");

		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output,
				RuleRedactor.builder().replaceIf(
						location -> location.getOwner().equals("acme.Query") && location.getField().equals("sql"),
						value -> "<SQL>").build());
		assertEquals(2, result.redactedStringCount(), "the two values of the field, the shared one included");
		TestRecordings.assertAbsent(output, queried, shared);
		List<RecordedEvent> events = RecordingFile.readAllEvents(output);
		assertEquals(2, events.size());
		for (RecordedEvent event : events) {
			assertEquals("<SQL>", event.getValue("sql"), "the JDK reads the simple type as its value");
			assertEquals(paired, event.getValue("pair.text"));
		}
		assertEquals(held, events.get(0).getValue("outer.inner.sql"), "the other field keeps its value");
		assertEquals("<SQL>", events.get(1).getValue("outer.inner.sql"),
				"the decision applies to the shared constant wherever it is read from");
	}

	/**
	 * Simple types chain: a declared simple type whose field refers to another simple type is read
	 * as that type's value, and a simple type whose string field is declared with a constant pool
	 * holds a key into the string pool. The value at the end of a chain is located at the field
	 * referring to the first link, from an event or from an entity constant, with the referrers of
	 * the entity, which stores a string of its own here, and a chain nothing refers to ends at the
	 * first link's own field.
	 */
	@Test
	void locatesTheValueAtTheEndOfAChainOfSimpleTypesAtTheReferringField(@TempDir
	Path dir) throws Exception {
		String pooled = "value stored in the string pool, behind two simple types";
		String inlined = "value stored inline in a simple type, behind another";
		String orphan = "value of a chain nothing refers to";
		String keyed = "value of a simple type holding a key into the string pool";
		String note = "note of the entity holding a chain";
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declareSimple(100, "test.Word", "text:20");
		recording.declareSimple(101, "test.Link", "word:100:pool");
		recording.declareSimple(102, "test.Keyed", "key:20:pool");
		recording.declareEvent(103, "test.Evt", "link:101:pool", "keyed:102:pool");
		recording.declare(104, "test.Holder", "link:101:pool", "note:20");
		recording.declare(105, "test.Outer", "inner:104:pool");
		recording.declareEvent(106, "test.Evt2", "outer:105:pool");
		recording.event(103, varint(1), varint(1));
		recording.event(106, varint(1));
		recording.checkpoint(pool(20, constant(1, string(pooled)), constant(2, string(keyed))),
				pool(100, constant(1, reference(1)), constant(2, string(inlined)), constant(3, string(orphan))),
				pool(101, constant(1, varint(1)), constant(2, varint(2)), constant(3, varint(3))),
				pool(102, constant(1, varint(2))), pool(104, constant(1, varint(2), string(note))),
				pool(105, constant(1, varint(1))));
		Path input = recording.write(dir.resolve("input.jfr"));
		assertReadsBack(input, "test.Evt", "link", pooled);
		assertReadsBack(input, "test.Evt", "keyed", keyed);
		assertReadsBack(input, "test.Evt2", "outer.inner.link", inlined);
		assertReadsBack(input, "test.Evt2", "outer.inner.note", note);
		Map<String, List<StringLocation>> locations = locationsOf(input, dir.resolve("unchanged.jfr"),
				Set.of(pooled, inlined, orphan, keyed, note));
		assertEquals(List.of("test.Evt.link (pooled)"), sorted(locations.get(pooled)),
				"the event, through the link, the word and the pool");
		assertEquals(List.of("test.Holder.link (pooled) referred to by test.Outer.inner"),
				sorted(locations.get(inlined)), "the entity's field, with the entity's referrers");
		assertEquals(List.of("test.Link.word (pooled)"), sorted(locations.get(orphan)),
				"the own field of the first link nothing refers to");
		assertEquals(List.of("test.Evt.keyed (pooled)"), sorted(locations.get(keyed)));
		assertEquals(List.of("test.Holder.note (pooled) referred to by test.Outer.inner"), sorted(locations.get(note)));

		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output, RuleRedactor.builder()
				.replaceIf(location -> location.getOwner().equals("test.Evt"), value -> "<X>").build());
		assertEquals(2, result.redactedStringCount(), "the pooled and the keyed value");
		assertEquals(1, result.rewrittenCheckpointCount());
		TestRecordings.assertAbsent(output, pooled, keyed);
		StringCountMap strings = scan(output).getStrings();
		assertEquals(2, strings.getCount(strings.indexOf("<X>"), StringScanner.CONSTANT_POOL),
				"the two entries of the string pool");
		assertReadsBack(output, "test.Evt", "link", "<X>");
		assertReadsBack(output, "test.Evt", "keyed", "<X>");
		assertReadsBack(output, "test.Evt2", "outer.inner.link", inlined);
	}

	/**
	 * A declared simple type whose one field is an array of strings or a struct is not read as one
	 * value, so it is an entity: its strings are located at its own field, with the fields of the
	 * constants referring to it as referrers, as the constants of any other type storing strings
	 */
	@Test
	void keepsADeclaredSimpleTypeWithAnArrayOrAStructFieldAnEntity(@TempDir
	Path dir) throws Exception {
		String first = "first tag of the array";
		String second = "second tag of the array";
		String nested = "string of the struct in the one field";
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declareSimple(100, "test.Tags", "tags:20:array");
		recording.declare(101, "test.Inner", "s:20");
		recording.declareSimple(102, "test.Wrap", "inner:101");
		recording.declare(103, "test.Holder", "texts:100:pool", "wrap:102:pool");
		recording.declareEvent(104, "test.Evt", "tags:100:pool", "wrap:102:pool");
		recording.event(104, varint(1), varint(1));
		recording.checkpoint(pool(100, constant(1, varint(2), string(first), string(second))),
				pool(102, constant(1, string(nested))), pool(103, constant(1, varint(1), varint(1))));
		Path input = recording.write(dir.resolve("input.jfr"));
		assertReadsBack(input, "test.Evt", "tags", "[" + first + ", " + second + "]");
		// The JDK reads the declared simple type over a struct as that struct's values, exposed as an
		// array since its API hides the fields of a simple type; the location keeps the struct's path
		assertReadsBack(input, "test.Evt", "wrap", "[" + nested + "]");
		Map<String, List<StringLocation>> locations = locationsOf(input, dir.resolve("unchanged.jfr"),
				Set.of(first, second, nested));
		assertEquals(List.of("test.Tags.tags (pooled) referred to by test.Holder.texts"), sorted(locations.get(first)),
				"an array of strings is no single value: an entity");
		assertEquals(List.of("test.Tags.tags (pooled) referred to by test.Holder.texts"),
				sorted(locations.get(second)));
		assertEquals(List.of("test.Wrap.inner.s (pooled) referred to by test.Holder.wrap"),
				sorted(locations.get(nested)), "a struct is no single value: an entity");

		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output, RuleRedactor.builder()
				.replaceIf(location -> location.getOwner().equals("test.Tags"), value -> "<X>").build());
		assertEquals(2, result.redactedStringCount());
		TestRecordings.assertAbsent(output, first, second);
		assertReadsBack(output, "test.Evt", "tags", "[<X>, <X>]");
	}

	/**
	 * A declared simple type without a string, like {@code jdk.types.ChunkHeader}, holds nothing to
	 * locate, and an event referring to it keeps its other strings where they are
	 */
	@Test
	void ignoresADeclaredSimpleTypeWithoutAString(@TempDir
	Path dir) throws Exception {
		String text = "text of an event referring to a numeric simple type";
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declareSimple(100, "test.Count", "count:1");
		recording.declareEvent(101, "test.Evt", "count:100:pool", "text:20");
		recording.event(101, varint(1), string(text));
		recording.checkpoint(pool(100, constant(1, varint(42))));
		Path input = recording.write(dir.resolve("input.jfr"));
		assertReadsBack(input, "test.Evt", "text", text);
		assertEquals(List.of("test.Evt.text (inline)"),
				sorted(locationsOf(input, dir.resolve("unchanged.jfr"), Set.of(text)).get(text)));
	}

	/**
	 * Declared simple types referring to each other in a cycle, or a type referring to itself, are
	 * read as nothing: they are entities, without strings, and the chain of their constants is not
	 * followed. The JDK's parser resolves such a constant to nothing either.
	 */
	@Test
	void treatsCyclesOfSimpleTypesAsEntities(@TempDir
	Path dir) throws Exception {
		String text = "text of an event referring to a cycle";
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declareSimple(100, "test.A", "b:101:pool");
		recording.declareSimple(101, "test.B", "a:100:pool");
		recording.declareSimple(102, "test.Self", "self:102:pool");
		recording.declareEvent(103, "test.Evt", "a:100:pool", "self:102:pool", "text:20");
		recording.event(103, varint(1), varint(1), string(text));
		recording.checkpoint(pool(100, constant(1, varint(1))), pool(101, constant(1, varint(1))),
				pool(102, constant(1, varint(1))));
		Path input = recording.write(dir.resolve("input.jfr"));
		assertReadsBack(input, "test.Evt", "text", text);
		assertReadsBack(input, "test.Evt", "a", (String) null);
		assertReadsBack(input, "test.Evt", "self", (String) null);
		List<String> all = new ArrayList<>();
		JfrRedactor.redact(input, dir.resolve("unchanged.jfr"), (value, locations) -> {
			all.add(value + " at " + sorted(locations));
			return value;
		});
		assertEquals(List.of(text + " at [test.Evt.text (inline)]"), all,
				"the constants of the cycles hold no strings, and nothing is located at them");
	}

	/**
	 * The fold applies to constants referred to through a constant pool. A struct of a simple type
	 * inlined in a field, a layout no known writer produces, keeps its own field path, inline in an
	 * event or in the constant of an entity, and a key inlined in such a struct leads to the string
	 * pool from the struct's field. The JDK's parser reads an inlined simple struct as its value
	 * only when it has compiled the simple type before the type inlining it, see
	 * {@link HandWrittenRecording}: the ids put the simple types in its table ahead of the others.
	 */
	@Test
	void keepsAnInlinedSimpleStructAtItsOwnField(@TempDir
	Path dir) throws Exception {
		String inEvent = "value of a simple struct inlined in an event";
		String inConstant = "value of a simple struct inlined in a constant";
		String pooled = "value of the string pool behind a simple struct inlined in an event";
		String text = "plain text of the event";
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declareSimple(107, "test.Simple", "s:20");
		recording.declareSimple(112, "test.Keyed", "key:20:pool");
		recording.declareEvent(104, "test.Evt", "f:107", "k:112", "text:20");
		recording.declare(101, "test.Ent", "g:107", "n:1");
		recording.declare(106, "test.Outer", "ent:101:pool");
		recording.declareEvent(103, "test.Evt2", "outer:106:pool");
		recording.event(104, string(inEvent), varint(1), string(text));
		recording.event(103, varint(1));
		recording.checkpoint(pool(20, constant(1, string(pooled))),
				pool(101, constant(1, string(inConstant), varint(5))), pool(106, constant(1, varint(1))));
		Path input = recording.write(dir.resolve("input.jfr"));
		assertReadsBack(input, "test.Evt", "f", inEvent);
		assertReadsBack(input, "test.Evt", "k", pooled);
		assertReadsBack(input, "test.Evt", "text", text);
		assertReadsBack(input, "test.Evt2", "outer.ent.g", inConstant);
		Map<String, List<StringLocation>> locations = locationsOf(input, dir.resolve("unchanged.jfr"),
				Set.of(inEvent, inConstant, pooled, text));
		assertEquals(List.of("test.Evt.f.s (inline)"), sorted(locations.get(inEvent)),
				"the struct's own field: the fold applies to constants referred to through a pool");
		assertEquals(List.of("test.Ent.g.s (pooled) referred to by test.Outer.ent"), sorted(locations.get(inConstant)));
		assertEquals(List.of("test.Evt.k.key (pooled)"), sorted(locations.get(pooled)),
				"the pool entry behind the inlined struct is a value of the struct's field");
		assertEquals(List.of("test.Evt.text (inline)"), sorted(locations.get(text)));

		Path output = dir.resolve("output.jfr");
		RedactionResult result = JfrRedactor.redact(input, output,
				RuleRedactor.builder().replaceIf(
						location -> location.getOwner().equals("test.Evt") && !location.getField().equals("text"),
						value -> "<X>").build());
		assertEquals(2, result.redactedStringCount(), "the inlined and the pooled value of the event's fields");
		TestRecordings.assertAbsent(output, inEvent, pooled);
		StringCountMap strings = scan(output).getStrings();
		assertEquals(1, strings.getCount(strings.indexOf("<X>"), StringScanner.INLINE));
		assertEquals(1, strings.getCount(strings.indexOf("<X>"), StringScanner.CONSTANT_POOL));
		assertReadsBack(output, "test.Evt", "f", "<X>");
		assertReadsBack(output, "test.Evt", "k", "<X>");
	}

	/**
	 * HotSpot's layout of a profile: the frames of a stack trace refer to methods, entities whose
	 * names are symbols, and to frame types, simple constants keyed from 0, and the state of a
	 * sample is a simple constant too. Neither the methods nor the stack traces store a string of
	 * their own, so neither has referrers: the frame types are located at the frames' field, the
	 * method names at the methods' field, and the state at the sample's field, all without
	 * referrers, whether or not a constant pool type refers to the stack traces, and the method of
	 * a frame is never decoded. The frame types, methods and states nothing refers to stay at their
	 * own field.
	 */
	@Test
	void locatesTheValuesOfTheFramesOfStackTracesAtTheFramesFields(@TempDir
	Path dir) throws Exception {
		String interpreted = "Interpreted";
		String compiled = "JIT compiled";
		String inlined = "Inlined";
		String running = "STATE_RUNNABLE";
		String sleeping = "STATE_SLEEPING";
		String method = "processRecord";
		String orphan = "finalize";
		for (boolean rooted : new boolean[] {false, true}) {
			HandWrittenRecording recording = new HandWrittenRecording();
			recording.declareSimple(100, "test.Symbol", "string:20");
			recording.declareSimple(101, "test.FrameType", "description:20");
			recording.declareSimple(102, "test.ThreadState", "name:20");
			recording.declare(103, "test.Method", "name:100:pool", "modifiers:1");
			recording.declare(104, "test.StackFrame", "method:103:pool", "lineNumber:1", "type:101:pool");
			recording.declare(105, "test.StackTrace", "truncated:1", "frames:104:array");
			recording.declareEvent(106, "test.Sample", "stackTrace:105:pool", "state:102:pool");
			if (rooted) {
				recording.declare(107, "test.Root", "trace:105:pool");
			}
			for (int i = 0; i < 3; i++) {
				recording.event(106, varint(1), varint(0));
			}
			List<byte[]> pools = new ArrayList<>(
					List.of(pool(100, constant(1, string(method)), constant(2, string(orphan))),
							pool(101, constant(0, string(interpreted)), constant(1, string(compiled)),
									constant(2, string(inlined))),
							pool(102, constant(0, string(running)), constant(1, string(sleeping))),
							pool(103, constant(1, varint(1), varint(9)), constant(2, varint(2), varint(9))),
							pool(105,
									constant(1, varint(0), varint(4), varint(1), varint(42), varint(1), varint(1),
											varint(43), varint(0), varint(1), varint(44), varint(1), varint(1),
											varint(45), varint(0)))));
			if (rooted) {
				pools.add(pool(107, constant(1, varint(1))));
			}
			recording.checkpoint(pools.toArray(new byte[0][]));
			Path input = recording.write(dir.resolve("input-" + rooted + ".jfr"));
			assertReadsBack(input, "test.Sample", "state", running, running, running);
			Map<String, List<StringLocation>> locations = locationsOf(input, dir.resolve("unchanged.jfr"),
					Set.of(interpreted, compiled, inlined, running, sleeping, method, orphan));
			String frames = "test.StackTrace.frames.type (pooled)";
			assertEquals(List.of(frames), sorted(locations.get(compiled)), "rooted: " + rooted);
			assertEquals(List.of(frames), sorted(locations.get(interpreted)),
					"key 0 is a frame type, rooted: " + rooted);
			assertEquals(List.of("test.FrameType.description (pooled)"), sorted(locations.get(inlined)),
					"a frame type no frame has, rooted: " + rooted);
			assertEquals(List.of("test.Method.name (pooled)"), sorted(locations.get(method)),
					"the method stores no string, so the frames referring to it are no referrers, rooted: " + rooted);
			assertEquals(List.of("test.Method.name (pooled)"), sorted(locations.get(orphan)),
					"a method no frame refers to, rooted: " + rooted);
			assertEquals(List.of("test.Sample.state (pooled)"), sorted(locations.get(running)), "rooted: " + rooted);
			assertEquals(List.of("test.ThreadState.name (pooled)"), sorted(locations.get(sleeping)),
					"a state no sample has, rooted: " + rooted);
		}
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

	/** Scans the recording, whose events and checkpoints must all be aligned */
	private static StringScanner scan(Path file) throws IOException {
		StringScanner scanner = new StringScanner(true);
		new StreamingChunkParser().parse(file, scanner);
		assertEquals(0, scanner.getMisalignedCount());
		return scanner;
	}
}
