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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedObject;
import jdk.jfr.consumer.RecordingFile;

/**
 * Writes a JFR 2.0 recording of one chunk by hand, for layouts no writer produces: the types,
 * declared in the metadata with their fields, and the events and checkpoints, written as raw
 * payloads built with the static helpers. The recording is readable by the JDK's parser as well,
 * which the tests assert with {@link #readValues}, so that a layout is known to be valid JFR and
 * not just one jfr-redact's parser accepts: every event type gets a {@code startTime} as its first
 * field, which the JDK reads as the event's time whatever the declaration says, and the checkpoints
 * are chained through their deltas, which the JDK follows back from the last one. The primitive
 * types the layouts need, {@code long} as type {@value #LONG} and {@code java.lang.String} as type
 * {@value #STRING}, are declared by the constructor. The recording is one chunk: concatenated
 * hand-written chunks share the metadata id 0, and the JDK then resolves the constants of every
 * chunk from the first chunk's pools, so read-backs are per recording.
 * <p>
 * The JDK's parser compiles the types in the order of its hash table of type ids, 32 slots for
 * fewer than 25 types, and that order decides two things for layouts no writer produces. A String
 * field declared with a constant pool registers the string pool's lookup, and a plain String field
 * compiled after it registers another, replacing the first ({@code ParserFactory
 * .createPrimitiveParser}), which is then never resolved and sends {@code ConstantMap.resolve} into
 * endless recursion; so the constructor declares a type with a plain String field, {@value #PLAIN},
 * at the slot the parser visits first, which keeps the ids below 300 free of. And a simple type
 * inlined in a field, rather than referred to through its pool, is read only when the simple type
 * was compiled before the type inlining it, so a test inlining one picks its ids accordingly.
 */
final class HandWrittenRecording {
	/** The type id of {@code long}, declared by the constructor */
	static final long LONG = 1;
	/** The type id of {@code java.lang.String}, the string pool, declared by the constructor */
	static final long STRING = 20;
	/**
	 * The type id of {@code jfr.redact.Plain}, a type with a plain String field declared by the
	 * constructor, in the first slot of the JDK parser's table: ids 500 and 301 hash to it
	 */
	static final long PLAIN = 500;
	private static final int HEADER_SIZE = 68;
	private static final int MAGIC = 0x464C5200;
	private static final int FEATURE_COMPRESSED_INTS = 1;

	/** The string table of the metadata, and the class elements referring to it */
	private final List<String> table = new ArrayList<>();
	private final Map<String, Integer> indexes = new HashMap<>();
	private final List<byte[]> classes = new ArrayList<>();
	/** The events and checkpoints, in order */
	private final ByteArrayOutputStream body = new ByteArrayOutputStream();
	/** The offset of the last checkpoint, 0 before the first */
	private int checkpointOffset;
	private long eventCount;

	HandWrittenRecording() {
		declare(LONG, "long");
		declare(STRING, "java.lang.String");
		declare(PLAIN, "jfr.redact.Plain", "text:" + STRING);
	}

	/**
	 * Declares a type, each field given as {@code name:typeId}, with {@code :pool} appended when
	 * the value is a key into the constant pool of the field's type and {@code :array} when the
	 * field is an array
	 */
	void declare(long id, String name, String ... fields) {
		declare(id, name, false, null, fields);
	}

	/**
	 * Declares a type with the {@code simpleType} attribute, which the JDK writes for a type with
	 * one field and no supertype, and whose constants every reader reads as that field's value
	 */
	void declareSimple(long id, String name, String field) {
		declare(id, name, true, null, field);
	}

	/**
	 * Declares an event type, with the {@code superType} of {@code jdk.jfr.Event} every writer
	 * gives its events, whose values are never constants in a checkpoint, and a {@code startTime}
	 * before the fields given, which {@link #event} writes
	 */
	void declareEvent(long id, String name, String ... fields) {
		String[] withStartTime = new String[fields.length + 1];
		withStartTime[0] = "startTime:" + LONG;
		System.arraycopy(fields, 0, withStartTime, 1, fields.length);
		declare(id, name, false, "jdk.jfr.Event", withStartTime);
	}

	private void declare(long id, String name, boolean simple, String superType, String ... fields) {
		ByteArrayOutputStream element = new ByteArrayOutputStream();
		List<String> classAttributes = new ArrayList<>(List.of("id", Long.toString(id), "name", name));
		if (simple) {
			classAttributes.addAll(List.of("simpleType", "true"));
		}
		if (superType != null) {
			classAttributes.addAll(List.of("superType", superType));
		}
		writeElement(element, "class", classAttributes, fields.length);
		for (String field : fields) {
			String[] parts = field.split(":");
			List<String> attributes = new ArrayList<>(List.of("name", parts[0], "class", parts[1]));
			for (int i = 2; i < parts.length; i++) {
				switch (parts[i]) {
				case "pool" -> attributes.addAll(List.of("constantPool", "true"));
				case "array" -> attributes.addAll(List.of("dimension", "1"));
				default -> throw new IllegalArgumentException(field);
				}
			}
			writeElement(element, "field", attributes, 0);
		}
		classes.add(element.toByteArray());
	}

	/**
	 * Writes an event of the type, its payload being the start time, which counts the events, and
	 * then the fields given in order
	 */
	void event(long typeId, byte[] ... payload) {
		body.writeBytes(eventBytes(typeId, bytes(varint(++eventCount), bytes(payload))));
	}

	/**
	 * Writes a checkpoint with the pools, each built with {@link #pool(long, byte[]...)}, chained
	 * to the previous checkpoint through the delta the JDK's parser follows from the last
	 * checkpoint back to the first: the start of the previous one minus the start of this one, 0
	 * for the first
	 */
	void checkpoint(byte[] ... pools) {
		int offset = HEADER_SIZE + body.size();
		ByteArrayOutputStream payload = new ByteArrayOutputStream();
		payload.writeBytes(varint(0)); // start time
		payload.writeBytes(varint(0)); // duration
		payload.writeBytes(varint(checkpointOffset == 0 ? 0 : checkpointOffset - offset));
		payload.write(0); // checkpoint type
		payload.writeBytes(varint(pools.length));
		for (byte[] pool : pools) {
			payload.writeBytes(pool);
		}
		checkpointOffset = offset;
		body.writeBytes(eventBytes(1, payload.toByteArray()));
	}

	/** Writes the chunk, with the metadata after the events and checkpoints */
	Path write(Path file) throws IOException {
		byte[] metadata = metadataEvent();
		int metadataOffset = HEADER_SIZE + body.size();
		ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE);
		header.putInt(MAGIC).putShort((short) 2).putShort((short) 0);
		header.putLong(metadataOffset + metadata.length).putLong(checkpointOffset).putLong(metadataOffset);
		header.putLong(0).putLong(0).putLong(0).putLong(1_000_000_000L); // start, duration, ticks
		header.putInt(FEATURE_COMPRESSED_INTS);
		Files.write(file, bytes(header.array(), body.toByteArray(), metadata));
		return file;
	}

	/**
	 * Reads the recording with the JDK's parser, which asserts that the layout is valid JFR, and
	 * returns the value of the field of every event of the type, in order: the field is a dotted
	 * path, and its value a string, resolved from the string pool and through the simple types the
	 * JDK reads as their value, or {@code null} where the JDK resolves nothing. The events of the
	 * other types are read too, so that a value they cannot decode fails the test.
	 */
	static List<String> readValues(Path file, String eventType, String field) throws IOException {
		List<String> values = new ArrayList<>();
		List<RecordedEvent> events;
		try {
			events = RecordingFile.readAllEvents(file);
		} catch (StackOverflowError e) {
			throw new AssertionError("The JDK's parser recursed endlessly resolving the constants of " + file
					+ ": a String field declared with a constant pool compiled before any plain String field, see "
					+ HandWrittenRecording.class.getSimpleName(), e);
		}
		for (RecordedEvent event : events) {
			if (event.getEventType().getName().equals(eventType)) {
				values.add(stringValue(event, field));
			}
		}
		return values;
	}

	/**
	 * Asserts the values {@link #readValues} reads back, as a list of them in event order, null
	 * where the JDK resolves nothing
	 */
	static void assertReadsBack(Path file, String eventType, String field, String ... expected) throws IOException {
		assertEquals(Arrays.asList(expected), readValues(file, eventType, field),
				"the JDK's values of " + eventType + "." + field);
	}

	/**
	 * The value of the field as a string: a string as it is, a struct's string field through the
	 * dotted path, followed a segment at a time since the JDK refuses a path through a field of a
	 * type declared simple, an array of strings as {@code [first, second]}, and the value of a
	 * simple type is what the JDK has resolved it to, null where it resolved nothing
	 */
	private static String stringValue(RecordedObject object, String field) {
		Object value = object;
		for (String part : field.split("\\.")) {
			if (value == null) {
				return null;
			}
			if (!(value instanceof RecordedObject struct)) {
				throw new AssertionError(field + ": " + part + " of a " + value.getClass().getName() + ": " + value);
			}
			value = struct.getValue(part);
		}
		if (value == null || value instanceof String) {
			return (String) value;
		}
		if (value instanceof Object[] array) {
			return Arrays.toString(array);
		}
		throw new AssertionError(field + " is a " + value.getClass().getName() + ": " + value);
	}

	/**
	 * A constant pool of the type, with the constants built with {@link #constant(long, byte[]...)}
	 */
	static byte[] pool(long typeId, byte[] ... constants) {
		ByteArrayOutputStream pool = new ByteArrayOutputStream();
		pool.writeBytes(varint(typeId));
		pool.writeBytes(varint(constants.length));
		for (byte[] constant : constants) {
			pool.writeBytes(constant);
		}
		return pool.toByteArray();
	}

	/** A constant with the key, its value being the fields in order */
	static byte[] constant(long key, byte[] ... value) {
		return bytes(varint(key), bytes(value));
	}

	/** A string in the UTF-8 encoding */
	static byte[] string(String value) {
		byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
		return bytes(new byte[] {3}, varint(utf8.length), utf8);
	}

	/** A string field referring to the entry of the string pool with the key */
	static byte[] reference(long key) {
		return bytes(new byte[] {2}, varint(key));
	}

	/**
	 * A compressed integer as JFR encodes it: seven bits per byte, the high bit flagging another
	 * byte, and at most nine bytes, the ninth carrying the remaining eight bits raw, which a
	 * negative number, such as the delta to the previous checkpoint, takes
	 */
	static byte[] varint(long value) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (int i = 0; i < 8; i++) {
			if ((value & ~0x7FL) == 0) {
				out.write((int) value);
				return out.toByteArray();
			}
			out.write((int) (value & 0x7F) | 0x80);
			value >>>= 7;
		}
		out.write((int) value);
		return out.toByteArray();
	}

	static byte[] bytes(byte[] ... parts) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (byte[] part : parts) {
			out.writeBytes(part);
		}
		return out.toByteArray();
	}

	/** An event: its size, which counts the size itself, the type and the payload */
	private static byte[] eventBytes(long typeId, byte[] payload) {
		byte[] rest = bytes(varint(typeId), payload);
		int size = rest.length + 1;
		while (size != rest.length + varint(size).length) {
			size = rest.length + varint(size).length;
		}
		return bytes(varint(size), rest);
	}

	/** The metadata event: the string table, then the element tree referring to it by index */
	private byte[] metadataEvent() {
		ByteArrayOutputStream tree = new ByteArrayOutputStream();
		writeElement(tree, "root", List.of(), 2);
		writeElement(tree, "metadata", List.of(), classes.size());
		for (byte[] element : classes) {
			tree.writeBytes(element);
		}
		writeElement(tree, "region", List.of(), 0);
		ByteArrayOutputStream payload = new ByteArrayOutputStream();
		payload.writeBytes(varint(0)); // start time
		payload.writeBytes(varint(0)); // duration
		payload.writeBytes(varint(0)); // metadata id
		payload.writeBytes(varint(table.size()));
		for (String s : table) {
			payload.writeBytes(string(s));
		}
		payload.writeBytes(tree.toByteArray());
		return eventBytes(0, payload.toByteArray());
	}

	/** An element: its name, the attributes as key and value pairs, and the number of children */
	private void writeElement(ByteArrayOutputStream out, String name, List<String> attributes, int children) {
		out.writeBytes(varint(index(name)));
		out.writeBytes(varint(attributes.size() / 2));
		for (String attribute : attributes) {
			out.writeBytes(varint(index(attribute)));
		}
		out.writeBytes(varint(children));
	}

	private int index(String s) {
		Integer index = indexes.get(s);
		if (index == null) {
			index = table.size();
			table.add(s);
			indexes.put(s, index);
		}
		return index;
	}
}
