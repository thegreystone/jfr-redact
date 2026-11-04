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
package se.hirt.jfr.redact.parser;

import static se.hirt.jfr.redact.parser.ChunkTypes.ARRAY_FLAG;
import static se.hirt.jfr.redact.parser.ChunkTypes.KIND_FIXED1;
import static se.hirt.jfr.redact.parser.ChunkTypes.KIND_FIXED2;
import static se.hirt.jfr.redact.parser.ChunkTypes.KIND_FIXED4;
import static se.hirt.jfr.redact.parser.ChunkTypes.KIND_FIXED8;
import static se.hirt.jfr.redact.parser.ChunkTypes.KIND_STRUCT;
import static se.hirt.jfr.redact.parser.ChunkTypes.KIND_UTF16;
import static se.hirt.jfr.redact.parser.ChunkTypes.KIND_UTF8;
import static se.hirt.jfr.redact.parser.ChunkTypes.TYPE_SHIFT;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import se.hirt.jfr.redact.InvalidRecordingException;
import se.hirt.jfr.redact.parser.ChunkTypes.Type;

/**
 * Compiles the JFR 0.9 (JDK 7 and 8) chunk metadata into {@link ChunkTypes}.
 * <p>
 * The metadata is a list of producers, each declaring data structures (lists of fields), event
 * types and content types (constant pools), both of which refer to a data structure. Event and
 * content type ids are separate id spaces. All integers are fixed width big-endian.
 */
final class LegacyMetadata {
	private static final int[] PRIMITIVE_KINDS = {KIND_FIXED1, // boolean
			KIND_FIXED1, // byte
			KIND_FIXED1, // u1
			KIND_FIXED2, // short
			KIND_FIXED2, // u2
			KIND_FIXED4, // int
			KIND_FIXED4, // u4
			KIND_FIXED8, // long
			KIND_FIXED8, // u8
			KIND_FIXED4, // float
			KIND_FIXED8, // double
			KIND_UTF8, // UTF-8 string
			KIND_UTF16 // UTF-16 string
	};
	private static final int DATA_TYPE_ARRAY = 13;
	private static final int DATA_TYPE_STRUCT = 14;
	private static final int DATA_TYPE_STRUCT_ARRAY = 15;
	private static final long BUFFER_LOST_EVENT_TYPE = 2;
	private static final int CONTENT_TYPE_NONE = 0;
	private static final int CONTENT_TYPE_THREAD = 7;
	private static final int CONTENT_TYPE_STACK_TRACE = 9;

	private final List<Type> types = new ArrayList<>();
	private final List<Type> eventTypes = new ArrayList<>();
	private final List<Type> poolTypes = new ArrayList<>();
	private final List<String> strings = new ArrayList<>();
	/**
	 * Types whose refTargets hold content type ids until resolved, pools share those of their
	 * struct
	 */
	private final List<Type> unresolvedTypes = new ArrayList<>();

	private LegacyMetadata() {
	}

	static ChunkTypes read(RecordingStream stream) throws IOException {
		stream.skip(4); // size
		int eventType = stream.readRawInt();
		if (eventType != 0) {
			throw new InvalidRecordingException("Expected metadata event, found event type " + eventType);
		}
		LegacyMetadata metadata = new LegacyMetadata();
		int producerCount = stream.readRawInt();
		for (int i = 0; i < producerCount; i++) {
			metadata.readProducer(stream);
		}
		metadata.addBufferLostEventType();
		metadata.resolveReferences();
		ChunkTypes chunkTypes = new ChunkTypes(true, metadata.types, metadata.eventTypes, metadata.poolTypes);
		chunkTypes.setMetadataStrings(metadata.strings.toArray(new String[0]));
		return chunkTypes;
	}

	private void readProducer(RecordingStream stream) throws IOException {
		stream.skip(4); // producer id
		String producerName = readUtf(stream);
		skipUtf(stream); // description
		skipUtf(stream); // URI
		int relationCount = stream.readRawInt();
		for (int i = 0; i < relationCount; i++) {
			skipUtf(stream);
		}

		// Data structure indices are local to the producer
		int structBase = types.size();
		int structCount = stream.readRawInt();
		for (int i = 0; i < structCount; i++) {
			Type struct = add(i, producerName + " struct " + i, 0);
			readStructFields(stream, struct, structBase, structCount);
			unresolvedTypes.add(struct);
		}

		int eventCount = stream.readRawInt();
		for (int i = 0; i < eventCount; i++) {
			int id = stream.readRawInt();
			skipUtf(stream); // name
			skipUtf(stream); // description
			String path = readUtf(stream);
			boolean hasStartTime = stream.read() != 0;
			boolean hasThread = stream.read() != 0;
			boolean hasStackTrace = stream.read() != 0;
			stream.skip(1); // requestable
			Type struct = getStruct(stream.readRawInt(), structBase, structCount);
			stream.skip(4); // unused

			int[] header = new int[4];
			int[] headerContentTypes = new int[4];
			String[] headerNames = new String[4];
			int headerLength = 0;
			headerNames[headerLength] = "endTime";
			header[headerLength++] = KIND_FIXED8;
			if (hasStartTime) {
				headerNames[headerLength] = "startTime";
				header[headerLength++] = KIND_FIXED8;
			}
			if (hasThread) {
				headerNames[headerLength] = "eventThread";
				headerContentTypes[headerLength] = CONTENT_TYPE_THREAD;
				header[headerLength++] = KIND_FIXED4;
			}
			if (hasStackTrace) {
				headerNames[headerLength] = "stackTrace";
				headerContentTypes[headerLength] = CONTENT_TYPE_STACK_TRACE;
				header[headerLength++] = KIND_FIXED8;
			}
			Type event = add(id, path, 0);
			event.fields = concat(header, headerLength, struct.fields);
			event.fieldNames = concat(headerNames, headerLength, struct.fieldNames);
			event.refTargets = concat(headerContentTypes, headerLength, struct.refTargets);
			eventTypes.add(event);
			unresolvedTypes.add(event);
		}

		int contentTypeCount = stream.readRawInt();
		for (int i = 0; i < contentTypeCount; i++) {
			int id = stream.readRawInt();
			String name = readUtf(stream);
			skipUtf(stream); // description
			int keyKind = primitiveKind(stream.read());
			Type pool = add(id, name, keyKind);
			Type struct = getStruct(stream.readRawInt(), structBase, structCount);
			pool.fields = struct.fields;
			pool.fieldNames = struct.fieldNames;
			pool.refTargets = struct.refTargets;
			poolTypes.add(pool);
		}
	}

	private void readStructFields(RecordingStream stream, Type struct, int structBase, int structCount)
			throws IOException {
		int[] ops = new int[stream.readRawInt()];
		String[] names = new String[ops.length];
		int[] contentTypes = new int[ops.length];
		for (int i = 0; i < ops.length; i++) {
			names[i] = readUtf(stream); // id
			skipUtf(stream); // name
			skipUtf(stream); // description
			stream.skip(1); // transition
			int dataType = stream.read();
			contentTypes[i] = stream.readRawInt();
			int structIndex = stream.readRawInt();
			stream.skip(4); // unused
			ops[i] = switch (dataType) {
			case DATA_TYPE_ARRAY -> primitiveKind(structIndex) | ARRAY_FLAG;
			case DATA_TYPE_STRUCT -> structOp(structIndex, structBase, structCount);
			case DATA_TYPE_STRUCT_ARRAY -> structOp(structIndex, structBase, structCount) | ARRAY_FLAG;
			default -> primitiveKind(dataType);
			};
		}
		struct.fields = ops;
		struct.fieldNames = names;
		struct.refTargets = contentTypes;
	}

	/**
	 * Replaces the content type ids with the type index of the constant pool they denote, or -1 for
	 * content types that are units rather than constant pools.
	 */
	private void resolveReferences() {
		Map<Integer, Type> poolsById = new HashMap<>();
		for (Type pool : poolTypes) {
			poolsById.put((int) pool.id, pool);
		}
		for (Type t : unresolvedTypes) {
			int[] targets = t.refTargets;
			for (int i = 0; i < targets.length; i++) {
				Type pool = targets[i] == CONTENT_TYPE_NONE ? null : poolsById.get(targets[i]);
				targets[i] = pool == null ? -1 : pool.index;
			}
		}
	}

	private static int[] concat(int[] head, int headLength, int[] tail) {
		int[] result = new int[headLength + tail.length];
		System.arraycopy(head, 0, result, 0, headLength);
		System.arraycopy(tail, 0, result, headLength, tail.length);
		return result;
	}

	private static String[] concat(String[] head, int headLength, String[] tail) {
		String[] result = new String[headLength + tail.length];
		System.arraycopy(head, 0, result, 0, headLength);
		System.arraycopy(tail, 0, result, headLength, tail.length);
		return result;
	}

	/** The JDK synthesizes this event type without declaring it: thread and number of bytes lost */
	private void addBufferLostEventType() {
		for (Type t : eventTypes) {
			if (t.id == BUFFER_LOST_EVENT_TYPE) {
				return;
			}
		}
		Type bufferLost = add(BUFFER_LOST_EVENT_TYPE, "Buffer Lost", 0);
		bufferLost.fields = new int[] {KIND_FIXED8, KIND_FIXED4, KIND_FIXED4};
		bufferLost.fieldNames = new String[] {"endTime", "eventThread", "bytesLost"};
		eventTypes.add(bufferLost);
	}

	private Type add(long id, String name, int keyKind) {
		Type type = new Type(types.size(), id, name, false, keyKind);
		types.add(type);
		return type;
	}

	private Type getStruct(int structIndex, int structBase, int structCount) throws IOException {
		checkStructIndex(structIndex, structCount);
		return types.get(structBase + structIndex);
	}

	private static int structOp(int structIndex, int structBase, int structCount) throws IOException {
		checkStructIndex(structIndex, structCount);
		return KIND_STRUCT | ((structBase + structIndex) << TYPE_SHIFT);
	}

	private static void checkStructIndex(int structIndex, int structCount) throws IOException {
		if (structIndex < 0 || structIndex >= structCount) {
			throw new InvalidRecordingException("Invalid data structure index " + structIndex);
		}
	}

	private static int primitiveKind(int dataType) throws IOException {
		if (dataType < 0 || dataType >= PRIMITIVE_KINDS.length) {
			throw new InvalidRecordingException("Unexpected data type " + dataType);
		}
		return PRIMITIVE_KINDS[dataType];
	}

	private String readUtf(RecordingStream stream) throws IOException {
		int length = stream.readRawShort() & 0xFFFF;
		int offset = stream.position();
		stream.skip(length);
		String s = new String(stream.array(), offset, length, StandardCharsets.UTF_8);
		strings.add(s);
		return s;
	}

	/** Strings not needed for parsing, kept since they are copies a redaction must know about */
	private void skipUtf(RecordingStream stream) throws IOException {
		readUtf(stream);
	}
}
