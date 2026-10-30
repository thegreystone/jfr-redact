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
import java.util.List;

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

	private final List<Type> types = new ArrayList<>();
	private final List<Type> eventTypes = new ArrayList<>();
	private final List<Type> poolTypes = new ArrayList<>();

	private LegacyMetadata() {
	}

	static ChunkTypes read(RecordingStream stream) throws IOException {
		stream.skip(4); // size
		int eventType = stream.readRawInt();
		if (eventType != 0) {
			throw new IOException("Expected metadata event, found event type " + eventType);
		}
		LegacyMetadata metadata = new LegacyMetadata();
		int producerCount = stream.readRawInt();
		for (int i = 0; i < producerCount; i++) {
			metadata.readProducer(stream);
		}
		metadata.addBufferLostEventType();
		return new ChunkTypes(true, metadata.types, metadata.eventTypes, metadata.poolTypes);
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
			struct.fields = readStructFields(stream, structBase, structCount);
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
			int[] structFields = getStruct(stream.readRawInt(), structBase, structCount).fields;
			stream.skip(4); // unused

			int[] header = new int[4];
			int headerLength = 0;
			header[headerLength++] = KIND_FIXED8; // end time
			if (hasStartTime) {
				header[headerLength++] = KIND_FIXED8;
			}
			if (hasThread) {
				header[headerLength++] = KIND_FIXED4;
			}
			if (hasStackTrace) {
				header[headerLength++] = KIND_FIXED8;
			}
			Type event = add(id, path, 0);
			event.fields = new int[headerLength + structFields.length];
			System.arraycopy(header, 0, event.fields, 0, headerLength);
			System.arraycopy(structFields, 0, event.fields, headerLength, structFields.length);
			eventTypes.add(event);
		}

		int contentTypeCount = stream.readRawInt();
		for (int i = 0; i < contentTypeCount; i++) {
			int id = stream.readRawInt();
			String name = readUtf(stream);
			skipUtf(stream); // description
			int keyKind = primitiveKind(stream.read());
			Type pool = add(id, name, keyKind);
			pool.fields = getStruct(stream.readRawInt(), structBase, structCount).fields;
			poolTypes.add(pool);
		}
	}

	private int[] readStructFields(RecordingStream stream, int structBase, int structCount) throws IOException {
		int[] ops = new int[stream.readRawInt()];
		for (int i = 0; i < ops.length; i++) {
			skipUtf(stream); // id
			skipUtf(stream); // name
			skipUtf(stream); // description
			stream.skip(1); // transition
			int dataType = stream.read();
			stream.skip(4); // content type
			int structIndex = stream.readRawInt();
			stream.skip(4); // unused
			ops[i] = switch (dataType) {
			case DATA_TYPE_ARRAY -> primitiveKind(structIndex) | ARRAY_FLAG;
			case DATA_TYPE_STRUCT -> structOp(structIndex, structBase, structCount);
			case DATA_TYPE_STRUCT_ARRAY -> structOp(structIndex, structBase, structCount) | ARRAY_FLAG;
			default -> primitiveKind(dataType);
			};
		}
		return ops;
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
			throw new IOException("Invalid data structure index " + structIndex);
		}
	}

	private static int primitiveKind(int dataType) throws IOException {
		if (dataType < 0 || dataType >= PRIMITIVE_KINDS.length) {
			throw new IOException("Unexpected data type " + dataType);
		}
		return PRIMITIVE_KINDS[dataType];
	}

	private static String readUtf(RecordingStream stream) {
		int length = stream.readRawShort() & 0xFFFF;
		String s = new String(stream.array(), stream.position(), length, StandardCharsets.UTF_8);
		stream.skip(length);
		return s;
	}

	private static void skipUtf(RecordingStream stream) {
		stream.skip(stream.readRawShort() & 0xFFFF);
	}
}
