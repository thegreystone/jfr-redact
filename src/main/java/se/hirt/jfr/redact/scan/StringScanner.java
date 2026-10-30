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
package se.hirt.jfr.redact.scan;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

import se.hirt.jfr.redact.parser.ChunkParserListener;
import se.hirt.jfr.redact.parser.ChunkTypes;
import se.hirt.jfr.redact.parser.ChunkTypes.Type;
import se.hirt.jfr.redact.parser.ChunkMetadata;
import se.hirt.jfr.redact.parser.RecordingStream;

/**
 * Collects every string stored in a recording, counting how often each one is stored inline in an
 * event and how often it is stored inside a constant pool (checkpoint event). References to the
 * string constant pool are not occurrences of the string bytes, and are only counted in total.
 * <p>
 * Strings are keyed by their UTF-8 encoding, so the same string stored as UTF-8, Latin-1 or char
 * array is counted as one.
 */
public final class StringScanner implements ChunkParserListener {
	public static final int INLINE = 0;
	public static final int CONSTANT_POOL = 1;

	private static final VarHandle LONG_LE = MethodHandles.byteArrayViewVarHandle(long[].class,
			ByteOrder.LITTLE_ENDIAN);
	private static final byte STRING_ENCODING_NULL = 0;
	private static final byte STRING_ENCODING_EMPTY_STRING = 1;
	private static final byte STRING_ENCODING_CONSTANT_POOL = 2;
	private static final byte STRING_ENCODING_UTF8_BYTE_ARRAY = 3;
	private static final byte STRING_ENCODING_CHAR_ARRAY = 4;
	private static final byte STRING_ENCODING_LATIN1_BYTE_ARRAY = 5;

	private final StringCountMap strings = new StringCountMap();
	private final boolean decodeAllEvents;
	private ChunkTypes types;
	private byte[] scratch = new byte[1024];

	private long chunkCount;
	private long eventCount;
	private long decodedEventCount;
	private long checkpointCount;
	private long constantCount;
	private long constantPoolReferenceCount;
	private long unknownEventCount;
	private long misalignedCount;
	private final long[] occurrences = new long[StringCountMap.CATEGORIES];

	/**
	 * @param decodeAllEvents
	 *            if {@code true}, events that cannot contain inlined strings are decoded anyway
	 *            instead of skipped, which is only useful to validate the decoding
	 */
	public StringScanner(boolean decodeAllEvents) {
		this.decodeAllEvents = decodeAllEvents;
	}

	public StringScanner() {
		this(false);
	}

	@Override
	public void onMetadata(ChunkMetadata metadata) throws IOException {
		chunkCount++;
		types = new ChunkTypes(metadata);
	}

	@Override
	public void onEvent(long typeId, RecordingStream stream, int payloadSize) throws IOException {
		eventCount++;
		Type type = types.getById(typeId);
		if (type == null) {
			unknownEventCount++;
			return;
		}
		if (!type.containsStrings && !decodeAllEvents) {
			return;
		}
		decodedEventCount++;
		int end = stream.position() + payloadSize;
		readFields(stream, type.fields, INLINE);
		if (stream.position() != end) {
			misalignedCount++;
		}
	}

	@Override
	public void onCheckpoint(RecordingStream stream, int payloadSize) throws IOException {
		checkpointCount++;
		int end = stream.position() + payloadSize;
		stream.skipVarint(); // start time
		stream.skipVarint(); // duration
		stream.skipVarint(); // delta to previous checkpoint
		stream.skip(1); // checkpoint type
		int poolCount = (int) stream.readVarint();
		for (int i = 0; i < poolCount; i++) {
			long typeId = stream.readVarint();
			Type type = types.getById(typeId);
			if (type == null) {
				throw new IOException("Constant pool for undeclared type id " + typeId);
			}
			int count = (int) stream.readVarint();
			constantCount += count;
			if (type.isString) {
				for (int j = 0; j < count; j++) {
					stream.skipVarint(); // constant key
					readString(stream, CONSTANT_POOL);
				}
			} else {
				int[] fields = type.fields;
				for (int j = 0; j < count; j++) {
					stream.skipVarint();
					readFields(stream, fields, CONSTANT_POOL);
				}
			}
		}
		if (stream.position() != end) {
			misalignedCount++;
		}
	}

	private void readFields(RecordingStream stream, int[] fields, int category) throws IOException {
		for (int op : fields) {
			if ((op & ChunkTypes.ARRAY_FLAG) == 0) {
				readValue(stream, op, category);
			} else {
				int length = (int) stream.readVarint();
				if ((op & ChunkTypes.KIND_MASK) == ChunkTypes.KIND_BYTE) {
					stream.skip(length);
				} else {
					for (int i = 0; i < length; i++) {
						readValue(stream, op, category);
					}
				}
			}
		}
	}

	private void readValue(RecordingStream stream, int op, int category) throws IOException {
		switch (op & ChunkTypes.KIND_MASK) {
		case ChunkTypes.KIND_BYTE -> stream.skip(1);
		case ChunkTypes.KIND_VARINT -> stream.skipVarint();
		case ChunkTypes.KIND_FLOAT -> stream.skip(4);
		case ChunkTypes.KIND_DOUBLE -> stream.skip(8);
		case ChunkTypes.KIND_STRING -> readString(stream, category);
		default -> readFields(stream, types.getByIndex(op >>> ChunkTypes.TYPE_SHIFT).fields, category);
		}
	}

	private void readString(RecordingStream stream, int category) throws IOException {
		byte encoding = stream.read();
		switch (encoding) {
		case STRING_ENCODING_NULL:
			return;
		case STRING_ENCODING_CONSTANT_POOL:
			stream.skipVarint();
			constantPoolReferenceCount++;
			return;
		case STRING_ENCODING_EMPTY_STRING:
			add(stream.array(), 0, 0, category);
			return;
		case STRING_ENCODING_UTF8_BYTE_ARRAY: {
			int length = readLength(stream);
			add(stream.array(), stream.position(), length, category);
			stream.skip(length);
			return;
		}
		case STRING_ENCODING_LATIN1_BYTE_ARRAY: {
			int length = readLength(stream);
			int offset = stream.position();
			byte[] array = stream.array();
			if (isAscii(array, offset, length)) {
				add(array, offset, length, category);
			} else {
				add(scratch, 0, latin1ToUtf8(array, offset, length), category);
			}
			stream.skip(length);
			return;
		}
		case STRING_ENCODING_CHAR_ARRAY:
			add(scratch, 0, charsToUtf8(stream, readLength(stream)), category);
			return;
		default:
			throw new IOException("Unknown string encoding " + encoding + " at offset " + (stream.position() - 1));
		}
	}

	private void add(byte[] source, int offset, int length, int category) {
		strings.add(source, offset, length, category);
		occurrences[category]++;
	}

	private static int readLength(RecordingStream stream) throws IOException {
		long length = stream.readVarint();
		if (length < 0 || length > stream.limit() - stream.position()) {
			throw new IOException("Invalid string length " + length + " at offset " + stream.position());
		}
		return (int) length;
	}

	private static boolean isAscii(byte[] b, int offset, int length) {
		int i = offset;
		int end = offset + length;
		for (; i <= end - 8; i += 8) {
			if (((long) LONG_LE.get(b, i) & 0x8080808080808080L) != 0) {
				return false;
			}
		}
		for (; i < end; i++) {
			if (b[i] < 0) {
				return false;
			}
		}
		return true;
	}

	private int latin1ToUtf8(byte[] b, int offset, int length) {
		ensureScratch(length * 2);
		byte[] out = scratch;
		int n = 0;
		for (int i = offset; i < offset + length; i++) {
			int c = b[i] & 0xFF;
			if (c < 0x80) {
				out[n++] = (byte) c;
			} else {
				out[n++] = (byte) (0xC0 | (c >> 6));
				out[n++] = (byte) (0x80 | (c & 0x3F));
			}
		}
		return n;
	}

	private int charsToUtf8(RecordingStream stream, int length) {
		ensureScratch(length * 3);
		byte[] out = scratch;
		int n = 0;
		int highSurrogate = -1;
		for (int i = 0; i < length; i++) {
			char c = (char) stream.readVarint();
			if (highSurrogate >= 0) {
				if (Character.isLowSurrogate(c)) {
					int codePoint = Character.toCodePoint((char) highSurrogate, c);
					out[n++] = (byte) (0xF0 | (codePoint >> 18));
					out[n++] = (byte) (0x80 | ((codePoint >> 12) & 0x3F));
					out[n++] = (byte) (0x80 | ((codePoint >> 6) & 0x3F));
					out[n++] = (byte) (0x80 | (codePoint & 0x3F));
					highSurrogate = -1;
					continue;
				}
				n = putChar(out, n, (char) highSurrogate);
				highSurrogate = -1;
			}
			if (Character.isHighSurrogate(c)) {
				highSurrogate = c;
			} else {
				n = putChar(out, n, c);
			}
		}
		if (highSurrogate >= 0) {
			n = putChar(out, n, (char) highSurrogate);
		}
		return n;
	}

	private static int putChar(byte[] out, int n, char c) {
		if (c < 0x80) {
			out[n++] = (byte) c;
		} else if (c < 0x800) {
			out[n++] = (byte) (0xC0 | (c >> 6));
			out[n++] = (byte) (0x80 | (c & 0x3F));
		} else {
			out[n++] = (byte) (0xE0 | (c >> 12));
			out[n++] = (byte) (0x80 | ((c >> 6) & 0x3F));
			out[n++] = (byte) (0x80 | (c & 0x3F));
		}
		return n;
	}

	private void ensureScratch(int size) {
		if (scratch.length < size) {
			scratch = new byte[Math.max(size, scratch.length * 2)];
		}
	}

	public StringCountMap getStrings() {
		return strings;
	}

	public long getChunkCount() {
		return chunkCount;
	}

	public long getEventCount() {
		return eventCount;
	}

	public long getDecodedEventCount() {
		return decodedEventCount;
	}

	public long getCheckpointCount() {
		return checkpointCount;
	}

	public long getConstantCount() {
		return constantCount;
	}

	public long getConstantPoolReferenceCount() {
		return constantPoolReferenceCount;
	}

	public long getUnknownEventCount() {
		return unknownEventCount;
	}

	/**
	 * @return the number of events and checkpoints where the decoded size did not match the declared
	 *         size, which should always be zero for well formed recordings
	 */
	public long getMisalignedCount() {
		return misalignedCount;
	}

	public long getOccurrenceCount(int category) {
		return occurrences[category];
	}
}
