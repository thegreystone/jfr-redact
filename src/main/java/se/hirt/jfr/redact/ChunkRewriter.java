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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import se.hirt.jfr.redact.parser.ChunkReader;
import se.hirt.jfr.redact.parser.ChunkTypes;
import se.hirt.jfr.redact.parser.ChunkTypes.Type;
import se.hirt.jfr.redact.parser.RecordingStream;
import se.hirt.jfr.redact.scan.StringCountMap;
import se.hirt.jfr.redact.internal.ChunkEvent;
import se.hirt.jfr.redact.internal.Utf8;

/**
 * Second redaction pass: writes the recording with the strings replaced. Chunks without replaced
 * strings are copied verbatim. In other chunks, events and checkpoints containing replaced strings
 * are re-encoded, everything in between is copied, and the offsets that moved are updated: the
 * chunk header and the checkpoint chain for JFR 1.0+, and the metadata offset and checkpoint chain
 * for JFR 0.9.
 */
final class ChunkRewriter {
	private static final long METADATA_TYPE = 0;
	private static final long CHECKPOINT_TYPE = 1;
	private static final int HEADER_SIZE_OFFSET = 8;
	private static final int HEADER_CONSTANT_POOL_OFFSET = 16;
	private static final int HEADER_METADATA_OFFSET = 24;
	private static final int LEGACY_HEADER_METADATA_OFFSET = 8;

	private final ChunkReader reader = new ChunkReader();
	private final StringDecoder decoder = new StringDecoder();
	/** Only the strings to replace */
	private final StringCountMap strings;
	private final String[] replacements;
	/** Per checkpoint in recording order, whether it stores a string to replace */
	private final boolean[] changedCheckpoints;
	private int checkpointOrdinal;
	/** Names of the event types storing strings to replace inline */
	private final Set<String> changedEventTypes;
	/**
	 * Per type index in the current chunk, whether events of the type may store strings to replace
	 */
	private boolean[] changedTypes;
	/** Encoded replacements per kind, created on demand */
	private final byte[][] encodedStrings;
	private final byte[][] encodedUtf8;
	private final byte[][] encodedUtf16;

	private ChunkTypes types;
	private boolean legacy;
	private RecordingStream stream;
	private byte[] in;

	private byte[] out = new byte[1 << 20];
	private int outSize;
	/** Start of the input not yet copied to the output */
	private int spanStart;
	private boolean chunkRewritten;
	private final Map<Integer, Integer> checkpointOffsets = new HashMap<>();

	private int[] patchStarts = new int[64];
	private int[] patchEnds = new int[64];
	private byte[][] patchBytes = new byte[64][];
	private int patchCount;

	private long chunkCount;
	private long rewrittenChunkCount;
	private long rewrittenEventCount;
	private long rewrittenCheckpointCount;
	private long replacedCount;

	/**
	 * @param strings
	 *            the strings to replace
	 * @param replacements
	 *            per string entry, the replacement
	 * @param changedCheckpoints
	 *            per checkpoint in recording order, whether it stores a string to replace: the
	 *            checkpoints are rewritten by this alone, every pool of a changed checkpoint
	 *            re-encoded
	 * @param changedEventTypes
	 *            the event types storing a string to replace inline, the only events decoded
	 */
	ChunkRewriter(StringCountMap strings, String[] replacements, boolean[] changedCheckpoints,
			Set<String> changedEventTypes) {
		this.strings = strings;
		this.replacements = replacements;
		this.changedCheckpoints = changedCheckpoints;
		this.changedEventTypes = changedEventTypes;
		this.encodedStrings = new byte[replacements.length][];
		this.encodedUtf8 = new byte[replacements.length][];
		this.encodedUtf16 = new byte[replacements.length][];
	}

	void rewrite(ReadableByteChannel input, WritableByteChannel output) throws IOException {
		reader.reset(input);
		while (true) {
			ChunkEvent event = new ChunkEvent(ChunkEvent.REWRITE);
			event.begin();
			if (!reader.next()) {
				break;
			}
			chunkCount++;
			types = reader.types();
			legacy = reader.legacy();
			stream = reader.stream();
			in = stream.array();
			outSize = 0;
			spanStart = 0;
			chunkRewritten = false;
			checkpointOffsets.clear();
			changedTypes = new boolean[types.size()];
			for (int i = 0; i < types.size(); i++) {
				changedTypes[i] = changedEventTypes.contains(types.getByIndex(i).name);
			}
			if (legacy) {
				rewriteLegacyChunk();
			} else {
				rewriteChunk();
			}
			if (chunkRewritten) {
				rewrittenChunkCount++;
				write(output, out, outSize);
			} else {
				write(output, in, reader.size());
			}
			if (event.shouldCommit()) {
				event.index = reader.chunkIndex();
				event.size = reader.size();
				event.legacy = legacy;
				event.rewritten = chunkRewritten;
				event.outputSize = chunkRewritten ? outSize : reader.size();
				event.commit();
			}
		}
	}

	private void rewriteChunk() throws IOException {
		int size = reader.size();
		int metadataOffset = reader.metadataOffset();
		int newMetadataOffset = metadataOffset;
		int eventStart = reader.headerSize();
		while (eventStart < size) {
			stream.position(eventStart);
			int eventEnd = eventStart + (int) stream.readVarint();
			int sizeLength = stream.position() - eventStart;
			long eventType = stream.readVarint();
			if (eventType == METADATA_TYPE) {
				if (eventStart == metadataOffset) {
					newMetadataOffset = outputPosition(eventStart);
				}
			} else if (eventType == CHECKPOINT_TYPE) {
				rewriteCheckpoint(eventStart, sizeLength, eventEnd);
			} else {
				rewriteEvent(eventType, eventStart, sizeLength, eventEnd);
			}
			eventStart = eventEnd;
		}
		if (chunkRewritten) {
			flush(size);
			putLong(HEADER_SIZE_OFFSET, outSize);
			putLong(HEADER_CONSTANT_POOL_OFFSET, newCheckpointOffset(reader.constantPoolOffset()));
			putLong(HEADER_METADATA_OFFSET, newMetadataOffset);
		}
	}

	private void rewriteLegacyChunk() throws IOException {
		int metadataOffset = reader.metadataOffset();
		int eventStart = reader.headerSize();
		while (eventStart < metadataOffset) {
			stream.position(eventStart);
			int eventEnd = eventStart + stream.readRawInt();
			long eventType = stream.readRawInt();
			if (eventType == CHECKPOINT_TYPE) {
				rewriteLegacyCheckpoint(eventStart, eventEnd);
			} else if (eventType != METADATA_TYPE) {
				rewriteEvent(eventType, eventStart, 4, eventEnd);
			}
			eventStart = eventEnd;
		}
		if (chunkRewritten) {
			int newMetadataOffset = outputPosition(metadataOffset);
			flush(reader.size());
			putLong(LEGACY_HEADER_METADATA_OFFSET, newMetadataOffset);
			putLong(newMetadataOffset + reader.legacyPreviousCheckpointPosition() - metadataOffset,
					newCheckpointOffset(reader.constantPoolOffset()));
		}
	}

	private void rewriteEvent(long eventType, int eventStart, int sizeLength, int eventEnd) throws IOException {
		Type type = types.getEventType(eventType);
		if (type == null) {
			throw new InvalidRecordingException(
					"Event of undeclared type " + eventType + ", cannot guarantee a complete redaction");
		}
		if (!type.containsStrings || !changedTypes[type.index]) {
			return;
		}
		patchCount = 0;
		collect(type);
		checkEnd(eventEnd);
		if (patchCount > 0) {
			replacedCount += patchCount;
			rewrittenEventCount++;
			emit(eventStart, sizeLength, eventEnd);
		}
	}

	private void rewriteCheckpoint(int eventStart, int sizeLength, int eventEnd) throws IOException {
		stream.skipVarint(); // start time
		stream.skipVarint(); // duration
		int deltaStart = stream.position();
		long delta = stream.readVarint();
		int deltaEnd = stream.position();
		stream.skip(1); // checkpoint type

		patchCount = 0;
		int newStart = outputPosition(eventStart);
		long newDelta = delta == 0 ? 0 : newCheckpointOffset(eventStart + delta) - newStart;
		int deltaPatches = 0;
		if (newDelta != delta) {
			addPatch(deltaStart, deltaEnd, encodeVarint(newDelta, deltaEnd - deltaStart));
			deltaPatches = 1;
		}
		if (changedCheckpoints[checkpointOrdinal++]) {
			int poolCount = (int) stream.readVarint();
			for (int i = 0; i < poolCount; i++) {
				Type type = types.getPoolType(stream.readVarint());
				int count = (int) stream.readVarint();
				for (int j = 0; j < count; j++) {
					stream.skipVarint(); // key
					if (type.isString) {
						string(ChunkTypes.KIND_STRING);
					} else {
						collect(type);
					}
				}
			}
			checkEnd(eventEnd);
		}
		checkpointOffsets.put(eventStart, newStart);
		if (patchCount > 0) {
			replacedCount += patchCount - deltaPatches;
			rewrittenCheckpointCount++;
			emit(eventStart, sizeLength, eventEnd);
		}
	}

	private void rewriteLegacyCheckpoint(int eventStart, int eventEnd) throws IOException {
		stream.skip(8); // timestamp
		int previousStart = stream.position();
		long previous = stream.readRawLong();

		patchCount = 0;
		int newStart = outputPosition(eventStart);
		long newPrevious = newCheckpointOffset(previous);
		int previousPatches = 0;
		if (newPrevious != previous) {
			addPatch(previousStart, previousStart + 8, longBytes(newPrevious));
			previousPatches = 1;
		}
		if (changedCheckpoints[checkpointOrdinal++]) {
			while (stream.position() < eventEnd) {
				Type type = types.getPoolType(stream.readRawInt());
				int count = stream.readRawInt();
				int keySize = ChunkTypes.fixedSize(type.keyKind);
				for (int j = 0; j < count; j++) {
					stream.skip(keySize);
					collect(type);
				}
			}
			checkEnd(eventEnd);
		}
		checkpointOffsets.put(eventStart, newStart);
		if (patchCount > 0) {
			replacedCount += patchCount - previousPatches;
			rewrittenCheckpointCount++;
			emit(eventStart, 4, eventEnd);
		}
	}

	/** Walks the fields of a value, adding a patch for every string to replace */
	private void collect(Type type) throws IOException {
		for (int op : type.fields) {
			if ((op & ChunkTypes.ARRAY_FLAG) == 0) {
				collectValue(op);
			} else {
				int length = legacy ? stream.readRawInt() : (int) stream.readVarint();
				int fixedSize = ChunkTypes.fixedSize(op & ChunkTypes.KIND_MASK);
				if (fixedSize > 0) {
					stream.skip(length * fixedSize);
				} else {
					for (int i = 0; i < length; i++) {
						collectValue(op);
					}
				}
			}
		}
	}

	private void collectValue(int op) throws IOException {
		int kind = op & ChunkTypes.KIND_MASK;
		switch (kind) {
		case ChunkTypes.KIND_FIXED1 -> stream.skip(1);
		case ChunkTypes.KIND_FIXED2 -> stream.skip(2);
		case ChunkTypes.KIND_FIXED4 -> stream.skip(4);
		case ChunkTypes.KIND_FIXED8 -> stream.skip(8);
		case ChunkTypes.KIND_VARINT -> stream.skipVarint();
		case ChunkTypes.KIND_STRING, ChunkTypes.KIND_UTF8, ChunkTypes.KIND_UTF16 -> string(kind);
		case ChunkTypes.KIND_STRUCT -> collect(types.getByIndex(op >>> ChunkTypes.TYPE_SHIFT));
		default -> throw new InvalidRecordingException("Unexpected field kind " + kind);
		}
	}

	private void string(int kind) throws IOException {
		int start = stream.position();
		if (decoder.read(stream, kind) != StringDecoder.STRING) {
			return;
		}
		int entry = strings.find(decoder.array, decoder.offset, decoder.length);
		if (entry >= 0) {
			addPatch(start, stream.position(), encoded(entry, kind));
		}
	}

	private byte[] encoded(int entry, int kind) throws IOException {
		switch (kind) {
		case ChunkTypes.KIND_UTF8: {
			if (encodedUtf8[entry] == null) {
				if (Utf8.hasUnpairedSurrogate(replacements[entry])) {
					throw new IOException("Unpaired surrogate in replacement for a JFR 0.9 UTF-8 string");
				}
				byte[] utf8 = replacements[entry].getBytes(StandardCharsets.UTF_8);
				if (utf8.length > 0xFFFF) {
					throw new IOException("Replacement too long for a JFR 0.9 string: " + utf8.length + " bytes");
				}
				byte[] encoded = new byte[2 + utf8.length];
				encoded[0] = (byte) (utf8.length >> 8);
				encoded[1] = (byte) utf8.length;
				System.arraycopy(utf8, 0, encoded, 2, utf8.length);
				encodedUtf8[entry] = encoded;
			}
			return encodedUtf8[entry];
		}
		case ChunkTypes.KIND_UTF16: {
			if (encodedUtf16[entry] == null) {
				String s = replacements[entry];
				ByteBuffer encoded = ByteBuffer.allocate(4 + s.length() * 2);
				encoded.putInt(s.length());
				for (int i = 0; i < s.length(); i++) {
					encoded.putChar(s.charAt(i));
				}
				encodedUtf16[entry] = encoded.array();
			}
			return encodedUtf16[entry];
		}
		default: {
			if (encodedStrings[entry] == null) {
				String replacement = replacements[entry];
				if (Utf8.hasUnpairedSurrogate(replacement)) {
					encodedStrings[entry] = encodeChars(replacement);
				} else {
					byte[] utf8 = replacement.getBytes(StandardCharsets.UTF_8);
					if (utf8.length == 0) {
						encodedStrings[entry] = new byte[] {1};
					} else {
						byte[] length = encodeVarint(utf8.length, 1);
						byte[] encoded = new byte[1 + length.length + utf8.length];
						encoded[0] = 3;
						System.arraycopy(length, 0, encoded, 1, length.length);
						System.arraycopy(utf8, 0, encoded, 1 + length.length, utf8.length);
						encodedStrings[entry] = encoded;
					}
				}
			}
			return encodedStrings[entry];
		}
		}
	}

	/** Uses JFR's char-array encoding to preserve every UTF-16 code unit. */
	private static byte[] encodeChars(String value) {
		ByteArrayOutputStream encoded = new ByteArrayOutputStream(value.length());
		encoded.write(4);
		encoded.writeBytes(encodeVarint(value.length(), 1));
		for (int i = 0; i < value.length(); i++) {
			int c = value.charAt(i);
			while (c >= 0x80) {
				encoded.write((c & 0x7F) | 0x80);
				c >>>= 7;
			}
			encoded.write(c);
		}
		return encoded.toByteArray();
	}

	private void addPatch(int start, int end, byte[] bytes) {
		if (patchCount == patchStarts.length) {
			int capacity = patchCount * 2;
			patchStarts = Arrays.copyOf(patchStarts, capacity);
			patchEnds = Arrays.copyOf(patchEnds, capacity);
			patchBytes = Arrays.copyOf(patchBytes, capacity);
		}
		patchStarts[patchCount] = start;
		patchEnds[patchCount] = end;
		patchBytes[patchCount] = bytes;
		patchCount++;
	}

	/**
	 * Writes the event in {@code [eventStart, eventEnd)} with the patches applied, and a new size.
	 * The size keeps its encoded width if it fits, as the JDK pads event sizes.
	 */
	private void emit(int eventStart, int sizeLength, int eventEnd) {
		flush(eventStart);
		chunkRewritten = true;
		int growth = 0;
		for (int i = 0; i < patchCount; i++) {
			growth += patchBytes[i].length - (patchEnds[i] - patchStarts[i]);
		}
		int body = eventEnd - eventStart - sizeLength + growth;
		if (legacy) {
			ensureOut(4);
			putInt(outSize, body + 4);
			outSize += 4;
		} else {
			int width = sizeLength;
			while (!fits(body + width, width)) {
				width++;
			}
			writeBytes(encodeVarint(body + width, width));
		}
		int cursor = eventStart + sizeLength;
		for (int i = 0; i < patchCount; i++) {
			copy(cursor, patchStarts[i]);
			writeBytes(patchBytes[i]);
			cursor = patchEnds[i];
		}
		copy(cursor, eventEnd);
		spanStart = eventEnd;
	}

	/** The output offset of an input offset at or after {@link #spanStart} */
	private int outputPosition(int inputPosition) {
		return outSize + (inputPosition - spanStart);
	}

	private long newCheckpointOffset(long oldOffset) throws IOException {
		if (oldOffset == 0) {
			return 0;
		}
		Integer newOffset = checkpointOffsets.get((int) oldOffset);
		if (newOffset == null) {
			throw new InvalidRecordingException("Reference to an unknown or later checkpoint at offset " + oldOffset);
		}
		return newOffset;
	}

	private void checkEnd(int end) throws IOException {
		if (stream.position() != end) {
			throw new InvalidRecordingException("Event at offset " + end + " did not decode to its declared size");
		}
	}

	private void flush(int upTo) {
		copy(spanStart, upTo);
		spanStart = upTo;
	}

	private void copy(int from, int to) {
		int length = to - from;
		ensureOut(length);
		System.arraycopy(in, from, out, outSize, length);
		outSize += length;
	}

	private void writeBytes(byte[] bytes) {
		ensureOut(bytes.length);
		System.arraycopy(bytes, 0, out, outSize, bytes.length);
		outSize += bytes.length;
	}

	private void ensureOut(int length) {
		if (outSize + length > out.length) {
			out = Arrays.copyOf(out, Math.max(outSize + length, out.length * 2));
		}
	}

	private void putLong(int offset, long value) {
		for (int i = 7; i >= 0; i--) {
			out[offset + i] = (byte) value;
			value >>>= 8;
		}
	}

	private void putInt(int offset, int value) {
		out[offset] = (byte) (value >>> 24);
		out[offset + 1] = (byte) (value >>> 16);
		out[offset + 2] = (byte) (value >>> 8);
		out[offset + 3] = (byte) value;
	}

	private static byte[] longBytes(long value) {
		return ByteBuffer.allocate(8).putLong(value).array();
	}

	private static boolean fits(long value, int width) {
		return width >= 9 || (value >= 0 && value < (1L << (7 * width)));
	}

	/**
	 * Encodes the value as a LEB128 varint of at least {@code minWidth} bytes, padding with
	 * continuation bytes, as readers accept padded varints.
	 */
	static byte[] encodeVarint(long value, int minWidth) {
		int width = Math.max(minWidth, 1);
		while (!fits(value, width)) {
			width++;
		}
		byte[] bytes = new byte[width];
		long v = value;
		for (int i = 0; i < width - 1; i++) {
			bytes[i] = (byte) ((v & 0x7F) | 0x80);
			v >>>= 7;
		}
		bytes[width - 1] = (byte) (width == 9 ? v : v & 0x7F);
		return bytes;
	}

	private static void write(WritableByteChannel channel, byte[] bytes, int length) throws IOException {
		ByteBuffer buffer = ByteBuffer.wrap(bytes, 0, length);
		while (buffer.hasRemaining()) {
			channel.write(buffer);
		}
	}

	long getChunkCount() {
		return chunkCount;
	}

	long getRewrittenChunkCount() {
		return rewrittenChunkCount;
	}

	long getRewrittenEventCount() {
		return rewrittenEventCount;
	}

	long getRewrittenCheckpointCount() {
		return rewrittenCheckpointCount;
	}

	long getReplacedCount() {
		return replacedCount;
	}
}
