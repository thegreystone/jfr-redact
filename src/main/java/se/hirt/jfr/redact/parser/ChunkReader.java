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

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

/**
 * Reads a recording one chunk at a time into a reusable buffer, and compiles the chunk metadata.
 * Supports JFR 0.9 (JDK 7 and 8) and JFR 1.0+ with compressed integers (JDK 11+ and 8u262+). Not
 * thread-safe.
 */
public final class ChunkReader {
	private static final int MAGIC = 0x464C5200; // "FLR\0"
	/** Magic and version, common to all versions */
	private static final int PREAMBLE_SIZE = 8;
	/** Preamble and metadata offset */
	public static final int LEGACY_HEADER_SIZE = 16;
	private static final int MAX_CHUNK_SIZE = Integer.MAX_VALUE - 8;

	private final RecordingStream stream = new RecordingStream();
	private byte[] buffer = new byte[1 << 20];
	private ReadableByteChannel channel;
	private int chunkIndex;

	private ChunkTypes types;
	private boolean legacy;
	private int size;
	private int headerSize;
	private int metadataOffset;
	private long constantPoolOffset;
	private int legacyPreviousCheckpointPosition;

	/**
	 * Starts reading chunks from the channel, which is not closed by the reader.
	 */
	public void reset(ReadableByteChannel channel) {
		this.channel = channel;
		this.chunkIndex = 0;
	}

	/**
	 * Reads the next chunk, after which the accessors describe it.
	 *
	 * @return {@code false} at the end of the recording
	 */
	public boolean next() throws IOException {
		if (!readFully(0, PREAMBLE_SIZE, true)) {
			return false;
		}
		chunkIndex++;
		stream.reset(buffer, PREAMBLE_SIZE);
		int magic = stream.readRawInt();
		if (magic != MAGIC) {
			throw new IOException(String.format("Not a JFR chunk, bad magic 0x%08X in chunk %d", magic, chunkIndex));
		}
		short major = stream.readRawShort();
		short minor = stream.readRawShort();
		if (major == 0 && minor == 9) {
			readLegacyChunk();
		} else if (major == 1 || major == 2) {
			readChunk(major, minor);
		} else {
			throw new IOException("Unsupported JFR version " + major + "." + minor);
		}
		return true;
	}

	private void readChunk(short major, short minor) throws IOException {
		readFully(PREAMBLE_SIZE, ChunkHeader.SIZE - PREAMBLE_SIZE, false);
		stream.reset(buffer, ChunkHeader.SIZE);
		stream.position(PREAMBLE_SIZE);
		ChunkHeader header = new ChunkHeader(stream, major, minor);
		if (!header.compressedInts) {
			throw new IOException("JFR " + major + "." + minor + " without compressed integers is not supported");
		}
		if (header.size < ChunkHeader.SIZE || header.size > MAX_CHUNK_SIZE) {
			throw new IOException("Unsupported size " + header.size + " of chunk " + chunkIndex
					+ (header.size == 0 ? " (recording still in progress?)" : ""));
		}
		int chunkSize = (int) header.size;
		if (header.metadataOffset < ChunkHeader.SIZE || header.metadataOffset >= chunkSize) {
			throw new IOException("Invalid metadata offset " + header.metadataOffset + " in chunk " + chunkIndex);
		}
		ensureCapacity(chunkSize, ChunkHeader.SIZE);
		readFully(ChunkHeader.SIZE, chunkSize - ChunkHeader.SIZE, false);
		stream.reset(buffer, chunkSize);

		stream.position((int) header.metadataOffset);
		types = ChunkTypes.fromMetadata(new ChunkMetadata(stream));
		legacy = false;
		size = chunkSize;
		headerSize = ChunkHeader.SIZE;
		metadataOffset = (int) header.metadataOffset;
		constantPoolOffset = header.constantPoolOffset;
	}

	/**
	 * A JFR 0.9 chunk has no size in its header. The metadata event is last, and its size gives the
	 * end of the chunk.
	 */
	private void readLegacyChunk() throws IOException {
		readFully(PREAMBLE_SIZE, LEGACY_HEADER_SIZE - PREAMBLE_SIZE, false);
		stream.reset(buffer, LEGACY_HEADER_SIZE);
		stream.position(PREAMBLE_SIZE);
		long offset = stream.readRawLong();
		if (offset < LEGACY_HEADER_SIZE || offset > MAX_CHUNK_SIZE - 4) {
			throw new IOException("Invalid metadata offset " + offset + " in chunk " + chunkIndex);
		}
		int metadataStart = (int) offset;
		ensureCapacity(metadataStart + 4, LEGACY_HEADER_SIZE);
		readFully(LEGACY_HEADER_SIZE, metadataStart + 4 - LEGACY_HEADER_SIZE, false);
		stream.reset(buffer, metadataStart + 4);
		stream.position(metadataStart);
		long chunkSize = offset + stream.readRawInt();
		if (chunkSize <= metadataStart + 4 || chunkSize > MAX_CHUNK_SIZE) {
			throw new IOException("Invalid metadata size at offset " + metadataStart + " in chunk " + chunkIndex);
		}
		ensureCapacity((int) chunkSize, metadataStart + 4);
		readFully(metadataStart + 4, (int) chunkSize - metadataStart - 4, false);
		stream.reset(buffer, (int) chunkSize);

		stream.position(metadataStart);
		types = LegacyMetadata.read(stream);
		// The metadata ends with start time, end time, start ticks, ticks per second and the offset
		// of the last checkpoint
		legacyPreviousCheckpointPosition = stream.position() + 4 * 8;
		stream.position(legacyPreviousCheckpointPosition);
		constantPoolOffset = stream.readRawLong();
		legacy = true;
		size = (int) chunkSize;
		headerSize = LEGACY_HEADER_SIZE;
		metadataOffset = metadataStart;
	}

	/** The stream over the current chunk, from offset 0 to {@link #size()} */
	public RecordingStream stream() {
		return stream;
	}

	public ChunkTypes types() {
		return types;
	}

	/** True for JFR 0.9 */
	public boolean legacy() {
		return legacy;
	}

	public int chunkIndex() {
		return chunkIndex;
	}

	public int size() {
		return size;
	}

	/** Offset of the first event */
	public int headerSize() {
		return headerSize;
	}

	public int metadataOffset() {
		return metadataOffset;
	}

	/**
	 * Offset of the checkpoint the chunk header (JFR 1.0+) or the metadata (JFR 0.9) points to, 0 if
	 * none
	 */
	public long constantPoolOffset() {
		return constantPoolOffset;
	}

	/** JFR 0.9: offset of the last checkpoint offset field inside the metadata event */
	public int legacyPreviousCheckpointPosition() {
		return legacyPreviousCheckpointPosition;
	}

	private void ensureCapacity(int capacity, int preserve) {
		if (buffer.length < capacity) {
			byte[] grown = new byte[Math.max(capacity, (int) Math.min(MAX_CHUNK_SIZE, buffer.length * 2L))];
			System.arraycopy(buffer, 0, grown, 0, preserve);
			buffer = grown;
		}
	}

	private boolean readFully(int offset, int length, boolean eofAllowed) throws IOException {
		ByteBuffer target = ByteBuffer.wrap(buffer, offset, length);
		while (target.hasRemaining()) {
			if (channel.read(target) < 0) {
				if (eofAllowed && target.position() == offset) {
					return false;
				}
				throw new EOFException("Unexpected end of recording");
			}
		}
		return true;
	}
}
