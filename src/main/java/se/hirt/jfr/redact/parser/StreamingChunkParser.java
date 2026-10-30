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
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Reads a recording one chunk at a time into a reusable buffer, so memory use is bounded by the
 * largest chunk rather than the recording. The metadata, normally found at the end of the chunk, is
 * reported first, followed by the events and checkpoints in stream order. Supports JFR 0.9 (JDK 7
 * and 8) and JFR 1.0+ with compressed integers (JDK 11+ and 8u262+). Not thread-safe.
 */
public final class StreamingChunkParser {
	private static final int MAGIC = 0x464C5200; // "FLR\0"
	/** Magic and version, common to all versions */
	private static final int PREAMBLE_SIZE = 8;
	/** Preamble and metadata offset */
	private static final int LEGACY_HEADER_SIZE = 16;
	private static final int MAX_CHUNK_SIZE = Integer.MAX_VALUE - 8;
	private static final long METADATA_TYPE = 0;
	private static final long CHECKPOINT_TYPE = 1;

	private final RecordingStream stream = new RecordingStream();
	private byte[] buffer = new byte[1 << 20];

	public void parse(Path path, ChunkParserListener listener) throws IOException {
		try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
			parse(channel, listener);
		}
	}

	/**
	 * Parses the recording read from the channel. The channel is not closed.
	 */
	public void parse(ReadableByteChannel channel, ChunkParserListener listener) throws IOException {
		for (int chunk = 1; readFully(channel, 0, PREAMBLE_SIZE, true); chunk++) {
			stream.reset(buffer, PREAMBLE_SIZE);
			int magic = stream.readRawInt();
			if (magic != MAGIC) {
				throw new IOException(String.format("Not a JFR chunk, bad magic 0x%08X in chunk %d", magic, chunk));
			}
			short major = stream.readRawShort();
			short minor = stream.readRawShort();
			if (major == 0 && minor == 9) {
				parseLegacyChunk(channel, chunk, listener);
			} else if (major == 1 || major == 2) {
				parseChunk(channel, chunk, major, minor, listener);
			} else {
				throw new IOException("Unsupported JFR version " + major + "." + minor);
			}
		}
	}

	private void parseChunk(ReadableByteChannel channel, int chunk, short major, short minor,
			ChunkParserListener listener) throws IOException {
		readFully(channel, PREAMBLE_SIZE, ChunkHeader.SIZE - PREAMBLE_SIZE, false);
		stream.reset(buffer, ChunkHeader.SIZE);
		stream.position(PREAMBLE_SIZE);
		ChunkHeader header = new ChunkHeader(stream, major, minor);
		if (!header.compressedInts) {
			throw new IOException("JFR " + major + "." + minor + " without compressed integers is not supported");
		}
		if (header.size < ChunkHeader.SIZE || header.size > MAX_CHUNK_SIZE) {
			throw new IOException("Unsupported size " + header.size + " of chunk " + chunk
					+ (header.size == 0 ? " (recording still in progress?)" : ""));
		}
		int size = (int) header.size;
		if (header.metadataOffset < ChunkHeader.SIZE || header.metadataOffset >= size) {
			throw new IOException("Invalid metadata offset " + header.metadataOffset + " in chunk " + chunk);
		}
		ensureCapacity(size, ChunkHeader.SIZE);
		readFully(channel, ChunkHeader.SIZE, size - ChunkHeader.SIZE, false);
		stream.reset(buffer, size);

		stream.position((int) header.metadataOffset);
		listener.onTypes(ChunkTypes.fromMetadata(new ChunkMetadata(stream)));

		int eventStart = ChunkHeader.SIZE;
		while (eventStart < size) {
			stream.position(eventStart);
			long eventSize = stream.readVarint();
			if (eventSize <= 0 || eventSize > size - eventStart) {
				throw new IOException("Invalid event size " + eventSize + " at offset " + eventStart + " in chunk "
						+ chunk);
			}
			int eventEnd = eventStart + (int) eventSize;
			dispatch(listener, stream.readVarint(), eventEnd);
			eventStart = eventEnd;
		}
		listener.onChunkEnd();
	}

	/**
	 * A JFR 0.9 chunk has no size in its header. The metadata event is last, and its size gives the
	 * end of the chunk.
	 */
	private void parseLegacyChunk(ReadableByteChannel channel, int chunk, ChunkParserListener listener)
			throws IOException {
		readFully(channel, PREAMBLE_SIZE, LEGACY_HEADER_SIZE - PREAMBLE_SIZE, false);
		stream.reset(buffer, LEGACY_HEADER_SIZE);
		stream.position(PREAMBLE_SIZE);
		long metadataOffset = stream.readRawLong();
		if (metadataOffset < LEGACY_HEADER_SIZE || metadataOffset > MAX_CHUNK_SIZE - 4) {
			throw new IOException("Invalid metadata offset " + metadataOffset + " in chunk " + chunk);
		}
		int metadataStart = (int) metadataOffset;
		ensureCapacity(metadataStart + 4, LEGACY_HEADER_SIZE);
		readFully(channel, LEGACY_HEADER_SIZE, metadataStart + 4 - LEGACY_HEADER_SIZE, false);
		stream.reset(buffer, metadataStart + 4);
		stream.position(metadataStart);
		long size = metadataOffset + stream.readRawInt();
		if (size <= metadataStart + 4 || size > MAX_CHUNK_SIZE) {
			throw new IOException("Invalid metadata size at offset " + metadataStart + " in chunk " + chunk);
		}
		ensureCapacity((int) size, metadataStart + 4);
		readFully(channel, metadataStart + 4, (int) size - metadataStart - 4, false);
		stream.reset(buffer, (int) size);

		stream.position(metadataStart);
		listener.onTypes(LegacyMetadata.read(stream));

		int eventStart = LEGACY_HEADER_SIZE;
		while (eventStart < metadataStart) {
			stream.position(eventStart);
			int eventSize = stream.readRawInt();
			if (eventSize < 8 || eventSize > metadataStart - eventStart) {
				throw new IOException("Invalid event size " + eventSize + " at offset " + eventStart + " in chunk "
						+ chunk);
			}
			int eventEnd = eventStart + eventSize;
			dispatch(listener, stream.readRawInt(), eventEnd);
			eventStart = eventEnd;
		}
		listener.onChunkEnd();
	}

	private void dispatch(ChunkParserListener listener, long eventType, int eventEnd) throws IOException {
		if (eventType == CHECKPOINT_TYPE) {
			listener.onCheckpoint(stream, eventEnd - stream.position());
		} else if (eventType != METADATA_TYPE) {
			listener.onEvent(eventType, stream, eventEnd - stream.position());
		}
	}

	private void ensureCapacity(int size, int preserve) {
		if (buffer.length < size) {
			byte[] grown = new byte[Math.max(size, (int) Math.min(MAX_CHUNK_SIZE, buffer.length * 2L))];
			System.arraycopy(buffer, 0, grown, 0, preserve);
			buffer = grown;
		}
	}

	private boolean readFully(ReadableByteChannel channel, int offset, int length, boolean eofAllowed)
			throws IOException {
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
