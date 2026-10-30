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
 * reported first, followed by the events and checkpoints in stream order. Not thread-safe.
 */
public final class StreamingChunkParser {
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
		for (int chunk = 1; readFully(channel, 0, ChunkHeader.SIZE, true); chunk++) {
			parseChunk(channel, chunk, listener);
		}
	}

	private void parseChunk(ReadableByteChannel channel, int chunk, ChunkParserListener listener)
			throws IOException {
		stream.reset(buffer, ChunkHeader.SIZE);
		ChunkHeader header = new ChunkHeader(stream);
		if (header.major != 2) {
			throw new IOException("Unsupported JFR version " + header.major + "." + header.minor);
		}
		if (!header.compressedInts) {
			throw new IOException("Recordings without compressed integers are not supported");
		}
		if (header.size < ChunkHeader.SIZE || header.size > MAX_CHUNK_SIZE) {
			throw new IOException("Unsupported size " + header.size + " of chunk " + chunk
					+ (header.size == 0 ? " (recording still in progress?)" : ""));
		}
		int size = (int) header.size;
		if (header.metadataOffset < ChunkHeader.SIZE || header.metadataOffset >= size) {
			throw new IOException("Invalid metadata offset " + header.metadataOffset + " in chunk " + chunk);
		}
		if (buffer.length < size) {
			byte[] grown = new byte[Math.max(size, (int) Math.min(MAX_CHUNK_SIZE, buffer.length * 2L))];
			System.arraycopy(buffer, 0, grown, 0, ChunkHeader.SIZE);
			buffer = grown;
		}
		readFully(channel, ChunkHeader.SIZE, size - ChunkHeader.SIZE, false);
		stream.reset(buffer, size);

		stream.position((int) header.metadataOffset);
		listener.onMetadata(new ChunkMetadata(stream));

		int eventStart = ChunkHeader.SIZE;
		while (eventStart < size) {
			stream.position(eventStart);
			long eventSize = stream.readVarint();
			if (eventSize <= 0 || eventSize > size - eventStart) {
				throw new IOException("Invalid event size " + eventSize + " at offset " + eventStart + " in chunk "
						+ chunk);
			}
			int eventEnd = eventStart + (int) eventSize;
			long eventType = stream.readVarint();
			if (eventType == CHECKPOINT_TYPE) {
				listener.onCheckpoint(stream, eventEnd - stream.position());
			} else if (eventType != METADATA_TYPE) {
				listener.onEvent(eventType, stream, eventEnd - stream.position());
			}
			eventStart = eventEnd;
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
