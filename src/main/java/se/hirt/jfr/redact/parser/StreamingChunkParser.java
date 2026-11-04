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

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import se.hirt.jfr.redact.InvalidRecordingException;

/**
 * Parses a recording one chunk at a time, using a {@link ChunkReader}, so memory use is bounded by
 * the largest chunk rather than the recording. The metadata, normally found at the end of the
 * chunk, is reported first, followed by the events and checkpoints in stream order. Not
 * thread-safe.
 */
public final class StreamingChunkParser {
	private static final long METADATA_TYPE = 0;
	private static final long CHECKPOINT_TYPE = 1;

	private final ChunkReader reader = new ChunkReader();

	/**
	 * Parses the recording in the file.
	 *
	 * @throws InvalidRecordingException
	 *             if the recording is invalid, see
	 *             {@link #parse(ReadableByteChannel, ChunkParserListener)}
	 */
	public void parse(Path path, ChunkParserListener listener) throws IOException {
		try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
			parse(channel, listener);
		}
	}

	/**
	 * Parses the recording read from the channel. The channel is not closed.
	 *
	 * @throws InvalidRecordingException
	 *             if the recording is corrupt, truncated or in an unsupported format, also when the
	 *             parser or the listener, which decodes the events, fails with an unchecked
	 *             exception or a stack overflow, which a corrupt recording can cause; the original
	 *             is the cause
	 */
	public void parse(ReadableByteChannel channel, ChunkParserListener listener) throws IOException {
		reader.reset(channel);
		try {
			while (reader.next()) {
				listener.onTypes(reader.types());
				if (reader.legacy()) {
					parseLegacyEvents(listener);
				} else {
					parseEvents(listener);
				}
				listener.onChunkEnd();
			}
		} catch (RuntimeException | StackOverflowError e) {
			throw decodingFailed(e);
		}
	}

	/**
	 * Reports an unexpected failure while decoding a recording, which a corrupt recording can cause
	 * in many ways, such as an index out of bounds, or a stack overflow from a type corrupted to
	 * contain itself
	 */
	private static InvalidRecordingException decodingFailed(Throwable cause) {
		return new InvalidRecordingException("Could not decode the recording, which may be corrupt (" + cause + ")",
				cause);
	}

	private void parseEvents(ChunkParserListener listener) throws IOException {
		RecordingStream stream = reader.stream();
		int size = reader.size();
		int eventStart = reader.headerSize();
		while (eventStart < size) {
			stream.position(eventStart);
			long eventSize = stream.readVarint();
			if (eventSize <= 0 || eventSize > size - eventStart) {
				throw new InvalidRecordingException("Invalid event size " + eventSize + " at offset " + eventStart
						+ " in chunk " + reader.chunkIndex());
			}
			int eventEnd = eventStart + (int) eventSize;
			dispatch(listener, stream, stream.readVarint(), eventEnd);
			eventStart = eventEnd;
		}
	}

	private void parseLegacyEvents(ChunkParserListener listener) throws IOException {
		RecordingStream stream = reader.stream();
		int metadataStart = reader.metadataOffset();
		int eventStart = reader.headerSize();
		while (eventStart < metadataStart) {
			stream.position(eventStart);
			int eventSize = stream.readRawInt();
			if (eventSize < 8 || eventSize > metadataStart - eventStart) {
				throw new InvalidRecordingException("Invalid event size " + eventSize + " at offset " + eventStart
						+ " in chunk " + reader.chunkIndex());
			}
			int eventEnd = eventStart + eventSize;
			dispatch(listener, stream, stream.readRawInt(), eventEnd);
			eventStart = eventEnd;
		}
	}

	private static void dispatch(ChunkParserListener listener, RecordingStream stream, long eventType, int eventEnd)
			throws IOException {
		if (eventType == CHECKPOINT_TYPE) {
			listener.onCheckpoint(stream, eventEnd - stream.position());
		} else if (eventType != METADATA_TYPE) {
			listener.onEvent(eventType, stream, eventEnd - stream.position());
		}
	}
}
