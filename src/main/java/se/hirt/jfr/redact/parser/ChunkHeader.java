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

/** The parts of a chunk header needed for parsing. */
public final class ChunkHeader {
	public static final int SIZE = 68;
	private static final int MAGIC = 0x464C5200; // "FLR\0"
	private static final int FEATURE_COMPRESSED_INTS = 1;

	public final short major;
	public final short minor;
	public final long size;
	public final long metadataOffset;
	public final boolean compressedInts;

	ChunkHeader(RecordingStream stream) throws IOException {
		int magic = stream.readRawInt();
		if (magic != MAGIC) {
			throw new IOException(String.format("Not a JFR chunk, bad magic 0x%08X", magic));
		}
		major = stream.readRawShort();
		minor = stream.readRawShort();
		size = stream.readRawLong();
		stream.skip(8); // constant pool offset
		metadataOffset = stream.readRawLong();
		stream.skip(4 * 8); // start nanos, duration, start ticks, ticks per second
		compressedInts = (stream.readRawInt() & FEATURE_COMPRESSED_INTS) != 0;
	}
}
