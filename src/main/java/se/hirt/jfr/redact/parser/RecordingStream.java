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
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

import se.hirt.jfr.redact.InvalidRecordingException;

/**
 * Cursor over the in-memory bytes of a single chunk. Reads and skips are bounded by the logical
 * chunk limit, even when the backing buffer is larger. Failed operations leave the cursor
 * unchanged.
 */
public final class RecordingStream {
	private static final VarHandle SHORT_BE = MethodHandles.byteArrayViewVarHandle(short[].class, ByteOrder.BIG_ENDIAN);
	private static final VarHandle INT_BE = MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.BIG_ENDIAN);
	private static final VarHandle LONG_BE = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.BIG_ENDIAN);

	private byte[] buffer;
	private int position;
	private int limit;

	void reset(byte[] buffer, int limit) {
		if (limit < 0 || limit > buffer.length) {
			throw new IllegalArgumentException("Invalid chunk limit " + limit + " for buffer size " + buffer.length);
		}
		this.buffer = buffer;
		this.limit = limit;
		this.position = 0;
	}

	/**
	 * @return the backing array, valid from index 0 to {@link #limit()}
	 */
	public byte[] array() {
		return buffer;
	}

	public int position() {
		return position;
	}

	public void position(int position) throws IOException {
		if (position < 0 || position > limit) {
			throw new InvalidRecordingException("Invalid position " + position + " for chunk limit " + limit);
		}
		this.position = position;
	}

	public int limit() {
		return limit;
	}

	public byte read() throws IOException {
		require(1);
		return buffer[position++];
	}

	public void skip(int bytes) throws IOException {
		require(bytes);
		position += bytes;
	}

	public short readRawShort() throws IOException {
		require(2);
		short value = (short) SHORT_BE.get(buffer, position);
		position += 2;
		return value;
	}

	public int readRawInt() throws IOException {
		require(4);
		int value = (int) INT_BE.get(buffer, position);
		position += 4;
		return value;
	}

	public long readRawLong() throws IOException {
		require(8);
		long value = (long) LONG_BE.get(buffer, position);
		position += 8;
		return value;
	}

	public long readVarint() throws IOException {
		if (limit - position < 9) {
			return readVarintNearLimit();
		}
		byte[] b = buffer;
		int p = position;
		long value = b[p++];
		if (value >= 0) {
			position = p;
			return value;
		}
		value &= 0x7F;
		for (int shift = 7; shift < 56; shift += 7) {
			long next = b[p++];
			value |= (next & 0x7F) << shift;
			if (next >= 0) {
				position = p;
				return value;
			}
		}
		// At most 9 bytes, the last one carrying a full 8 bits
		value |= (b[p++] & 0xFFL) << 56;
		position = p;
		return value;
	}

	public void skipVarint() throws IOException {
		if (limit - position < 9) {
			readVarintNearLimit();
			return;
		}
		byte[] b = buffer;
		int p = position;
		for (int i = 0; i < 8; i++) {
			if (b[p++] >= 0) {
				position = p;
				return;
			}
		}
		position = p + 1;
	}

	/** Fewer than nine bytes remain; check each byte and only commit a complete varint. */
	private long readVarintNearLimit() throws InvalidRecordingException {
		int p = position;
		long value = 0;
		for (int shift = 0; p < limit; shift += 7) {
			long next = buffer[p++];
			value |= (next & 0x7F) << shift;
			if (next >= 0) {
				position = p;
				return value;
			}
		}
		throw new InvalidRecordingException("Truncated varint at offset " + position + " in chunk of size " + limit);
	}

	private void require(int bytes) throws IOException {
		if (bytes < 0) {
			throw new InvalidRecordingException("Invalid byte count " + bytes + " at offset " + position);
		}
		if (bytes > limit - position) {
			throw new InvalidRecordingException("Unexpected end of chunk at offset " + position + ": need " + bytes
					+ " bytes, have " + (limit - position));
		}
	}
}
