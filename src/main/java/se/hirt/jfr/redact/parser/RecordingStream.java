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

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

/**
 * Cursor over the in-memory bytes of a single chunk. Bounds are not checked explicitly; reading
 * past the backing array surfaces as an {@link ArrayIndexOutOfBoundsException}.
 */
public final class RecordingStream {
	private static final VarHandle SHORT_BE = MethodHandles.byteArrayViewVarHandle(short[].class, ByteOrder.BIG_ENDIAN);
	private static final VarHandle INT_BE = MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.BIG_ENDIAN);
	private static final VarHandle LONG_BE = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.BIG_ENDIAN);

	private byte[] buffer;
	private int position;
	private int limit;

	void reset(byte[] buffer, int limit) {
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

	public void position(int position) {
		this.position = position;
	}

	public int limit() {
		return limit;
	}

	public byte read() {
		return buffer[position++];
	}

	public void skip(int bytes) {
		position += bytes;
	}

	public short readRawShort() {
		short value = (short) SHORT_BE.get(buffer, position);
		position += 2;
		return value;
	}

	public int readRawInt() {
		int value = (int) INT_BE.get(buffer, position);
		position += 4;
		return value;
	}

	public long readRawLong() {
		long value = (long) LONG_BE.get(buffer, position);
		position += 8;
		return value;
	}

	public long readVarint() {
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

	public void skipVarint() {
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
}
