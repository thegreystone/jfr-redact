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

import java.io.IOException;

import se.hirt.jfr.redact.parser.ChunkTypes;
import se.hirt.jfr.redact.parser.RecordingStream;

/**
 * Decodes a string value of any encoding into its UTF-8 bytes, which is how strings are keyed. After
 * {@link #read(RecordingStream, int)} returned {@link #STRING}, the UTF-8 bytes are in
 * {@code array[offset, offset + length)}, either in the chunk buffer or in an internal scratch buffer.
 */
final class StringDecoder {
	static final int NULL = 0;
	static final int STRING = 1;
	/** A reference to a constant in the string pool, the key is in {@link #reference} */
	static final int REFERENCE = 2;

	byte[] array;
	int offset;
	int length;
	long reference;

	private byte[] scratch = new byte[1024];
	private char[] chars = new char[256];

	/**
	 * @param kind
	 *            {@link ChunkTypes#KIND_STRING}, {@link ChunkTypes#KIND_UTF8} or
	 *            {@link ChunkTypes#KIND_UTF16}
	 */
	int read(RecordingStream stream, int kind) throws IOException {
		switch (kind) {
		case ChunkTypes.KIND_UTF8: {
			int len = stream.readRawShort() & 0xFFFF;
			checkLength(stream, len);
			setRange(stream.array(), stream.position(), len);
			stream.skip(len);
			return STRING;
		}
		case ChunkTypes.KIND_UTF16: {
			int len = stream.readRawInt();
			checkLength(stream, len * 2L);
			char[] c = ensureChars(len);
			for (int i = 0; i < len; i++) {
				c[i] = (char) stream.readRawShort();
			}
			scratch(len * 3);
			setRange(scratch, 0, charsToUtf8(c, len));
			return STRING;
		}
		default:
			return readEncoded(stream);
		}
	}

	private int readEncoded(RecordingStream stream) throws IOException {
		byte encoding = stream.read();
		switch (encoding) {
		case 0:
			return NULL;
		case 1:
			setRange(stream.array(), 0, 0);
			return STRING;
		case 2:
			reference = stream.readVarint();
			return REFERENCE;
		case 3: {
			int len = readLength(stream);
			setRange(stream.array(), stream.position(), len);
			stream.skip(len);
			return STRING;
		}
		case 4: {
			int len = readLength(stream);
			char[] c = ensureChars(len);
			for (int i = 0; i < len; i++) {
				c[i] = (char) stream.readVarint();
			}
			scratch(len * 3);
			setRange(scratch, 0, charsToUtf8(c, len));
			return STRING;
		}
		case 5: {
			int len = readLength(stream);
			byte[] b = stream.array();
			int start = stream.position();
			byte[] out = scratch(len * 2);
			int n = 0;
			for (int i = start; i < start + len; i++) {
				int c = b[i] & 0xFF;
				if (c < 0x80) {
					out[n++] = (byte) c;
				} else {
					out[n++] = (byte) (0xC0 | (c >> 6));
					out[n++] = (byte) (0x80 | (c & 0x3F));
				}
			}
			setRange(out, 0, n);
			stream.skip(len);
			return STRING;
		}
		default:
			throw new IOException("Unknown string encoding " + encoding + " at offset " + (stream.position() - 1));
		}
	}

	private void setRange(byte[] array, int offset, int length) {
		this.array = array;
		this.offset = offset;
		this.length = length;
	}

	private static int readLength(RecordingStream stream) throws IOException {
		long len = stream.readVarint();
		checkLength(stream, len);
		return (int) len;
	}

	private static void checkLength(RecordingStream stream, long byteLength) throws IOException {
		if (byteLength < 0 || byteLength > stream.limit() - stream.position()) {
			throw new IOException("Invalid string length " + byteLength + " at offset " + stream.position());
		}
	}

	private byte[] scratch(int size) {
		if (scratch.length < size) {
			scratch = new byte[Math.max(size, scratch.length * 2)];
		}
		return scratch;
	}

	private char[] ensureChars(int size) {
		if (chars.length < size) {
			chars = new char[Math.max(size, chars.length * 2)];
		}
		return chars;
	}

	private int charsToUtf8(char[] c, int len) {
		byte[] out = scratch;
		int n = 0;
		for (int i = 0; i < len; i++) {
			char ch = c[i];
			if (Character.isHighSurrogate(ch) && i + 1 < len && Character.isLowSurrogate(c[i + 1])) {
				int codePoint = Character.toCodePoint(ch, c[++i]);
				out[n++] = (byte) (0xF0 | (codePoint >> 18));
				out[n++] = (byte) (0x80 | ((codePoint >> 12) & 0x3F));
				out[n++] = (byte) (0x80 | ((codePoint >> 6) & 0x3F));
				out[n++] = (byte) (0x80 | (codePoint & 0x3F));
			} else if (ch < 0x80) {
				out[n++] = (byte) ch;
			} else if (ch < 0x800) {
				out[n++] = (byte) (0xC0 | (ch >> 6));
				out[n++] = (byte) (0x80 | (ch & 0x3F));
			} else {
				out[n++] = (byte) (0xE0 | (ch >> 12));
				out[n++] = (byte) (0x80 | ((ch >> 6) & 0x3F));
				out[n++] = (byte) (0x80 | (ch & 0x3F));
			}
		}
		return n;
	}
}
