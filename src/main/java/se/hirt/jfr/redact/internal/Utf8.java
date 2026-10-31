/*
 * Copyright (C) 2026 Marcus Hirt
 *
 * This software is free:
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
package se.hirt.jfr.redact.internal;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Lossless UTF-8 keys for Java strings. Well-formed strings use ordinary UTF-8; unpaired UTF-16
 * surrogates use their three-byte encoding (WTF-8), matching the scanner's character conversion.
 * These internal keys must not be written as JFR UTF-8 strings: use a character encoding for
 * unpaired surrogates instead.
 */
public final class Utf8 {

	private Utf8() {
	}

	public static byte[] encode(String value) {
		int surrogate = firstUnpairedSurrogate(value, 0);
		if (surrogate < 0) {
			return value.getBytes(StandardCharsets.UTF_8);
		}
		ByteArrayOutputStream out = new ByteArrayOutputStream(value.length());
		int copied = 0;
		do {
			if (copied < surrogate) {
				out.writeBytes(value.substring(copied, surrogate).getBytes(StandardCharsets.UTF_8));
			}
			char unit = value.charAt(surrogate);
			out.write(0xE0 | (unit >> 12));
			out.write(0x80 | ((unit >> 6) & 0x3F));
			out.write(0x80 | (unit & 0x3F));
			copied = surrogate + 1;
			surrogate = firstUnpairedSurrogate(value, copied);
		} while (surrogate >= 0);
		if (copied < value.length()) {
			out.writeBytes(value.substring(copied).getBytes(StandardCharsets.UTF_8));
		}
		return out.toByteArray();
	}

	public static String decode(byte[] bytes, int offset, int length) {
		Objects.checkFromIndexSize(offset, length, bytes.length);
		int end = offset + length;
		int surrogate = firstEncodedSurrogate(bytes, offset, end);
		if (surrogate < 0) {
			return new String(bytes, offset, length, StandardCharsets.UTF_8);
		}
		StringBuilder out = new StringBuilder(length);
		int copied = offset;
		do {
			if (copied < surrogate) {
				out.append(new String(bytes, copied, surrogate - copied, StandardCharsets.UTF_8));
			}
			out.append((char) (0xD000 | ((bytes[surrogate + 1] & 0x3F) << 6) | (bytes[surrogate + 2] & 0x3F)));
			copied = surrogate + 3;
			surrogate = firstEncodedSurrogate(bytes, copied, end);
		} while (surrogate >= 0);
		if (copied < end) {
			out.append(new String(bytes, copied, end - copied, StandardCharsets.UTF_8));
		}
		return out.toString();
	}

	public static boolean hasUnpairedSurrogate(String value) {
		return firstUnpairedSurrogate(value, 0) >= 0;
	}

	private static int firstUnpairedSurrogate(String value, int start) {
		for (int i = start; i < value.length(); i++) {
			char unit = value.charAt(i);
			if (Character.isHighSurrogate(unit)) {
				if (i + 1 < value.length() && Character.isLowSurrogate(value.charAt(i + 1))) {
					i++;
				} else {
					return i;
				}
			} else if (Character.isLowSurrogate(unit)) {
				return i;
			}
		}
		return -1;
	}

	private static int firstEncodedSurrogate(byte[] bytes, int start, int end) {
		for (int i = start; i < end - 2; i++) {
			if ((bytes[i] & 0xFF) == 0xED && (bytes[i + 1] & 0xE0) == 0xA0 && (bytes[i + 2] & 0xC0) == 0x80) {
				return i;
			}
		}
		return -1;
	}
}
