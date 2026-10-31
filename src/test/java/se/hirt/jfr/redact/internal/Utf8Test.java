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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;

class Utf8Test {

	@Test
	void preservesOrdinaryUtf8Encoding() {
		for (String value : List.of("", "ASCII\u0000text", "Küssnacht 秘密", "\uD7FF\uE000\uFFFD",
				"\uD800\uDC00\uDBFF\uDFFF", "emoji 😀")) {
			byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
			assertFalse(Utf8.hasUnpairedSurrogate(value));
			assertArrayEquals(bytes, Utf8.encode(value));
			assertEquals(value, Utf8.decode(bytes, 0, bytes.length));
		}
	}

	@Test
	void preservesExactUnpairedSurrogateEncodings() {
		String[] values = {"\uD800", "\uD801", "\uDC00", "\uDFFF"};
		String[] encodings = {"eda080", "eda081", "edb080", "edbfbf"};
		for (int i = 0; i < values.length; i++) {
			byte[] bytes = HexFormat.of().parseHex(encodings[i]);
			assertTrue(Utf8.hasUnpairedSurrogate(values[i]));
			assertArrayEquals(bytes, Utf8.encode(values[i]));
			assertEquals(values[i], Utf8.decode(bytes, 0, bytes.length));
		}
	}

	@Test
	void roundTripsEveryUtf16Unit() {
		for (int unit = Character.MIN_VALUE; unit <= Character.MAX_VALUE; unit++) {
			String value = String.valueOf((char) unit);
			byte[] bytes = Utf8.encode(value);
			assertEquals(value, Utf8.decode(bytes, 0, bytes.length));
			assertEquals(Character.isSurrogate((char) unit), Utf8.hasUnpairedSurrogate(value));
		}
	}

	@Test
	void preservesMixedSurrogatesAndPairedCharactersWithinByteRanges() {
		for (String value : List.of("\uD800suffix", "prefix\uDC00", "before\uD801after", "\uD800\uD800\uDC00\uDC00",
				"\uDC00\uD800", "é\uD800秘密😀\uDC00?\uFFFD", "\uD800\uDC00\uD800\uDBFF\uDFFF")) {
			byte[] bytes = Utf8.encode(value);
			byte[] padded = new byte[bytes.length + 6];
			byte[] outerSurrogate = HexFormat.of().parseHex("eda082");
			System.arraycopy(outerSurrogate, 0, padded, 0, 3);
			System.arraycopy(bytes, 0, padded, 3, bytes.length);
			System.arraycopy(outerSurrogate, 0, padded, 3 + bytes.length, 3);
			assertEquals(value, Utf8.decode(padded, 3, bytes.length));
			assertEquals("", Utf8.decode(padded, 3, 0));
		}
	}

	@Test
	void keepsStandardDecoderBehaviorForOtherMalformedOrTruncatedBytes() {
		for (String hex : List.of("ff", "c3", "c328", "f09080", "eda0", "eda041")) {
			byte[] bytes = HexFormat.of().parseHex(hex);
			assertEquals(new String(bytes, StandardCharsets.UTF_8), Utf8.decode(bytes, 0, bytes.length));
		}
		byte[] bytes = HexFormat.of().parseHex("ffeda080ff");
		assertEquals("\uFFFD\uD800\uFFFD", Utf8.decode(bytes, 0, bytes.length));
		assertEquals("\uFFFD", Utf8.decode(bytes, 1, 2));
	}
}
