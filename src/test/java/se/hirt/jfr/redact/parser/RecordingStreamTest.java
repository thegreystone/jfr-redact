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
package se.hirt.jfr.redact.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.EOFException;
import java.io.IOException;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class RecordingStreamTest {

	@Test
	void readsNeverUseStaleBytesBeyondReusedChunkLimit() throws Exception {
		RecordingStream stream = new RecordingStream();
		byte[] reused = {42, 99};
		stream.reset(reused, reused.length);
		assertEquals(42, stream.read());
		assertEquals(99, stream.read());
		stream.reset(reused, 1);
		assertEquals(42, stream.read());
		assertThrows(EOFException.class, stream::read);
		assertEquals(1, stream.position(), "a failed read must not advance into stale bytes");
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("fixedReaders")
	void fixedReadsRespectEveryLogicalBoundary(String name, int width, FixedReader read, long expected)
			throws Exception {
		byte[] buffer = HexFormat.of().parseHex("0011fedcba98765432105566");
		RecordingStream stream = new RecordingStream();
		stream.reset(buffer, 2 + width);
		stream.position(2);
		assertEquals(expected, read.read(stream), name);
		assertEquals(stream.limit(), stream.position());
		assertThrows(EOFException.class, () -> read.read(stream));
		assertEquals(stream.limit(), stream.position());
		for (int available = 0; available < width; available++) {
			stream.reset(buffer, 2 + available);
			stream.position(2);
			assertThrows(EOFException.class, () -> read.read(stream), name + " with " + available + " bytes");
			assertEquals(2, stream.position(), "a truncated fixed-width read must not advance");
		}
	}

	private static Stream<Arguments> fixedReaders() {
		return Stream.of(Arguments.of("byte", 1, (FixedReader) RecordingStream::read, (long) (byte) 0xFE),
				Arguments.of("short", 2, (FixedReader) RecordingStream::readRawShort, (long) (short) 0xFEDC),
				Arguments.of("int", 4, (FixedReader) RecordingStream::readRawInt, (long) 0xFEDCBA98),
				Arguments.of("long", 8, (FixedReader) RecordingStream::readRawLong, 0xFEDCBA9876543210L));
	}

	@FunctionalInterface
	private interface FixedReader {
		long read(RecordingStream stream) throws IOException;
	}

	@Test
	void cursorMovesStayWithinLogicalLimitWithoutOverflow() throws Exception {
		RecordingStream stream = new RecordingStream();
		stream.reset(new byte[8], 4);
		stream.skip(0);
		assertEquals(0, stream.position());
		stream.skip(4);
		assertEquals(4, stream.position());
		stream.skip(0);
		assertEquals(4, stream.position());
		stream.position(0);
		stream.position(4);
		stream.position(2);
		for (int amount : List.of(-1, Integer.MIN_VALUE)) {
			assertThrows(IOException.class, () -> stream.skip(amount));
			assertEquals(2, stream.position());
		}
		for (int amount : List.of(3, Integer.MAX_VALUE)) {
			assertThrows(EOFException.class, () -> stream.skip(amount));
			assertEquals(2, stream.position());
		}
		for (int position : List.of(-1, Integer.MIN_VALUE, 5, Integer.MAX_VALUE)) {
			assertThrows(IOException.class, () -> stream.position(position));
			assertEquals(2, stream.position());
		}
	}

	@Test
	void resetRejectsLimitsOutsideTheBackingArray() throws Exception {
		RecordingStream stream = new RecordingStream();
		byte[] original = new byte[4];
		stream.reset(original, 3);
		stream.position(2);
		for (int limit : List.of(-1, 5, Integer.MAX_VALUE)) {
			assertThrows(IllegalArgumentException.class, () -> stream.reset(original, limit));
			assertSame(original, stream.array());
			assertEquals(3, stream.limit());
			assertEquals(2, stream.position());
		}
		stream.reset(original, 0);
		assertEquals(0, stream.position());
		assertEquals(0, stream.limit());
		assertThrows(EOFException.class, stream::read);
	}

	@ParameterizedTest(name = "varint {0}")
	@MethodSource("varints")
	void readsAndSkipsExactlyTheCompleteVarint(String hex, long expected) throws Exception {
		byte[] encoded = HexFormat.of().parseHex(hex);
		byte[] buffer = java.util.Arrays.copyOf(padded(encoded), encoded.length + 2);
		RecordingStream stream = new RecordingStream();
		stream.reset(buffer, 2 + encoded.length);
		stream.position(2);
		assertEquals(expected, stream.readVarint());
		assertEquals(stream.limit(), stream.position());
		assertThrows(EOFException.class, stream::readVarint);
		assertEquals(stream.limit(), stream.position());
		stream.position(2);
		stream.skipVarint();
		assertEquals(stream.limit(), stream.position());
		assertThrows(EOFException.class, stream::skipVarint);
		assertEquals(stream.limit(), stream.position());
	}

	@ParameterizedTest(name = "truncated varint {0}")
	@MethodSource("varints")
	void incompleteVarintPrefixesCannotReadOrSkipIntoSpareCapacity(String hex, long expected) throws Exception {
		byte[] encoded = HexFormat.of().parseHex(hex);
		byte[] buffer = padded(encoded);
		RecordingStream stream = new RecordingStream();
		for (int available = 0; available < encoded.length; available++) {
			stream.reset(buffer, 2 + available);
			stream.position(2);
			assertThrows(EOFException.class, stream::readVarint, "available bytes: " + available);
			assertEquals(2, stream.position(), "a truncated varint read must not advance");
			assertThrows(EOFException.class, stream::skipVarint, "available bytes: " + available);
			assertEquals(2, stream.position(), "a truncated varint skip must not advance");
		}
	}

	private static byte[] padded(byte[] encoded) {
		byte[] buffer = new byte[encoded.length + 4];
		System.arraycopy(encoded, 0, buffer, 2, encoded.length);
		return buffer;
	}

	private static Stream<Arguments> varints() {
		return Stream.of(Arguments.of("7f", 127L), Arguments.of("8001", 1L << 7), Arguments.of("808001", 1L << 14),
				Arguments.of("80808001", 1L << 21), Arguments.of("8080808001", 1L << 28),
				Arguments.of("808080808001", 1L << 35), Arguments.of("80808080808001", 1L << 42),
				Arguments.of("8080808080808001", 1L << 49), Arguments.of("808080808080808001", 1L << 56),
				Arguments.of("808080808080808080", Long.MIN_VALUE), Arguments.of("ffffffffffffffff7f", Long.MAX_VALUE),
				Arguments.of("ffffffffffffffffff", -1L), Arguments.of("808080808080808000", 0L));
	}
}
