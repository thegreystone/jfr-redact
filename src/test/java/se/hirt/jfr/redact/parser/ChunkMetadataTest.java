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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ChunkMetadataTest {

	private static final byte[] ROOT = "root".getBytes(StandardCharsets.US_ASCII);

	@ParameterizedTest
	@ValueSource(ints = {3, 5, 4})
	void readsMinimalMetadataInEachArrayEncoding(int encoding) throws Exception {
		byte[] bytes = metadata(encoding, 1, ROOT.length);
		RecordingStream stream = new RecordingStream();
		stream.reset(bytes, bytes.length);
		ChunkMetadata metadata = new ChunkMetadata(stream);
		assertArrayEquals(new String[] {"root"}, metadata.getStrings());
		assertTrue(metadata.getClasses().isEmpty());
		assertEquals(bytes.length, stream.position());
	}

	@ParameterizedTest
	@ValueSource(ints = {3, 5, 4})
	void rejectsDeclaredLengthsThatWouldWrapToTheActualLength(int encoding) {
		byte[] bytes = metadata(encoding, 1, (1L << 32) + ROOT.length);
		RecordingStream stream = new RecordingStream();
		stream.reset(bytes, bytes.length);
		assertThrows(IOException.class, () -> new ChunkMetadata(stream));
	}

	@Test
	void rejectsStringTableCountsThatWouldWrapToOneEntry() {
		byte[] bytes = metadata(3, (1L << 32) + 1, ROOT.length);
		RecordingStream stream = new RecordingStream();
		stream.reset(bytes, bytes.length);
		assertThrows(IOException.class, () -> new ChunkMetadata(stream));
	}

	@ParameterizedTest
	@ValueSource(ints = {3, 5, 4})
	void rejectsTruncatedArraysEvenWhenTheCompletePayloadIsInSpareCapacity(int encoding) {
		byte[] bytes = metadata(encoding, 1, ROOT.length);
		RecordingStream stream = new RecordingStream();
		// Leave the last payload character and the three root-tree bytes beyond the logical limit.
		stream.reset(bytes, bytes.length - 4);
		assertThrows(IOException.class, () -> new ChunkMetadata(stream));
		assertTrue(stream.position() <= stream.limit());
	}

	private static byte[] metadata(int encoding, long tableCount, long stringLength) {
		ByteArrayOutputStream body = new ByteArrayOutputStream();
		body.writeBytes(new byte[] {0, 0, 0, 0}); // metadata type, timing and id
		writeVarint(body, tableCount);
		body.write(encoding);
		writeVarint(body, stringLength);
		// ASCII bytes also encode the same four varint characters for encoding 4.
		body.writeBytes(ROOT);
		body.writeBytes(new byte[] {0, 0, 0}); // root string index, no attributes, no children
		ByteArrayOutputStream event = new ByteArrayOutputStream();
		writeVarint(event, body.size() + 1);
		event.writeBytes(body.toByteArray());
		return event.toByteArray();
	}

	private static void writeVarint(ByteArrayOutputStream out, long value) {
		while ((value & ~0x7FL) != 0) {
			out.write((int) (value & 0x7F) | 0x80);
			value >>>= 7;
		}
		out.write((int) value);
	}
}
