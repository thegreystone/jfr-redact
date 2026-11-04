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
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import se.hirt.jfr.redact.InvalidRecordingException;
import se.hirt.jfr.redact.JfrRedactor;

class ChunkReaderTest {
	@Test
	void rejectsTruncatedMetadataInsteadOfReadingThePreviousChunksTail(@TempDir
	Path dir) throws Exception {
		Path fixture = Path.of(ChunkReaderTest.class.getResource("/recordings/jdk9-basic.jfr").toURI());
		byte[] first = Files.readAllBytes(fixture);
		byte[] smaller = truncatedChunkWithStaleZero(first);
		assertTrue(smaller.length < first.length);
		assertEquals(0, first[smaller.length], "the previous chunk leaves a zero just outside the new logical limit");
		ByteArrayOutputStream recording = new ByteArrayOutputStream();
		recording.writeBytes(first);
		recording.writeBytes(smaller);
		byte[] original = recording.toByteArray();
		Path input = Files.write(dir.resolve("truncated-metadata.jfr"), original);
		try (FileChannel channel = FileChannel.open(input)) {
			ChunkReader reader = new ChunkReader();
			reader.reset(channel);
			assertTrue(reader.next());
			assertEquals(first.length, reader.size(), "the fixture must provide one larger valid chunk");
			InvalidRecordingException failure = assertThrows(InvalidRecordingException.class, reader::next);
			assertTrue(failure.getMessage() != null && !failure.getMessage().isBlank());
		}
		byte[] previousOutput = {1, 2, 3, 4};
		Path output = Files.write(dir.resolve("output.jfr"), previousOutput);
		List<String> before = fileNames(dir);
		assertThrows(InvalidRecordingException.class,
				() -> JfrRedactor.redact(input, output, (value, locations) -> "<REDACTED>"));
		assertArrayEquals(original, Files.readAllBytes(input));
		assertArrayEquals(previousOutput, Files.readAllBytes(output));
		assertEquals(before, fileNames(dir), "failed parsing must leave no temporary output files");
	}

	private static byte[] truncatedChunkWithStaleZero(byte[] first) {
		for (int padding = 0; padding < 1024; padding++) {
			byte[] chunk = truncatedMetadataChunk(padding);
			if (chunk.length < first.length && first[chunk.length] == 0) {
				return chunk;
			}
		}
		throw new AssertionError("The fixture has no suitable stale zero byte");
	}

	private static byte[] truncatedMetadataChunk(int padding) {
		ByteArrayOutputStream body = new ByteArrayOutputStream();
		// Metadata type, timing, id, two strings: "root" and unused padding.
		body.writeBytes(new byte[] {0, 0, 0, 0, 2, 3, 4, 'r', 'o', 'o', 't', 3});
		body.writeBytes(varint(padding));
		body.writeBytes("x".repeat(padding).getBytes(StandardCharsets.UTF_8));
		// Root string index, no attributes, then a child-count varint missing its final byte.
		body.writeBytes(new byte[] {0, 0, (byte) 0x80});
		ByteArrayOutputStream metadata = new ByteArrayOutputStream();
		for (int width = 1;; width++) {
			byte[] size = varint(body.size() + width);
			if (size.length == width) {
				metadata.writeBytes(size);
				break;
			}
		}
		metadata.writeBytes(body.toByteArray());
		ByteBuffer chunk = ByteBuffer.allocate(ChunkHeader.SIZE + metadata.size());
		chunk.putInt(0, 0x464C5200);
		chunk.putShort(4, (short) 2);
		chunk.putShort(6, (short) 1);
		chunk.putLong(8, chunk.capacity());
		chunk.putLong(24, ChunkHeader.SIZE);
		chunk.putInt(64, 1);
		chunk.position(ChunkHeader.SIZE);
		chunk.put(metadata.toByteArray());
		return chunk.array();
	}

	private static byte[] varint(int value) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		while ((value & ~0x7F) != 0) {
			out.write((value & 0x7F) | 0x80);
			value >>>= 7;
		}
		out.write(value);
		return out.toByteArray();
	}

	private static List<String> fileNames(Path dir) throws IOException {
		try (var files = Files.list(dir)) {
			return files.map(path -> path.getFileName().toString()).sorted().toList();
		}
	}
}
