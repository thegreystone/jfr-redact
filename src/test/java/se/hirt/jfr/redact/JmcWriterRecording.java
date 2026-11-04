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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.function.Consumer;

import org.openjdk.jmc.flightrecorder.writer.api.Recording;
import org.openjdk.jmc.flightrecorder.writer.api.Recordings;
import org.openjdk.jmc.flightrecorder.writer.api.TypedValue;
import org.openjdk.jmc.flightrecorder.writer.api.Types;

/**
 * Writes recordings with JDK Mission Control's pure-Java {@code flightrecorder.writer}, which
 * stores every non-empty string of an event or a constant through the {@code java.lang.String}
 * pool, one entry per distinct string, a layout HotSpot never produces. Chunks are self-contained,
 * so the recordings can be concatenated into one with several chunks.
 */
final class JmcWriterRecording {
	private JmcWriterRecording() {
	}

	/** Writes a recording of one chunk, closing it so that the file is complete */
	static Path write(Path file, Consumer<Recording> body) throws IOException {
		try (Recording recording = Recordings.newRecording(file)) {
			body.accept(recording);
		}
		return file;
	}

	/**
	 * A thread constant with the value as its Java name, and other names not containing the value
	 */
	static TypedValue thread(Recording recording, String javaName) {
		return recording.getType(Types.JDK.THREAD)
				.asValue(b -> b.putField("javaName", javaName).putField("osName", "os-4711")
						.putField("osThreadId", 4711L).putField("group", g -> g.putField("name", "group-4711")));
	}

	/** Concatenates recordings into one with a chunk per recording */
	static Path concatenate(Path file, Path ... recordings) throws IOException {
		Files.deleteIfExists(file);
		for (Path recording : recordings) {
			Files.write(file, Files.readAllBytes(recording), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
		}
		return file;
	}
}
