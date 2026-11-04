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
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Objects;

import se.hirt.jfr.redact.internal.PhaseEvent;
import se.hirt.jfr.redact.internal.RedactionEvent;
import se.hirt.jfr.redact.parser.StreamingChunkParser;
import se.hirt.jfr.redact.scan.StringCountMap;

/**
 * Redacts the strings of a JFR recording into a new recording.
 * <p>
 * The input is read twice. The first pass collects every distinct string and its locations, after
 * which the {@link StringRedactor} decides on each string. The second pass writes the recording
 * with every occurrence of a redacted string replaced, wherever it is stored: inline in events, in
 * constant pools, and in every chunk. Strings in the metadata (type, field and annotation names and
 * values) are not redacted. A redacted string that also occurs in the metadata, as a whole string
 * or within a longer one, is reported in {@link RedactionResult#redactedInMetadata()}, and is the
 * only way a copy of a redacted string can remain.
 * <p>
 * Input and output must identify different files, including through links. The recording is written
 * to a temporary file beside the output, then published with an atomic replacement. Failed
 * processing leaves an existing output untouched. The output filesystem must support atomic
 * replacement.
 */
public final class JfrRedactor {
	private JfrRedactor() {
	}

	/**
	 * Writes a copy of the recording with the strings replaced as the redactor decides.
	 *
	 * @throws InvalidRecordingException
	 *             if the recording cannot be processed: it is corrupt, in an unsupported format,
	 *             or, as a {@link TruncatedRecordingException}, incomplete. When decoding fails
	 *             with an unchecked exception or a stack overflow, which a corrupt recording can
	 *             cause, the original is the cause. Exceptions thrown by the redactor are passed on
	 *             as they are.
	 * @throws IOException
	 *             if the files cannot be read or written, or a replacement cannot be stored in a
	 *             JFR 0.9 recording, being too long or holding an unpaired surrogate
	 */
	public static RedactionResult redact(Path input, Path output, StringRedactor redactor) throws IOException {
		Path destination = output.toAbsolutePath();
		if (Files.exists(destination) && Files.isSameFile(input, destination)) {
			throw new IOException("Input and output refer to the same file: " + output);
		}
		RedactionEvent event = new RedactionEvent();
		event.begin();
		PhaseEvent phase = PhaseEvent.start(PhaseEvent.COLLECT);
		LocationCollector collector = new LocationCollector();
		new StreamingChunkParser().parse(input, collector);
		phase.commit();
		phase = PhaseEvent.start(PhaseEvent.LOCATE);
		StringCountMap strings = collector.getStrings();
		List<List<StringLocation>> locations = collector.getLocationsByEntry();
		phase.commit();

		StringCountMap changedStrings = new StringCountMap();
		List<String> changedReplacements = new ArrayList<>();
		boolean[] changed = new boolean[strings.size()];
		Set<String> changedEventTypes = new HashSet<>();
		List<String> redactedInMetadata = new ArrayList<>();
		long redactedCount = 0;
		phase = PhaseEvent.start(PhaseEvent.DECIDE);
		for (int entry = 0; entry < strings.size(); entry++) {
			String value = strings.getString(entry);
			String replacement = Objects.requireNonNull(redactor.redact(value, locations.get(entry)),
					"The redactor returned null for a string");
			if (replacement != value && !replacement.equals(value)) {
				byte[] utf8 = strings.getBytes(entry);
				changedStrings.add(utf8, 0, utf8.length, 0);
				changedReplacements.add(replacement);
				changed[entry] = true;
				redactedCount++;
				// The checkpoints to rewrite are known from the strings each stores, see the
				// collector; the event types from the inline locations of the redacted strings
				for (StringLocation location : locations.get(entry)) {
					if (location == StringLocation.METADATA) {
						redactedInMetadata.add(value);
					} else if (!location.isPooled()) {
						changedEventTypes.add(location.getOwner());
					}
				}
			}
		}
		phase.commit();

		try (TemporaryOutput temporary = new TemporaryOutput(destination)) {
			RedactionResult result;
			phase = PhaseEvent.start(PhaseEvent.REWRITE);
			if (redactedCount == 0) {
				Files.copy(input, temporary.path, StandardCopyOption.REPLACE_EXISTING);
				result = new RedactionResult(strings.size(), 0, collector.getChunkCount(), 0, 0, 0, 0, List.of());
			} else {
				ChunkRewriter rewriter = new ChunkRewriter(changedStrings, changedReplacements.toArray(new String[0]),
						collector.getChangedCheckpoints(changed), changedEventTypes);
				try (FileChannel in = FileChannel.open(input, StandardOpenOption.READ);
						FileChannel out = FileChannel.open(temporary.path, StandardOpenOption.WRITE)) {
					rewriter.rewrite(in, out);
				} catch (RuntimeException | StackOverflowError e) {
					throw new InvalidRecordingException(
							"Could not decode the recording, which may be corrupt (" + e + ")", e);
				}
				result = new RedactionResult(strings.size(), redactedCount, rewriter.getChunkCount(),
						rewriter.getRewrittenChunkCount(), rewriter.getRewrittenEventCount(),
						rewriter.getRewrittenCheckpointCount(), rewriter.getReplacedCount(),
						Collections.unmodifiableList(redactedInMetadata));
			}
			phase.commit();
			phase = PhaseEvent.start(PhaseEvent.PUBLISH);
			temporary.publish();
			phase.commit();
			if (event.shouldCommit()) {
				event.inputSize = Files.size(input);
				event.chunks = result.chunkCount();
				event.rewrittenChunks = result.rewrittenChunkCount();
				event.strings = result.stringCount();
				event.redactedStrings = result.redactedStringCount();
				event.replacedOccurrences = result.replacedOccurrenceCount();
				event.rewrittenEvents = result.rewrittenEventCount();
				event.rewrittenCheckpoints = result.rewrittenCheckpointCount();
				event.commit();
			}
			return result;
		}
	}

	private static final class TemporaryOutput implements AutoCloseable {
		private final Path destination;
		private final Path path;
		private boolean published;

		TemporaryOutput(Path destination) throws IOException {
			this.destination = destination;
			this.path = Files.createTempFile(destination.getParent(), ".jfr-redact-", ".tmp");
		}

		void publish() throws IOException {
			Files.move(path, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
			published = true;
		}

		@Override
		public void close() throws IOException {
			if (!published) {
				Files.deleteIfExists(path);
			}
		}
	}
}
