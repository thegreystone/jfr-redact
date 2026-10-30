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

import se.hirt.jfr.redact.parser.StreamingChunkParser;
import se.hirt.jfr.redact.scan.StringCountMap;

/**
 * Redacts the strings of a JFR recording into a new recording.
 * <p>
 * The input is read twice. The first pass collects every distinct string and its locations, after
 * which the {@link StringRedactor} decides on each string. The second pass writes the recording with
 * every occurrence of a redacted string replaced, wherever it is stored: inline in events, in
 * constant pools, and in every chunk. Strings in the metadata (type, field and annotation names and
 * values) are not redacted. A redacted string that also occurs in the metadata is reported in
 * {@link RedactionResult#redactedInMetadata()}, and is the only way a copy of a redacted string can
 * remain.
 */
public final class JfrRedactor {
	private JfrRedactor() {
	}

	public static RedactionResult redact(Path input, Path output, StringRedactor redactor) throws IOException {
		LocationCollector collector = new LocationCollector();
		new StreamingChunkParser().parse(input, collector);
		StringCountMap strings = collector.getStrings();
		List<List<StringLocation>> locations = collector.getLocationsByEntry();

		StringCountMap changedStrings = new StringCountMap();
		List<String> changedReplacements = new ArrayList<>();
		boolean[] changed = new boolean[strings.size()];
		Set<String> changedEventTypes = new HashSet<>();
		Set<String> changedPoolTypes = new HashSet<>();
		List<String> redactedInMetadata = new ArrayList<>();
		long redactedCount = 0;
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
				for (StringLocation location : locations.get(entry)) {
					if (location == StringLocation.METADATA) {
						redactedInMetadata.add(value);
					} else if (location.isConstant()) {
						changedPoolTypes.add(location.getOwner());
					} else {
						changedEventTypes.add(location.getOwner());
					}
				}
			}
		}

		if (redactedCount == 0) {
			Files.copy(input, output, StandardCopyOption.REPLACE_EXISTING);
			return new RedactionResult(strings.size(), 0, 0, 0, 0, 0, 0, List.of());
		}
		ChunkRewriter rewriter = new ChunkRewriter(changedStrings, changedReplacements.toArray(new String[0]),
				collector.getChangedCheckpoints(changed), changedEventTypes, changedPoolTypes);
		try (FileChannel in = FileChannel.open(input, StandardOpenOption.READ);
				FileChannel out = FileChannel.open(output, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
						StandardOpenOption.TRUNCATE_EXISTING)) {
			rewriter.rewrite(in, out);
		}
		return new RedactionResult(strings.size(), redactedCount, rewriter.getChunkCount(),
				rewriter.getRewrittenChunkCount(), rewriter.getRewrittenEventCount(),
				rewriter.getRewrittenCheckpointCount(), rewriter.getReplacedCount(),
				Collections.unmodifiableList(redactedInMetadata));
	}
}
