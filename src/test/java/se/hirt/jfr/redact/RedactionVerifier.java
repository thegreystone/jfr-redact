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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import jdk.jfr.ValueDescriptor;
import jdk.jfr.consumer.RecordedClass;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedObject;
import jdk.jfr.consumer.RecordingFile;
import se.hirt.jfr.redact.parser.ChunkParserListener;
import se.hirt.jfr.redact.parser.ChunkTypes;
import se.hirt.jfr.redact.parser.RecordingStream;
import se.hirt.jfr.redact.parser.StreamingChunkParser;
import se.hirt.jfr.redact.scan.StringCountMap;
import se.hirt.jfr.redact.scan.StringScanner;

/**
 * Redacts a recording and verifies the result independently of the rewriter. Can be run on any
 * recording: {@code java -cp target/classes:target/test-classes
 * se.hirt.jfr.redact.RedactionVerifier <recording.jfr>...}
 */
public final class RedactionVerifier {
	/** Raw byte search is quadratic-ish, so it is limited to the longest redacted strings */
	private static final int RAW_SEARCH_LIMIT = 300;
	/** How many classes outside their packages {@link #checkClassPackageInvariant} spells out */
	private static final int CLASS_PROBLEMS_REPORTED = 5;

	private RedactionVerifier() {
	}

	/**
	 * Redacts every string of at least {@code minLength} characters with a unique replacement,
	 * which is shorter or longer than the original.
	 */
	public static StringRedactor aggressive(int minLength) {
		int[] counter = new int[1];
		return (value, locations) -> {
			if (value.length() < minLength) {
				return value;
			}
			int id = counter[0]++;
			return "~" + Integer.toHexString(id) + "~".repeat(id % 23);
		};
	}

	/**
	 * @return a list of problems found, empty if the redaction is correct
	 */
	public static List<String> verify(Path input, Path output, StringRedactor redactor, boolean useJdkParser)
			throws IOException {
		List<String> problems = new ArrayList<>();
		Map<String, String> decisions = new LinkedHashMap<>();
		RedactionResult result = JfrRedactor.redact(input, output, (value, locations) -> {
			String replacement = redactor.redact(value, locations);
			if (!replacement.equals(value)) {
				decisions.put(value, replacement);
			}
			return replacement;
		});

		StringScanner before = scan(input);
		StringScanner after = scan(output);
		check(problems, after.getMisalignedCount() == 0, "misaligned events or checkpoints in the output");
		check(problems, after.getUnknownEventCount() == 0, "events of unknown types in the output");
		check(problems, before.getUnresolvedReferenceCount() == after.getUnresolvedReferenceCount(),
				"unresolved references changed: " + before.getUnresolvedReferenceCount() + " -> "
						+ after.getUnresolvedReferenceCount());
		check(problems, before.getChunkCount() == after.getChunkCount(), "chunk count changed");
		check(problems, before.getEventCount() == after.getEventCount(), "event count changed");
		check(problems, before.getCheckpointCount() == after.getCheckpointCount(), "checkpoint count changed");
		check(problems, before.getConstantCount() == after.getConstantCount(), "constant count changed");
		check(problems, before.getReferenceCount() == after.getReferenceCount(),
				"reference count changed: " + before.getReferenceCount() + " -> " + after.getReferenceCount());
		check(problems, eventTypeCounts(input).equals(eventTypeCounts(output)), "event counts per type changed");

		StringCountMap in = before.getStrings();
		StringCountMap out = after.getStrings();
		Map<String, long[]> expected = new HashMap<>();
		for (int e = 0; e < in.size(); e++) {
			String value = in.getString(e);
			String target = decisions.getOrDefault(value, value);
			long[] counts = expected.computeIfAbsent(target, k -> new long[3]);
			counts[0] += in.getCount(e, StringScanner.INLINE);
			counts[1] += in.getCount(e, StringScanner.CONSTANT_POOL);
			counts[2] += in.getReferenceCount(e);
		}
		for (String original : decisions.keySet()) {
			if (!expected.containsKey(original) && out.indexOf(original) >= 0) {
				problems.add("redacted string remains as a value: " + shorten(original));
			}
		}
		check(problems, expected.size() == out.size(),
				"distinct strings: expected " + expected.size() + ", found " + out.size());
		int countMismatches = 0;
		for (Map.Entry<String, long[]> entry : expected.entrySet()) {
			int e = out.indexOf(entry.getKey());
			long[] c = entry.getValue();
			if (e < 0 || out.getCount(e, StringScanner.INLINE) != c[0]
					|| out.getCount(e, StringScanner.CONSTANT_POOL) != c[1] || out.getReferenceCount(e) != c[2]) {
				if (countMismatches++ < 5) {
					problems.add("counts differ for " + shorten(entry.getKey()));
				}
			}
		}

		checkMetadataReport(problems, decisions, metadataStrings(output), result.redactedInMetadata());
		problems.addAll(rawSearch(output, decisions, expected, result.redactedInMetadata()));

		if (useJdkParser) {
			check(problems, jdkEventCounts(input).equals(jdkEventCounts(output)),
					"the JDK parser reads different event counts");
		}
		System.out.printf(
				"%s: %,d of %,d strings redacted (%,d also in metadata), %,d occurrences, %,d/%,d chunks rewritten, %s%n",
				input.getFileName(), result.redactedStringCount(), result.stringCount(),
				result.redactedInMetadata().size(), result.replacedOccurrenceCount(), result.rewrittenChunkCount(),
				result.chunkCount(), problems.isEmpty() ? "OK" : problems.size() + " problems");
		return problems;
	}

	/** Checks every changed value, independently of raw encodings and the raw-search limit. */
	private static void checkMetadataReport(
		List<String> problems, Map<String, String> decisions, List<String> metadata, List<String> reported) {
		Set<String> expected = new HashSet<>();
		for (String original : decisions.keySet()) {
			for (String text : metadata) {
				if (original.isEmpty() ? text.isEmpty() : text.contains(original)) {
					expected.add(original);
					break;
				}
			}
		}
		Set<String> actual = new HashSet<>(reported);
		check(problems, actual.size() == reported.size(), "duplicate strings in the metadata report");
		int missing = 0;
		for (String original : decisions.keySet()) {
			if (expected.contains(original) && !actual.contains(original) && missing++ < 5) {
				problems.add("unreported redacted string remains in metadata: " + shorten(original));
			}
		}
		int unexpected = 0;
		for (String original : actual) {
			if (!expected.contains(original) && unexpected++ < 5) {
				problems.add("incorrectly reported redacted string in metadata: " + shorten(original));
			}
		}
	}

	/** Searches the raw output for the longest redacted strings, as UTF-8 and UTF-16 */
	private static List<String> rawSearch(
		Path output, Map<String, String> decisions, Map<String, long[]> kept, List<String> reportedInMetadata)
			throws IOException {
		List<String> problems = new ArrayList<>();
		byte[] bytes = Files.readAllBytes(output);
		List<String> originals = new ArrayList<>(decisions.keySet());
		originals.removeIf(kept::containsKey);
		originals.sort((a, b) -> b.length() - a.length());
		List<long[]> regions = regions(output);
		for (String original : originals.subList(0, Math.min(RAW_SEARCH_LIMIT, originals.size()))) {
			int at = indexOf(bytes, original.getBytes(StandardCharsets.UTF_8));
			if (at < 0) {
				at = indexOf(bytes, original.getBytes(StandardCharsets.UTF_16BE));
			}
			if (at < 0) {
				continue;
			}
			boolean inMetadata = region(regions, at).equals("metadata");
			if (inMetadata && reportedInMetadata.contains(original)) {
				continue;
			}
			problems.add("redacted string found in the raw output, in the " + region(regions, at) + ": "
					+ shorten(original));
		}
		return problems;
	}

	private static List<String> metadataStrings(Path recording) throws IOException {
		List<String> strings = new ArrayList<>();
		try (var channel = java.nio.channels.FileChannel.open(recording)) {
			se.hirt.jfr.redact.parser.ChunkReader reader = new se.hirt.jfr.redact.parser.ChunkReader();
			reader.reset(channel);
			while (reader.next()) {
				for (String s : reader.types().getMetadataStrings()) {
					if (s != null) {
						strings.add(s);
					}
				}
			}
		}
		return strings;
	}

	/** Absolute ranges of all events in the recording: start, end and event type */
	private static List<long[]> regions(Path recording) throws IOException {
		List<long[]> regions = new ArrayList<>();
		try (var channel = java.nio.channels.FileChannel.open(recording)) {
			se.hirt.jfr.redact.parser.ChunkReader reader = new se.hirt.jfr.redact.parser.ChunkReader();
			reader.reset(channel);
			long chunkStart = 0;
			while (reader.next()) {
				RecordingStream stream = reader.stream();
				int end = reader.legacy() ? reader.size() : reader.size();
				for (int pos = reader.headerSize(); pos < end;) {
					stream.position(pos);
					int size = reader.legacy() ? stream.readRawInt() : (int) stream.readVarint();
					long type = reader.legacy() ? stream.readRawInt() : stream.readVarint();
					regions.add(new long[] {chunkStart + pos, chunkStart + pos + size, type});
					pos += size;
				}
				chunkStart += reader.size();
			}
		}
		return regions;
	}

	private static String region(List<long[]> regions, long offset) {
		for (long[] r : regions) {
			if (offset >= r[0] && offset < r[1]) {
				return r[2] == 0 ? "metadata" : r[2] == 1 ? "checkpoint at " + r[0] : "event at " + r[0];
			}
		}
		return "chunk header";
	}

	private static int indexOf(byte[] haystack, byte[] needle) {
		if (needle.length == 0) {
			return -1;
		}
		byte first = needle[0];
		for (int i = 0, last = haystack.length - needle.length; i <= last; i++) {
			if (haystack[i] == first
					&& java.util.Arrays.equals(haystack, i, i + needle.length, needle, 0, needle.length)) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Checks what parsers deriving the simple name of a class from its package name assume, as JDK
	 * Mission Control's does: that the name of every class the JDK's parser reaches, through event
	 * fields, stack frames, class loaders, old object samples and other values, starts with the
	 * name of its package followed by a separator, and goes on. Array classes are checked by their
	 * component class, and classes without a package are not checked. Constants are shared, so a
	 * stack trace, a method or a class is visited once per chunk. Values the JDK's parser fails to
	 * read, as it does for some fields written by JMC's writer, where {@code jfr print} fails the
	 * same way, are skipped. The {@link #aggressive} redactor breaks the invariant by design, so
	 * {@link #verify} does not check it.
	 *
	 * @return the problems found, the first {@value #CLASS_PROBLEMS_REPORTED} classes spelled out
	 *         and the rest counted, empty if every class name starts with its package name
	 */
	public static List<String> checkClassPackageInvariant(Path recording) throws IOException {
		List<String> problems = new ArrayList<>();
		Set<Object> seen = Collections.newSetFromMap(new IdentityHashMap<>());
		int[] counts = new int[2]; // Classes checked, and classes outside their packages
		try (RecordingFile file = new RecordingFile(recording)) {
			while (file.hasMoreEvents()) {
				checkClasses(file.readEvent(), seen, problems, counts);
			}
		}
		check(problems, counts[0] > 0, "no classes reached");
		if (counts[1] > CLASS_PROBLEMS_REPORTED) {
			problems.add("... and " + (counts[1] - CLASS_PROBLEMS_REPORTED) + " more classes outside their packages");
		}
		return problems;
	}

	private static void checkClasses(Object value, Set<Object> seen, List<String> problems, int[] counts) {
		if (value instanceof Object[] array) {
			for (Object element : array) {
				checkClasses(element, seen, problems, counts);
			}
			return;
		}
		if (!(value instanceof RecordedObject object)) {
			return;
		}
		if (!(object instanceof RecordedEvent) && !seen.add(object)) {
			return; // A constant visited before
		}
		if (object instanceof RecordedClass type) {
			checkClass(type, problems, counts);
		}
		for (ValueDescriptor field : object.getFields()) {
			if (field.getFields().isEmpty()) {
				continue; // A primitive or a string, which cannot hold a class
			}
			Object nested;
			try {
				nested = object.getValue(field.getName());
			} catch (RuntimeException e) {
				continue; // A field the JDK's parser cannot read
			}
			checkClasses(nested, seen, problems, counts);
		}
	}

	private static void checkClass(RecordedClass type, List<String> problems, int[] counts) {
		String name = type.getName();
		String component = name.replaceFirst("^\\[+", "");
		if (component.length() < name.length()) {
			if (!component.startsWith("L") || !component.endsWith(";")) {
				return; // A primitive array, which has no package
			}
			component = component.substring(1, component.length() - 1);
		}
		counts[0]++;
		RecordedObject pkg = type.hasField("package") ? type.getValue("package") : null;
		String packageName = pkg == null ? null : pkg.getString("name");
		if (packageName == null || packageName.isEmpty()) {
			return;
		}
		// The JDK's parser gives names in source form, the package constant is in internal form
		String prefix = packageName.replace('/', '.') + ".";
		if (!component.startsWith(prefix) || component.length() == prefix.length()) {
			if (counts[1]++ < CLASS_PROBLEMS_REPORTED) {
				problems.add("class " + name + " is not named within its package " + packageName);
			}
		}
	}

	private static StringScanner scan(Path recording) throws IOException {
		StringScanner scanner = new StringScanner(true, true);
		new StreamingChunkParser().parse(recording, scanner);
		return scanner;
	}

	private static Map<String, Integer> eventTypeCounts(Path recording) throws IOException {
		Map<String, Integer> counts = new TreeMap<>();
		new StreamingChunkParser().parse(recording, new ChunkParserListener() {
			private ChunkTypes types;

			@Override
			public void onTypes(ChunkTypes t) {
				types = t;
			}

			@Override
			public void onCheckpoint(RecordingStream stream, int payloadSize) {
			}

			@Override
			public void onEvent(long typeId, RecordingStream stream, int payloadSize) {
				ChunkTypes.Type type = types.getEventType(typeId);
				counts.merge(type == null ? "?" + typeId : type.name, 1, Integer::sum);
			}

			@Override
			public void onChunkEnd() {
			}
		});
		return counts;
	}

	private static Map<String, Integer> jdkEventCounts(Path recording) throws IOException {
		Map<String, Integer> counts = new TreeMap<>();
		try (RecordingFile file = new RecordingFile(recording)) {
			while (file.hasMoreEvents()) {
				RecordedEvent event = file.readEvent();
				counts.merge(event.getEventType().getName(), 1, Integer::sum);
			}
		}
		return counts;
	}

	private static void check(List<String> problems, boolean condition, String problem) {
		if (!condition) {
			problems.add(problem);
		}
	}

	private static String shorten(String s) {
		String oneLine = s.replace('\n', ' ');
		return oneLine.length() > 60 ? oneLine.substring(0, 57) + "..." : oneLine;
	}

	public static void main(String[] args) throws IOException {
		boolean failed = false;
		for (String arg : args) {
			Path input = Path.of(arg);
			Path output = Files.createTempFile("redacted", ".jfr");
			boolean legacy = isLegacy(input);
			List<String> problems = verify(input, output, aggressive(4), !legacy);
			for (String problem : problems) {
				System.out.println("  " + problem);
			}
			failed |= !problems.isEmpty();
			Files.delete(output);
		}
		System.exit(failed ? 1 : 0);
	}

	private static boolean isLegacy(Path recording) throws IOException {
		byte[] header = new byte[8];
		try (var in = Files.newInputStream(recording)) {
			in.readNBytes(header, 0, 8);
		}
		return header[5] == 0;
	}
}
