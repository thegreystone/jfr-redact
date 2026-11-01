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
package se.hirt.jfr.redact.cli;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;

import se.hirt.jfr.redact.parser.StreamingChunkParser;
import se.hirt.jfr.redact.RuleRedactor;
import se.hirt.jfr.redact.JfrRedactor;
import se.hirt.jfr.redact.RedactionResult;
import se.hirt.jfr.redact.StringRedactor;
import se.hirt.jfr.redact.scan.StringCountMap;
import se.hirt.jfr.redact.scan.StringScanner;

public final class Main {
	private static final String USAGE = """
			Usage: jfr-redact scan [options] <recording.jfr>
			       jfr-redact redact [--hash-thread-names] [--hash-class-names <regex>]...
			                         [--hash-method-names <regex>]...
			                         [--rename-package <package> <new name>]...
			                         [--replace <pattern> <replacement>]... [--match <regex>]...
			                         [--replacement <text>] <recording.jfr> <redacted.jfr>

			Lists all strings stored in the recording, with the number of times each one is stored
			inline in events and in constant pools.

			Options:
			  --top <n>      Number of strings to print (default 20, 0 for none)
			  --sort <key>   Sort by occurrences (default), references, inlined or length, highest first
			                 Length counts Unicode code points; references implies --references
			  --table        Print the strings as a terminal friendly table: the string in ASCII, cropped
			                 to 40 characters, its length, its total number of occurrences, how many of
			                 those are inlined in events, and the references to the constants containing
			                 it. Characters outside printable ASCII are shown as ~, and the empty string
			                 as <EMPTY>. Implies --references
			  --references   Also count the direct references to the constants containing each string,
			                 from events and from other constants. Decodes nearly all events, so slower
			  --out <file>   Write all strings to a tab separated file: inline, constant pool,
			                 references (if counted), string
			  --validate     Decode all events, also those that cannot contain strings, and verify that
			                 every event decodes to its declared size

			Redact replaces strings everywhere they are stored in the recording, and writes the result to
			a new recording. Rules are tried in the order given, with --match last.

			Options:
			  --hash-thread-names   Replace thread names with Thread-<hash of the name> and thread group
			                        names with ThreadGroup-<hash of the name>
			  --hash-class-names <regex>
			                        Replace the part of class names matching the expression (the first
			                        group, if any) with a hash, segment by segment, as in
			                        'com\\.acme\\.(.*)', which turns com.acme.secret.Foo into
			                        com.acme.<hash>.<hash> and its package into com.acme.<hash>: as
			                        constants, in descriptors, thread dumps and old-object descriptions.
			                        Package and module names the expression matches, followed by a dot,
			                        are hashed alike, so prefix expressions hide packages, while
			                        '(.*)Impl$' hashes simple names only. Can be repeated: the
			                        expressions form one rule, in the place of the first, and for each
			                        part of a name, the package or the simple name, the first expression
			                        covering a piece of it decides
			  --hash-method-names <regex>
			                        Same for method names. Can be repeated
			  --rename-package <package> <new name>
			                        Rename a package and its subpackages, in source form (java.util.List),
			                        internal form (java/util/List) and descriptors. Can be repeated
			  --replace <pattern> <replacement>
			                        Replace strings matching a pattern, which may start and/or end with *,
			                        as in --replace 'java.util.*' 'utilz.*'. A * in the replacement is the
			                        matched remainder. Can be repeated
			  --match <regex>       Replace strings containing a match of the regular expression with the
			                        --replacement text. Can be repeated
			  --replacement <text>  Replacement for --match (default <REDACTED>)
			""";

	private static final int TABLE_STRING_WIDTH = 40;
	private static final String ELLIPSIS = "...";
	private static final char NON_ASCII_MARKER = '~';

	private enum SortOrder {
		OCCURRENCES("most common"), REFERENCES("most referenced"), INLINED("most inlined"), LENGTH("longest");

		private final String description;

		SortOrder(String description) {
			this.description = description;
		}

		static SortOrder parse(String value) {
			return switch (value) {
			case "occurrences" -> OCCURRENCES;
			case "references" -> REFERENCES;
			case "inlined" -> INLINED;
			case "length" -> LENGTH;
			default -> throw new IllegalArgumentException(
					"Unknown sort order: " + value + " (expected occurrences, references, inlined or length)");
			};
		}
	}

	private Main() {
	}

	public static void main(String[] args) {
		try {
			System.exit(run(args, System.out, System.err));
		} catch (IOException | IllegalArgumentException e) {
			System.err.println("Error: " + e.getMessage());
			System.exit(1);
		}
	}

	static int run(String[] args, PrintStream out, PrintStream err) throws IOException {
		if (args.length > 0 && "redact".equals(args[0])) {
			return redact(args, out, err);
		}
		if (args.length == 0 || !"scan".equals(args[0])) {
			err.print(USAGE);
			return 2;
		}
		int top = 20;
		Path outFile = null;
		boolean validate = false;
		boolean table = false;
		boolean references = false;
		SortOrder sort = SortOrder.OCCURRENCES;
		Path recording = null;
		for (int i = 1; i < args.length; i++) {
			switch (args[i]) {
			case "--top" -> top = Integer.parseInt(requireValue(args, ++i));
			case "--sort" -> sort = SortOrder.parse(requireValue(args, ++i));
			case "--out" -> outFile = Path.of(requireValue(args, ++i));
			case "--validate" -> validate = true;
			case "--table" -> table = true;
			case "--references" -> references = true;
			default -> {
				if (args[i].startsWith("-") || recording != null) {
					err.println("Unexpected argument: " + args[i]);
					err.print(USAGE);
					return 2;
				}
				recording = Path.of(args[i]);
			}
			}
		}
		if (recording == null) {
			err.print(USAGE);
			return 2;
		}

		long start = System.nanoTime();
		StringScanner scanner = new StringScanner(validate, references || table || sort == SortOrder.REFERENCES);
		new StreamingChunkParser().parse(recording, scanner);
		long elapsedNanos = System.nanoTime() - start;

		printSummary(out, recording, scanner, elapsedNanos);
		StringCountMap strings = scanner.getStrings();
		Integer[] sorted = sortStrings(strings, sort);
		if (top > 0) {
			if (table) {
				printTable(out, strings, sorted, top, sort);
			} else {
				printTop(out, strings, sorted, top);
			}
		}
		if (outFile != null) {
			writeTsv(outFile, strings, sorted, scanner.isCountingReferences());
			out.println("Wrote " + strings.size() + " strings to " + outFile);
		}
		if (validate && scanner.getMisalignedCount() > 0) {
			err.println("Validation failed: " + scanner.getMisalignedCount()
					+ " events or checkpoints did not decode to their declared size");
			return 1;
		}
		return 0;
	}

	private static int redact(String[] args, PrintStream out, PrintStream err) throws IOException {
		List<Pattern> patterns = new ArrayList<>();
		RuleRedactor.Builder globs = RuleRedactor.builder();
		boolean anyGlob = false;
		String replacement = "<REDACTED>";
		List<Path> files = new ArrayList<>();
		for (int i = 1; i < args.length; i++) {
			switch (args[i]) {
			case "--match" -> patterns.add(Pattern.compile(requireValue(args, ++i)));
			case "--hash-class-names" -> {
				globs.hashClassNames(requireValue(args, ++i));
				anyGlob = true;
			}
			case "--hash-method-names" -> {
				globs.hashMethodNames(requireValue(args, ++i));
				anyGlob = true;
			}
			case "--hash-thread-names" -> {
				globs.hashThreadNames();
				anyGlob = true;
			}
			case "--rename-package" -> {
				String packageName = requireValue(args, ++i);
				globs.renamePackage(packageName, requireValue(args, ++i));
				anyGlob = true;
			}
			case "--replace" -> {
				String pattern = requireValue(args, ++i);
				globs.replace(pattern, requireValue(args, ++i));
				anyGlob = true;
			}
			case "--replacement" -> replacement = requireValue(args, ++i);
			default -> {
				if (args[i].startsWith("-")) {
					err.println("Unexpected argument: " + args[i]);
					err.print(USAGE);
					return 2;
				}
				files.add(Path.of(args[i]));
			}
			}
		}
		if (files.size() != 2 || (patterns.isEmpty() && !anyGlob)) {
			err.print(USAGE);
			return 2;
		}
		String fixedReplacement = replacement;
		StringRedactor regexRedactor = (value, locations) -> {
			for (Pattern pattern : patterns) {
				if (pattern.matcher(value).find()) {
					return fixedReplacement;
				}
			}
			return value;
		};
		long start = System.nanoTime();
		RedactionResult result = JfrRedactor.redact(files.get(0), files.get(1), globs.build().orElse(regexRedactor));
		double millis = (System.nanoTime() - start) / 1e6;
		out.printf("Redacted %s into %s in %.1f ms%n", files.get(0), files.get(1), millis);
		out.printf("Strings: %,d of %,d redacted, %,d stored occurrences replaced%n", result.redactedStringCount(),
				result.stringCount(), result.replacedOccurrenceCount());
		out.printf("Chunks: %,d of %,d rewritten, %,d events and %,d checkpoints re-encoded%n",
				result.rewrittenChunkCount(), result.chunkCount(), result.rewrittenEventCount(),
				result.rewrittenCheckpointCount());
		if (!result.redactedInMetadata().isEmpty()) {
			err.printf("Warning: %,d redacted strings also occur in the metadata, where they remain:%n",
					result.redactedInMetadata().size());
			List<String> shown = result.redactedInMetadata().subList(0,
					Math.min(10, result.redactedInMetadata().size()));
			for (String s : shown) {
				err.println("  " + toTableCell(s));
			}
			if (shown.size() < result.redactedInMetadata().size()) {
				err.printf("  ... and %,d more%n", result.redactedInMetadata().size() - shown.size());
			}
		}
		return 0;
	}

	private static String requireValue(String[] args, int i) {
		if (i >= args.length) {
			throw new IllegalArgumentException("Missing value for " + args[i - 1]);
		}
		return args[i];
	}

	private static void printSummary(PrintStream out, Path recording, StringScanner scanner, long elapsedNanos)
			throws IOException {
		long bytes = Files.size(recording);
		double millis = elapsedNanos / 1e6;
		out.printf("Scanned %s (%,d bytes) in %.1f ms (%.1f MB/s)%n", recording, bytes, millis,
				bytes / 1e6 / (millis / 1e3));
		out.printf("Chunks: %,d  Events: %,d (decoded %,d)  Checkpoints: %,d  Constants: %,d%n",
				scanner.getChunkCount(), scanner.getEventCount(), scanner.getDecodedEventCount(),
				scanner.getCheckpointCount(), scanner.getConstantCount());
		out.printf("Strings: %,d unique, %,d inline, %,d in constant pools, %,d constant pool references%n",
				scanner.getStrings().size(), scanner.getOccurrenceCount(StringScanner.INLINE),
				scanner.getOccurrenceCount(StringScanner.CONSTANT_POOL), scanner.getConstantPoolReferenceCount());
		if (scanner.isCountingReferences()) {
			out.printf("References: %,d to constants containing strings (%,d unresolved)%n",
					scanner.getReferenceCount(), scanner.getUnresolvedReferenceCount());
		}
		if (scanner.getUnknownEventCount() > 0) {
			out.printf("Warning: %,d events of undeclared types were skipped%n", scanner.getUnknownEventCount());
		}
		if (scanner.getMisalignedCount() > 0) {
			out.printf("Warning: %,d events or checkpoints did not decode to their declared size%n",
					scanner.getMisalignedCount());
		}
	}

	private static Integer[] sortStrings(StringCountMap strings, SortOrder sort) {
		Integer[] entries = new Integer[strings.size()];
		Arrays.setAll(entries, i -> i);
		Comparator<Integer> occurrences = Comparator.comparingLong((Integer e) -> strings.getTotalCount(e)).reversed();
		Comparator<Integer> order = switch (sort) {
		case OCCURRENCES -> occurrences;
		case REFERENCES -> Comparator.comparingLong((Integer e) -> strings.getReferenceCount(e)).reversed();
		case INLINED -> Comparator.comparingLong((Integer e) -> strings.getCount(e, StringScanner.INLINE)).reversed();
		case LENGTH -> {
			int[] lengths = new int[strings.size()];
			for (int e = 0; e < lengths.length; e++) {
				String value = strings.getString(e);
				lengths[e] = value.codePointCount(0, value.length());
			}
			yield Comparator.comparingInt((Integer e) -> lengths[e]).reversed();
		}
		};
		Arrays.sort(entries, sort == SortOrder.OCCURRENCES ? order : order.thenComparing(occurrences));
		return entries;
	}

	private static void printTop(PrintStream out, StringCountMap strings, Integer[] sorted, int top) {
		out.println();
		out.printf("%12s %12s  %s%n", "Inline", "Pool", "String");
		for (int i = 0; i < Math.min(top, sorted.length); i++) {
			int e = sorted[i];
			out.printf("%,12d %,12d  %s%n", strings.getCount(e, StringScanner.INLINE),
					strings.getCount(e, StringScanner.CONSTANT_POOL), escape(strings.getString(e)));
		}
	}

	private static void printTable(PrintStream out, StringCountMap strings, Integer[] sorted, int top, SortOrder sort) {
		String format = "%-" + TABLE_STRING_WIDTH + "s %10s %12s %12s %12s%n";
		out.println();
		out.printf(format, "String", "Length", "Occurrences", "Inlined", "References");
		out.printf(format, "-".repeat(TABLE_STRING_WIDTH), "-".repeat(10), "-".repeat(12), "-".repeat(12),
				"-".repeat(12));
		int shown = Math.min(top, sorted.length);
		for (int i = 0; i < shown; i++) {
			int e = sorted[i];
			String s = strings.getString(e);
			out.printf(format, toTableCell(s), String.format("%,d", s.codePointCount(0, s.length())),
					String.format("%,d", strings.getTotalCount(e)),
					String.format("%,d", strings.getCount(e, StringScanner.INLINE)),
					String.format("%,d", strings.getReferenceCount(e)));
		}
		out.println();
		String order = sort.description;
		if (shown == sorted.length) {
			out.printf("Showing all %,d strings, %s first.%n", sorted.length, order);
		} else {
			out.printf("Showing the top %,d %s strings of %,d.%n", shown, order, sorted.length);
		}
	}

	/**
	 * Renders the string in printable ASCII, cropped with an ellipsis to fit the table column.
	 */
	static String toTableCell(String s) {
		if (s.isEmpty()) {
			return "<EMPTY>";
		}
		StringBuilder sb = new StringBuilder(TABLE_STRING_WIDTH);
		int codePoints = s.codePointCount(0, s.length());
		int visible = codePoints <= TABLE_STRING_WIDTH ? codePoints : TABLE_STRING_WIDTH - ELLIPSIS.length();
		for (int i = 0, n = 0; n < visible; n++) {
			int c = s.codePointAt(i);
			sb.append(c >= 0x20 && c < 0x7F ? (char) c : NON_ASCII_MARKER);
			i += Character.charCount(c);
		}
		if (visible < codePoints) {
			sb.append(ELLIPSIS);
		}
		return sb.toString();
	}

	private static void writeTsv(Path file, StringCountMap strings, Integer[] sorted, boolean references)
			throws IOException {
		try (Writer writer = new BufferedWriter(Files.newBufferedWriter(file, StandardCharsets.UTF_8), 1 << 16)) {
			writer.write(references ? "inline\tconstantPool\treferences\tstring\n" : "inline\tconstantPool\tstring\n");
			for (int e : sorted) {
				writer.write(Long.toString(strings.getCount(e, StringScanner.INLINE)));
				writer.write('\t');
				writer.write(Long.toString(strings.getCount(e, StringScanner.CONSTANT_POOL)));
				writer.write('\t');
				if (references) {
					writer.write(Long.toString(strings.getReferenceCount(e)));
					writer.write('\t');
				}
				writer.write(escape(strings.getString(e)));
				writer.write('\n');
			}
		}
	}

	static String escape(String s) {
		StringBuilder sb = null;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			String replacement = switch (c) {
			case '\t' -> "\\t";
			case '\n' -> "\\n";
			case '\r' -> "\\r";
			case '\\' -> "\\\\";
			default -> {
				boolean unpaired = Character.isHighSurrogate(c)
						? i + 1 == s.length() || !Character.isLowSurrogate(s.charAt(i + 1))
						: Character.isLowSurrogate(c) && (i == 0 || !Character.isHighSurrogate(s.charAt(i - 1)));
				yield unpaired ? String.format("\\u%04X", (int) c) : null;
			}
			};
			if (replacement != null && sb == null) {
				sb = new StringBuilder(s.length() + 16).append(s, 0, i);
			}
			if (sb != null) {
				if (replacement != null) {
					sb.append(replacement);
				} else {
					sb.append(c);
				}
			}
		}
		return sb == null ? s : sb.toString();
	}
}
