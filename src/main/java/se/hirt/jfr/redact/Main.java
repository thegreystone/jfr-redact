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

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;

import se.hirt.jfr.redact.parser.StreamingChunkParser;
import se.hirt.jfr.redact.scan.StringCountMap;
import se.hirt.jfr.redact.scan.StringScanner;

public final class Main {
	private static final String USAGE = """
			Usage: jfr-redact scan [options] <recording.jfr>

			Lists all strings stored in the recording, with the number of times each one is stored
			inline in events and in constant pools.

			Options:
			  --top <n>      Number of strings to print, sorted by occurrences (default 20, 0 for none)
			  --table        Print the strings as a terminal friendly table: the string in ASCII, cropped
			                 to 40 characters, its length, its total number of occurrences and how many of
			                 those are inlined in events. Characters outside printable ASCII are shown
			                 as ~, and the empty string as <EMPTY>
			  --out <file>   Write all strings to a tab separated file: inline, constant pool, string
			  --validate     Decode all events, also those that cannot contain strings, and verify that
			                 every event decodes to its declared size
			""";

	private static final int TABLE_STRING_WIDTH = 40;
	private static final String ELLIPSIS = "...";
	private static final char NON_ASCII_MARKER = '~';

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
		if (args.length == 0 || !"scan".equals(args[0])) {
			err.print(USAGE);
			return 2;
		}
		int top = 20;
		Path outFile = null;
		boolean validate = false;
		boolean table = false;
		Path recording = null;
		for (int i = 1; i < args.length; i++) {
			switch (args[i]) {
			case "--top" -> top = Integer.parseInt(requireValue(args, ++i));
			case "--out" -> outFile = Path.of(requireValue(args, ++i));
			case "--validate" -> validate = true;
			case "--table" -> table = true;
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
		StringScanner scanner = new StringScanner(validate);
		new StreamingChunkParser().parse(recording, scanner);
		long elapsedNanos = System.nanoTime() - start;

		printSummary(out, recording, scanner, elapsedNanos);
		StringCountMap strings = scanner.getStrings();
		Integer[] sorted = sortByOccurrences(strings);
		if (top > 0) {
			if (table) {
				printTable(out, strings, sorted, top);
			} else {
				printTop(out, strings, sorted, top);
			}
		}
		if (outFile != null) {
			writeTsv(outFile, strings, sorted);
			out.println("Wrote " + strings.size() + " strings to " + outFile);
		}
		if (validate && scanner.getMisalignedCount() > 0) {
			err.println("Validation failed: " + scanner.getMisalignedCount()
					+ " events or checkpoints did not decode to their declared size");
			return 1;
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
		if (scanner.getUnknownEventCount() > 0) {
			out.printf("Warning: %,d events of undeclared types were skipped%n", scanner.getUnknownEventCount());
		}
		if (scanner.getMisalignedCount() > 0) {
			out.printf("Warning: %,d events or checkpoints did not decode to their declared size%n",
					scanner.getMisalignedCount());
		}
	}

	private static Integer[] sortByOccurrences(StringCountMap strings) {
		Integer[] entries = new Integer[strings.size()];
		Arrays.setAll(entries, i -> i);
		Arrays.sort(entries, Comparator.comparingLong((Integer e) -> strings.getTotalCount(e)).reversed());
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

	private static void printTable(PrintStream out, StringCountMap strings, Integer[] sorted, int top) {
		String format = "%-" + TABLE_STRING_WIDTH + "s %10s %12s %12s%n";
		out.println();
		out.printf(format, "String", "Length", "Occurrences", "Inlined");
		out.printf(format, "-".repeat(TABLE_STRING_WIDTH), "-".repeat(10), "-".repeat(12), "-".repeat(12));
		int shown = Math.min(top, sorted.length);
		for (int i = 0; i < shown; i++) {
			int e = sorted[i];
			String s = strings.getString(e);
			out.printf(format, toTableCell(s), String.format("%,d", s.codePointCount(0, s.length())),
					String.format("%,d", strings.getTotalCount(e)),
					String.format("%,d", strings.getCount(e, StringScanner.INLINE)));
		}
		out.println();
		if (shown == sorted.length) {
			out.printf("Showing all %,d strings, most common first.%n", sorted.length);
		} else {
			out.printf("Showing the top %,d most common strings of %,d.%n", shown, sorted.length);
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

	private static void writeTsv(Path file, StringCountMap strings, Integer[] sorted) throws IOException {
		try (Writer writer = new BufferedWriter(Files.newBufferedWriter(file, StandardCharsets.UTF_8), 1 << 16)) {
			writer.write("inline\tconstantPool\tstring\n");
			for (int e : sorted) {
				writer.write(Long.toString(strings.getCount(e, StringScanner.INLINE)));
				writer.write('\t');
				writer.write(Long.toString(strings.getCount(e, StringScanner.CONSTANT_POOL)));
				writer.write('\t');
				writer.write(escape(strings.getString(e)));
				writer.write('\n');
			}
		}
	}

	private static String escape(String s) {
		StringBuilder sb = null;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			String replacement = switch (c) {
			case '\t' -> "\\t";
			case '\n' -> "\\n";
			case '\r' -> "\\r";
			case '\\' -> "\\\\";
			default -> null;
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
