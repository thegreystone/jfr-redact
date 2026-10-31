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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import jdk.jfr.Event;
import jdk.jfr.Name;
import jdk.jfr.Recording;
import jdk.jfr.StackTrace;

class MainTest {
	@Test
	void tableCell() {
		assertEquals("<EMPTY>", Main.toTableCell(""));
		assertEquals("java.lang.Thread", Main.toTableCell("java.lang.Thread"));
		assertEquals("K~ssnacht~~", Main.toTableCell("Küssnacht\t😀"));
		assertEquals("x".repeat(40), Main.toTableCell("x".repeat(40)));
		assertEquals("x".repeat(37) + "...", Main.toTableCell("x".repeat(41)));
		assertEquals("~".repeat(37) + "...", Main.toTableCell("€".repeat(100)));
	}

	@Test
	void escapesLoneSurrogatesLosslesslyForUtf8Output(@TempDir
	Path dir) throws Exception {
		Map<String, String> cases = new LinkedHashMap<>();
		cases.put("\uD800", "\\uD800");
		cases.put("\uDC00", "\\uDC00");
		cases.put("\uD800start", "\\uD800start");
		cases.put("end\uDC00", "end\\uDC00");
		cases.put("before\uD800middle\uDC00after", "before\\uD800middle\\uDC00after");
		cases.put("\uD83D\uDE00", "\uD83D\uDE00");
		cases.put("A\uD83D\uDE00B", "A\uD83D\uDE00B");
		cases.put("\uD800\uD83D\uDE00\uDC00", "\\uD800\uD83D\uDE00\\uDC00");
		cases.put("\\uD800\\uDC00", "\\\\uD800\\\\uDC00");
		cases.put("\uFFFD", "\uFFFD");
		cases.put("?", "?");
		cases.put("\\\t\r\n", "\\\\\\t\\r\\n");

		Path file = dir.resolve("escaped-strings.txt");
		Files.write(file, cases.keySet().stream().map(Main::escape).toList(), StandardCharsets.UTF_8);
		List<String> written = Files.readAllLines(file, StandardCharsets.UTF_8);
		assertEquals(List.copyOf(cases.values()), written);
		int index = 0;
		for (String original : cases.keySet()) {
			Properties decoded = new Properties();
			decoded.load(new StringReader("value=" + written.get(index++)));
			assertEquals(original, decoded.getProperty("value"), "escaping must preserve the original UTF-16 units");
		}
	}

	@Test
	void sortsTableByOccurrencesOrReferences() throws Exception {
		String recording = recording().toString();
		List<TableRow> occurrences = tableRows(run("scan", "--table", "--top", "10000", recording));
		assertTrue(occurrences.size() > 5);
		assertEquals(occurrences,
				tableRows(run("scan", "--table", "--sort", "occurrences", "--top", "10000", recording)));
		for (int i = 1; i < occurrences.size(); i++) {
			assertTrue(occurrences.get(i - 1).occurrences() >= occurrences.get(i).occurrences());
		}

		String output = run("scan", "--table", "--sort", "references", "--top", "10000", recording);
		List<TableRow> references = tableRows(output);
		assertEquals(occurrences.size(), references.size());
		assertNotEquals(occurrences, references, "the fixture must distinguish the two sort orders");
		assertTrue(references.getFirst().references() > 0);
		boolean occurrenceTieBreakExercised = false;
		for (int i = 1; i < references.size(); i++) {
			TableRow previous = references.get(i - 1);
			TableRow current = references.get(i);
			assertTrue(previous.references() >= current.references());
			if (previous.references() == current.references()) {
				assertTrue(previous.occurrences() >= current.occurrences());
				occurrenceTieBreakExercised |= previous.occurrences() > current.occurrences();
			}
		}
		assertTrue(occurrenceTieBreakExercised, "the fixture must exercise occurrence tie breaking");
		assertTrue(output.contains("most referenced"));
		assertEquals(references.subList(0, 5),
				tableRows(run("scan", "--table", "--sort", "references", "--top", "5", recording)),
				"top must be applied after sorting");
	}

	@Test
	void referenceSortCountsReferencesAndOrdersTsv(@TempDir
	Path dir) throws Exception {
		Path tsv = dir.resolve("strings.tsv");
		String output = run("scan", "--sort", "references", "--top", "0", "--out", tsv.toString(),
				recording().toString());
		assertTrue(output.contains("References:"), "reference sorting must enable reference counting");
		List<String> lines = Files.readAllLines(tsv);
		assertEquals("inline\tconstantPool\treferences\tstring", lines.getFirst());
		long previousReferences = Long.MAX_VALUE;
		long previousOccurrences = Long.MAX_VALUE;
		boolean countedReferences = false;
		for (String line : lines.subList(1, lines.size())) {
			String[] fields = line.split("\t", -1);
			long occurrences = Long.parseLong(fields[0]) + Long.parseLong(fields[1]);
			long references = Long.parseLong(fields[2]);
			assertTrue(previousReferences >= references);
			if (previousReferences == references) {
				assertTrue(previousOccurrences >= occurrences);
			}
			countedReferences |= references > 0;
			previousReferences = references;
			previousOccurrences = occurrences;
		}
		assertTrue(countedReferences);
	}

	@Test
	void sortsTablesByInlineCountsOrLength() throws Exception {
		String recording = recording().toString();
		for (String key : List.of("inlined", "length")) {
			String output = run("scan", "--table", "--sort", key, "--top", "10000", recording);
			List<TableRow> rows = tableRows(output);
			assertTrue(rows.size() > 5);
			boolean occurrenceTieBreakExercised = false;
			for (int i = 1; i < rows.size(); i++) {
				TableRow previous = rows.get(i - 1);
				TableRow current = rows.get(i);
				long previousMetric = key.equals("inlined") ? previous.inlined() : previous.length();
				long currentMetric = key.equals("inlined") ? current.inlined() : current.length();
				assertTrue(previousMetric >= currentMetric, key);
				if (previousMetric == currentMetric) {
					assertTrue(previous.occurrences() >= current.occurrences(), key);
					occurrenceTieBreakExercised |= previous.occurrences() > current.occurrences();
				}
			}
			assertTrue(occurrenceTieBreakExercised, "the fixture must exercise occurrence tie breaking for " + key);
			assertTrue(output.contains(key.equals("inlined") ? "most inlined" : "longest"));
			assertEquals(rows.subList(0, 5), tableRows(run("scan", "--table", "--sort", key, "--top", "5", recording)));
		}
	}

	@Test
	void inlineAndLengthSortsOrderPlainOutputAndTsvWithoutCountingReferences(@TempDir
	Path dir) throws Exception {
		for (String key : List.of("inlined", "length")) {
			Path tsv = dir.resolve(key + ".tsv");
			String output = run("scan", "--sort", key, "--top", "5", "--out", tsv.toString(), recording().toString());
			assertFalse(output.contains("References:"), key + " must not enable reference counting");
			List<String> lines = Files.readAllLines(tsv);
			assertEquals("inline\tconstantPool\tstring", lines.getFirst());
			List<String[]> rows = lines.stream().skip(1).map(line -> line.split("\t", -1)).toList();
			assertTrue(rows.size() > 5, "TSV must contain all strings regardless of top");
			long previousMetric = Long.MAX_VALUE;
			long previousOccurrences = Long.MAX_VALUE;
			for (String[] row : rows) {
				long inlined = Long.parseLong(row[0]);
				long occurrences = inlined + Long.parseLong(row[1]);
				String value = row[2].translateEscapes();
				long metric = key.equals("inlined") ? inlined : value.codePointCount(0, value.length());
				assertTrue(previousMetric >= metric, key);
				if (previousMetric == metric) {
					assertTrue(previousOccurrences >= occurrences, key);
				}
				previousMetric = metric;
				previousOccurrences = occurrences;
			}
			List<String> plainStrings = output.lines().dropWhile(line -> !line.stripLeading().startsWith("Inline"))
					.skip(1).limit(5).map(line -> line.substring(27)).toList();
			assertEquals(rows.subList(0, 5).stream().map(row -> row[2]).toList(), plainStrings);
		}
	}

	@Test
	void lengthSortCountsSupplementaryCharactersOnce(@TempDir
	Path dir) throws Exception {
		Path file = dir.resolve("unicode-length.jfr");
		try (Recording recording = new Recording()) {
			recording.enable(LengthEvent.class);
			recording.start();
			for (String value : List.of("😀".repeat(20), "A".repeat(30), "B".repeat(20), "B".repeat(20))) {
				LengthEvent event = new LengthEvent();
				event.value = value;
				event.commit();
			}
			recording.stop();
			recording.dump(file);
		}
		List<TableRow> rows = tableRows(run("scan", "--table", "--sort", "length", "--top", "10000", file.toString()));
		TableRow emoji = rows.stream().filter(row -> row.value().equals("~".repeat(20))).findFirst().orElseThrow();
		TableRow longer = rows.stream().filter(row -> row.value().equals("A".repeat(30))).findFirst().orElseThrow();
		TableRow tied = rows.stream().filter(row -> row.value().equals("B".repeat(20))).findFirst().orElseThrow();
		assertEquals(20, emoji.length());
		assertEquals(30, longer.length());
		assertTrue(rows.indexOf(longer) < rows.indexOf(emoji), "length must count code points, not UTF-16 units");
		assertTrue(tied.occurrences() > emoji.occurrences());
		assertTrue(rows.indexOf(tied) < rows.indexOf(emoji), "equal lengths must use occurrence counts");
	}

	@Test
	void rejectsInvalidOrMissingSortOrder() {
		assertThrows(IllegalArgumentException.class, () -> run("scan", "--sort", "invalid"));
		assertThrows(IllegalArgumentException.class, () -> run("scan", "--sort"));
	}

	private static Path recording() throws Exception {
		return Path.of(MainTest.class.getResource("/recordings/jdk9-basic.jfr").toURI());
	}

	private static String run(String ... args) throws Exception {
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		ByteArrayOutputStream errors = new ByteArrayOutputStream();
		try (PrintStream out = new PrintStream(output, true, StandardCharsets.UTF_8);
				PrintStream err = new PrintStream(errors, true, StandardCharsets.UTF_8)) {
			assertEquals(0, Main.run(args, out, err), errors.toString(StandardCharsets.UTF_8));
		}
		return output.toString(StandardCharsets.UTF_8);
	}

	private static List<TableRow> tableRows(String output) {
		return output.lines().dropWhile(line -> !line.startsWith("-".repeat(40))).skip(1)
				.takeWhile(line -> !line.isEmpty())
				.map(line -> new TableRow(line.substring(0, 40).stripTrailing(), tableNumber(line.substring(41, 51)),
						tableNumber(line.substring(52, 64)), tableNumber(line.substring(65, 77)),
						tableNumber(line.substring(78))))
				.toList();
	}

	private static long tableNumber(String value) {
		return Long.parseLong(value.replaceAll("[^0-9]", ""));
	}

	private record TableRow(String value, long length, long occurrences, long inlined, long references) {
	}

	@Name("test.SortLength")
	@StackTrace(false)
	static class LengthEvent extends Event {
		String value;
	}
}
