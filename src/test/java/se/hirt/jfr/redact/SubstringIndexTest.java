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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Set;

import org.junit.jupiter.api.Test;

class SubstringIndexTest {
	@Test
	void findsWhatContainsFinds() {
		Random random = new Random(7);
		for (int round = 0; round < 50; round++) {
			List<String> strings = new ArrayList<>();
			for (int i = random.nextInt(30); i > 0; i--) {
				strings.add(randomString(random, random.nextInt(12)));
			}
			SubstringIndex index = new SubstringIndex(strings);
			for (int query = 0; query < 500; query++) {
				String value;
				if (!strings.isEmpty() && random.nextBoolean()) {
					String s = strings.get(random.nextInt(strings.size()));
					int start = random.nextInt(s.length() + 1);
					value = s.substring(start, start + random.nextInt(s.length() - start + 1));
				} else {
					value = randomString(random, random.nextInt(8));
				}
				assertEquals(bruteForce(strings, value), index.occursIn(value), strings + " " + value);
			}
		}
	}

	@Test
	void neverMatchesAcrossStrings() {
		SubstringIndex index = new SubstringIndex(List.of("abc", "def"));
		assertTrue(index.occursIn("bc") && index.occursIn("de") && index.occursIn("abc"));
		assertFalse(index.occursIn("cd") || index.occursIn("bcd") || index.occursIn("cde"));
	}

	@Test
	void findsTheEmptyStringOnlyAsAString() {
		assertFalse(new SubstringIndex(List.of("abc")).occursIn(""));
		assertTrue(new SubstringIndex(List.of("abc", "")).occursIn(""));
		assertFalse(new SubstringIndex(Set.of()).occursIn("a"));
	}

	@Test
	void comparesCharactersNotCodePoints() {
		SubstringIndex index = new SubstringIndex(List.of("x😀y"));
		assertTrue(index.occursIn("\uD83D") && index.occursIn("\uDE00y") && index.occursIn("x😀"));
	}

	/**
	 * The definition: equal to one of the strings, or within a longer one, never the empty string
	 */
	private static boolean bruteForce(List<String> strings, String value) {
		if (strings.contains(value)) {
			return true;
		}
		if (value.isEmpty()) {
			return false;
		}
		return strings.stream().anyMatch(s -> s.length() > value.length() && s.contains(value));
	}

	private static String randomString(Random random, int length) {
		StringBuilder s = new StringBuilder();
		for (int i = 0; i < length; i++) {
			s.append("abé\uD83D".charAt(random.nextInt(4)));
		}
		return s.toString();
	}
}
