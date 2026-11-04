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

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Answers whether a string occurs within any of a fixed set of strings, in time proportional to its
 * length rather than to the size of the set. The positions of every 3-character substring of the
 * set are indexed; a query looks up the rarest of its own and compares the string at those
 * positions only.
 */
final class SubstringIndex {
	private static final int GRAM = 3;

	private final Set<String> strings;
	/** The substrings shorter than a gram, which the gram index cannot find */
	private final Set<String> shortSubstrings = new HashSet<>();
	private final int longest;
	/** The strings joined, and for each position the start and end of its string in it */
	private final String text;
	private final int[] stringStart;
	private final int[] stringEnd;
	private final Map<Long, int[]> gramPositions = new HashMap<>();

	SubstringIndex(Collection<String> strings) {
		this.strings = Set.copyOf(strings);
		StringBuilder joined = new StringBuilder();
		int longest = 0;
		for (String s : this.strings) {
			joined.append(s);
			longest = Math.max(longest, s.length());
			for (int length = 1; length < GRAM; length++) {
				for (int i = 0; i + length <= s.length(); i++) {
					shortSubstrings.add(s.substring(i, i + length));
				}
			}
		}
		this.longest = longest;
		text = joined.toString();
		stringStart = new int[text.length()];
		stringEnd = new int[text.length()];
		Map<Long, Integer> counts = new HashMap<>();
		int position = 0;
		for (String s : this.strings) {
			int end = position + s.length();
			for (int i = position; i < end; i++) {
				stringStart[i] = position;
				stringEnd[i] = end;
				if (i + GRAM <= end) {
					counts.merge(gram(text, i), 1, Integer::sum);
				}
			}
			position = end;
		}
		Map<Long, Integer> filled = new HashMap<>();
		counts.forEach((gram, count) -> gramPositions.put(gram, new int[count]));
		for (int i = 0; i + GRAM <= text.length(); i++) {
			if (i + GRAM <= stringEnd[i]) {
				long gram = gram(text, i);
				int index = filled.merge(gram, 1, Integer::sum) - 1;
				gramPositions.get(gram)[index] = i;
			}
		}
	}

	/**
	 * @return {@code true} if the value is one of the strings, or occurs within one that is longer;
	 *         the empty string only if it is one of the strings
	 */
	boolean occursIn(String value) {
		if (strings.contains(value)) {
			return true;
		}
		int length = value.length();
		if (length == 0 || length >= longest) {
			return false;
		}
		if (length < GRAM) {
			return shortSubstrings.contains(value);
		}
		int[] rarest = null;
		int rarestOffset = 0;
		for (int offset = 0; offset + GRAM <= length; offset++) {
			int[] positions = gramPositions.get(gram(value, offset));
			if (positions == null) {
				return false;
			}
			if (rarest == null || positions.length < rarest.length) {
				rarest = positions;
				rarestOffset = offset;
			}
		}
		for (int position : rarest) {
			int start = position - rarestOffset;
			if (start >= stringStart[position] && start + length <= stringEnd[position]
					&& text.regionMatches(start, value, 0, length)) {
				return true;
			}
		}
		return false;
	}

	private static long gram(String s, int at) {
		return (long) s.charAt(at) << 32 | (long) s.charAt(at + 1) << 16 | s.charAt(at + 2);
	}
}
