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

import java.util.Arrays;
import java.util.Collection;
import java.util.Set;

/**
 * Answers whether a string occurs within any of a fixed set of strings, in time proportional to its
 * length rather than to the size of the set. The positions of every 3-character substring of the
 * set are indexed; a query looks up the rarest of its own and compares the string at those
 * positions only. A string shorter than that is searched for in the joined strings.
 */
final class SubstringIndex {
	private static final int GRAM = 3;
	private static final long GOLDEN = 0x9E3779B97F4A7C15L;

	private final Set<String> strings;
	private final int longest;
	/** The strings joined, and for each position the end of its string in it */
	private final String text;
	private final int[] stringEnd;
	/**
	 * The grams, an open addressing table of their keys scrambled by {@link #GOLDEN}, which keeps
	 * them distinct while spreading them over the slots, and per slot its positions in the text, at
	 * {@code positions[offsets[slot], offsets[slot + 1])}
	 */
	private final long[] slotKeys;
	private final int[] offsets;
	private final int[] positions;
	private final int shift;

	SubstringIndex(Collection<String> strings) {
		this.strings = Set.copyOf(strings);
		StringBuilder joined = new StringBuilder();
		int longest = 0;
		for (String s : this.strings) {
			joined.append(s);
			longest = Math.max(longest, s.length());
		}
		this.longest = longest;
		text = joined.toString();
		stringEnd = new int[text.length()];
		int position = 0;
		for (String s : this.strings) {
			int end = position + s.length();
			Arrays.fill(stringEnd, position, end, end);
			position = end;
		}
		int bits = Math.max(4, 64 - Long.numberOfLeadingZeros(Math.max(1, text.length()) * 2L));
		shift = 64 - bits;
		slotKeys = new long[1 << bits];
		int[] counts = new int[(1 << bits) + 1];
		for (int i = 0; i + GRAM <= text.length(); i++) {
			if (i + GRAM <= stringEnd[i]) {
				counts[slot(key(text, i), true)]++;
			}
		}
		offsets = new int[(1 << bits) + 1];
		for (int slot = 0; slot < counts.length - 1; slot++) {
			offsets[slot + 1] = offsets[slot] + counts[slot];
		}
		positions = new int[offsets[offsets.length - 1]];
		int[] filled = Arrays.copyOf(offsets, offsets.length - 1);
		for (int i = 0; i + GRAM <= text.length(); i++) {
			if (i + GRAM <= stringEnd[i]) {
				positions[filled[slot(key(text, i), false)]++] = i;
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
			for (int at = text.indexOf(value); at >= 0; at = text.indexOf(value, at + 1)) {
				if (at + length <= stringEnd[at]) {
					return true;
				}
			}
			return false;
		}
		int rarest = -1;
		int rarestOffset = 0;
		for (int offset = 0; offset + GRAM <= length; offset++) {
			int slot = find(key(value, offset));
			if (slot < 0) {
				return false;
			}
			if (rarest < 0 || count(slot) < count(rarest)) {
				rarest = slot;
				rarestOffset = offset;
			}
		}
		for (int p = offsets[rarest]; p < offsets[rarest + 1]; p++) {
			int start = positions[p] - rarestOffset;
			if (start >= 0 && start + length <= stringEnd[start] && text.regionMatches(start, value, 0, length)) {
				return true;
			}
		}
		return false;
	}

	private int count(int slot) {
		return offsets[slot + 1] - offsets[slot];
	}

	/** The slot of the key, inserting it if absent and {@code insert} */
	private int slot(long key, boolean insert) {
		int mask = slotKeys.length - 1;
		for (int slot = (int) (key >>> shift);; slot = (slot + 1) & mask) {
			if (slotKeys[slot] == key) {
				return slot;
			}
			if (slotKeys[slot] == 0) {
				if (!insert) {
					throw new IllegalStateException("A gram missing from the index");
				}
				slotKeys[slot] = key;
				return slot;
			}
		}
	}

	/** @return the slot of the key, or -1 if absent */
	private int find(long key) {
		int mask = slotKeys.length - 1;
		for (int slot = (int) (key >>> shift);; slot = (slot + 1) & mask) {
			if (slotKeys[slot] == key) {
				return slot;
			}
			if (slotKeys[slot] == 0) {
				return -1;
			}
		}
	}

	/** The gram at the position, scrambled, never 0, which marks an empty slot */
	private static long key(String s, int at) {
		long gram = (long) s.charAt(at) << 32 | (long) s.charAt(at + 1) << 16 | s.charAt(at + 2);
		return (gram + 1) * GOLDEN;
	}
}
