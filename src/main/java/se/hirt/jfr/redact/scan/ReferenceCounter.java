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
package se.hirt.jfr.redact.scan;

import java.util.Arrays;

/**
 * Counts the references to the constants of a chunk that contain strings, and credits them to those
 * strings. Constant keys are only unique within a chunk, and constants are commonly written after
 * the events referring to them, so references are tallied per (pool, key) and resolved by
 * {@link #flush(StringCountMap)} at the end of each chunk.
 */
final class ReferenceCounter {
	private static final long M1 = 0x9E3779B97F4A7C15L;
	private static final long M2 = 0xBF58476D1CE4E5B9L;

	/** Entry index + 1, 0 meaning empty */
	private int[] slots = new int[1 << 12];
	private int mask = slots.length - 1;
	private int size;

	private long[] keys = new long[1 << 11];
	private int[] pools = new int[1 << 11];
	private long[] counts = new long[1 << 11];
	/** Range of the constant's strings in {@link #strings}, start is -1 until the constant is seen */
	private int[] starts = new int[1 << 11];
	private int[] ends = new int[1 << 11];

	/** String entry indices of the constants, in the order read */
	private int[] strings = new int[1 << 12];
	private int stringCount;
	private int constantStart = -1;

	private long referenceCount;
	private long unresolvedReferenceCount;

	void reference(int pool, long key) {
		if (key == 0) {
			return; // null reference
		}
		int entry = entry(pool, key);
		counts[entry]++;
		referenceCount++;
	}

	void beginConstant() {
		constantStart = stringCount;
	}

	/** Records a string found while reading a constant, ignored outside of constants */
	void addString(int stringEntry) {
		if (constantStart < 0) {
			return;
		}
		if (stringCount == strings.length) {
			strings = Arrays.copyOf(strings, strings.length * 2);
		}
		strings[stringCount++] = stringEntry;
	}

	void endConstant(int pool, long key) {
		int entry = entry(pool, key);
		starts[entry] = constantStart;
		ends[entry] = stringCount;
		constantStart = -1;
	}

	void flush(StringCountMap stringCounts) {
		for (int entry = 0; entry < size; entry++) {
			long count = counts[entry];
			if (count == 0) {
				continue;
			}
			if (starts[entry] < 0) {
				unresolvedReferenceCount += count;
				continue;
			}
			for (int i = starts[entry]; i < ends[entry]; i++) {
				stringCounts.addReferences(strings[i], count);
			}
		}
		Arrays.fill(slots, 0);
		size = 0;
		stringCount = 0;
		constantStart = -1;
	}

	long getReferenceCount() {
		return referenceCount;
	}

	long getUnresolvedReferenceCount() {
		return unresolvedReferenceCount;
	}

	private int entry(int pool, long key) {
		int hash = hash(pool, key);
		for (int slot = hash & mask;; slot = (slot + 1) & mask) {
			int entry = slots[slot] - 1;
			if (entry < 0) {
				return insert(pool, key, slot);
			}
			if (keys[entry] == key && pools[entry] == pool) {
				return entry;
			}
		}
	}

	private int insert(int pool, long key, int slot) {
		int entry = size++;
		if (entry == keys.length) {
			int capacity = keys.length * 2;
			keys = Arrays.copyOf(keys, capacity);
			pools = Arrays.copyOf(pools, capacity);
			counts = Arrays.copyOf(counts, capacity);
			starts = Arrays.copyOf(starts, capacity);
			ends = Arrays.copyOf(ends, capacity);
		}
		keys[entry] = key;
		pools[entry] = pool;
		counts[entry] = 0;
		starts[entry] = -1;
		ends[entry] = -1;
		slots[slot] = entry + 1;
		if (size * 2 > slots.length) {
			rehash();
		}
		return entry;
	}

	private void rehash() {
		int[] newSlots = new int[slots.length * 2];
		int newMask = newSlots.length - 1;
		for (int entry = 0; entry < size; entry++) {
			int slot = hash(pools[entry], keys[entry]) & newMask;
			while (newSlots[slot] != 0) {
				slot = (slot + 1) & newMask;
			}
			newSlots[slot] = entry + 1;
		}
		slots = newSlots;
		mask = newMask;
	}

	private static int hash(int pool, long key) {
		long h = (key ^ ((long) pool << 48)) * M1;
		h ^= h >>> 29;
		h *= M2;
		return (int) (h ^ (h >>> 32));
	}
}
