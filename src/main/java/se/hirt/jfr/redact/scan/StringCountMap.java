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

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Open addressing hash map from UTF-8 encoded strings to occurrence counts per category. Keys are
 * looked up directly from a source byte range and only copied into an internal arena on first
 * insertion, so counting an already known string does not allocate.
 */
public final class StringCountMap {
	public static final int CATEGORIES = 2;

	private static final VarHandle LONG_LE = MethodHandles.byteArrayViewVarHandle(long[].class,
			ByteOrder.LITTLE_ENDIAN);
	private static final long M1 = 0x9E3779B97F4A7C15L;
	private static final long M2 = 0xBF58476D1CE4E5B9L;

	/** Entry index + 1, 0 meaning empty */
	private int[] slots = new int[1 << 12];
	private int mask = slots.length - 1;
	private int size;

	private int[] hashes = new int[1 << 11];
	private int[] offsets = new int[1 << 11];
	private int[] lengths = new int[1 << 11];
	private long[] counts = new long[(1 << 11) * CATEGORIES];

	private byte[] arena = new byte[1 << 16];
	private int arenaUsed;

	/**
	 * Counts one occurrence of the UTF-8 encoded string in {@code source[offset, offset + length)}.
	 */
	public void add(byte[] source, int offset, int length, int category) {
		int hash = hash(source, offset, length);
		int slot = hash & mask;
		while (true) {
			int entry = slots[slot] - 1;
			if (entry < 0) {
				entry = insert(source, offset, length, hash, slot);
				counts[entry * CATEGORIES + category]++;
				return;
			}
			if (hashes[entry] == hash && lengths[entry] == length && Arrays.equals(arena, offsets[entry],
					offsets[entry] + length, source, offset, offset + length)) {
				counts[entry * CATEGORIES + category]++;
				return;
			}
			slot = (slot + 1) & mask;
		}
	}

	/**
	 * @return the entry index of the string, or -1 if not present
	 */
	public int indexOf(String s) {
		byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
		int hash = hash(bytes, 0, bytes.length);
		for (int slot = hash & mask;; slot = (slot + 1) & mask) {
			int entry = slots[slot] - 1;
			if (entry < 0) {
				return -1;
			}
			if (hashes[entry] == hash && lengths[entry] == bytes.length
					&& Arrays.equals(arena, offsets[entry], offsets[entry] + bytes.length, bytes, 0, bytes.length)) {
				return entry;
			}
		}
	}

	public int size() {
		return size;
	}

	public String getString(int entry) {
		return new String(arena, offsets[entry], lengths[entry], StandardCharsets.UTF_8);
	}

	public long getCount(int entry, int category) {
		return counts[entry * CATEGORIES + category];
	}

	public long getTotalCount(int entry) {
		long total = 0;
		for (int i = 0; i < CATEGORIES; i++) {
			total += counts[entry * CATEGORIES + i];
		}
		return total;
	}

	private int insert(byte[] source, int offset, int length, int hash, int slot) {
		if (arenaUsed > arena.length - length) {
			long required = (long) arenaUsed + length;
			if (required > Integer.MAX_VALUE - 8) {
				throw new IllegalStateException("Too much unique string data: " + required + " bytes");
			}
			arena = Arrays.copyOf(arena, (int) Math.min(Integer.MAX_VALUE - 8, Math.max(required, arena.length * 2L)));
		}
		System.arraycopy(source, offset, arena, arenaUsed, length);

		int entry = size++;
		if (entry == hashes.length) {
			int capacity = hashes.length * 2;
			hashes = Arrays.copyOf(hashes, capacity);
			offsets = Arrays.copyOf(offsets, capacity);
			lengths = Arrays.copyOf(lengths, capacity);
			counts = Arrays.copyOf(counts, capacity * CATEGORIES);
		}
		hashes[entry] = hash;
		offsets[entry] = arenaUsed;
		lengths[entry] = length;
		arenaUsed += length;

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
			int slot = hashes[entry] & newMask;
			while (newSlots[slot] != 0) {
				slot = (slot + 1) & newMask;
			}
			newSlots[slot] = entry + 1;
		}
		slots = newSlots;
		mask = newMask;
	}

	static int hash(byte[] b, int offset, int length) {
		long h = length * M1;
		int i = offset;
		int end = offset + length;
		for (; i <= end - 8; i += 8) {
			h = Long.rotateLeft(h ^ ((long) LONG_LE.get(b, i) * M1), 29) * M2;
		}
		if (i < end) {
			long tail = 0;
			for (int shift = 0; i < end; i++, shift += 8) {
				tail |= (b[i] & 0xFFL) << shift;
			}
			h = Long.rotateLeft(h ^ (tail * M1), 29) * M2;
		}
		h ^= h >>> 31;
		h *= M1;
		return (int) (h ^ (h >>> 32));
	}
}
