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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class StringCountMapTest {
	@Test
	void countsAcrossGrowth() {
		StringCountMap map = new StringCountMap();
		int n = 200_000;
		for (int round = 0; round < 3; round++) {
			for (int i = 0; i < n; i++) {
				byte[] bytes = ("prefix-" + i).getBytes(StandardCharsets.UTF_8);
				byte[] padded = new byte[bytes.length + 7];
				System.arraycopy(bytes, 0, padded, 3, bytes.length);
				map.add(padded, 3, bytes.length, round == 2 ? StringScanner.CONSTANT_POOL : StringScanner.INLINE);
			}
		}
		assertEquals(n, map.size());
		for (int i = 0; i < n; i += 997) {
			int entry = map.indexOf("prefix-" + i);
			assertEquals("prefix-" + i, map.getString(entry));
			assertEquals(2, map.getCount(entry, StringScanner.INLINE));
			assertEquals(1, map.getCount(entry, StringScanner.CONSTANT_POOL));
		}
		assertEquals(-1, map.indexOf("prefix-" + n));
	}

	@Test
	void emptyString() {
		StringCountMap map = new StringCountMap();
		map.add(new byte[0], 0, 0, StringScanner.INLINE);
		map.add(new byte[4], 2, 0, StringScanner.INLINE);
		assertEquals(1, map.size());
		assertEquals(2, map.getCount(map.indexOf(""), StringScanner.INLINE));
	}
}
