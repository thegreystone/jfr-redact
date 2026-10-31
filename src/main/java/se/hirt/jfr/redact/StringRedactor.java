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

import java.util.List;

/**
 * Decides what each string in a recording is replaced with.
 * <p>
 * The redactor is called once per distinct string in the recording, after the whole recording has
 * been analyzed, with every location the string is stored at. The decision applies to all
 * occurrences of the string, so that no copy of a redacted string remains in the redacted
 * recording. Calls are made from a single thread.
 */
@FunctionalInterface
public interface StringRedactor {
	/**
	 * @param value
	 *            the original Java string, including any unpaired UTF-16 surrogates
	 * @param locations
	 *            the distinct locations where the string is stored
	 * @return {@code value} to keep the string, or the non-null replacement
	 */
	String redact(String value, List<StringLocation> locations);

	/**
	 * @return a redactor that asks {@code other} about the strings this redactor keeps
	 */
	default StringRedactor orElse(StringRedactor other) {
		return (value, locations) -> {
			String replacement = redact(value, locations);
			return replacement.equals(value) ? other.redact(value, locations) : replacement;
		};
	}
}
