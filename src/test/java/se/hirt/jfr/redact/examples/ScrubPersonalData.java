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
package se.hirt.jfr.redact.examples;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import se.hirt.jfr.redact.JfrRedactor;
import se.hirt.jfr.redact.RedactionResult;
import se.hirt.jfr.redact.StringLocation;
import se.hirt.jfr.redact.StringRedactor;

/**
 * Replaces personal tokens, such as user, host and domain names, wherever they occur inside any
 * string of a recording, for example inside paths, environment variables and thread names. Tokens are
 * replaced in the order given, so put longer tokens before tokens they contain.
 * <p>
 * Usage: {@code java -cp target/classes:target/test-classes
 * se.hirt.jfr.redact.examples.ScrubPersonalData <recording.jfr> <scrubbed.jfr> <token>=<replacement>...}
 */
public final class ScrubPersonalData implements StringRedactor {
	private final Map<String, String> replacements;

	public ScrubPersonalData(Map<String, String> replacements) {
		this.replacements = new LinkedHashMap<>(replacements);
	}

	@Override
	public String redact(String value, List<StringLocation> locations) {
		String result = value;
		for (Map.Entry<String, String> replacement : replacements.entrySet()) {
			result = result.replace(replacement.getKey(), replacement.getValue());
		}
		return result;
	}

	public static void main(String[] args) throws IOException {
		Map<String, String> replacements = new LinkedHashMap<>();
		for (int i = 2; i < args.length; i++) {
			int separator = args[i].indexOf('=');
			replacements.put(args[i].substring(0, separator), args[i].substring(separator + 1));
		}
		RedactionResult result = JfrRedactor.redact(Path.of(args[0]), Path.of(args[1]),
				new ScrubPersonalData(replacements));
		System.out.printf("Scrubbed %,d of %,d strings%n", result.redactedStringCount(), result.stringCount());
		result.redactedInMetadata().forEach(s -> System.out.println("  remains in metadata: " + s));
	}
}
