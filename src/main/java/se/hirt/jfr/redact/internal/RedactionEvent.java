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
package se.hirt.jfr.redact.internal;

import jdk.jfr.Category;
import jdk.jfr.DataAmount;
import jdk.jfr.Description;
import jdk.jfr.Event;
import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;

/**
 * The redaction of a recording. Holds sizes and counts only, never paths or strings of the
 * recording, since the recording of the redacting JVM may be shared.
 */
@Name("se.hirt.jfr.redact.Redaction")
@Label("Redaction")
@Category("JFR Redact")
@Description("The redaction of a recording into a new recording")
@StackTrace(false)
public final class RedactionEvent extends Event {
	@Label("Input Size")
	@DataAmount
	public long inputSize;

	@Label("Chunks")
	public long chunks;

	@Label("Rewritten Chunks")
	public long rewrittenChunks;

	@Label("Strings")
	@Description("The distinct strings of the recording")
	public long strings;

	@Label("Redacted Strings")
	public long redactedStrings;

	@Label("Replaced Occurrences")
	@Description("The stored copies of redacted strings that were replaced")
	public long replacedOccurrences;

	@Label("Rewritten Events")
	public long rewrittenEvents;

	@Label("Rewritten Checkpoints")
	public long rewrittenCheckpoints;
}
