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
import jdk.jfr.Description;
import jdk.jfr.Event;
import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;

/** A phase of a redaction, named by one of the constants */
@Name("se.hirt.jfr.redact.Phase")
@Label("Redaction Phase")
@Category("JFR Redact")
@Description("A phase of a redaction")
@StackTrace(false)
public final class PhaseEvent extends Event {
	/** Parsing the recording and collecting the locations of its strings */
	public static final String COLLECT = "Collect";
	/** Grouping the locations by string, and finding the strings that also occur in the metadata */
	public static final String LOCATE = "Locate";
	/** Asking the redactor about every distinct string */
	public static final String DECIDE = "Decide";
	/** Writing the redacted recording to a temporary file */
	public static final String REWRITE = "Rewrite";
	/** Moving the temporary file to the output */
	public static final String PUBLISH = "Publish";

	@Label("Phase")
	public String phase;

	private PhaseEvent(String phase) {
		this.phase = phase;
	}

	/** @return the phase, begun, to be committed when it ends */
	public static PhaseEvent start(String phase) {
		PhaseEvent event = new PhaseEvent(phase);
		event.begin();
		return event;
	}
}
