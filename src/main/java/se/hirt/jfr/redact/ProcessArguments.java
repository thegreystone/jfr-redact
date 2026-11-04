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

import java.util.Set;

/**
 * Strips the arguments of a command line, see {@link RuleRedactor.Builder#stripProcessArguments()}
 */
final class ProcessArguments {
	private static final String BUNDLE = ".app/Contents/";
	private static final String BUNDLE_EXECUTABLES = "/MacOS/";
	private static final String[] ARGUMENT_STARTS = {" -", " /", " \"", " '"};
	/** The processes of the Windows kernel, whose names have spaces but no arguments */
	private static final Set<String> WINDOWS_KERNEL_PROCESSES = Set.of("System Idle Process", "Memory Compression",
			"Secure System", "System Interrupts");

	private ProcessArguments() {
	}

	/**
	 * @return the executable followed by {@code <REDACTED>} if the command line has arguments, or
	 *         else the command line
	 */
	static String strip(String commandLine) {
		int end = executableEnd(commandLine);
		if (end >= commandLine.length() || commandLine.startsWith(" " + Secrets.REDACTED, end)) {
			return commandLine;
		}
		return commandLine.substring(0, end) + " " + Secrets.REDACTED;
	}

	/**
	 * Where the executable ends: at the end of a name in brackets, such as {@code [System Process]}
	 * or {@code [kworker/0:1]}, or of the name of a process of the Windows kernel, such as
	 * {@code Memory Compression}; at its closing quote, after {@code .exe}, past the name of a
	 * macOS application bundle's executable, which repeats the bundle's name, spaces and all, and
	 * else at the first space after the last path separator before the first argument starting with
	 * a dash, a slash or a quote
	 */
	static int executableEnd(String commandLine) {
		if (commandLine.startsWith("[") && commandLine.endsWith("]")
				|| WINDOWS_KERNEL_PROCESSES.contains(commandLine)) {
			return commandLine.length();
		}
		if (commandLine.startsWith("\"")) {
			int close = commandLine.indexOf('"', 1);
			return close < 0 ? commandLine.length() : close + 1;
		}
		int exe = Secrets.indexOfIgnoreCase(commandLine, ".exe", 0);
		while (exe >= 0) {
			int end = exe + 4;
			if (end == commandLine.length() || commandLine.charAt(end) == ' ') {
				return end;
			}
			exe = Secrets.indexOfIgnoreCase(commandLine, ".exe", end);
		}
		int from = 0;
		int bundle = commandLine.indexOf(BUNDLE);
		if (bundle >= 0) {
			from = bundle + BUNDLE.length();
			int executables = commandLine.indexOf(BUNDLE_EXECUTABLES, bundle);
			if (executables >= 0) {
				// The innermost bundle, as helpers are bundles within bundles
				int inner = commandLine.lastIndexOf(BUNDLE, executables);
				String name = commandLine.substring(commandLine.lastIndexOf('/', inner) + 1, inner);
				from = executables + BUNDLE_EXECUTABLES.length();
				if (commandLine.startsWith(name, from)) {
					from += name.length();
				}
			}
		}
		int limit = commandLine.length();
		for (String start : ARGUMENT_STARTS) {
			int at = commandLine.indexOf(start, from);
			if (at >= 0 && at < limit) {
				limit = at;
			}
		}
		if (bundle >= 0) {
			return limit;
		}
		int separator = Math.max(commandLine.lastIndexOf('/', limit - 1), commandLine.lastIndexOf('\\', limit - 1));
		int space = commandLine.indexOf(' ', separator + 1);
		return space < 0 || space > limit ? limit : space;
	}
}
