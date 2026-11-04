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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Replaces a user's identity in strings, see {@link RuleRedactor.Builder#anonymizeUser} */
final class UserAnonymizer {
	static final String EMAIL = "<EMAIL>";
	private static final String USER = "user";
	private static final String HOST = "host";
	private static final String THREAD_NAME = "Thread Name: ";
	private static final String THREAD_GROUP = "Thread Group: ";
	private static final int MAX_LOCAL_PART = 64;
	private static final int MAX_DOMAIN = 253;

	/**
	 * The forms of the home directories, longest first: as given, with the other separator, with
	 * doubled backslashes, and each with {@code %20} for spaces
	 */
	private final List<String> homes = new ArrayList<>();
	/** Pairs of a name and its replacement, longest first */
	private final List<String[]> names = new ArrayList<>();

	UserAnonymizer(UserIdentity identity) {
		Set<String> forms = new LinkedHashSet<>();
		for (String home : identity.homeDirectories()) {
			for (String form : List.of(home, home.replace('\\', '/'), home.replace('/', '\\'),
					home.replace("\\", "\\\\"))) {
				forms.add(form);
				forms.add(form.replace(" ", "%20"));
			}
		}
		homes.addAll(forms);
		homes.sort(Comparator.comparingInt(String::length).reversed());
		for (String user : identity.userNames()) {
			names.add(new String[] {user, USER});
		}
		for (String host : identity.hostNames()) {
			names.add(new String[] {host, HOST});
		}
		names.sort(Comparator.comparingInt((String[] pair) -> pair[0].length()).reversed());
	}

	/**
	 * @return the text with home directories, e-mail addresses and names replaced, the same
	 *         instance if none occurs; names of code are kept, and names in thread dumps and old
	 *         object descriptions are only replaced in thread names
	 */
	String anonymize(String text, List<StringLocation> locations) {
		boolean threadDump = false;
		boolean description = false;
		for (StringLocation location : locations) {
			if (location.isClassName() || location.isMethodName() || location.isMethodDescriptor()
					|| location.isPackageName() || location.isModuleName()) {
				return text;
			}
			threadDump |= location.isThreadDump();
			description |= location.isOldObjectDescription();
		}
		String result = replaceHomes(text);
		result = replaceEmails(result);
		if (threadDump) {
			result = replaceNamesInQuotes(result);
		} else if (description) {
			result = replaceNamesInThreadNames(result);
		} else {
			result = replaceNames(result);
		}
		return result.equals(text) ? text : result;
	}

	/** Replaces the last segment of each home directory, keeping the path to it as written */
	private String replaceHomes(String text) {
		String result = text;
		for (String home : homes) {
			int keep = home.length() - UserIdentity.lastSegment(home).length();
			result = replace(result, home, keep, USER, true);
		}
		return result;
	}

	private String replaceNames(String text) {
		String result = text;
		for (String[] name : names) {
			result = replace(result, name[0], 0, name[1], false);
		}
		return result;
	}

	/** Replaces names within the quotes of each line, the thread names of a thread dump */
	private String replaceNamesInQuotes(String dump) {
		StringBuilder result = null;
		int copied = 0;
		for (int open = dump.indexOf('"'); open >= 0;) {
			int lineEnd = dump.indexOf('\n', open);
			int close = dump.indexOf('"', open + 1);
			if (close < 0 || lineEnd >= 0 && close > lineEnd) {
				open = lineEnd < 0 ? -1 : dump.indexOf('"', lineEnd);
				continue;
			}
			String name = dump.substring(open + 1, close);
			String replaced = replaceNames(name);
			if (!replaced.equals(name)) {
				if (result == null) {
					result = new StringBuilder(dump.length());
				}
				result.append(dump, copied, open + 1).append(replaced);
				copied = close;
			}
			open = dump.indexOf('"', close + 1);
		}
		return result == null ? dump : result.append(dump, copied, dump.length()).toString();
	}

	private String replaceNamesInThreadNames(String description) {
		for (String prefix : List.of(THREAD_NAME, THREAD_GROUP)) {
			if (description.startsWith(prefix)) {
				return prefix + replaceNames(description.substring(prefix.length()));
			}
		}
		return description;
	}

	/**
	 * Replaces each occurrence of the text, ignoring case, not followed by a character that would
	 * continue it, and for a name not preceded by one either
	 *
	 * @param keep
	 *            the length of the start of each occurrence to keep as written
	 * @param path
	 *            {@code true} for a home directory, which may follow anything, and may be followed
	 *            by anything but a letter, digit, {@code .}, {@code _} or {@code -}
	 */
	private static String replace(String text, String find, int keep, String replacement, boolean path) {
		StringBuilder result = null;
		int copied = 0;
		for (int at = Secrets.indexOfIgnoreCase(text, find, 0); at >= 0;) {
			int end = at + find.length();
			boolean before = path || at == 0 || !Character.isLetterOrDigit(text.charAt(at - 1));
			boolean after = end == text.length() || !continues(text.charAt(end), path);
			if (before && after) {
				if (result == null) {
					result = new StringBuilder(text.length());
				}
				result.append(text, copied, at + keep).append(replacement);
				copied = end;
				at = Secrets.indexOfIgnoreCase(text, find, end);
			} else {
				at = Secrets.indexOfIgnoreCase(text, find, at + 1);
			}
		}
		return result == null ? text : result.append(text, copied, text.length()).toString();
	}

	private static boolean continues(char c, boolean path) {
		return Character.isLetterOrDigit(c) || path && (c == '.' || c == '_' || c == '-');
	}

	/**
	 * Replaces each e-mail address, found at its {@code @}: a local part, and a domain of at least
	 * two labels, none all digits, the last of letters only, so that a module version in a stack
	 * frame, {@code java.base@25.0.4} or {@code hibernate.core@6.4.4.Final}, is no address, and
	 * neither is a path segment, {@code /a@b.com}, or a Git remote, {@code git@github.com:acme}
	 */
	static String replaceEmails(String text) {
		StringBuilder result = null;
		int copied = 0;
		for (int at = text.indexOf('@'); at >= 0; at = text.indexOf('@', at + 1)) {
			int start = at;
			while (start > copied && at - start < MAX_LOCAL_PART && isLocalPart(text.charAt(start - 1))) {
				start--;
			}
			if (start == at || start > 0 && text.charAt(start - 1) == '/') {
				continue;
			}
			int end = at + 1;
			while (end < text.length() && end - at <= MAX_DOMAIN && isDomain(text.charAt(end))) {
				end++;
			}
			while (end > at + 1 && (text.charAt(end - 1) == '.' || text.charAt(end - 1) == '-')) {
				end--;
			}
			if (!isDomainName(text.substring(at + 1, end))
					|| end + 1 < text.length() && text.charAt(end) == ':' && !Character.isDigit(text.charAt(end + 1))) {
				continue;
			}
			if (result == null) {
				result = new StringBuilder(text.length());
			}
			result.append(text, copied, start).append(EMAIL);
			copied = end;
			at = end - 1;
		}
		return result == null ? text : result.append(text, copied, text.length()).toString();
	}

	private static boolean isDomainName(String domain) {
		String[] labels = domain.split("\\.", -1);
		if (labels.length < 2) {
			return false;
		}
		for (String label : labels) {
			if (label.isEmpty() || label.chars().allMatch(Character::isDigit)) {
				return false;
			}
		}
		String top = labels[labels.length - 1];
		return top.length() >= 2 && top.chars().allMatch(Character::isLetter);
	}

	private static boolean isLocalPart(char c) {
		return Character.isLetterOrDigit(c) || ".+_%-".indexOf(c) >= 0;
	}

	private static boolean isDomain(char c) {
		return Character.isLetterOrDigit(c) || c == '.' || c == '-';
	}
}
