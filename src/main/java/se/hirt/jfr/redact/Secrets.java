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
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Recognizes secrets: names saying their value is secret, and credentials with recognizable
 * formats. Every search starts at a literal and is bounded, so a string is scanned in linear time.
 */
final class Secrets {
	static final String REDACTED = "<REDACTED>";

	/** The last segments of names whose value is secret */
	private static final Set<String> SECRET_SEGMENTS = Set.of("password", "passwd", "pwd", "passphrase", "passcode",
			"secret", "secrets", "token", "tokens", "credential", "credentials", "creds", "apikey", "apikeys",
			"privatekey", "jwt", "dsn", "cookie", "cookies", "auth", "key", "keys", "pat", "storepass", "keypass",
			"srcstorepass", "deststorepass", "srckeypass", "destkeypass");
	/** The endings of last segments of names whose value is secret, as in {@code PGPASSWORD} */
	private static final String[] SECRET_ENDINGS = {"password", "passwd", "secret", "token"};
	/** The names of environment variables ending in a secret segment that are not secret */
	private static final Set<String> NOT_SECRET = Set.of("pwd", "oldpwd");

	/**
	 * Credentials with recognizable formats, each starting with a literal: AWS access keys, GitHub
	 * tokens, Slack tokens, Google API keys, Stripe keys, {@code sk-} API keys and JSON web tokens
	 */
	private static final Pattern TOKENS = Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"
			+ "|\\bgh[pousr]_[A-Za-z0-9]{36,255}\\b" + "|\\bgithub_pat_[A-Za-z0-9_]{22,255}"
			+ "|\\bxox[abposr]-[A-Za-z0-9-]{10,255}" + "|\\bAIza[0-9A-Za-z_-]{35}"
			+ "|\\b[rs]k_live_[0-9A-Za-z]{24,255}" + "|(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,255}"
			+ "|\\beyJ[A-Za-z0-9_-]{8,4096}\\.eyJ[A-Za-z0-9_-]{8,4096}\\.[A-Za-z0-9_-]{0,4096}");
	/** The literals one of which a string must contain for {@link #TOKENS} to match */
	private static final String[] TOKEN_LITERALS = {"AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
			"github_pat_", "xox", "AIza", "k_live_", "sk-", "eyJ"};
	/** The token of a bearer or of an {@code Authorization} value, the first group */
	private static final Pattern BEARER = Pattern.compile("(?i)\\bbearer\\s+([A-Za-z0-9._~+/=-]{8,4096})");
	private static final Pattern AUTHORIZATION = Pattern.compile(
			"(?i)authorization[\"']?\\s{0,8}[:=]\\s{0,8}[\"']?(?:(?:basic|bearer|digest|token|negotiate)\\s{1,8})?([^\\s\"',;]{4,4096})");
	private static final String PEM_BEGIN = "-----BEGIN ";
	private static final String PEM_END = "-----END ";
	private static final String PRIVATE_KEY = "PRIVATE KEY-----";
	private static final int MAX_NAME = 128;

	private Secrets() {
	}

	/**
	 * @return {@code true} if the name, of an environment variable, a property, an argument or a
	 *         parameter, says its value is secret: its last segment, split at punctuation and at
	 *         changes to upper case, is one of the secret segments or ends with one of the secret
	 *         endings, or its last two are {@code connection} and {@code string}
	 */
	static boolean isSecretName(String name) {
		if (NOT_SECRET.contains(name.toLowerCase(Locale.ROOT))) {
			return false;
		}
		List<String> segments = segments(name);
		if (segments.isEmpty()) {
			return false;
		}
		String last = segments.getLast();
		if (SECRET_SEGMENTS.contains(last)) {
			return true;
		}
		for (String ending : SECRET_ENDINGS) {
			if (last.endsWith(ending)) {
				return true;
			}
		}
		return segments.size() > 1 && last.equals("string") && segments.get(segments.size() - 2).equals("connection");
	}

	/** The name split at characters other than letters and digits, and at changes to upper case */
	static List<String> segments(String name) {
		List<String> segments = new ArrayList<>();
		int start = -1;
		for (int i = 0; i <= name.length(); i++) {
			char c = i < name.length() ? name.charAt(i) : ' ';
			boolean part = Character.isLetterOrDigit(c);
			boolean boundary = !part || start >= 0 && Character.isUpperCase(c) && i > start
					&& (Character.isLowerCase(name.charAt(i - 1)) || Character.isDigit(name.charAt(i - 1))
							|| i + 1 < name.length() && Character.isLowerCase(name.charAt(i + 1))
									&& Character.isUpperCase(name.charAt(i - 1)));
			if (boundary && start >= 0) {
				segments.add(name.substring(start, i).toLowerCase(Locale.ROOT));
				start = -1;
			}
			if (part && start < 0) {
				start = i;
			}
		}
		return segments;
	}

	/**
	 * Replaces the secret parts of credentials with recognizable formats and the values of
	 * arguments and parameters with secret names, see {@link RuleRedactor.Builder#redactSecrets()}
	 *
	 * @return the text with the secrets replaced, the same instance if it holds none
	 */
	static String redactFormats(String text) {
		String result = redactPrivateKeys(text);
		if (containsAny(result, TOKEN_LITERALS)) {
			result = TOKENS.matcher(result).replaceAll(REDACTED);
		}
		if (containsIgnoreCase(result, "bearer")) {
			result = replaceGroup(BEARER, result);
		}
		if (containsIgnoreCase(result, "uthorization")) {
			result = replaceGroup(AUTHORIZATION, result);
		}
		if (result.contains("://")) {
			result = redactUrlPasswords(result);
		}
		if (result.indexOf('=') >= 0) {
			result = redactAssignments(result);
		}
		if (result.indexOf('-') >= 0) {
			result = redactOptionValues(result);
		}
		return result.equals(text) ? text : result;
	}

	/** Replaces each private key in PEM format, to its end line or to the end of the text */
	private static String redactPrivateKeys(String text) {
		int begin = text.indexOf(PEM_BEGIN);
		if (begin < 0) {
			return text;
		}
		StringBuilder result = new StringBuilder(text.length());
		int copied = 0;
		while (begin >= 0) {
			int headerEnd = text.indexOf("-----", begin + PEM_BEGIN.length());
			if (headerEnd < 0) {
				break;
			}
			int next;
			if (text.startsWith(PRIVATE_KEY, headerEnd - PRIVATE_KEY.length() + 5)) {
				int end = text.indexOf(PEM_END, headerEnd + 5);
				int endLine = end < 0 ? -1 : text.indexOf("-----", end + PEM_END.length());
				next = endLine < 0 ? text.length() : endLine + 5;
				result.append(text, copied, begin).append(REDACTED);
				copied = next;
			} else {
				next = headerEnd + 5;
			}
			begin = text.indexOf(PEM_BEGIN, next);
		}
		return copied == 0 ? text : result.append(text, copied, text.length()).toString();
	}

	private static String replaceGroup(Pattern pattern, String text) {
		Matcher m = pattern.matcher(text);
		StringBuilder result = null;
		int copied = 0;
		while (m.find()) {
			if (text.startsWith(REDACTED, m.start(1))) {
				continue;
			}
			if (result == null) {
				result = new StringBuilder(text.length());
			}
			result.append(text, copied, m.start(1)).append(REDACTED);
			copied = m.end(1);
		}
		return result == null ? text : result.append(text, copied, text.length()).toString();
	}

	/** Replaces the password of each URL with one, as in {@code scheme://user:password@host} */
	private static String redactUrlPasswords(String text) {
		StringBuilder result = null;
		int copied = 0;
		for (int scheme = text.indexOf("://"); scheme >= 0; scheme = text.indexOf("://", scheme + 3)) {
			int start = scheme + 3;
			int end = start;
			while (end < text.length() && "/?#\"' \t\r\n<>".indexOf(text.charAt(end)) < 0) {
				end++;
			}
			int at = text.lastIndexOf('@', end - 1);
			if (at < start) {
				continue;
			}
			int colon = text.indexOf(':', start);
			if (colon < 0 || colon >= at - 1 || text.startsWith(REDACTED, colon + 1)) {
				continue;
			}
			if (result == null) {
				result = new StringBuilder(text.length());
			}
			result.append(text, copied, colon + 1).append(REDACTED);
			copied = at;
		}
		return result == null ? text : result.append(text, copied, text.length()).toString();
	}

	/**
	 * Replaces the value of each assignment to a secret name, as in {@code -Ddb.password=value},
	 * {@code --api-key=value}, {@code DB_TOKEN=value}, {@code ?password=value&} and
	 * {@code AccountKey=value;}: a value in quotes to the closing quote, or else to the next
	 * whitespace, {@code &}, {@code ;} or quote
	 */
	private static String redactAssignments(String text) {
		StringBuilder result = null;
		int copied = 0;
		for (int equals = text.indexOf('='); equals >= 0; equals = text.indexOf('=', equals + 1)) {
			int nameStart = equals;
			while (nameStart > 0 && equals - nameStart < MAX_NAME && isNamePart(text.charAt(nameStart - 1))) {
				nameStart--;
			}
			String name = optionName(text, nameStart, equals);
			if (name.isEmpty() || !isSecretName(name)) {
				continue;
			}
			int valueStart = equals + 1;
			int valueEnd = valueEnd(text, valueStart, "&;");
			if (valueStart < valueEnd && text.charAt(valueStart) == text.charAt(valueEnd - 1)
					&& (text.charAt(valueStart) == '"' || text.charAt(valueStart) == '\'')
					&& valueEnd - valueStart > 1) {
				valueStart++;
				valueEnd--;
			}
			if (!isRedactable(text, valueStart, valueEnd) || valueStart < copied) {
				continue;
			}
			if (result == null) {
				result = new StringBuilder(text.length());
			}
			result.append(text, copied, valueStart).append(REDACTED);
			copied = valueEnd;
			equals = Math.max(equals, valueEnd - 1);
		}
		return result == null ? text : result.append(text, copied, text.length()).toString();
	}

	/**
	 * Replaces the value following an option with a secret name, as in {@code --password value} and
	 * {@code -storepass value}: the next word, unless it starts with {@code -}
	 */
	private static String redactOptionValues(String text) {
		StringBuilder result = null;
		int copied = 0;
		for (int dash = text.indexOf('-'); dash >= 0; dash = text.indexOf('-', dash + 1)) {
			if (dash > 0 && !Character.isWhitespace(text.charAt(dash - 1)) || dash + 1 >= text.length()) {
				continue;
			}
			int nameStart = text.charAt(dash + 1) == '-' ? dash + 2 : dash + 1;
			int nameEnd = nameStart;
			while (nameEnd < text.length() && nameEnd - nameStart < MAX_NAME && isNamePart(text.charAt(nameEnd))
					&& text.charAt(nameEnd) != '=') {
				nameEnd++;
			}
			if (nameEnd == nameStart || nameEnd >= text.length() || text.charAt(nameEnd) != ' '
					|| !isSecretName(text.substring(nameStart, nameEnd))) {
				continue;
			}
			int valueStart = nameEnd;
			while (valueStart < text.length() && text.charAt(valueStart) == ' ') {
				valueStart++;
			}
			int valueEnd = valueEnd(text, valueStart, "");
			if (valueStart >= text.length() || text.charAt(valueStart) == '-'
					|| !isRedactable(text, valueStart, valueEnd)) {
				continue;
			}
			if (result == null) {
				result = new StringBuilder(text.length());
			}
			result.append(text, copied, valueStart).append(REDACTED);
			copied = valueEnd;
			dash = valueEnd - 1;
		}
		return result == null ? text : result.append(text, copied, text.length()).toString();
	}

	/**
	 * The name of an assignment without the dashes of an option, and the {@code D} of {@code -D}
	 */
	private static String optionName(String text, int start, int end) {
		int dashes = 0;
		while (start + dashes < end && text.charAt(start + dashes) == '-') {
			dashes++;
		}
		int nameStart = start + dashes;
		if (dashes == 1 && nameStart < end && text.charAt(nameStart) == 'D') {
			nameStart++;
		}
		return text.substring(nameStart, end);
	}

	/** The end of a value: a quoted value's closing quote, or else the next whitespace or stop */
	private static int valueEnd(String text, int start, String stops) {
		if (start < text.length() && (text.charAt(start) == '"' || text.charAt(start) == '\'')) {
			int close = text.indexOf(text.charAt(start), start + 1);
			return close < 0 ? text.length() : close + 1;
		}
		int end = start;
		while (end < text.length()) {
			char c = text.charAt(end);
			if (Character.isWhitespace(c) || c == '"' || c == '\'' || stops.indexOf(c) >= 0) {
				break;
			}
			end++;
		}
		return end;
	}

	/** A value worth replacing: not empty, a boolean or a replacement already */
	private static boolean isRedactable(String text, int start, int end) {
		if (start >= end || text.startsWith(REDACTED, start)) {
			return false;
		}
		String value = text.substring(start, end);
		return !value.equalsIgnoreCase("true") && !value.equalsIgnoreCase("false");
	}

	private static boolean isNamePart(char c) {
		return c == '_' || c == '.' || c == '-' || Character.isLetterOrDigit(c);
	}

	private static boolean containsAny(String text, String[] literals) {
		for (String literal : literals) {
			if (text.contains(literal)) {
				return true;
			}
		}
		return false;
	}

	static boolean containsIgnoreCase(String text, String literal) {
		return indexOfIgnoreCase(text, literal, 0) >= 0;
	}

	/** The first occurrence of the literal at or after {@code from}, ignoring case */
	static int indexOfIgnoreCase(String text, String literal, int from) {
		int last = text.length() - literal.length();
		if (literal.isEmpty()) {
			return from <= text.length() ? from : -1;
		}
		char first = literal.charAt(0);
		char upper = Character.toUpperCase(first);
		char lower = Character.toLowerCase(first);
		for (int i = Math.max(0, from); i <= last; i++) {
			char c = text.charAt(i);
			if ((c == upper || c == lower || Character.toLowerCase(c) == lower)
					&& text.regionMatches(true, i, literal, 0, literal.length())) {
				return i;
			}
		}
		return -1;
	}
}
