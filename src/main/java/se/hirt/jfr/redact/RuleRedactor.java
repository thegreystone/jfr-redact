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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * A {@link StringRedactor} applying simple rules, without regular expressions. Rules are tried in
 * order, and the first matching rule decides. The kinds of rules are:
 * <ul>
 * <li>{@link Builder#hashThreadNames()} replaces thread names with {@code Thread-<hash>}.</li>
 * <li>{@link Builder#hashClassNames(String)} replaces the part of class names matching a regular
 * expression with a hash.</li>
 * <li>{@link Builder#hashMethodNames(String)} does the same for method names.</li>
 * <li>{@link Builder#replaceIf(Predicate, UnaryOperator)} replaces strings stored at given
 * locations.</li>
 * <li>{@link Builder#renamePackage(String, String)} renames a Java package and its subpackages,
 * wherever its name occurs: in source form ({@code java.util.HashMap}), in internal form
 * ({@code java/util/HashMap}), and in method descriptors and array class names
 * ({@code (Ljava/util/List;)V}, {@code [Ljava/util/HashMap;}).</li>
 * <li>{@link Builder#replace(String, String)} replaces strings matching a glob pattern.</li>
 * </ul>
 * A pattern may start and/or end with {@code *}, which matches any characters, so matching is
 * always one of {@code equals}, {@code startsWith}, {@code endsWith} or {@code contains}:
 * <table>
 * <caption>Patterns and replacements</caption>
 * <tr>
 * <th>Pattern</th>
 * <th>Matches</th>
 * <th>Replacement</th>
 * </tr>
 * <tr>
 * <td>{@code java/util}</td>
 * <td>exactly the text</td>
 * <td>a fixed string</td>
 * </tr>
 * <tr>
 * <td>{@code java.util.*}</td>
 * <td>strings starting with the text</td>
 * <td>a fixed string, or one with a {@code *} which is replaced by the rest of the string, as in
 * {@code utilz.*}</td>
 * </tr>
 * <tr>
 * <td>{@code *.internal}</td>
 * <td>strings ending with the text</td>
 * <td>a fixed string, or one with a {@code *} which is replaced by the start of the string</td>
 * </tr>
 * <tr>
 * <td>{@code *java/util/*}</td>
 * <td>strings containing the text</td>
 * <td>a fixed string, or {@code *text*} to replace every occurrence of the matched text, as in
 * {@code *utilz/*}</td>
 * </tr>
 * <tr>
 * <td>{@code *}</td>
 * <td>every string</td>
 * <td>a fixed string</td>
 * </tr>
 * </table>
 * A literal {@code *} is written as {@code \*}, in patterns as well as replacements, so
 * {@code "\\*\\*\\*"} in Java source is the replacement {@code ***}. Example:
 *
 * <pre>{@code
 * StringRedactor redactor = RuleRedactor.builder().hashThreadNames().renamePackage("java.util", "utilz")
 * 		.replace("*password*", "<REDACTED>").build();
 * }</pre>
 *
 * Some strings are documents embedding other strings, see {@link StringLocation#isComposite()}.
 * Rules process these strings in order. Specialized rules rewrite their embedded values: thread
 * names are hashed the same way as elsewhere, in the headers and lock owners of thread dumps and in
 * the {@code Thread Name:} of old object descriptions, and packages are renamed in class names.
 * Glob and location-based rules match the whole current text, including preceding rewrites, and the
 * first matching whole-string rule decides. Location predicates see all locations of the value.
 * <p>
 * Since a decision applies to every occurrence of a string, a rule matching a string at one
 * location replaces it everywhere. For example, hashing the thread name {@code main} also renames
 * methods named {@code main}.
 */
public final class RuleRedactor implements StringRedactor {
	private final Rule[] rules;

	private RuleRedactor(Rule[] rules) {
		this.rules = rules;
	}

	public static Builder builder() {
		return new Builder();
	}

	/** A rule, returning the replacement or {@code null} if it does not apply */
	private interface Rule {
		String apply(String value, List<StringLocation> locations);

		/**
		 * Rewrites embedded values, or returns {@code null} to apply the rule to the whole string
		 * instead.
		 */
		default String rewriteComposite(String text, StringLocation location) {
			return null;
		}
	}

	/** Builds a {@link RuleRedactor} from rules, tried in the order added */
	public static final class Builder {
		private final List<Rule> rules = new ArrayList<>();

		private Builder() {
		}

		/**
		 * Adds a rule replacing strings matching the pattern.
		 *
		 * @throws IllegalArgumentException
		 *             if the pattern has a {@code *} other than first or last, or the replacement
		 *             has more {@code *} than the pattern allows
		 */
		public Builder replace(String pattern, String replacement) {
			rules.add(new GlobRule(pattern, replacement));
			return this;
		}

		/**
		 * Adds a rule replacing strings stored at a location matching the predicate.
		 *
		 * @param where
		 *            the locations, for example {@link StringLocation#isThreadName()}
		 * @param replacement
		 *            computes the replacement from the string
		 */
		public Builder replaceIf(Predicate<StringLocation> where, UnaryOperator<String> replacement) {
			rules.add((value, locations) -> {
				for (StringLocation location : locations) {
					if (where.test(location)) {
						return replacement.apply(value);
					}
				}
				return null;
			});
			return this;
		}

		/**
		 * Adds a rule replacing every thread name with {@code Thread-} and the first 8 hex digits
		 * of the SHA-256 of the name. The same name always gets the same replacement, also across
		 * recordings. Note that names that can be guessed can be found by hashing guesses, which
		 * {@link #hashThreadNames(byte[])} prevents.
		 */
		public Builder hashThreadNames() {
			rules.add(new ThreadNameRule(name -> "Thread-" + hex(digest("SHA-256", null, name))));
			return this;
		}

		/**
		 * Like {@link #hashThreadNames()}, but uses HMAC-SHA256 with a secret key, so that names
		 * cannot be found by hashing guesses without the key.
		 */
		public Builder hashThreadNames(byte[] key) {
			byte[] keyCopy = key.clone();
			rules.add(new ThreadNameRule(name -> "Thread-" + hex(digest("HmacSHA256", keyCopy, name))));
			return this;
		}

		/**
		 * Adds a rule replacing the part of class names matching a regular expression with a base64
		 * hash of that part. The expression is matched against the class name in source form, such
		 * as {@code com.acme.secret.Foo}, and the part replaced is the first capture group if the
		 * expression has one, or else the whole match. For example, {@code com\.acme\.(.*)} turns
		 * {@code com.acme.secret.Foo} into {@code com.acme.<hash>}. The class name is replaced
		 * wherever it occurs: in internal form ({@code com/acme/secret/Foo}), in method descriptors
		 * and in thread dumps. The same text always gets the same hash. Package names are not class
		 * names, so they are not affected.
		 */
		public Builder hashClassNames(String regex) {
			rules.add(new ClassNameRule(Pattern.compile(regex), text -> base64(digest("SHA-256", null, text))));
			return this;
		}

		/**
		 * Like {@link #hashClassNames(String)}, but uses HMAC-SHA256 with a secret key, so that
		 * names cannot be found by hashing guesses without the key.
		 */
		public Builder hashClassNames(String regex, byte[] key) {
			byte[] keyCopy = key.clone();
			rules.add(new ClassNameRule(Pattern.compile(regex), text -> base64(digest("HmacSHA256", keyCopy, text))));
			return this;
		}

		/**
		 * Adds a rule replacing the part of method names matching a regular expression with a
		 * base64 hash of that part, the first capture group if the expression has one, or else the
		 * whole match. Method names are replaced as constants and in the stack traces of thread
		 * dumps. Since a decision applies to every occurrence of a string, a method name is
		 * replaced in all classes declaring a method with that name. The expression is searched
		 * for, so {@code (processRecord)} also replaces the name inside
		 * {@code lambda$processRecord$0}.
		 */
		public Builder hashMethodNames(String regex) {
			rules.add(new MethodNameRule(Pattern.compile(regex), text -> base64(digest("SHA-256", null, text))));
			return this;
		}

		/**
		 * Like {@link #hashMethodNames(String)}, but uses HMAC-SHA256 with a secret key.
		 */
		public Builder hashMethodNames(String regex, byte[] key) {
			byte[] keyCopy = key.clone();
			rules.add(new MethodNameRule(Pattern.compile(regex), text -> base64(digest("HmacSHA256", keyCopy, text))));
			return this;
		}

		/**
		 * Adds a rule renaming a package and its subpackages, wherever the package name occurs.
		 *
		 * @param packageName
		 *            the package, in source form, such as {@code java.util}
		 * @param newName
		 *            the new name of the package, in source form
		 * @throws IllegalArgumentException
		 *             if a name is not a valid package name
		 */
		public Builder renamePackage(String packageName, String newName) {
			rules.add(new PackageRule(packageName, newName));
			return this;
		}

		public RuleRedactor build() {
			return new RuleRedactor(rules.toArray(new Rule[0]));
		}
	}

	@Override
	public String redact(String value, List<StringLocation> locations) {
		for (StringLocation location : locations) {
			if (location.isComposite()) {
				String text = value;
				for (Rule rule : rules) {
					String rewritten = rule.rewriteComposite(text, location);
					if (rewritten != null) {
						text = rewritten;
					} else {
						String replacement = rule.apply(text, locations);
						if (replacement != null) {
							return replacement;
						}
					}
				}
				return text;
			}
		}
		for (Rule rule : rules) {
			String replacement = rule.apply(value, locations);
			if (replacement != null) {
				return replacement;
			}
		}
		return value;
	}

	/**
	 * Applies the rules that do not depend on locations.
	 *
	 * @return the replacement of the first matching rule, or {@code value} if no rule matches
	 */
	public String redact(String value) {
		return redact(value, List.of());
	}

	private static byte[] digest(String algorithm, byte[] key, String value) {
		byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
		try {
			if (key == null) {
				return MessageDigest.getInstance(algorithm).digest(bytes);
			}
			Mac mac = Mac.getInstance(algorithm);
			mac.init(new SecretKeySpec(key, algorithm));
			return mac.doFinal(bytes);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(algorithm + " not available", e);
		}
	}

	private static String hex(byte[] hash) {
		return HexFormat.of().formatHex(hash, 0, 4);
	}

	/**
	 * 72 bits of the hash, base64 encoded with characters valid in Java identifiers, starting with
	 * {@code _} if it would start with a digit
	 */
	private static String base64(byte[] hash) {
		String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOf(hash, 9)).replace('-',
				'$');
		return Character.isDigit(encoded.charAt(0)) ? '_' + encoded : encoded;
	}

	private static final class GlobRule implements Rule {
		private final boolean anyStart;
		private final boolean anyEnd;
		private final String text;
		/** The replacement split at its {@code *} */
		private final String[] parts;

		GlobRule(String pattern, String replacement) {
			List<String> patternParts = splitAtStars(pattern);
			if (patternParts.size() > 3 || patternParts.size() == 3 && !patternParts.get(0).isEmpty()
					|| patternParts.size() == 3 && !patternParts.get(2).isEmpty()) {
				throw new IllegalArgumentException(
						"Only a leading and a trailing * are supported, use \\* for a literal *: " + pattern);
			}
			if (patternParts.size() == 2 && !patternParts.get(0).isEmpty() && !patternParts.get(1).isEmpty()) {
				throw new IllegalArgumentException(
						"Only a leading and a trailing * are supported, use \\* for a literal *: " + pattern);
			}
			anyStart = patternParts.size() > 1 && patternParts.get(0).isEmpty();
			anyEnd = patternParts.size() > 1 && patternParts.get(patternParts.size() - 1).isEmpty()
					&& !(patternParts.size() == 2 && anyStart);
			text = patternParts.size() == 1 ? patternParts.get(0) : patternParts.size() == 3 ? patternParts.get(1)
					: anyStart ? patternParts.get(1) : patternParts.get(0);
			parts = splitAtStars(replacement).toArray(new String[0]);
			int stars = parts.length - 1;
			boolean valid;
			if (text.isEmpty() && (anyStart || anyEnd)) {
				valid = stars == 0;
			} else if (anyStart && anyEnd) {
				valid = stars == 0 || stars == 2 && parts[0].isEmpty() && parts[2].isEmpty();
			} else if (anyStart || anyEnd) {
				valid = stars <= 1;
			} else {
				valid = stars == 0;
			}
			if (!valid) {
				throw new IllegalArgumentException("Unsupported use of * in the replacement " + replacement
						+ " for the pattern " + pattern + ", use \\* for a literal *");
			}
		}

		/** Splits at unescaped {@code *}, unescaping {@code \*} and {@code \\} */
		private static List<String> splitAtStars(String s) {
			List<String> parts = new ArrayList<>();
			StringBuilder current = new StringBuilder();
			for (int i = 0; i < s.length(); i++) {
				char c = s.charAt(i);
				if (c == '\\' && i + 1 < s.length() && (s.charAt(i + 1) == '*' || s.charAt(i + 1) == '\\')) {
					current.append(s.charAt(++i));
				} else if (c == '*') {
					parts.add(current.toString());
					current.setLength(0);
				} else {
					current.append(c);
				}
			}
			parts.add(current.toString());
			return parts;
		}

		@Override
		public String apply(String value, List<StringLocation> locations) {
			if (text.isEmpty() && (anyStart || anyEnd)) {
				return parts[0];
			}
			if (anyStart && anyEnd) {
				if (!value.contains(text)) {
					return null;
				}
				return parts.length == 1 ? parts[0] : value.replace(text, parts[1]);
			}
			if (anyEnd) {
				if (!value.startsWith(text)) {
					return null;
				}
				return parts.length == 1 ? parts[0] : parts[0] + value.substring(text.length()) + parts[1];
			}
			if (anyStart) {
				if (!value.endsWith(text)) {
					return null;
				}
				return parts.length == 1 ? parts[0]
						: parts[0] + value.substring(0, value.length() - text.length()) + parts[1];
			}
			return value.equals(text) ? parts[0] : null;
		}
	}

	/** Replaces thread names, also in the headers and lock owners of thread dumps */
	private static final class ThreadNameRule implements Rule {
		/** Markers ending the quoted name in a thread dump header, such as "main" #1 prio=5 */
		private static final String[] HEADER_NAME_ENDS = {"\" #", "\" daemon", "\" prio=", "\" os_prio=", "\" cpu=",
				"\":"};

		private final UnaryOperator<String> replacement;

		ThreadNameRule(UnaryOperator<String> replacement) {
			this.replacement = replacement;
		}

		@Override
		public String apply(String value, List<StringLocation> locations) {
			for (StringLocation location : locations) {
				if (location.isThreadName()) {
					return replacement.apply(value);
				}
			}
			return null;
		}

		private static final String OLD_OBJECT_THREAD_NAME = "Thread Name: ";

		@Override
		public String rewriteComposite(String text, StringLocation location) {
			if (location.isThreadDump()) {
				return rewriteThreadDump(text);
			}
			if (text.startsWith(OLD_OBJECT_THREAD_NAME)) {
				return OLD_OBJECT_THREAD_NAME + replacement.apply(text.substring(OLD_OBJECT_THREAD_NAME.length()));
			}
			return text;
		}

		private String rewriteThreadDump(String dump) {
			Set<String> names = new HashSet<>();
			for (int lineStart = 0; lineStart < dump.length();) {
				int lineEnd = dump.indexOf('\n', lineStart);
				if (lineEnd < 0) {
					lineEnd = dump.length();
				}
				if (dump.charAt(lineStart) == '"') {
					int nameEnd = headerNameEnd(dump, lineStart, lineEnd);
					if (nameEnd > lineStart + 1) {
						names.add(dump.substring(lineStart + 1, nameEnd));
					}
				}
				lineStart = lineEnd + 1;
			}
			// Longest first, so that a name contained in another is not replaced inside it
			List<String> sorted = new ArrayList<>(names);
			sorted.sort((a, b) -> b.length() - a.length());
			String result = dump;
			for (String name : sorted) {
				result = result.replace('"' + name + '"', '"' + replacement.apply(name) + '"');
			}
			return result;
		}

		private static int headerNameEnd(String dump, int lineStart, int lineEnd) {
			int end = -1;
			for (String marker : HEADER_NAME_ENDS) {
				int at = dump.indexOf(marker, lineStart + 1);
				if (at > 0 && at < lineEnd && (end < 0 || at < end)) {
					end = at;
				}
			}
			return end;
		}
	}

	/**
	 * Java identifier characters, including Unicode letters, currency symbols and combining marks.
	 */
	private static final String DUMP_CLASS_NAME = "\\p{javaJavaIdentifierPart}+(?:\\.\\p{javaJavaIdentifierPart}+)*";

	/**
	 * A stack frame in a thread dump, {@code at java.util.List.of(java.base@25/List.java:1)}: the
	 * class, the method and the location, which is a file name and line, {@code Native Method} or
	 * {@code Unknown Source}, possibly prefixed by a module
	 */
	private static final Pattern DUMP_FRAME = Pattern
			.compile("\\bat (" + DUMP_CLASS_NAME + ")\\.([\\p{javaJavaIdentifierPart}<>]+)\\(([^()/]*/)?([^()]*)\\)");
	/** The file name of a frame location, Foo.java:12 */
	private static final Pattern DUMP_FILE = Pattern
			.compile("([\\p{javaJavaIdentifierPart}-]+)(\\.\\p{javaJavaIdentifierPart}+(?::\\d+)?)");

	/**
	 * Replaces the part of the text matching the pattern, the first group if any, with its hash.
	 *
	 * @return the new text, or {@code null} if the pattern does not match
	 */
	private static String replaceMatch(Pattern pattern, UnaryOperator<String> hash, String text) {
		Matcher m = pattern.matcher(text);
		if (!m.find()) {
			return null;
		}
		int group = m.groupCount() >= 1 ? 1 : 0;
		if (m.start(group) < 0 || m.start(group) == m.end(group)) {
			return null;
		}
		return text.substring(0, m.start(group)) + hash.apply(m.group(group)) + text.substring(m.end(group));
	}

	/** Replaces the part of method names matching an expression with a hash */
	private static final class MethodNameRule implements Rule {
		private final Pattern pattern;
		private final UnaryOperator<String> hash;

		MethodNameRule(Pattern pattern, UnaryOperator<String> hash) {
			this.pattern = pattern;
			this.hash = hash;
		}

		@Override
		public String apply(String value, List<StringLocation> locations) {
			for (StringLocation location : locations) {
				if (location.isMethodName()) {
					return replaceMatch(pattern, hash, value);
				}
			}
			return null;
		}

		@Override
		public String rewriteComposite(String text, StringLocation location) {
			if (!location.isThreadDump()) {
				return text;
			}
			Matcher m = DUMP_FRAME.matcher(text);
			StringBuilder result = null;
			int copied = 0;
			while (m.find()) {
				String renamed = replaceMatch(pattern, hash, m.group(2));
				if (renamed != null) {
					if (result == null) {
						result = new StringBuilder(text.length() + 64);
					}
					result.append(text, copied, m.start(2)).append(renamed);
					copied = m.end(2);
				}
			}
			return result == null ? text : result.append(text, copied, text.length()).toString();
		}
	}

	/** Replaces the part of class names matching an expression with a hash */
	private static final class ClassNameRule implements Rule {
		/** An object in a thread dump, such as a lock: (a java.util.HashMap) */
		private static final Pattern OBJECT = Pattern.compile("(\\(a )(" + DUMP_CLASS_NAME + ")(\\))");

		private final Pattern pattern;
		private final UnaryOperator<String> hash;

		ClassNameRule(Pattern pattern, UnaryOperator<String> hash) {
			this.pattern = pattern;
			this.hash = hash;
		}

		@Override
		public String apply(String value, List<StringLocation> locations) {
			for (StringLocation location : locations) {
				if (location.isClassName()) {
					return renameInternal(value);
				}
				if (location.isMethodDescriptor()) {
					return renameInDescriptor(value);
				}
			}
			return null;
		}

		@Override
		public String rewriteComposite(String text, StringLocation location) {
			if (!location.isThreadDump()) {
				return text;
			}
			return rewriteObjects(rewriteFrames(text));
		}

		/**
		 * Renames the classes of the frames, and hashes the source file names of renamed classes,
		 * as they would reveal the class names
		 */
		private String rewriteFrames(String text) {
			Matcher m = DUMP_FRAME.matcher(text);
			StringBuilder result = null;
			int copied = 0;
			while (m.find()) {
				String renamed = renameSource(m.group(1));
				if (renamed == null) {
					continue;
				}
				if (result == null) {
					result = new StringBuilder(text.length() + 64);
				}
				result.append(text, copied, m.start(1)).append(renamed);
				copied = m.end(1);
				Matcher file = DUMP_FILE.matcher(m.group(4));
				if (file.matches()) {
					result.append(text, copied, m.start(4)).append(hash.apply(file.group(1)));
					copied = m.start(4) + file.end(1);
				}
			}
			return result == null ? text : result.append(text, copied, text.length()).toString();
		}

		private String rewriteObjects(String text) {
			Pattern classPattern = OBJECT;
			Matcher m = classPattern.matcher(text);
			StringBuilder result = null;
			int copied = 0;
			while (m.find()) {
				String renamed = renameSource(m.group(2));
				if (renamed != null) {
					if (result == null) {
						result = new StringBuilder(text.length() + 64);
					}
					result.append(text, copied, m.start(2)).append(renamed);
					copied = m.end(2);
				}
			}
			return result == null ? text : result.append(text, copied, text.length()).toString();
		}

		/** @return the renamed source form name, or {@code null} if it does not match */
		private String renameSource(String name) {
			return replaceMatch(pattern, hash, name);
		}

		private String renameInternal(String internalName) {
			String renamed = renameSource(internalName.replace('/', '.'));
			return renamed == null ? null : renamed.replace('.', '/');
		}

		private String renameInDescriptor(String descriptor) {
			StringBuilder result = null;
			int copied = 0;
			for (int i = 0; i < descriptor.length(); i++) {
				if (descriptor.charAt(i) != 'L') {
					continue;
				}
				int end = descriptor.indexOf(';', i);
				if (end < 0) {
					break;
				}
				String renamed = renameInternal(descriptor.substring(i + 1, end));
				if (renamed != null) {
					if (result == null) {
						result = new StringBuilder(descriptor.length() + 16);
					}
					result.append(descriptor, copied, i + 1).append(renamed);
					copied = end;
				}
				i = end;
			}
			return result == null ? null : result.append(descriptor, copied, descriptor.length()).toString();
		}
	}

	/**
	 * Renames a package in source form, in internal form, and in the class names of descriptors and
	 * array class names, which are parsed by the descriptor grammar. A name only matches at package
	 * boundaries, so renaming {@code java.util} leaves {@code java.utility} alone.
	 */
	private static final class PackageRule implements Rule {
		private final String sourceName;
		private final String internalName;
		private final String newSourceName;
		private final String newInternalName;

		PackageRule(String packageName, String newName) {
			checkPackageName(packageName);
			checkPackageName(newName);
			sourceName = packageName;
			internalName = packageName.replace('.', '/');
			newSourceName = newName;
			newInternalName = newName.replace('.', '/');
		}

		private static void checkPackageName(String name) {
			if (name.isEmpty() || name.startsWith(".") || name.endsWith(".") || name.contains("..")
					|| name.indexOf('/') >= 0 || name.indexOf('*') >= 0) {
				throw new IllegalArgumentException("Not a package name in source form: " + name);
			}
		}

		@Override
		public String apply(String value, List<StringLocation> locations) {
			if (startsWithPackage(value, 0, value.length(), sourceName, '.')) {
				return newSourceName + value.substring(sourceName.length());
			}
			if (value.indexOf(internalName) < 0) {
				return null;
			}
			char first = value.charAt(0);
			if (first == '(' || first == '[' || first == 'L' && value.endsWith(";")) {
				return renameInDescriptor(value);
			}
			if (startsWithPackage(value, 0, value.length(), internalName, '/')) {
				return newInternalName + value.substring(internalName.length());
			}
			return null;
		}

		/**
		 * Renames the dotted class names in the text, such as in {@code at java.util.List.of(...)}
		 */
		@Override
		public String rewriteComposite(String dump, StringLocation location) {
			StringBuilder result = null;
			int copied = 0;
			for (int at = dump.indexOf(sourceName); at >= 0; at = dump.indexOf(sourceName, at + 1)) {
				int end = at + sourceName.length();
				boolean startsName = at == 0 || !isNamePart(dump.charAt(at - 1));
				boolean endsPackage = end == dump.length() || dump.charAt(end) == '.' || !isNamePart(dump.charAt(end));
				if (startsName && endsPackage && at >= copied) {
					if (result == null) {
						result = new StringBuilder(dump.length() + 64);
					}
					result.append(dump, copied, at).append(newSourceName);
					copied = end;
				}
			}
			return result == null ? dump : result.append(dump, copied, dump.length()).toString();
		}

		private static boolean isNamePart(char c) {
			return Character.isJavaIdentifierPart(c) || c == '.';
		}

		/**
		 * Renames the class names in a method descriptor ({@code (ILjava/util/List;)V}), field
		 * descriptor ({@code Ljava/util/List;}) or array class name ({@code [Ljava/util/List;}).
		 */
		private String renameInDescriptor(String descriptor) {
			StringBuilder result = null;
			int copied = 0;
			for (int i = 0; i < descriptor.length(); i++) {
				if (descriptor.charAt(i) != 'L') {
					continue;
				}
				int end = descriptor.indexOf(';', i);
				if (end < 0) {
					break;
				}
				if (startsWithPackage(descriptor, i + 1, end, internalName, '/')) {
					if (result == null) {
						result = new StringBuilder(descriptor.length() + 16);
					}
					result.append(descriptor, copied, i + 1).append(newInternalName);
					copied = i + 1 + internalName.length();
				}
				i = end;
			}
			return result == null ? null : result.append(descriptor, copied, descriptor.length()).toString();
		}

		/**
		 * True if {@code value[start, end)} is the package or starts with it followed by the
		 * separator
		 */
		private static boolean startsWithPackage(String value, int start, int end, String name, char separator) {
			int nameEnd = start + name.length();
			return nameEnd <= end && value.startsWith(name, start)
					&& (nameEnd == end || value.charAt(nameEnd) == separator);
		}
	}
}
