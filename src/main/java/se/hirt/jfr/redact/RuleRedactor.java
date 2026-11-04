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

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import se.hirt.jfr.redact.internal.Utf8;

/**
 * A {@link StringRedactor} applying rules. Rules are tried in order, and the first matching rule
 * decides. The kinds of rules are:
 * <ul>
 * <li>{@link Builder#hashThreadNames()} replaces thread names with {@code Thread-<hash>} and thread
 * group names with {@code ThreadGroup-<hash>}.</li>
 * <li>{@link Builder#hashClassNames(String)} replaces the part of class names matching a regular
 * expression with a hash, segment by segment, and the package and module names the expression
 * matches alike, so that every class name keeps starting with the name of its package. Several
 * expressions form one rule, in the place of the first, and for each part of a name, the package or
 * the simple name, the first expression covering a piece of it decides.</li>
 * <li>{@link Builder#hashMethodNames(String)} does the same for method names.</li>
 * <li>{@link Builder#replaceIf(Predicate, UnaryOperator)} replaces strings stored at given
 * locations.</li>
 * <li>{@link Builder#renamePackage(String, String)} renames a Java package and its subpackages,
 * wherever its name occurs: in source form ({@code java.util.HashMap}), in internal form
 * ({@code java/util/HashMap}), and in method descriptors and array class names
 * ({@code (Ljava/util/List;)V}, {@code [Ljava/util/HashMap;}).</li>
 * <li>{@link Builder#replace(String, String)} replaces strings matching a glob pattern.</li>
 * <li>{@link Builder#replaceMatching(String, String)} replaces strings containing a match of a
 * regular expression.</li>
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
 * Rules process these strings in order. Specialized rules rewrite their embedded values the same
 * way as elsewhere: thread names in the headers and lock owners of thread dumps and in the
 * {@code Thread Name:} of old object descriptions, thread group names in their
 * {@code Thread Group:}, class names in the frames and lock objects of thread dumps and in the
 * {@code Class Name:} of old object descriptions, module names in the locations of the frames,
 * method names in the frames, and packages in class names. Glob and location-based rules match the
 * whole current text, including preceding rewrites, and the first matching whole-string rule
 * decides. Location predicates see all locations of the value.
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
		/** Where the one class name rule is among the rules, or -1 before the first expression */
		private int classNames = -1;

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
		 * Adds a rule replacing every string containing a match of the regular expression, as a
		 * whole, with the replacement, as {@code --match} does on the command line. Thread dumps
		 * and old object descriptions are matched as the preceding rules rewrote them.
		 *
		 * @throws java.util.regex.PatternSyntaxException
		 *             if the expression is invalid
		 */
		public Builder replaceMatching(String regex, String replacement) {
			Pattern pattern = Pattern.compile(regex);
			Objects.requireNonNull(replacement, "replacement");
			rules.add((value, locations) -> pattern.matcher(value).find() ? replacement : null);
			return this;
		}

		/**
		 * Adds a rule replacing every thread name with {@code Thread-} and the first 8 hex digits
		 * of the SHA-256 of the name, and every thread group name with {@code ThreadGroup-} and the
		 * same hash of the group name, since group names often mirror the thread names they
		 * contain. A name that is both a thread and a thread group name is replaced as a thread
		 * name. The groups the JVM creates itself, {@code system} and {@code main}, name nothing of
		 * the application and are left alone unless they are also thread names. The empty name of
		 * an unnamed virtual thread is not a thread name and is left to later rules. The same name
		 * always gets the same replacement, also across recordings. Note that names that can be
		 * guessed can be found by hashing guesses, which {@link #hashThreadNames(byte[])} prevents.
		 */
		public Builder hashThreadNames() {
			rules.add(new ThreadNameRule(name -> hex(digest("SHA-256", null, name))));
			return this;
		}

		/**
		 * Like {@link #hashThreadNames()}, but uses HMAC-SHA256 with a secret key, so that names
		 * cannot be found by hashing guesses without the key.
		 */
		public Builder hashThreadNames(byte[] key) {
			byte[] keyCopy = key.clone();
			rules.add(new ThreadNameRule(name -> hex(digest("HmacSHA256", keyCopy, name))));
			return this;
		}

		/**
		 * Adds a rule replacing the part of class names matching a regular expression with a base64
		 * hash of that part, segment by segment, and the package and module names the expression
		 * matches alike, so that every class name keeps starting with the name of its package,
		 * which JDK Mission Control relies on to derive the simple name of a class, and so that the
		 * packages the expression hides are hidden wherever they are stored. The expression is
		 * searched for in the class name in source form, such as {@code com.acme.secret.Foo}, and
		 * the part found is the first capture group if the expression has one, or else the whole
		 * match. The piece of that part within the simple name, {@code Foo}, is replaced by its
		 * hash; nested classes ({@code Outer$Inner}) and the host of a hidden class
		 * ({@code Host$$Lambda}) are one segment. The package, {@code com.acme.secret}, is handled
		 * on its own: the expression is searched for in the package name followed by a dot,
		 * {@code com.acme.secret.}, and in every segment the part found covers, the covered
		 * characters are replaced by their hash, never the dots. Package names stored on their own
		 * ({@link StringLocation#isPackageName()}) and module names
		 * ({@link StringLocation#isModuleName()}) are replaced the same way, so that the package
		 * part of a class name, the constant of its package and the name of its module always
		 * agree.
		 * <p>
		 * For example, {@code com\.acme\.(.*)} turns {@code com.acme.secret.Foo} into
		 * {@code com.acme.<hash>.<hash>} and the package {@code com.acme.secret} into
		 * {@code com.acme.<hash>}, and {@code (.*)} hashes every segment of every class, package
		 * and module name. Package segments are only hashed where the expression matches the
		 * package itself, followed by a dot: {@code (.*)Impl$} turns
		 * {@code com.acme.secret.FooImpl} into {@code com.acme.secret.<hash>Impl} and leaves the
		 * package, which the recording stored readably on its own anyway. Prefix expressions such
		 * as {@code com\.acme\.(.*)} or {@code (.*)} are the way to hide packages. Only the first
		 * match of the expression counts, so a literal found in the package before the simple name
		 * leaves the simple name alone: {@code Secret} turns {@code com.acme.Secret.SecretService}
		 * into {@code com.acme.<hash>.SecretService}. An expression anchored to the end of the
		 * name, such as {@code Secret[^.]*$}, hashes the simple name instead, and a second
		 * expression can hash the package. Two kinds of expression change nothing: one whose group
		 * covers package segments only while the rest of it requires the simple name, as in
		 * {@code (com\.acme)\.secret\.Foo}, since the package is matched on its own, and one
		 * anchored to the end of a package name, as in {@code (secret)$}, since the package is
		 * followed by a dot; end it with the dot instead, as in {@code (secret)\.}.
		 * <p>
		 * The class name is replaced wherever it occurs: in internal form
		 * ({@code com/acme/secret/Foo}), in array class names ({@code [Lcom/acme/secret/Foo;}), in
		 * method descriptors, in the frames and lock objects of thread dumps, whose module segments
		 * ({@code java.base@21/}) are hashed as module names and whose source file names
		 * ({@code Foo.java:12}) are hashed with the class, as is the bare name of the class HotSpot
		 * prints as the location of a generated class ({@code LambdaForm$MH}), in the
		 * {@code Class Name:} of old object descriptions and in the inline class names and
		 * descriptors of {@code jdk.CompilerInlining} events. Array prefixes and descriptor
		 * delimiters are preserved, and primitive arrays are unchanged. A hidden class, such as
		 * {@code com.acme.Foo$$Lambda/0x00007fb87c2252f8}, is matched by its host class,
		 * {@code com.acme.Foo$$Lambda}, also in the form of JVMTI class signatures,
		 * {@code com/acme/Foo$$Lambda.0x00007fb87c2252f8}, and the address or identity hash the JVM
		 * appends in each run is kept, so that the class gets the same hash in every form, and from
		 * JDK 21 on in every run, while JDK 8 to 20 number their lambda proxy classes per run, as
		 * in {@code Foo$$Lambda$269} and {@code Foo$$Lambda$14}. The same text always gets the same
		 * hash. Free text naming classes or packages is not touched: module locations
		 * ({@code jrt:/jdk.jfr}), JVM arguments, exception messages, paths and the like.
		 * <p>
		 * Since segments are hashed one by one, a short and common segment such as {@code impl} or
		 * {@code util} is easy to guess from its unkeyed hash, which is the same in every package
		 * it occurs in; use {@link #hashClassNames(String, byte[])} when the names must stay
		 * secret.
		 * <p>
		 * Several expressions, added by repeated calls, form one rule, in the place of the first.
		 * For each part of a name, the package or the simple name, the first expression covering a
		 * piece of it decides, with its own hash, so that the package part of a class, the constant
		 * of its package and the name of its module always agree, whichever expression hashed the
		 * simple name. For example, {@code com\.acme\.(.*)} followed by {@code (.*)} turns
		 * {@code com.acme.secret.Foo} into {@code com.acme.<hash>.<hash>} and {@code org.other.Bar}
		 * into {@code <hash>.<hash>.<hash>}, while {@code com.acme.Baz} becomes
		 * {@code <hash>.<hash>.<hash>}, since the first expression covers nothing of the package
		 * {@code com.acme} itself and the second does.
		 */
		public Builder hashClassNames(String regex) {
			return hashClassNames(Pattern.compile(regex), text -> base64(digest("SHA-256", null, text)));
		}

		/**
		 * Like {@link #hashClassNames(String)}, but uses HMAC-SHA256 with a secret key, so that
		 * names cannot be found by hashing guesses without the key. Keyed and unkeyed expressions
		 * combine like any others: each part of a name is hashed by the expression deciding it.
		 */
		public Builder hashClassNames(String regex, byte[] key) {
			byte[] keyCopy = key.clone();
			return hashClassNames(Pattern.compile(regex), text -> base64(digest("HmacSHA256", keyCopy, text)));
		}

		/**
		 * Adds the expression to the class name rule, which is one rule for all the expressions, in
		 * the place of the first, so that the package part of a class, the constant of its package
		 * and the name of its module are always decided by the same expression.
		 */
		private Builder hashClassNames(Pattern pattern, UnaryOperator<String> hash) {
			SegmentHasher hasher = new SegmentHasher(pattern, hash);
			if (classNames < 0) {
				classNames = rules.size();
				rules.add(new ClassNameRule(List.of(hasher)));
			} else {
				rules.set(classNames, ((ClassNameRule) rules.get(classNames)).with(hasher));
			}
			return this;
		}

		/**
		 * Adds a rule replacing the part of method names matching a regular expression with a
		 * base64 hash of that part, the first capture group if the expression has one, or else the
		 * whole match. Method names are replaced as constants, in the stack traces of thread dumps
		 * and in the inline callee names of {@code jdk.CompilerInlining} events, see
		 * {@link StringLocation#isMethodName()}. Since a decision applies to every occurrence of a
		 * string, a method name is replaced in all classes declaring a method with that name. The
		 * expression is searched for, so {@code (processRecord)} also replaces the name inside
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
		byte[] bytes = Utf8.encode(value);
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

	/**
	 * Replaces thread names, also in the headers and lock owners of thread dumps and in old object
	 * descriptions, and thread group names
	 */
	private static final class ThreadNameRule implements Rule {
		/** Markers ending the quoted name in a thread dump header, such as "main" #1 prio=5 */
		private static final String[] HEADER_NAME_ENDS = {"\" #", "\" daemon", "\" prio=", "\" os_prio=", "\" cpu=",
				"\":"};
		private static final String OLD_OBJECT_THREAD_NAME = "Thread Name: ";
		private static final String OLD_OBJECT_THREAD_GROUP = "Thread Group: ";
		/** The thread groups the JVM creates itself, which name nothing of the application */
		private static final Set<String> JVM_THREAD_GROUPS = Set.of("system", "main");

		private final UnaryOperator<String> hash;

		ThreadNameRule(UnaryOperator<String> hash) {
			this.hash = hash;
		}

		private String replaceThreadName(String name) {
			return "Thread-" + hash.apply(name);
		}

		private String replaceGroupName(String name) {
			return "ThreadGroup-" + hash.apply(name);
		}

		@Override
		public String apply(String value, List<StringLocation> locations) {
			if (value.isEmpty()) {
				return null; // The empty name of an unnamed virtual thread is no name
			}
			boolean group = false;
			for (StringLocation location : locations) {
				if (location.isThreadName()) {
					return replaceThreadName(value);
				}
				group |= location.isThreadGroupName();
			}
			return group && !JVM_THREAD_GROUPS.contains(value) ? replaceGroupName(value) : null;
		}

		@Override
		public String rewriteComposite(String text, StringLocation location) {
			if (location.isThreadDump()) {
				return rewriteThreadDump(text);
			}
			return rewriteDescription(text);
		}

		/**
		 * Replaces the thread or thread group name of an old object description, unless it is empty
		 * or a thread group of the JVM's own
		 */
		private String rewriteDescription(String text) {
			if (text.startsWith(OLD_OBJECT_THREAD_NAME) && text.length() > OLD_OBJECT_THREAD_NAME.length()) {
				return OLD_OBJECT_THREAD_NAME + replaceThreadName(text.substring(OLD_OBJECT_THREAD_NAME.length()));
			}
			if (text.startsWith(OLD_OBJECT_THREAD_GROUP)) {
				String name = text.substring(OLD_OBJECT_THREAD_GROUP.length());
				if (!name.isEmpty() && !JVM_THREAD_GROUPS.contains(name)) {
					return OLD_OBJECT_THREAD_GROUP + replaceGroupName(name);
				}
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
				result = result.replace('"' + name + '"', '"' + replaceThreadName(name) + '"');
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
	 * Java identifier characters, including Unicode letters, currency symbols and combining marks
	 */
	private static final String DUMP_IDENTIFIER = "\\p{javaJavaIdentifierPart}+";
	/**
	 * The address or identity hash the JVM appends to the name of a hidden class after a slash, as
	 * in {@code com.acme.Foo$$Lambda/0x00007fb87c2252f8} or, in JDK 8 to 14,
	 * {@code com.acme.Foo$$Lambda$269/286774984}
	 */
	private static final String HIDDEN_CLASS_SLASH_SUFFIX = "/(?:0x[0-9a-fA-F]+|\\d+)";
	/**
	 * A class name in a thread dump: identifiers separated by dots, and for a hidden class its
	 * suffix. A slash is accepted only where it starts a suffix, so the slashed frames of JRockit
	 * dumps, {@code at com/acme/Foo.run()V(Foo.java:12)}, do not match, as before. Whether a lone
	 * {@code /<decimal>} segment is a suffix or the class of a one-segment package is decided when
	 * the name is renamed, see {@code isClassOfSingleSegmentPackage}.
	 */
	private static final String DUMP_CLASS_NAME = DUMP_IDENTIFIER + "(?:\\." + DUMP_IDENTIFIER + ")*(?:"
			+ HIDDEN_CLASS_SLASH_SUFFIX + ")?";

	/**
	 * A stack frame in a thread dump, {@code at java.util.List.of(java.base@25/List.java:1)}: the
	 * class, the method and the location, which is a file name and line, {@code Native Method} or
	 * {@code Unknown Source}, possibly prefixed by a module. Everything up to a slash within the
	 * parentheses is taken to be the module HotSpot prints, {@code java.base@25/} or {@code demo/},
	 * which a {@code SourceFile} attribute with a slash, as compilers other than javac may write,
	 * would also satisfy: its first path segment is then renamed like a module.
	 */
	private static final Pattern DUMP_FRAME = Pattern
			.compile("\\bat (" + DUMP_CLASS_NAME + ")\\.([\\p{javaJavaIdentifierPart}<>]+)\\(([^()/]*/)?([^()]*)\\)");
	/**
	 * The file name of a frame location, {@code Foo.java:12} or {@code Foo.java}. The other
	 * locations HotSpot prints, {@code Native Method}, {@code Unknown Source}, {@code Redefined}
	 * and the bare name of a generated class, {@code LambdaForm$MH}, do not match; the bare name is
	 * recognized by the class of the frame, see {@code ClassNameRule.rewriteFrames}.
	 */
	private static final Pattern DUMP_FILE = Pattern
			.compile("([\\p{javaJavaIdentifierPart}-]+)(\\.\\p{javaJavaIdentifierPart}+(?::\\d+)?)");

	/**
	 * Finds the part of the text to replace: the first group of the first match if the pattern has
	 * one, or else the whole match.
	 *
	 * @return the start and end of the part, or {@code null} if the pattern does not match or the
	 *         part is empty
	 */
	private static int[] matchSpan(Pattern pattern, String text) {
		Matcher m = pattern.matcher(text);
		if (!m.find()) {
			return null;
		}
		int group = m.groupCount() >= 1 ? 1 : 0;
		if (m.start(group) < 0 || m.start(group) == m.end(group)) {
			return null;
		}
		return new int[] {m.start(group), m.end(group)};
	}

	/**
	 * Replaces the part of the text matching the pattern, the first group if any, with its hash.
	 *
	 * @return the new text, or {@code null} if the pattern does not match
	 */
	private static String replaceMatch(Pattern pattern, UnaryOperator<String> hash, String text) {
		int[] span = matchSpan(pattern, text);
		if (span == null) {
			return null;
		}
		return text.substring(0, span[0]) + hash.apply(text.substring(span[0], span[1])) + text.substring(span[1]);
	}

	/**
	 * True if a quote precedes the position on its line, which puts it inside a quoted thread name:
	 * in a header, {@code "worker (a com.acme.Foo)" #12 prio=5}, or in a deadlock's
	 * {@code which is held by "worker (a com.acme.Foo)"}. Frames and lock lines have no quote
	 * before the class name. Thread names are rewritten as a whole by {@link ThreadNameRule}. A
	 * name spanning lines is only protected on its first line.
	 */
	private static boolean inQuotedName(String text, int position) {
		return text.indexOf('"', text.lastIndexOf('\n', position) + 1, position) >= 0;
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
				String renamed = inQuotedName(text, m.start()) ? null : replaceMatch(pattern, hash, m.group(2));
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

	/**
	 * Hashes the parts of qualified names in source form that one expression covers, segment by
	 * segment: the part of a match within a dot-separated segment is replaced by the hash of that
	 * part, and a dot never is. A package name is matched followed by a dot, as it appears in the
	 * names of its classes, and a class name is matched whole, hashing only the part of the match
	 * within its last segment, the simple name; {@link ClassNameRule} maps the package of the class
	 * as a package name, so that the package part of a class name is always mapped to the same text
	 * as the package name on its own, which keeps every class within its package, and maps a module
	 * name like a package name. The replaced part of a match is its first group if the expression
	 * has one, or else the whole match, and an empty part is no match, as in
	 * {@link RuleRedactor#replaceMatch}.
	 *
	 * @see Builder#hashClassNames(String)
	 */
	private static final class SegmentHasher {
		private final Pattern pattern;
		private final UnaryOperator<String> hash;

		SegmentHasher(Pattern pattern, UnaryOperator<String> hash) {
			this.pattern = pattern;
			this.hash = hash;
		}

		/**
		 * Maps a package or module name in source form, such as {@code com.acme.secret}: matches
		 * the expression against the name followed by a dot and hashes the covered part of each
		 * segment
		 *
		 * @return the mapped name, or {@code null} if no part of a segment is covered, as for the
		 *         empty name of the default package or the unnamed module
		 */
		String mapPackage(String name) {
			if (name.isEmpty()) {
				return null;
			}
			int[] span = matchSpan(pattern, name + '.');
			return span == null ? null : hashCovered(name, span[0], Math.min(span[1], name.length()));
		}

		/**
		 * Hashes the part of the last segment of a class name, starting at {@code start}, that the
		 * match against the whole name covers
		 *
		 * @return the mapped simple name, or {@code null} if the match does not reach the segment
		 */
		private String mapSimpleName(String name, int start) {
			int[] span = matchSpan(pattern, name);
			if (span == null || span[1] <= start) {
				return null;
			}
			int from = Math.max(span[0], start);
			return name.substring(start, from) + hash.apply(name.substring(from, span[1])) + name.substring(span[1]);
		}

		/**
		 * Replaces the part of each dot-separated segment of the text within {@code [from, to)}
		 * with the hash of that part, never a dot
		 *
		 * @return the new text, or {@code null} if no part of a segment is covered
		 */
		private String hashCovered(String text, int from, int to) {
			StringBuilder result = null;
			int copied = 0;
			for (int segment = 0; segment <= text.length();) {
				int end = text.indexOf('.', segment);
				if (end < 0) {
					end = text.length();
				}
				int start = Math.max(segment, from);
				int stop = Math.min(end, to);
				if (start < stop) {
					if (result == null) {
						result = new StringBuilder(text.length() + 32);
					}
					result.append(text, copied, start).append(hash.apply(text.substring(start, stop)));
					copied = stop;
				}
				segment = end + 1;
			}
			return result == null ? null : result.append(text, copied, text.length()).toString();
		}
	}

	/**
	 * Replaces the part of class names matching an expression with a hash, segment by segment, and
	 * the package and module names the expression matches alike, see {@link SegmentHasher}
	 */
	private static final class ClassNameRule implements Rule {
		/**
		 * The class of an object in a thread dump, which may be an array class, as the group
		 * following one of the templates HotSpot prints. The name ends at a parenthesis, a comma or
		 * the end of the line.
		 */
		private static final String OBJECT_CLASS_NAME = "(\\[+L" + DUMP_CLASS_NAME + ";|" + DUMP_CLASS_NAME
				+ ")(?=[),]|$)";
		/**
		 * The class of a lock, {@code (a java.util.HashMap)} or {@code (a [Lcom.acme.Foo;)}, or of
		 * the class a Class mirror stands for, {@code (a java.lang.Class for com.acme.Foo)}. The
		 * rare templates below have patterns of their own, so that each pattern starts with a
		 * literal, which keeps the scan of a large dump cheap.
		 */
		private static final Pattern LOCK_OBJECT = Pattern
				.compile("\\(a (?:java\\.lang\\.Class for )?" + OBJECT_CLASS_NAME, Pattern.MULTILINE);
		/** The object of a deadlock, {@code (object 0x000000076b4d8f88, a com.acme.Foo),} */
		private static final Pattern DEADLOCK_OBJECT = Pattern
				.compile("\\(object 0x[0-9a-fA-F]+, a " + OBJECT_CLASS_NAME, Pattern.MULTILINE);
		/**
		 * The class being initialized, ending the line
		 * {@code waiting on the Class initialization monitor for com.acme.Foo}
		 */
		private static final Pattern CLASS_INITIALIZATION_MONITOR = Pattern
				.compile("Class initialization monitor for " + OBJECT_CLASS_NAME, Pattern.MULTILINE);
		/**
		 * The suffix the JVM appends to the name of a hidden class in source form, which differs
		 * between runs. Class name constants carry the identity hash in JDK 8 to 14,
		 * {@code Foo$$Lambda$269/286774984}, the address and the identity hash in JDK 15 to 22,
		 * {@code Foo$$Lambda+0x00007fb87c2252f8/262911569}, and the address alone from JDK 23 on,
		 * {@code Foo$$Lambda/0x00007fb87c2252f8}, which is also what thread dumps print since JDK
		 * 15, after printing the identity hash before.
		 */
		private static final Pattern HIDDEN_CLASS_SUFFIX = Pattern
				.compile("(?:\\+0x[0-9a-fA-F]+)?(?:" + HIDDEN_CLASS_SLASH_SUFFIX + ")?$");
		/**
		 * The suffix of a hidden class in internal form, as in descriptors and array class names,
		 * {@code com/acme/Foo$$Lambda+0x00007fb87c2252f8}: the address alone. The identity hash is
		 * only appended to names in source form, so a trailing {@code /<digits>} segment of an
		 * internal name is a class or package name. JVMTI class signatures separate the address
		 * with a dot instead, {@code com/acme/Foo$$Lambda.0x00007fb87c2252f8}, as written by
		 * profilers that take class names from JVMTI.
		 */
		private static final Pattern INTERNAL_HIDDEN_CLASS_SUFFIX = Pattern.compile("[+.]0x[0-9a-fA-F]+$");
		private static final String OLD_OBJECT_CLASS_NAME = "Class Name: ";

		/**
		 * The expressions in the order added: for each part of a name, the package or the simple
		 * name, the first one covering a piece of it decides, with its hash
		 */
		private final List<SegmentHasher> hashers;

		ClassNameRule(List<SegmentHasher> hashers) {
			this.hashers = hashers;
		}

		/** @return a rule trying the expression after the others */
		ClassNameRule with(SegmentHasher hasher) {
			List<SegmentHasher> more = new ArrayList<>(hashers);
			more.add(hasher);
			return new ClassNameRule(List.copyOf(more));
		}

		/**
		 * A renamed class or package: the new name, and the hash of the expression that decided the
		 * simple name of the class, or else its package, which also hashes the source file names of
		 * its frames, so that a file named like its class gets the hash of the class
		 */
		private record Renamed(String name, UnaryOperator<String> hash) {
		}

		@Override
		public String apply(String value, List<StringLocation> locations) {
			// A name stored both as a class and as a package, which javac forbids and the JVM allows,
			// is renamed as the package, whichever location comes first, so that its classes stay in it
			boolean className = false;
			boolean descriptor = false;
			for (StringLocation location : locations) {
				if (location.isPackageName() || location.isModuleName()) {
					return renamePackageName(value);
				}
				className |= location.isClassName();
				descriptor |= location.isMethodDescriptor();
			}
			return className ? renameClassName(value) : descriptor ? renameInDescriptor(value) : null;
		}

		/**
		 * Maps a package or module name in source form by the first expression covering a piece of
		 * it, see {@link SegmentHasher#mapPackage}
		 *
		 * @return the mapped name with the hash of that expression, or {@code null} if no
		 *         expression covers a piece of a segment
		 */
		private Renamed mapPackage(String name) {
			for (SegmentHasher hasher : hashers) {
				String mapped = hasher.mapPackage(name);
				if (mapped != null) {
					return new Renamed(mapped, hasher.hash);
				}
			}
			return null;
		}

		/**
		 * Maps the simple name of a class, starting at {@code start} of the name in source form, by
		 * the first expression whose match reaches into it, see {@link SegmentHasher#mapSimpleName}
		 *
		 * @return the mapped simple name with the hash of that expression, or {@code null} if no
		 *         expression reaches into it
		 */
		private Renamed mapSimpleName(String name, int start) {
			for (SegmentHasher hasher : hashers) {
				String mapped = hasher.mapSimpleName(name, start);
				if (mapped != null) {
					return new Renamed(mapped, hasher.hash);
				}
			}
			return null;
		}

		/**
		 * Maps a class name in source form without the suffix of a hidden class, such as
		 * {@code com.acme.secret.Foo} or {@code Foo} in the default package: the simple name by the
		 * first expression reaching into it and the package by the first covering a piece of it, as
		 * the package name on its own is mapped
		 *
		 * @return the mapped name, or {@code null} if no expression covers a piece of the package
		 *         or of the simple name
		 */
		private Renamed mapClass(String name) {
			int dot = name.lastIndexOf('.');
			Renamed simpleName = mapSimpleName(name, dot + 1);
			if (dot < 0) {
				return simpleName;
			}
			Renamed packageName = mapPackage(name.substring(0, dot));
			if (packageName == null && simpleName == null) {
				return null;
			}
			String renamed = (packageName == null ? name.substring(0, dot) : packageName.name()) + '.'
					+ (simpleName == null ? name.substring(dot + 1) : simpleName.name());
			return new Renamed(renamed, (simpleName == null ? packageName : simpleName).hash());
		}

		@Override
		public String rewriteComposite(String text, StringLocation location) {
			if (location.isThreadDump()) {
				return rewriteObjects(rewriteFrames(text));
			}
			if (text.startsWith(OLD_OBJECT_CLASS_NAME)) {
				String renamed = renameClassName(text.substring(OLD_OBJECT_CLASS_NAME.length()));
				return renamed == null ? text : OLD_OBJECT_CLASS_NAME + renamed;
			}
			return text;
		}

		/**
		 * Renames the classes of the frames, except within quoted thread names, hashes the source
		 * file names of renamed classes, as they would reveal the class names, and the bare name
		 * HotSpot prints as the location of a generated class instead of a file, which is the name
		 * of the class, and renames the modules of the locations like packages. The other
		 * locations, {@code Native Method}, {@code Unknown Source} and {@code Redefined}, stay. The
		 * file name and the bare name are hashed by the expression that renamed the class, see
		 * {@link Renamed}.
		 */
		private String rewriteFrames(String text) {
			Matcher m = DUMP_FRAME.matcher(text);
			StringBuilder result = null;
			int copied = 0;
			while (m.find()) {
				if (inQuotedName(text, m.start())) {
					continue;
				}
				Renamed renamed = renameClass(m.group(1), false);
				String module = m.start(3) < 0 ? null : renameFrameModule(m.group(3));
				if (renamed == null && module == null) {
					continue;
				}
				if (result == null) {
					result = new StringBuilder(text.length() + 64);
				}
				if (renamed != null) {
					result.append(text, copied, m.start(1)).append(renamed.name());
					copied = m.end(1);
				}
				if (module != null) {
					result.append(text, copied, m.start(3)).append(module);
					copied = m.end(3);
				}
				if (renamed != null) {
					String location = m.group(4);
					Matcher file = DUMP_FILE.matcher(location);
					if (file.matches()) {
						result.append(text, copied, m.start(4)).append(renamed.hash().apply(file.group(1)));
						copied = m.start(4) + file.end(1);
					} else if (location.equals(simpleHostName(m.group(1)))) {
						result.append(text, copied, m.start(4)).append(renamed.hash().apply(location));
						copied = m.end(4);
					}
				}
			}
			return result == null ? text : result.append(text, copied, text.length()).toString();
		}

		/**
		 * The simple name of the host class of a frame, {@code LambdaForm$MH} for
		 * {@code java.lang.invoke.LambdaForm$MH/0x00007fb87c0c4800}, which HotSpot prints as the
		 * location of a generated class, whose source file is named like the class and has no
		 * extension
		 */
		private static String simpleHostName(String className) {
			String host = className.substring(0, suffixStart(HIDDEN_CLASS_SUFFIX, className));
			return host.substring(host.lastIndexOf('.') + 1);
		}

		/**
		 * Renames the module of a frame location, {@code java.base@21.0.1/} or {@code demo/}, like
		 * a package, keeping the version and the slash
		 *
		 * @return the renamed text, or {@code null} if the module is not renamed
		 */
		private String renameFrameModule(String module) {
			int end = module.indexOf('@');
			if (end < 0) {
				end = module.length() - 1; // The slash
			}
			Renamed renamed = mapPackage(module.substring(0, end));
			return renamed == null ? null : renamed.name() + module.substring(end);
		}

		/**
		 * Renames a package or module name as the package part of its classes is renamed, keeping
		 * the form of the input: HotSpot stores package names in internal form,
		 * {@code com/acme/secret}, and module names in source form, {@code java.base}
		 *
		 * @return the renamed name, or {@code null} if no part of a segment is covered
		 */
		private String renamePackageName(String name) {
			if (name.indexOf('/') < 0) {
				return nameOf(mapPackage(name));
			}
			Renamed renamed = mapPackage(name.replace('/', '.'));
			return renamed == null ? null : renamed.name().replace('.', '/');
		}

		private static String nameOf(Renamed renamed) {
			return renamed == null ? null : renamed.name();
		}

		/**
		 * Renames the classes of the objects of every template, except within quoted thread names
		 */
		private String rewriteObjects(String text) {
			return rewriteObjects(CLASS_INITIALIZATION_MONITOR,
					rewriteObjects(DEADLOCK_OBJECT, rewriteObjects(LOCK_OBJECT, text)));
		}

		private String rewriteObjects(Pattern objects, String text) {
			Matcher m = objects.matcher(text);
			StringBuilder result = null;
			int copied = 0;
			while (m.find()) {
				String renamed = inQuotedName(text, m.start()) ? null : renameClassName(m.group(1));
				if (renamed != null) {
					if (result == null) {
						result = new StringBuilder(text.length() + 64);
					}
					result.append(text, copied, m.start(1)).append(renamed);
					copied = m.end(1);
				}
			}
			return result == null ? text : result.append(text, copied, text.length()).toString();
		}

		/**
		 * Renames a class name in any of its forms: in source form ({@code com.acme.Foo}) or
		 * internal form ({@code com/acme/Foo}), with the suffix of a hidden class, or an array
		 * class in either form ({@code [Lcom.acme.Foo;}), whose component class is renamed.
		 * Primitive arrays never match; the pattern decides for the names of primitive types, such
		 * as the class name constant {@code int}.
		 *
		 * @return the renamed name, or {@code null} if the pattern does not match
		 */
		private String renameClassName(String name) {
			if (!name.startsWith("[")) {
				return nameOf(renameClass(name, false));
			}
			int component = name.lastIndexOf('[') + 1;
			if (component >= name.length() || name.charAt(component) != 'L' || !name.endsWith(";")) {
				return null;
			}
			Renamed renamed = renameClass(name.substring(component + 1, name.length() - 1), false);
			return renamed == null ? null : name.substring(0, component + 1) + renamed.name() + ";";
		}

		/**
		 * Renames a class that is not an array: splits off the suffix of a hidden class, maps the
		 * source form of the host class segment by segment, and keeps the form of the input, so
		 * that slashed names stay slashed and dotted names dotted.
		 *
		 * @param internal
		 *            {@code true} if the name is known to be in internal form, as in a descriptor,
		 *            or {@code false} to decide by the name: a name without dots is in internal
		 *            form if a slash precedes its suffix, or if its only slash starts a suffix that
		 *            is more likely a class name, see {@link #isClassOfSingleSegmentPackage}, and
		 *            so is a name whose only dot starts the suffix of a JVMTI signature, see
		 *            {@link #INTERNAL_HIDDEN_CLASS_SUFFIX}. A dotted name may end in a slash
		 *            segment that is no suffix, and a name in the default package has no separator
		 *            to decide by, which the suffix grammar does.
		 * @return the renamed name with the hash of the expression that renamed it, or {@code null}
		 *         if no expression matches
		 */
		private Renamed renameClass(String name, boolean internal) {
			int hostEnd = name.length();
			if (!internal) {
				// Only a name with a slash or a plus can carry a suffix, which spares most frames the pattern
				if (name.indexOf('/') >= 0 || name.indexOf('+') >= 0) {
					hostEnd = suffixStart(HIDDEN_CLASS_SUFFIX, name);
				}
				int dot = name.indexOf('.');
				internal = dot < 0
						&& (name.lastIndexOf('/', hostEnd - 1) >= 0 || isClassOfSingleSegmentPackage(name, hostEnd))
						|| dot >= 0 && dot == suffixStart(INTERNAL_HIDDEN_CLASS_SUFFIX, name);
			}
			if (internal) {
				hostEnd = suffixStart(INTERNAL_HIDDEN_CLASS_SUFFIX, name);
			}
			String host = name.substring(0, hostEnd);
			Renamed renamed = mapClass(internal ? host.replace('/', '.') : host);
			if (renamed == null || !internal && hostEnd == name.length()) {
				return renamed;
			}
			return new Renamed((internal ? renamed.name().replace('.', '/') : renamed.name()) + name.substring(hostEnd),
					renamed.hash());
		}

		/**
		 * True if the slash segment starting at {@code suffixStart}, which the suffix grammar
		 * accepts, is more likely the class of a single-segment package than the suffix of a hidden
		 * class in the default package: a decimal segment after a host without a {@code $}, as in
		 * {@code acme/123}. JDK 8 to 14 appended the identity hash to generated hosts with one, as
		 * in {@code Gen$$Lambda$5/286774984}, and an address, as in {@code Gen/0x000000002e045c38},
		 * has named a hidden class of any host since JDK 15, while no Java class is named like one.
		 */
		private static boolean isClassOfSingleSegmentPackage(String name, int suffixStart) {
			return suffixStart < name.length() && name.charAt(suffixStart) == '/'
					&& !name.startsWith("/0x", suffixStart) && name.lastIndexOf('$', suffixStart) < 0;
		}

		/**
		 * @return where the suffix matching the pattern starts, or the length of the name if it has
		 *         none, which cannot happen with {@link #HIDDEN_CLASS_SUFFIX}, whose parts are all
		 *         optional
		 */
		private static int suffixStart(Pattern suffix, String name) {
			Matcher m = suffix.matcher(name);
			return m.find() ? m.start() : name.length();
		}

		/** Renames the classes of a method descriptor, such as {@code (ILcom/acme/Foo;)V} */
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
				String renamed = nameOf(renameClass(descriptor.substring(i + 1, end), true));
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
