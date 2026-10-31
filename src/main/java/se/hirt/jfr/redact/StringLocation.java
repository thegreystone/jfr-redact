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
 * Where in a recording a string is stored. Instances are interned, so they can be compared by
 * identity.
 */
public final class StringLocation {
	/**
	 * The string also occurs in the metadata of the recording, as a type, field or annotation name
	 * or value. Strings in the metadata are not redacted, so a redacted string with this location
	 * remains in the redacted recording, which is reported in
	 * {@link RedactionResult#redactedInMetadata()}.
	 */
	public static final StringLocation METADATA = new StringLocation("metadata", "strings", false, List.of());

	private final String owner;
	private final String field;
	private final boolean constant;
	private final List<String> referrers;

	StringLocation(String owner, String field, boolean constant, List<String> referrers) {
		this.owner = owner;
		this.field = field;
		this.constant = constant;
		this.referrers = referrers;
	}

	/**
	 * @return the name of the event type, or of the constant pool type, storing the string, for
	 *         example {@code jdk.ThreadStart} or {@code jdk.types.Symbol}
	 */
	public String getOwner() {
		return owner;
	}

	/**
	 * @return the path of the field holding the string within the owner, with nested fields
	 *         separated by dots, for example {@code string}
	 */
	public String getField() {
		return field;
	}

	/**
	 * @return {@code true} if the string is stored in a constant pool, {@code false} if it is
	 *         inlined in an event
	 */
	public boolean isConstant() {
		return constant;
	}

	/**
	 * @return for strings in constant pools, the fields of other constants that refer to the
	 *         constant holding the string, in the same chunk, as {@code owner.field}. For example,
	 *         a method name is stored in a {@code jdk.types.Symbol} constant referred to by
	 *         {@code jdk.types.Method.name}. References from events are not included.
	 */
	public List<String> getReferrers() {
		return referrers;
	}

	/**
	 * @return {@code true} if this is the name of a thread: {@code java.lang.Thread.javaName} and
	 *         {@code java.lang.Thread.osName} in JFR 1.0+, {@code Thread.name} in JFR 0.9
	 */
	public boolean isThreadName() {
		if (!constant) {
			return false;
		}
		return switch (owner) {
		case "java.lang.Thread" -> field.equals("javaName") || field.equals("osName");
		case "Thread" -> field.equals("name");
		default -> false;
		};
	}

	/**
	 * @return {@code true} if this is a class name, in internal form such as
	 *         {@code java/util/HashMap}: a constant referred to by {@code java.lang.Class.name}
	 *         (JFR 1.0+) or {@code Class.name} (JFR 0.9)
	 */
	public boolean isClassName() {
		return isReferredToBy("java.lang.Class.name", "Class.name");
	}

	/**
	 * @return {@code true} if this is a method descriptor, such as {@code (Ljava/util/List;)V}
	 */
	public boolean isMethodDescriptor() {
		return isReferredToBy("jdk.types.Method.descriptor", "com.oracle.jfr.types.Method.descriptor",
				"Method.signature");
	}

	/**
	 * @return {@code true} if this is a method name
	 */
	public boolean isMethodName() {
		return isReferredToBy("jdk.types.Method.name", "com.oracle.jfr.types.Method.name", "Method.name");
	}

	/**
	 * @return {@code true} if this is a package name, in internal form such as {@code java/util}
	 */
	public boolean isPackageName() {
		return isReferredToBy("jdk.types.Package.name", "com.oracle.jfr.types.Package.name");
	}

	private boolean isReferredToBy(String ... fields) {
		for (String referrer : referrers) {
			for (String field : fields) {
				if (referrer.equals(field)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * @return {@code true} if this is the text of a thread dump, which contains thread names and
	 *         class names: {@code jdk.ThreadDump.result} in JFR 1.0+,
	 *         {@code vm/runtime/thread_dump.result} in JFR 0.9
	 */
	public boolean isThreadDump() {
		return !constant && field.equals("result")
				&& (owner.equals("jdk.ThreadDump") || owner.equals("vm/runtime/thread_dump"));
	}

	/**
	 * @return {@code true} if this is the description of an old object sample or its GC root, such
	 *         as {@code Thread Name: main}
	 */
	public boolean isOldObjectDescription() {
		return constant && field.equals("description")
				&& (owner.equals("jdk.types.OldObject") || owner.equals("jdk.types.OldObjectGcRoot"));
	}

	/**
	 * @return {@code true} if strings at this location are documents embedding other strings, such
	 *         as thread names, rather than single values: thread dumps and old object descriptions
	 */
	public boolean isComposite() {
		return isThreadDump() || isOldObjectDescription();
	}

	@Override
	public String toString() {
		String s = owner + "." + field + (constant ? " (constant)" : " (inline)");
		return referrers.isEmpty() ? s : s + " referred to by " + String.join(", ", referrers);
	}
}
