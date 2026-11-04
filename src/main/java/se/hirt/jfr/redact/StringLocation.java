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
 * Where in a recording a string is stored: the field whose value it is, and whether that value is
 * inlined in an event or stored in a constant pool, in a checkpoint event.
 * <p>
 * A constant pool type the metadata declares a simple type, one with a single field, such as
 * {@code jdk.types.Symbol} or {@code jdk.types.ThreadState}, is read by every reader as that value:
 * a class name is the value of {@code java.lang.Class.name}, the state of a sample the value of
 * {@code jdk.ExecutionSample.state}, so such a string is located at the fields referring to the
 * constant, as a constant, through chains of simple types. The {@code java.lang.String} constant
 * pool is read the same way, so a value stored in it belongs to the field referring to it, from an
 * event or from a constant, and is located there: a class name a writer stores as a symbol
 * referring to the pool folds twice, through the symbol and the pool, to the class's field. The
 * simple type or the pool itself is the location only of a constant that no field of its chunk
 * refers to, and a constant referred to in one chunk and in none of another is located both ways.
 * The other constant pool types, {@code java.lang.Thread}, {@code jdk.types.Method} and the rest,
 * are entities: their strings are located at their fields, and the fields of other constants
 * referring to an entity storing strings itself are the {@linkplain #getReferrers() referrers}; an
 * entity whose names are all symbols or pool entries, such as a class, has none. JFR 0.9 declares
 * no simple types, so there the location is the storing constant, {@code UTFConstant.utf8}, with
 * the field referring to it as a referrer. Instances are interned, so they can be compared by
 * identity.
 */
public final class StringLocation {
	/**
	 * The string also occurs in the metadata of the recording, as a type, field or annotation name
	 * or value, either as a whole string or within a longer one. Strings in the metadata are not
	 * redacted, so a redacted string with this location remains in the redacted recording, which is
	 * reported in {@link RedactionResult#redactedInMetadata()}.
	 */
	public static final StringLocation METADATA = new StringLocation("metadata", "strings", false, List.of());

	/**
	 * The fields whose constant values are the names the predicates classify, as owner and field
	 * pairs, in JDK 11+ and in JDK 9 and 10
	 */
	private static final String[] CLASS_NAME_FIELDS = {"java.lang.Class", "name"};
	private static final String[] METHOD_NAME_FIELDS = {"jdk.types.Method", "name", "com.oracle.jfr.types.Method",
			"name"};
	private static final String[] METHOD_DESCRIPTOR_FIELDS = {"jdk.types.Method", "descriptor",
			"com.oracle.jfr.types.Method", "descriptor"};
	private static final String[] PACKAGE_NAME_FIELDS = {"jdk.types.Package", "name", "com.oracle.jfr.types.Package",
			"name"};
	private static final String[] MODULE_NAME_FIELDS = {"jdk.types.Module", "name", "com.oracle.jfr.types.Module",
			"name"};
	/**
	 * The fields of Datadog's events holding class names in source form, such as
	 * {@code com.acme.SecretException}, inline or pooled
	 */
	private static final String[] DATADOG_CLASS_NAME_FIELDS = {"datadog.ExceptionSample", "type",
			"datadog.ExceptionCount", "type", "datadog.DirectAllocationSample", "allocatingClass",
			"datadog.DirectAllocationTotal", "allocatingClass"};
	/** The JFR 0.9 fields referring to the interned strings of class and method names */
	private static final String[] LEGACY_CLASS_NAME_REFERRERS = {"Class.name"};
	private static final String[] LEGACY_METHOD_NAME_REFERRERS = {"Method.name"};
	private static final String[] LEGACY_METHOD_DESCRIPTOR_REFERRERS = {"Method.signature"};

	/**
	 * The owners and fields of the values of environment variables, system properties and security
	 * properties: JDK 11+, JDK 9 and 10, JDK 7 and 8, seen in recordings of the JMC tutorial though
	 * no test recording covers them, and JRockit
	 */
	private static final String[] ENVIRONMENT_VARIABLE_VALUES = {"jdk.InitialEnvironmentVariable", "value",
			"com.oracle.jdk.InitialEnvironmentVariable", "value", "os/initial_environment_variable", "value",
			"os/environment", "variables.value"};
	private static final String[] SYSTEM_PROPERTY_VALUES = {"jdk.InitialSystemProperty", "value",
			"com.oracle.jdk.InitialSystemProperty", "value", "vm/initial_system_property", "value",
			"vm/system_properties", "properties.value"};
	private static final String[] SECURITY_PROPERTY_VALUES = {"jdk.InitialSecurityProperty", "value",
			"jdk.SecurityPropertyModification", "value"};
	/**
	 * The command lines of processes, with the same versions as above, and those the JVM started
	 */
	private static final String[] PROCESS_COMMAND_LINES = {"jdk.SystemProcess", "commandLine",
			"com.oracle.jdk.SystemProcess", "commandLine", "os/system_process", "commandLine", "os/processes",
			"processes.commandLine", "jdk.ProcessStart", "command"};

	private final String owner;
	private final String field;
	private final boolean pooled;
	private final List<String> referrers;
	private final String key;

	StringLocation(String owner, String field, boolean pooled, List<String> referrers) {
		this(owner, field, pooled, referrers, null);
	}

	StringLocation(String owner, String field, boolean pooled, List<String> referrers, String key) {
		this.owner = owner;
		this.field = field;
		this.pooled = pooled;
		this.referrers = referrers;
		this.key = key;
	}

	/**
	 * @return the name of the event type, or of the constant pool type, whose field holds the
	 *         string, for example {@code jdk.ThreadStart} or {@code jdk.types.Method}
	 */
	public String getOwner() {
		return owner;
	}

	/**
	 * @return the path of the field holding the string within the owner, with nested fields
	 *         separated by dots, for example {@code name} or {@code frames.type}
	 */
	public String getField() {
		return field;
	}

	/**
	 * @return {@code true} if the string is stored in a constant pool: in the constant of the
	 *         owner, such as the name of a thread in {@code java.lang.Thread}, or in the constant
	 *         of a simple type or the {@code java.lang.String} pool that the field refers to, such
	 *         as the name of a method in the {@code jdk.types.Symbol} that
	 *         {@code jdk.types.Method.name} refers to, or the value of an event field the writer
	 *         pooled; {@code false} if it is inlined in an event. This tells how a copy of the
	 *         string is stored, not what it is: the JDK's Java event writer inlines or pools a
	 *         string by its length and by how recently it was seen, so the values of one event
	 *         field can be located both ways, and a rule on the owner and field reaches both.
	 */
	public boolean isPooled() {
		return pooled;
	}

	/**
	 * @return for strings in constant pools, the fields of other constants that refer to the
	 *         constant holding the value, in the same chunk, as {@code owner.field}. Recorded only
	 *         for constants that hold strings themselves, inline, such as a thread group, whose
	 *         name is referred to by {@code java.lang.Thread.group}: a class or method name, whose
	 *         string comes from a symbol or the string pool, has none, however many constants refer
	 *         to the class or the method. A simple type the field refers to, such as
	 *         {@code jdk.types.Symbol}, is read as the value of the field, so it is no referrer,
	 *         and the constant of a simple type that nothing refers to, located at its own field,
	 *         has none; neither are references from events referrers.
	 */
	public List<String> getReferrers() {
		return referrers;
	}

	/**
	 * @return for the value of a type that has a field named {@code key} next to the field named
	 *         {@code value}, such as an environment variable or a system property, the key it is
	 *         the value of, for example {@code user.home}, whether key and value are inline or
	 *         pooled; {@code null} for other fields, and for a value whose key could not be read,
	 *         such as one referring to a string missing from its chunk's string pool, so a rule on
	 *         keys must treat a value of such a field without a key as having any key
	 */
	public String getKey() {
		return key;
	}

	/**
	 * @return {@code true} if this is the value of an environment variable, whose name is the
	 *         {@linkplain #getKey() key}: {@code jdk.InitialEnvironmentVariable.value} in JDK 11+,
	 *         {@code com.oracle.jdk.InitialEnvironmentVariable.value} in JDK 9 and 10,
	 *         {@code os/initial_environment_variable.value} in JDK 7 and 8 and
	 *         {@code os/environment.variables.value} in JRockit
	 */
	public boolean isEnvironmentVariableValue() {
		return isOwnerAndField(ENVIRONMENT_VARIABLE_VALUES);
	}

	/**
	 * @return {@code true} if this is the value of a system property, whose name is the
	 *         {@linkplain #getKey() key}: {@code jdk.InitialSystemProperty.value} in JDK 11+,
	 *         {@code com.oracle.jdk.InitialSystemProperty.value} in JDK 9 and 10,
	 *         {@code vm/initial_system_property.value} in JDK 7 and 8 and
	 *         {@code vm/system_properties.properties.value} in JRockit
	 */
	public boolean isSystemPropertyValue() {
		return isOwnerAndField(SYSTEM_PROPERTY_VALUES);
	}

	/**
	 * @return {@code true} if this is the value of a security property, whose name is the
	 *         {@linkplain #getKey() key}: {@code jdk.InitialSecurityProperty.value} and
	 *         {@code jdk.SecurityPropertyModification.value}
	 */
	public boolean isSecurityPropertyValue() {
		return isOwnerAndField(SECURITY_PROPERTY_VALUES);
	}

	/**
	 * @return {@code true} if this is the command line of a process, an executable followed by its
	 *         arguments: {@code jdk.SystemProcess.commandLine}, the processes running when the
	 *         recording started, in JDK 11+, {@code com.oracle.jdk.SystemProcess.commandLine} in
	 *         JDK 9 and 10, {@code os/system_process.commandLine} in JDK 7 and 8,
	 *         {@code os/processes.processes.commandLine} in JRockit, and
	 *         {@code jdk.ProcessStart.command}, the processes the JVM started
	 */
	public boolean isProcessCommandLine() {
		return isOwnerAndField(PROCESS_COMMAND_LINES);
	}

	private boolean isOwnerAndField(String[] ownersAndFields) {
		for (int i = 0; i < ownersAndFields.length; i += 2) {
			if (owner.equals(ownersAndFields[i]) && field.equals(ownersAndFields[i + 1])) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return {@code true} if this is the name of a thread: {@code java.lang.Thread.javaName} and
	 *         {@code java.lang.Thread.osName} in JFR 1.0+, {@code Thread.name} in JFR 0.9, whether
	 *         the writer stored the name in the thread's constant or in the string pool
	 */
	public boolean isThreadName() {
		if (!pooled) {
			return false;
		}
		return switch (owner) {
		case "java.lang.Thread" -> field.equals("javaName") || field.equals("osName");
		case "Thread" -> field.equals("name");
		default -> false;
		};
	}

	/**
	 * @return {@code true} if this is the name of a thread group:
	 *         {@code jdk.types.ThreadGroup.name} in JDK 11+,
	 *         {@code com.oracle.jfr.types.ThreadGroup.name} in JDK 9 and 10, and
	 *         {@code ThreadGroup.name} in JFR 0.9, whether the writer stored the name in the
	 *         group's constant or in the string pool
	 */
	public boolean isThreadGroupName() {
		if (!pooled) {
			return false;
		}
		return switch (owner) {
		case "jdk.types.ThreadGroup", "com.oracle.jfr.types.ThreadGroup", "ThreadGroup" -> field.equals("name");
		default -> false;
		};
	}

	/**
	 * @return {@code true} if this is a class name, in internal form such as
	 *         {@code java/util/HashMap}: the value of {@code java.lang.Class.name} as a constant,
	 *         whether the writer stored it in a {@code jdk.types.Symbol} or in the string pool, the
	 *         class of the inlined method of a {@code jdk.CompilerInlining} event
	 *         ({@code com.oracle.jdk.CompilerInlining} in JDK 9 and 10), which is written inline,
	 *         or in JFR 0.9 a constant referred to by {@code Class.name}; or in source form such as
	 *         {@code java.util.HashMap}, the class of an exception or allocation in Datadog's
	 *         events: {@code datadog.ExceptionSample.type}, {@code datadog.ExceptionCount.type} and
	 *         the {@code allocatingClass} of {@code datadog.DirectAllocationSample} and
	 *         {@code datadog.DirectAllocationTotal}, inline or pooled
	 */
	public boolean isClassName() {
		return isPooledValueOf(CLASS_NAME_FIELDS) || isReferredToBy(LEGACY_CLASS_NAME_REFERRERS)
				|| isCompilerInliningCallee("callee.type") || isValueOf(DATADOG_CLASS_NAME_FIELDS);
	}

	/**
	 * @return {@code true} if this is a method descriptor, such as {@code (Ljava/util/List;)V}: the
	 *         value of {@code jdk.types.Method.descriptor}
	 *         ({@code com.oracle.jfr.types.Method.descriptor} in JDK 9 and 10) as a constant, the
	 *         descriptor of the callee of a {@code jdk.CompilerInlining} event, written inline, or
	 *         in JFR 0.9 a constant referred to by {@code Method.signature}
	 */
	public boolean isMethodDescriptor() {
		return isPooledValueOf(METHOD_DESCRIPTOR_FIELDS) || isReferredToBy(LEGACY_METHOD_DESCRIPTOR_REFERRERS)
				|| isCompilerInliningCallee("callee.descriptor");
	}

	/**
	 * @return {@code true} if this is a method name: the value of {@code jdk.types.Method.name}
	 *         ({@code com.oracle.jfr.types.Method.name} in JDK 9 and 10) as a constant, the name of
	 *         the callee of a {@code jdk.CompilerInlining} event, written inline, or in JFR 0.9 a
	 *         constant referred to by {@code Method.name}
	 */
	public boolean isMethodName() {
		return isPooledValueOf(METHOD_NAME_FIELDS) || isReferredToBy(LEGACY_METHOD_NAME_REFERRERS)
				|| isCompilerInliningCallee("callee.name");
	}

	/**
	 * @return {@code true} if this is a package name, in internal form such as {@code java/util}:
	 *         the value of {@code jdk.types.Package.name} (JDK 11+) or
	 *         {@code com.oracle.jfr.types.Package.name} (JDK 9 and 10) as a constant. JFR 0.9
	 *         stores no package names. The default package is named by the empty string.
	 */
	public boolean isPackageName() {
		return isPooledValueOf(PACKAGE_NAME_FIELDS);
	}

	/**
	 * @return {@code true} if this is a module name, in source form such as {@code java.base}: the
	 *         value of {@code jdk.types.Module.name} (JDK 11+) or
	 *         {@code com.oracle.jfr.types.Module.name} (JDK 9 and 10) as a constant. The version
	 *         and location of a module, {@code 21.0.1} and {@code jrt:/java.base}, are other
	 *         strings.
	 */
	public boolean isModuleName() {
		return isPooledValueOf(MODULE_NAME_FIELDS);
	}

	/**
	 * True if this is the field of the inlined method of a {@code jdk.CompilerInlining} event,
	 * whose class name, method name and descriptor are written inline, not as constants
	 */
	private boolean isCompilerInliningCallee(String calleeField) {
		return !pooled && field.equals(calleeField)
				&& (owner.equals("jdk.CompilerInlining") || owner.equals("com.oracle.jdk.CompilerInlining"));
	}

	/** True if this is a pooled value of one of the fields, given as owner and field pairs */
	private boolean isPooledValueOf(String[] ownersAndFields) {
		return pooled && isValueOf(ownersAndFields);
	}

	/** True if this is a value of one of the fields, given as owner and field pairs */
	private boolean isValueOf(String[] ownersAndFields) {
		for (int i = 0; i < ownersAndFields.length; i += 2) {
			if (owner.equals(ownersAndFields[i]) && field.equals(ownersAndFields[i + 1])) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The JFR 0.9 form of a name: JRockit declares no simple types, so its interned strings are
	 * located at the constant storing them, {@code UTFConstant.utf8}, and the field referring to
	 * the constant, {@code Class.name} or {@code Method.name}, tells what the string is. In JFR
	 * 1.0+ the referring field is the location itself, and the referrers name nothing.
	 */
	private boolean isReferredToBy(String[] fields) {
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
	 *         class names: {@code jdk.ThreadDump.result} in JDK 11+,
	 *         {@code com.oracle.jdk.ThreadDump.result} in JDK 9 and 10 and
	 *         {@code vm/runtime/thread_dump.result} in JFR 0.9, wherever the writer stored it;
	 *         HotSpot inlines it in the event
	 */
	public boolean isThreadDump() {
		return field.equals("result") && switch (owner) {
		case "jdk.ThreadDump", "com.oracle.jdk.ThreadDump", "vm/runtime/thread_dump" -> true;
		default -> false;
		};
	}

	/**
	 * @return {@code true} if this is the description of an old object sample or its GC root, such
	 *         as {@code Thread Name: main}: {@code jdk.types.OldObject} and
	 *         {@code jdk.types.OldObjectGcRoot} in JDK 11+, {@code com.oracle.jfr.types.OldObject}
	 *         and {@code com.oracle.jfr.types.OldObjectGcRoot} in JDK 10
	 */
	public boolean isOldObjectDescription() {
		return pooled && field.equals("description") && switch (owner) {
		case "jdk.types.OldObject", "jdk.types.OldObjectGcRoot", "com.oracle.jfr.types.OldObject",
				"com.oracle.jfr.types.OldObjectGcRoot" ->
			true;
		default -> false;
		};
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
		String s = owner + "." + field + (pooled ? " (pooled)" : " (inline)");
		if (key != null) {
			s += " for key " + key;
		}
		return referrers.isEmpty() ? s : s + " referred to by " + String.join(", ", referrers);
	}
}
