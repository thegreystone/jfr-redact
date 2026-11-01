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

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

import org.openjdk.jmc.common.IMCClassLoader;
import org.openjdk.jmc.common.IMCFrame;
import org.openjdk.jmc.common.IMCMethod;
import org.openjdk.jmc.common.IMCModule;
import org.openjdk.jmc.common.IMCOldObject;
import org.openjdk.jmc.common.IMCOldObjectGcRoot;
import org.openjdk.jmc.common.IMCPackage;
import org.openjdk.jmc.common.IMCStackTrace;
import org.openjdk.jmc.common.IMCThread;
import org.openjdk.jmc.common.IMCThreadGroup;
import org.openjdk.jmc.common.IMCType;
import org.openjdk.jmc.common.item.IAccessorKey;
import org.openjdk.jmc.common.item.IItem;
import org.openjdk.jmc.common.item.IItemCollection;
import org.openjdk.jmc.common.item.IItemIterable;
import org.openjdk.jmc.common.item.IMemberAccessor;
import org.openjdk.jmc.common.item.IType;
import org.openjdk.jmc.flightrecorder.CouldNotLoadRecordingException;
import org.openjdk.jmc.flightrecorder.JfrLoaderToolkit;

/**
 * Reads a recording the way JDK Mission Control does and touches every value of every event, so
 * that JMC's model converts every name. JMC derives the simple name of a class from the name of its
 * package, {@code name.substring(packageName.length() + 1)} in {@code JfrJavaClass.convertNames},
 * so it requires every class name to start with the name of its package followed by a separator,
 * and throws or yields garbage names otherwise. Constants are shared, so every class, method, stack
 * trace, thread and other structure is visited once, and the events, classes and frames reached are
 * counted, to compare a redacted recording with its original. Can be run on any recording:
 * {@code java -cp <test classpath> se.hirt.jfr.redact.JmcModel <recording.jfr>...}
 */
final class JmcModel {
	/** How many problems are spelled out; the rest are counted */
	private static final int PROBLEMS_REPORTED = 10;

	private final List<String> problems = new ArrayList<>();
	private final Set<Object> seen = Collections.newSetFromMap(new IdentityHashMap<>());
	private int problemCount;
	private int items;
	private int classes;
	private int frames;

	private JmcModel() {
	}

	/** Loads the recording with JMC's parser and visits every value of every event */
	static JmcModel load(Path recording) throws IOException, CouldNotLoadRecordingException {
		IItemCollection events = JfrLoaderToolkit.loadEvents(recording.toFile());
		JmcModel model = new JmcModel();
		for (IItemIterable iterable : events) {
			IType<IItem> type = iterable.getType();
			List<IMemberAccessor<?, IItem>> accessors = new ArrayList<>();
			for (IAccessorKey<?> key : type.getAccessorKeys().keySet()) {
				accessors.add(type.getAccessor(key));
			}
			for (IItem item : iterable) {
				model.items++;
				for (IMemberAccessor<?, IItem> accessor : accessors) {
					try {
						model.visit(accessor.getMember(item));
					} catch (RuntimeException e) {
						model.problem("reading " + type.getIdentifier() + ": " + e);
					}
				}
			}
		}
		if (model.problemCount > PROBLEMS_REPORTED) {
			model.problems.add("... and " + (model.problemCount - PROBLEMS_REPORTED) + " more");
		}
		return model;
	}

	/**
	 * @return the problems JMC's model has with the recording: values it cannot convert and classes
	 *         whose full name is not their package name and simple name, the first
	 *         {@value #PROBLEMS_REPORTED} spelled out and the rest counted, empty if there are none
	 */
	List<String> problems() {
		return problems;
	}

	/** @return the number of events read */
	int items() {
		return items;
	}

	/** @return the number of distinct classes reached */
	int classes() {
		return classes;
	}

	/** @return the number of frames of the distinct stack traces reached */
	int frames() {
		return frames;
	}

	private void problem(String problem) {
		if (problemCount++ < PROBLEMS_REPORTED) {
			problems.add(problem);
		}
	}

	private void visit(Object value) {
		if (value instanceof IMCType type) {
			if (seen.add(type)) {
				visitType(type);
			}
		} else if (value instanceof IMCMethod method) {
			if (seen.add(method)) {
				visit(method.getType());
				method.getMethodName();
				method.getFormalDescriptor();
			}
		} else if (value instanceof IMCStackTrace trace) {
			if (seen.add(trace)) {
				for (IMCFrame frame : trace.getFrames()) {
					visit(frame);
				}
			}
		} else if (value instanceof IMCFrame frame) {
			frames++;
			visit(frame.getMethod());
			frame.getType();
		} else if (value instanceof IMCThread thread) {
			if (seen.add(thread)) {
				thread.getThreadName();
				visit(thread.getThreadGroup());
			}
		} else if (value instanceof IMCThreadGroup group) {
			if (seen.add(group)) {
				group.getName();
				visit(group.getParent());
			}
		} else if (value instanceof IMCOldObject object) {
			if (seen.add(object)) {
				visit(object.getType());
				object.getDescription();
				object.getReferrerArray();
				object.getReferrerField();
				visit(object.getReferrer());
			}
		} else if (value instanceof IMCOldObjectGcRoot root) {
			root.getDescription();
			root.getSystem();
			root.getType();
		} else if (value instanceof IMCClassLoader loader) {
			if (seen.add(loader)) {
				loader.getName();
				visit(loader.getType());
			}
		} else if (value instanceof IMCPackage pkg) {
			if (seen.add(pkg)) {
				pkg.getName();
				visit(pkg.getModule());
			}
		} else if (value instanceof IMCModule module) {
			if (seen.add(module)) {
				module.getName();
				module.getVersion();
				module.getLocation();
				visit(module.getClassLoader());
			}
		} else if (value instanceof Object[] array) {
			for (Object element : array) {
				visit(element);
			}
		} else if (value instanceof Iterable<?> iterable) {
			for (Object element : iterable) {
				visit(element);
			}
		}
	}

	/** Converts the names of the class, as JMC does for display, equality and hashing */
	private void visitType(IMCType type) {
		classes++;
		String fullName;
		String simpleName;
		IMCPackage pkg;
		try {
			fullName = type.getFullName();
			simpleName = type.getTypeName();
			pkg = type.getPackage();
			type.hashCode();
		} catch (RuntimeException e) {
			problem("converting a class name: " + e);
			return;
		}
		visit(pkg);
		String packageName = pkg == null ? null : pkg.getName();
		if (simpleName == null || simpleName.isEmpty()) {
			problem("empty simple name of " + fullName + " in package " + packageName);
		} else if (packageName != null && !packageName.isEmpty()) {
			if (!fullName.equals(packageName + "." + simpleName)) {
				problem("the class " + fullName + " in package " + packageName + " has the simple name " + simpleName);
			}
		} else if (!fullName.equals(simpleName)) {
			problem("the class " + fullName + " without a package has the simple name " + simpleName);
		}
	}

	public static void main(String[] args) throws IOException, CouldNotLoadRecordingException {
		boolean failed = false;
		for (String arg : args) {
			JmcModel model = load(Path.of(arg));
			System.out.printf("%s: JMC read %,d events, %,d classes and %,d frames, %,d problems%n", arg, model.items,
					model.classes, model.frames, model.problemCount);
			for (String problem : model.problems) {
				System.out.println("  " + problem);
			}
			failed |= model.problemCount > 0;
		}
		System.exit(failed ? 1 : 0);
	}
}
