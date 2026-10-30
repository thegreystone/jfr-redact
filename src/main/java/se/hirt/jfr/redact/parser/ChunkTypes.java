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
package se.hirt.jfr.redact.parser;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import se.hirt.jfr.redact.parser.ChunkMetadata.ClassElement;
import se.hirt.jfr.redact.parser.ChunkMetadata.FieldElement;

/**
 * The chunk metadata compiled into compact per-type field programs, so that values can be walked
 * without any per-field lookups or allocation. Each field is encoded as a single int:
 * {@code kind | ARRAY_FLAG? | (structTypeIndex << TYPE_SHIFT)}.
 */
public final class ChunkTypes {
	/** boolean and byte: a single raw byte */
	public static final int KIND_BYTE = 0;
	/** short, char, int, long and constant pool references */
	public static final int KIND_VARINT = 1;
	public static final int KIND_FLOAT = 2;
	public static final int KIND_DOUBLE = 3;
	public static final int KIND_STRING = 4;
	/** Inlined struct, the type index is in the upper bits */
	public static final int KIND_STRUCT = 5;
	public static final int KIND_MASK = 0x7;
	public static final int ARRAY_FLAG = 0x8;
	public static final int TYPE_SHIFT = 4;

	public static final String STRING_TYPE = "java.lang.String";
	private static final int MAX_DENSE_ID = 1 << 16;

	/** A compiled type */
	public static final class Type {
		public final int index;
		public final long id;
		public final String name;
		public final boolean isString;
		/** The field programs, in serialization order */
		public int[] fields;
		/** True if a value of this type can contain an inlined (not constant pool referenced) string */
		public boolean containsStrings;

		Type(int index, ClassElement element) {
			this.index = index;
			this.id = element.id;
			this.name = element.name;
			this.isString = STRING_TYPE.equals(element.name);
		}
	}

	private final Type[] types;
	private final Type[] denseById;
	private final Map<Long, Type> sparseById;

	public ChunkTypes(ChunkMetadata metadata) throws IOException {
		List<ClassElement> classes = metadata.getClasses();
		types = new Type[classes.size()];
		Map<Long, Type> byId = new HashMap<>(classes.size() * 2);
		long maxId = -1;
		for (int i = 0; i < types.length; i++) {
			types[i] = new Type(i, classes.get(i));
			byId.put(types[i].id, types[i]);
			maxId = Math.max(maxId, types[i].id);
		}
		for (int i = 0; i < types.length; i++) {
			types[i].fields = compileFields(classes.get(i), byId);
		}
		computeContainsStrings();

		if (maxId < MAX_DENSE_ID) {
			denseById = new Type[(int) maxId + 1];
			for (Type t : types) {
				if (t.id >= 0) {
					denseById[(int) t.id] = t;
				}
			}
			sparseById = null;
		} else {
			denseById = null;
			sparseById = byId;
		}
	}

	/**
	 * @return the type with the given id, or {@code null} if not declared in this chunk
	 */
	public Type getById(long id) {
		if (denseById != null) {
			return id >= 0 && id < denseById.length ? denseById[(int) id] : null;
		}
		return sparseById.get(id);
	}

	public Type getByIndex(int index) {
		return types[index];
	}

	public int size() {
		return types.length;
	}

	private static int[] compileFields(ClassElement element, Map<Long, Type> byId) throws IOException {
		int[] ops = new int[element.fields.size()];
		for (int i = 0; i < ops.length; i++) {
			FieldElement field = element.fields.get(i);
			Type fieldType = byId.get(field.typeId);
			if (fieldType == null) {
				throw new IOException("Field " + element.name + "." + field.name + " has undeclared type id "
						+ field.typeId);
			}
			int op = field.constantPool ? KIND_VARINT : kindOf(fieldType);
			if (op == KIND_STRUCT) {
				op |= fieldType.index << TYPE_SHIFT;
			}
			if (field.dimension > 0) {
				op |= ARRAY_FLAG;
			}
			ops[i] = op;
		}
		return ops;
	}

	private static int kindOf(Type type) {
		return switch (type.name) {
		case "boolean", "byte" -> KIND_BYTE;
		case "short", "char", "int", "long" -> KIND_VARINT;
		case "float" -> KIND_FLOAT;
		case "double" -> KIND_DOUBLE;
		case STRING_TYPE -> KIND_STRING;
		default -> KIND_STRUCT;
		};
	}

	private void computeContainsStrings() {
		for (Type t : types) {
			t.containsStrings = t.isString;
		}
		boolean changed = true;
		while (changed) {
			changed = false;
			for (Type t : types) {
				if (!t.containsStrings && anyFieldContainsStrings(t)) {
					t.containsStrings = true;
					changed = true;
				}
			}
		}
	}

	private boolean anyFieldContainsStrings(Type t) {
		for (int op : t.fields) {
			int kind = op & KIND_MASK;
			if (kind == KIND_STRING || (kind == KIND_STRUCT && types[op >>> TYPE_SHIFT].containsStrings)) {
				return true;
			}
		}
		return false;
	}
}
