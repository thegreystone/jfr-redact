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
import java.util.ArrayList;
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
	/** boolean and byte */
	public static final int KIND_FIXED1 = 0;
	/** short, char, int, long and constant pool references */
	public static final int KIND_VARINT = 1;
	/** float, and int in JFR 0.9 */
	public static final int KIND_FIXED4 = 2;
	/** double, and long in JFR 0.9 */
	public static final int KIND_FIXED8 = 3;
	/** String with a leading encoding byte */
	public static final int KIND_STRING = 4;
	/** Inlined struct, the type index is in the upper bits */
	public static final int KIND_STRUCT = 5;
	/** short in JFR 0.9 */
	public static final int KIND_FIXED2 = 6;
	/** JFR 0.9 string: unsigned short byte count followed by UTF-8 */
	public static final int KIND_UTF8 = 7;
	/** JFR 0.9 string: int char count followed by UTF-16 */
	public static final int KIND_UTF16 = 8;
	public static final int KIND_MASK = 0xF;
	public static final int ARRAY_FLAG = 0x10;
	public static final int TYPE_SHIFT = 5;

	public static final String STRING_TYPE = "java.lang.String";
	private static final int MAX_DENSE_ID = 1 << 16;

	/** A compiled type */
	public static final class Type {
		public final int index;
		public final long id;
		public final String name;
		public final boolean isString;
		/** The kind of the keys in a constant pool of this type */
		public final int keyKind;
		/** The field programs, in serialization order */
		public int[] fields;
		/** True if a value of this type can contain an inlined (not constant pool referenced) string */
		public boolean containsStrings;

		Type(int index, long id, String name, boolean isString, int keyKind) {
			this.index = index;
			this.id = id;
			this.name = name;
			this.isString = isString;
			this.keyKind = keyKind;
		}
	}

	/** JFR 0.9, with fixed width integers and array lengths */
	public final boolean legacy;
	private final Type[] types;
	private final IdLookup eventTypes;
	/** The event type lookup array, if dense, to keep the per event lookup cheap */
	private final Type[] denseEventTypes;
	private final IdLookup poolTypes;

	ChunkTypes(boolean legacy, List<Type> types, List<Type> eventTypes, List<Type> poolTypes) {
		this.legacy = legacy;
		this.types = types.toArray(new Type[0]);
		this.eventTypes = new IdLookup(eventTypes);
		this.denseEventTypes = this.eventTypes.dense;
		this.poolTypes = eventTypes == poolTypes ? this.eventTypes : new IdLookup(poolTypes);
		computeContainsStrings();
	}

	static ChunkTypes fromMetadata(ChunkMetadata metadata) throws IOException {
		List<ClassElement> classes = metadata.getClasses();
		List<Type> types = new ArrayList<>(classes.size());
		Map<Long, Type> byId = new HashMap<>(classes.size() * 2);
		for (ClassElement c : classes) {
			Type type = new Type(types.size(), c.id, c.name, STRING_TYPE.equals(c.name), KIND_VARINT);
			types.add(type);
			byId.put(c.id, type);
		}
		for (int i = 0; i < classes.size(); i++) {
			types.get(i).fields = compileFields(classes.get(i), byId);
		}
		return new ChunkTypes(false, types, types, types);
	}

	/**
	 * @return the event type with the given id, or {@code null} if not declared in this chunk
	 */
	public Type getEventType(long id) {
		Type[] dense = denseEventTypes;
		if (dense != null) {
			return id >= 0 && id < dense.length ? dense[(int) id] : null;
		}
		return eventTypes.get(id);
	}

	/**
	 * @return the type of the constant pool with the given id, or {@code null} if not declared
	 */
	public Type getPoolType(long id) {
		return poolTypes.get(id);
	}

	public Type getByIndex(int index) {
		return types[index];
	}

	public int size() {
		return types.length;
	}

	public static boolean isStringKind(int kind) {
		return kind == KIND_STRING || kind == KIND_UTF8 || kind == KIND_UTF16;
	}

	/**
	 * @return the encoded size of values of the kind, or 0 if not of fixed size
	 */
	public static int fixedSize(int kind) {
		return switch (kind) {
		case KIND_FIXED1 -> 1;
		case KIND_FIXED2 -> 2;
		case KIND_FIXED4 -> 4;
		case KIND_FIXED8 -> 8;
		default -> 0;
		};
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
		case "boolean", "byte" -> KIND_FIXED1;
		case "short", "char", "int", "long" -> KIND_VARINT;
		case "float" -> KIND_FIXED4;
		case "double" -> KIND_FIXED8;
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
			if (isStringKind(kind) || (kind == KIND_STRUCT && types[op >>> TYPE_SHIFT].containsStrings)) {
				return true;
			}
		}
		return false;
	}

	private static final class IdLookup {
		private final Type[] dense;
		private final Map<Long, Type> sparse;

		IdLookup(List<Type> types) {
			long maxId = -1;
			long minId = 0;
			for (Type t : types) {
				maxId = Math.max(maxId, t.id);
				minId = Math.min(minId, t.id);
			}
			if (minId >= 0 && maxId < MAX_DENSE_ID) {
				dense = new Type[(int) maxId + 1];
				for (Type t : types) {
					dense[(int) t.id] = t;
				}
				sparse = null;
			} else {
				dense = null;
				sparse = new HashMap<>(types.size() * 2);
				for (Type t : types) {
					sparse.put(t.id, t);
				}
			}
		}

		Type get(long id) {
			if (dense != null) {
				return id >= 0 && id < dense.length ? dense[(int) id] : null;
			}
			return sparse.get(id);
		}
	}
}
