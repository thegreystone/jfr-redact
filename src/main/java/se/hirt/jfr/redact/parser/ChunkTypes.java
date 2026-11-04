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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import se.hirt.jfr.redact.InvalidRecordingException;

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
	/**
	 * Reference to a constant, only used in {@link Type#referenceFields} and
	 * {@link Type#locationFields}, for the references each program follows. The type index of the
	 * constant pool is in the upper bits, and the key is encoded as the pool's
	 * {@link Type#keyKind}.
	 */
	public static final int KIND_REF = 9;
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
		/** The field names, parallel to {@link #fields} */
		public String[] fieldNames;
		/**
		 * True if a value of this type can contain an inlined (not constant pool referenced) string
		 */
		public boolean containsStrings;
		/**
		 * Like {@link #fields}, but with references to constants that contain strings encoded as
		 * {@link ChunkTypes#KIND_REF}. Only set after {@link ChunkTypes#prepareReferences()}.
		 */
		public int[] referenceFields;
		/** True if a value of this type can contain a reference to a constant containing strings */
		public boolean containsReferences;
		/**
		 * True if a constant of this type folds into the fields referring to it: every reader reads
		 * the constant as its one value, so that value belongs to the referring fields and is
		 * located there. The {@value ChunkTypes#STRING_TYPE} pool folds by definition, referred to
		 * through the encoding of a string, and so does a type the metadata declares simple whose
		 * one field is a scalar string, inline or a key into the string pool, or a reference to
		 * another folding type, a chain. A declared simple type over an array, a struct, a number
		 * or a cycle is an entity, whose strings are located at its own field.
		 */
		public boolean folds;
		/**
		 * True if a value of this type can contain a reference to a folding constant, directly or
		 * through inline structs: a String field declared with a constant pool, whose values are
		 * keys into the string pool, or a field of a simple type, such as the state of a sample.
		 */
		public boolean containsFoldingReferences;
		/**
		 * Like {@link #referenceFields}, the program counting references to stored strings, but
		 * also with the references to the folding types storing no string of their own, the chains
		 * of simple types, encoded as {@link ChunkTypes#KIND_REF}: the program locating the strings
		 * of a recording, which follows every reference to a constant holding strings, inline or
		 * folded, and leaves the references to the other entities, such as the method of a stack
		 * frame, as numbers to skip. Only set after {@link ChunkTypes#prepareReferences()}.
		 */
		public int[] locationFields;
		/** Declared {@code simpleType}, see {@link ChunkMetadata.ClassElement#simpleType} */
		boolean simpleType;
		/**
		 * Per field, the type index of the referenced constant pool, or -1. Null if no references.
		 */
		int[] refTargets;

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
	/** The index of the {@value #STRING_TYPE} type, or -1 if not declared */
	public final int stringTypeIndex;
	/** All strings stored in the metadata, may contain nulls */
	private String[] metadataStrings = new String[0];
	private final Type[] types;
	private final IdLookup eventTypes;
	/** The event type lookup array, if dense, to keep the per event lookup cheap */
	private final Type[] denseEventTypes;
	private final IdLookup poolTypes;
	private boolean referencesPrepared;

	ChunkTypes(boolean legacy, List<Type> types, List<Type> eventTypes, List<Type> poolTypes) {
		this.legacy = legacy;
		this.types = types.toArray(new Type[0]);
		this.eventTypes = new IdLookup(eventTypes);
		this.denseEventTypes = this.eventTypes.dense;
		this.poolTypes = eventTypes == poolTypes ? this.eventTypes : new IdLookup(poolTypes);
		int stringIndex = -1;
		for (Type t : this.types) {
			if (t.isString) {
				stringIndex = t.index;
			}
		}
		this.stringTypeIndex = stringIndex;
		computeContainsStrings();
		computeFolding();
		computeContainsFoldingReferences();
	}

	/**
	 * Compiles {@link Type#referenceFields}, {@link Type#containsReferences} and
	 * {@link Type#locationFields}, which are only computed on demand since they are only needed to
	 * count references and to locate the strings of a recording.
	 */
	public void prepareReferences() {
		if (referencesPrepared) {
			return;
		}
		compileReferenceFields();
		computeContainsReferences();
		compileLocationFields();
		referencesPrepared = true;
	}

	static ChunkTypes fromMetadata(ChunkMetadata metadata) throws IOException {
		List<ClassElement> classes = metadata.getClasses();
		List<Type> types = new ArrayList<>(classes.size());
		Map<Long, Type> byId = new HashMap<>(classes.size() * 2);
		for (ClassElement c : classes) {
			Type type = new Type(types.size(), c.id, c.name, STRING_TYPE.equals(c.name), KIND_VARINT);
			type.simpleType = c.simpleType;
			types.add(type);
			byId.put(c.id, type);
		}
		for (int i = 0; i < classes.size(); i++) {
			compileFields(classes.get(i), types.get(i), byId);
		}
		ChunkTypes chunkTypes = new ChunkTypes(false, types, types, types);
		chunkTypes.metadataStrings = metadata.getStrings();
		return chunkTypes;
	}

	/**
	 * @return all strings stored in the chunk metadata, such as type and field names, labels and
	 *         descriptions. May contain nulls.
	 */
	public String[] getMetadataStrings() {
		return metadataStrings;
	}

	void setMetadataStrings(String[] metadataStrings) {
		this.metadataStrings = metadataStrings;
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

	private static void compileFields(ClassElement element, Type type, Map<Long, Type> byId) throws IOException {
		int[] ops = new int[element.fields.size()];
		String[] names = new String[ops.length];
		int[] refTargets = null;
		for (int i = 0; i < ops.length; i++) {
			FieldElement field = element.fields.get(i);
			names[i] = field.name;
			Type fieldType = byId.get(field.typeId);
			if (fieldType == null) {
				throw new InvalidRecordingException(
						"Field " + element.name + "." + field.name + " has undeclared type id " + field.typeId);
			}
			if (field.constantPool) {
				if (refTargets == null) {
					refTargets = new int[ops.length];
					Arrays.fill(refTargets, -1);
				}
				refTargets[i] = fieldType.index;
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
		type.fields = ops;
		type.fieldNames = names;
		type.refTargets = refTargets;
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

	private void compileReferenceFields() {
		for (Type t : types) {
			int[] targets = t.refTargets;
			t.referenceFields = t.fields;
			if (targets == null) {
				continue;
			}
			for (int i = 0; i < targets.length; i++) {
				int target = targets[i];
				if (target >= 0 && types[target].containsStrings && isKeyCompatible(t.fields[i], types[target])) {
					if (t.referenceFields == t.fields) {
						t.referenceFields = t.fields.clone();
					}
					t.referenceFields[i] = KIND_REF | (t.fields[i] & ARRAY_FLAG) | (target << TYPE_SHIFT);
				}
			}
		}
	}

	/** In JFR 0.9 the reference is a plain number field, which must be as wide as the pool key */
	private boolean isKeyCompatible(int op, Type pool) {
		int kind = op & KIND_MASK;
		if (legacy) {
			return fixedSize(kind) > 0 && fixedSize(kind) == fixedSize(pool.keyKind);
		}
		return kind == KIND_VARINT && pool.keyKind == KIND_VARINT;
	}

	private void computeContainsReferences() {
		boolean changed = true;
		while (changed) {
			changed = false;
			for (Type t : types) {
				if (!t.containsReferences && anyFieldContainsReferences(t)) {
					t.containsReferences = true;
					changed = true;
				}
			}
		}
	}

	private boolean anyFieldContainsReferences(Type t) {
		for (int op : t.referenceFields) {
			int kind = op & KIND_MASK;
			if (kind == KIND_REF || (kind == KIND_STRUCT && types[op >>> TYPE_SHIFT].containsReferences)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The least fixpoint of {@link Type#folds}: the string pool folds, then every declared simple
	 * type whose one scalar field is a string or refers to a type that folds already, until nothing
	 * changes. The types of a cycle never reach a string, so they stay entities, and the chains of
	 * folding types form a hierarchy, which bounds the links the collector follows. Whether the
	 * type has a supertype is not considered: the JDK's parser reads any type declared simple as
	 * its one value.
	 */
	private void computeFolding() {
		for (Type t : types) {
			t.folds = t.isString;
		}
		boolean changed = true;
		while (changed) {
			changed = false;
			for (Type t : types) {
				if (!t.folds && foldsIntoItsField(t)) {
					t.folds = true;
					changed = true;
				}
			}
		}
	}

	private boolean foldsIntoItsField(Type t) {
		if (!t.simpleType || t.fields.length != 1 || (t.fields[0] & ARRAY_FLAG) != 0) {
			return false;
		}
		int target = t.refTargets == null ? -1 : t.refTargets[0];
		if (target >= 0) {
			return types[target].folds && isKeyCompatible(t.fields[0], types[target]);
		}
		return (t.fields[0] & KIND_MASK) == KIND_STRING;
	}

	private void computeContainsFoldingReferences() {
		boolean changed = true;
		while (changed) {
			changed = false;
			for (Type t : types) {
				if (!t.containsFoldingReferences && anyFieldRefersToFolding(t)) {
					t.containsFoldingReferences = true;
					changed = true;
				}
			}
		}
	}

	private boolean anyFieldRefersToFolding(Type t) {
		for (int i = 0; i < t.fields.length; i++) {
			int op = t.fields[i];
			if ((op & KIND_MASK) == KIND_STRUCT) {
				if (types[op >>> TYPE_SHIFT].containsFoldingReferences) {
					return true;
				}
			} else if (t.refTargets != null && t.refTargets[i] >= 0 && types[t.refTargets[i]].folds
					&& isKeyCompatible(op, types[t.refTargets[i]])) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The program locating strings follows the references of {@link Type#referenceFields}, to the
	 * constants storing strings, and also those to the folding types storing none, the chains of
	 * simple types, whose values are the values of the referring fields all the same. A reference
	 * to any other type, an entity whose strings are all folded from the constants it refers to,
	 * such as a class, whose name is a symbol, or a method, is left as a number: its constants have
	 * no referrers, see {@link se.hirt.jfr.redact.StringLocation#getReferrers()}.
	 */
	private void compileLocationFields() {
		for (Type t : types) {
			int[] targets = t.refTargets;
			t.locationFields = t.referenceFields;
			if (targets == null) {
				continue;
			}
			for (int i = 0; i < targets.length; i++) {
				int target = targets[i];
				if (target >= 0 && types[target].folds && !types[target].containsStrings
						&& isKeyCompatible(t.fields[i], types[target])) {
					if (t.locationFields == t.referenceFields) {
						t.locationFields = t.referenceFields.clone();
					}
					t.locationFields[i] = KIND_REF | (t.fields[i] & ARRAY_FLAG) | (target << TYPE_SHIFT);
				}
			}
		}
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
