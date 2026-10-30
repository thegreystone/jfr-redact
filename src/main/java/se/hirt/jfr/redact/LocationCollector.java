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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import se.hirt.jfr.redact.parser.ChunkParserListener;
import se.hirt.jfr.redact.parser.ChunkTypes;
import se.hirt.jfr.redact.parser.ChunkTypes.Type;
import se.hirt.jfr.redact.parser.RecordingStream;
import se.hirt.jfr.redact.scan.StringCountMap;
import se.hirt.jfr.redact.scan.StringScanner;

/**
 * First redaction pass: collects every distinct string with all the locations it is stored at.
 * Fails on anything that could hide strings from the redaction, such as events of undeclared types.
 */
final class LocationCollector implements ChunkParserListener {
	private static final String NO_FIELD = "value";

	private final StringCountMap strings = new StringCountMap();
	private final StringDecoder decoder = new StringDecoder();
	private ChunkTypes types;
	private boolean legacy;

	/** Field locations: owner, path and whether in a constant, interned over the whole recording */
	private final Map<String, Integer> fieldLocationIds = new HashMap<>();
	private final List<String> fieldLocationOwners = new ArrayList<>();
	private final List<String> fieldLocationPaths = new ArrayList<>();
	private final List<Boolean> fieldLocationConstant = new ArrayList<>();

	/** Referrer sets, id 0 being the empty set */
	private final Map<List<String>, Integer> referrerSetIds = new HashMap<>();
	private final List<List<String>> referrerSets = new ArrayList<>();

	/** Locations: field location and referrer set */
	private final Map<Long, Integer> locationIds = new HashMap<>();
	private final List<StringLocation> locations = new ArrayList<>();

	/** Distinct (string entry, location id) pairs */
	private final LongSet pairs = new LongSet();
	private final Set<String> metadataStrings = new HashSet<>();

	/** Per checkpoint, in recording order, the string entries stored in it */
	private int[] checkpointStarts = new int[1024];
	private int checkpointCount;
	private int[] checkpointStrings = new int[1 << 14];
	private int checkpointStringCount;

	/**
	 * Per chunk: struct nesting contexts, each an owner, path prefix and constant flag, with per field
	 * caches of the child contexts and field locations (-1 until computed)
	 */
	private final List<String> contextOwners = new ArrayList<>();
	private final List<String> contextPaths = new ArrayList<>();
	private final List<Boolean> contextConstant = new ArrayList<>();
	private final List<int[]> contextChildren = new ArrayList<>();
	/** Index 0 is for constants without fields, see {@link #fieldLocation(int, Type, int)} */
	private final List<int[]> contextFieldLocations = new ArrayList<>();
	private int[] rootContexts;

	/** Per chunk: the strings of each constant, and the fields of other constants referring to it */
	private final ConstantTable constants = new ConstantTable();
	private ConstantRecord currentConstant;
	/** Recently added references, to skip repeated ones, cleared per chunk */
	private final long[] recentKeys = new long[256];
	private final int[] recentPools = new int[256];
	private final int[] recentSources = new int[256];
	/** Referrer set ids of single referrers, by field location, -1 until computed */
	private int[] singleReferrerSets = new int[256];

	private static final class ConstantRecord {
		int[] entries = new int[2];
		int[] fieldLocations = new int[2];
		int count;
		int[] referrers = new int[1];
		int referrerCount;

		void reset() {
			count = 0;
			referrerCount = 0;
		}

		void add(int entry, int fieldLocation) {
			if (count == entries.length) {
				entries = Arrays.copyOf(entries, count * 2);
				fieldLocations = Arrays.copyOf(fieldLocations, count * 2);
			}
			entries[count] = entry;
			fieldLocations[count] = fieldLocation;
			count++;
		}

		void addReferrer(int fieldLocation) {
			for (int i = 0; i < referrerCount; i++) {
				if (referrers[i] == fieldLocation) {
					return;
				}
			}
			if (referrerCount == referrers.length) {
				referrers = Arrays.copyOf(referrers, referrerCount * 2);
			}
			referrers[referrerCount++] = fieldLocation;
		}
	}

	/** Open addressing map from (pool, key) to reusable constant records */
	private static final class ConstantTable {
		private int[] slots = new int[1 << 12];
		private int mask = slots.length - 1;
		private int size;
		private int[] pools = new int[1 << 11];
		private long[] keys = new long[1 << 11];
		private ConstantRecord[] records = new ConstantRecord[1 << 11];

		ConstantRecord get(int pool, long key) {
			int hash = hash(pool, key);
			for (int slot = hash & mask;; slot = (slot + 1) & mask) {
				int entry = slots[slot] - 1;
				if (entry < 0) {
					return insert(pool, key, slot);
				}
				if (keys[entry] == key && pools[entry] == pool) {
					return records[entry];
				}
			}
		}

		private ConstantRecord insert(int pool, long key, int slot) {
			int entry = size++;
			if (entry == keys.length) {
				pools = Arrays.copyOf(pools, entry * 2);
				keys = Arrays.copyOf(keys, entry * 2);
				records = Arrays.copyOf(records, entry * 2);
			}
			pools[entry] = pool;
			keys[entry] = key;
			if (records[entry] == null) {
				records[entry] = new ConstantRecord();
			} else {
				records[entry].reset();
			}
			slots[slot] = entry + 1;
			if (size * 2 > slots.length) {
				int[] newSlots = new int[slots.length * 2];
				int newMask = newSlots.length - 1;
				for (int e = 0; e < size; e++) {
					int s = hash(pools[e], keys[e]) & newMask;
					while (newSlots[s] != 0) {
						s = (s + 1) & newMask;
					}
					newSlots[s] = e + 1;
				}
				slots = newSlots;
				mask = newMask;
			}
			return records[entry];
		}

		int size() {
			return size;
		}

		ConstantRecord record(int entry) {
			return records[entry];
		}

		void clear() {
			Arrays.fill(slots, 0);
			size = 0;
		}

		private static int hash(int pool, long key) {
			long h = (key ^ ((long) pool << 48)) * 0x9E3779B97F4A7C15L;
			return (int) (h ^ (h >>> 29) ^ (h >>> 47));
		}
	}

	/** Open addressing set of longs */
	private static final class LongSet {
		private long[] slots = new long[1 << 14];
		private boolean containsMinusOne;
		private int size;

		/** Stored as value + 1, so that 0 means empty */
		void add(long value) {
			if (value == -1) {
				containsMinusOne = true;
				return;
			}
			long stored = value + 1;
			int mask = slots.length - 1;
			long h = stored * 0x9E3779B97F4A7C15L;
			for (int slot = (int) (h ^ (h >>> 32)) & mask;; slot = (slot + 1) & mask) {
				if (slots[slot] == stored) {
					return;
				}
				if (slots[slot] == 0) {
					slots[slot] = stored;
					if (++size * 2 > slots.length) {
						grow();
					}
					return;
				}
			}
		}

		private void grow() {
			long[] old = slots;
			slots = new long[old.length * 2];
			size = 0;
			for (long stored : old) {
				if (stored != 0) {
					add(stored - 1);
				}
			}
		}

		void forEach(java.util.function.LongConsumer consumer) {
			for (long stored : slots) {
				if (stored != 0) {
					consumer.accept(stored - 1);
				}
			}
			if (containsMinusOne) {
				consumer.accept(-1);
			}
		}
	}

	LocationCollector() {
		referrerSets.add(Collections.emptyList());
		referrerSetIds.put(Collections.emptyList(), 0);
		Arrays.fill(singleReferrerSets, -1);
	}

	StringCountMap getStrings() {
		return strings;
	}

	/**
	 * @return per string entry, the distinct locations of the string
	 */
	List<List<StringLocation>> getLocationsByEntry() {
		List<List<StringLocation>> result = new ArrayList<>(strings.size());
		for (int i = 0; i < strings.size(); i++) {
			result.add(new ArrayList<>(2));
		}
		pairs.forEach(pair -> result.get((int) (pair >>> 32)).add(locations.get((int) pair)));
		for (int i = 0; i < strings.size(); i++) {
			if (metadataStrings.contains(strings.getString(i))) {
				result.get(i).add(StringLocation.METADATA);
			}
		}
		return result;
	}

	/**
	 * @return per checkpoint in recording order, whether it stores any of the strings marked as
	 *         changed
	 */
	boolean[] getChangedCheckpoints(boolean[] changedStrings) {
		boolean[] changed = new boolean[checkpointCount];
		checkpointStarts[checkpointCount] = checkpointStringCount;
		for (int c = 0; c < checkpointCount; c++) {
			for (int i = checkpointStarts[c]; i < checkpointStarts[c + 1]; i++) {
				if (changedStrings[checkpointStrings[i]]) {
					changed[c] = true;
					break;
				}
			}
		}
		return changed;
	}

	@Override
	public void onTypes(ChunkTypes types) {
		this.types = types;
		this.legacy = types.legacy;
		types.prepareReferences();
		for (String s : types.getMetadataStrings()) {
			if (s != null) {
				metadataStrings.add(s);
			}
		}
		contextOwners.clear();
		contextPaths.clear();
		contextConstant.clear();
		contextChildren.clear();
		contextFieldLocations.clear();
		rootContexts = new int[types.size() * 2];
		Arrays.fill(rootContexts, -1);
	}

	@Override
	public void onEvent(long typeId, RecordingStream stream, int payloadSize) throws IOException {
		Type type = types.getEventType(typeId);
		if (type == null) {
			throw new IOException("Event of undeclared type " + typeId + ", cannot guarantee a complete redaction");
		}
		if (!type.containsStrings) {
			return;
		}
		int end = stream.position() + payloadSize;
		walkEvent(stream, type, rootContext(type, false));
		checkEnd(stream, end, type);
	}

	@Override
	public void onCheckpoint(RecordingStream stream, int payloadSize) throws IOException {
		int end = stream.position() + payloadSize;
		if (checkpointCount + 1 >= checkpointStarts.length) {
			checkpointStarts = Arrays.copyOf(checkpointStarts, checkpointStarts.length * 2);
		}
		checkpointStarts[checkpointCount++] = checkpointStringCount;
		if (legacy) {
			stream.skip(16); // timestamp, offset of previous checkpoint
			while (stream.position() < end) {
				Type type = getPoolType(stream.readRawInt());
				readConstants(stream, type, stream.readRawInt());
			}
		} else {
			stream.skipVarint(); // start time
			stream.skipVarint(); // duration
			stream.skipVarint(); // delta to previous checkpoint
			stream.skip(1); // checkpoint type
			int poolCount = (int) stream.readVarint();
			for (int i = 0; i < poolCount; i++) {
				Type type = getPoolType(stream.readVarint());
				readConstants(stream, type, (int) stream.readVarint());
			}
		}
		if (stream.position() != end) {
			throw new IOException("Checkpoint did not decode to its declared size");
		}
	}

	@Override
	public void onChunkEnd() {
		for (int c = 0; c < constants.size(); c++) {
			ConstantRecord constant = constants.record(c);
			if (constant.count == 0) {
				continue;
			}
			int referrerSet = referrerSetId(constant);
			for (int i = 0; i < constant.count; i++) {
				addPair(constant.entries[i], locationId(constant.fieldLocations[i], referrerSet));
			}
		}
		constants.clear();
		Arrays.fill(recentKeys, 0);
	}

	private void readConstants(RecordingStream stream, Type type, int count) throws IOException {
		int context = rootContext(type, true);
		for (int i = 0; i < count; i++) {
			long key = readKey(stream, type.keyKind);
			if (type.containsStrings) {
				currentConstant = constants.get(type.index, key);
			}
			if (type.isString) {
				readConstantString(stream, ChunkTypes.KIND_STRING, context, -1, type);
			} else {
				walkConstant(stream, type, context);
			}
			currentConstant = null;
		}
	}

	private void walkEvent(RecordingStream stream, Type type, int context) throws IOException {
		int[] fields = type.fields;
		for (int i = 0; i < fields.length; i++) {
			int op = fields[i];
			if ((op & ChunkTypes.ARRAY_FLAG) == 0) {
				readEventValue(stream, op, type, i, context);
			} else {
				int length = legacy ? stream.readRawInt() : (int) stream.readVarint();
				int fixedSize = ChunkTypes.fixedSize(op & ChunkTypes.KIND_MASK);
				if (fixedSize > 0) {
					stream.skip(length * fixedSize);
				} else {
					for (int j = 0; j < length; j++) {
						readEventValue(stream, op, type, i, context);
					}
				}
			}
		}
	}

	private void readEventValue(RecordingStream stream, int op, Type type, int field, int context)
			throws IOException {
		int kind = op & ChunkTypes.KIND_MASK;
		switch (kind) {
		case ChunkTypes.KIND_FIXED1 -> stream.skip(1);
		case ChunkTypes.KIND_FIXED2 -> stream.skip(2);
		case ChunkTypes.KIND_FIXED4 -> stream.skip(4);
		case ChunkTypes.KIND_FIXED8 -> stream.skip(8);
		case ChunkTypes.KIND_VARINT -> stream.skipVarint();
		case ChunkTypes.KIND_STRING, ChunkTypes.KIND_UTF8, ChunkTypes.KIND_UTF16 -> {
			if (decoder.read(stream, kind) == StringDecoder.STRING) {
				int entry = strings.add(decoder.array, decoder.offset, decoder.length, StringScanner.INLINE);
				addPair(entry, locationId(fieldLocation(context, type, field), 0));
			}
		}
		case ChunkTypes.KIND_STRUCT -> {
			Type struct = types.getByIndex(op >>> ChunkTypes.TYPE_SHIFT);
			walkEvent(stream, struct, childContext(context, type, field));
		}
		default -> throw new IOException("Unexpected field kind " + kind);
		}
	}

	private void walkConstant(RecordingStream stream, Type type, int context) throws IOException {
		int[] fields = type.referenceFields;
		for (int i = 0; i < fields.length; i++) {
			int op = fields[i];
			if ((op & ChunkTypes.ARRAY_FLAG) == 0) {
				readConstantValue(stream, op, type, i, context);
			} else {
				int length = legacy ? stream.readRawInt() : (int) stream.readVarint();
				int fixedSize = ChunkTypes.fixedSize(op & ChunkTypes.KIND_MASK);
				if (fixedSize > 0) {
					stream.skip(length * fixedSize);
				} else {
					for (int j = 0; j < length; j++) {
						readConstantValue(stream, op, type, i, context);
					}
				}
			}
		}
	}

	private void readConstantValue(RecordingStream stream, int op, Type type, int field, int context)
			throws IOException {
		int kind = op & ChunkTypes.KIND_MASK;
		switch (kind) {
		case ChunkTypes.KIND_FIXED1 -> stream.skip(1);
		case ChunkTypes.KIND_FIXED2 -> stream.skip(2);
		case ChunkTypes.KIND_FIXED4 -> stream.skip(4);
		case ChunkTypes.KIND_FIXED8 -> stream.skip(8);
		case ChunkTypes.KIND_VARINT -> stream.skipVarint();
		case ChunkTypes.KIND_STRING, ChunkTypes.KIND_UTF8, ChunkTypes.KIND_UTF16 -> readConstantString(stream, kind,
				context, field, type);
		case ChunkTypes.KIND_REF -> {
			Type pool = types.getByIndex(op >>> ChunkTypes.TYPE_SHIFT);
			addReference(pool.index, readKey(stream, pool.keyKind), fieldLocation(context, type, field));
		}
		case ChunkTypes.KIND_STRUCT -> {
			Type struct = types.getByIndex(op >>> ChunkTypes.TYPE_SHIFT);
			walkConstant(stream, struct, childContext(context, type, field));
		}
		default -> throw new IOException("Unexpected field kind " + kind);
		}
	}

	private void readConstantString(RecordingStream stream, int kind, int context, int field, Type type)
			throws IOException {
		int result = decoder.read(stream, kind);
		if (result == StringDecoder.STRING) {
			int entry = strings.add(decoder.array, decoder.offset, decoder.length, StringScanner.CONSTANT_POOL);
			currentConstant.add(entry, fieldLocation(context, type, field));
			if (checkpointStringCount == checkpointStrings.length) {
				checkpointStrings = Arrays.copyOf(checkpointStrings, checkpointStringCount * 2);
			}
			checkpointStrings[checkpointStringCount++] = entry;
		} else if (result == StringDecoder.REFERENCE && types.stringTypeIndex >= 0) {
			addReference(types.stringTypeIndex, decoder.reference, fieldLocation(context, type, field));
		}
	}

	private void addReference(int pool, long key, int sourceFieldLocation) {
		if (key == 0) {
			return; // null reference
		}
		// Most references repeat, such as every stack frame referring to one of a few frame types
		int slot = (int) ((key * 0x9E3779B97F4A7C15L + pool * 31 + sourceFieldLocation) >>> 56) & 0xFF;
		if (recentKeys[slot] == key && recentPools[slot] == pool && recentSources[slot] == sourceFieldLocation) {
			return;
		}
		recentKeys[slot] = key;
		recentPools[slot] = pool;
		recentSources[slot] = sourceFieldLocation;
		constants.get(pool, key).addReferrer(sourceFieldLocation);
	}

	private void addPair(int entry, int location) {
		pairs.add(((long) entry << 32) | location);
	}

	private int rootContext(Type type, boolean constant) {
		int slot = type.index * 2 + (constant ? 1 : 0);
		if (rootContexts[slot] < 0) {
			rootContexts[slot] = newContext(type.name, "", constant, type);
		}
		return rootContexts[slot];
	}

	/** The context of the struct in the field, the context's type being {@code type} */
	private int childContext(int context, Type type, int field) {
		int[] children = contextChildren.get(context);
		int child = children[field];
		if (child < 0) {
			Type struct = types.getByIndex(type.fields[field] >>> ChunkTypes.TYPE_SHIFT);
			child = newContext(contextOwners.get(context), join(contextPaths.get(context), type.fieldNames[field]),
					contextConstant.get(context), struct);
			children[field] = child;
		}
		return child;
	}

	private int newContext(String owner, String path, boolean constant, Type type) {
		contextOwners.add(owner);
		contextPaths.add(path);
		contextConstant.add(constant);
		int[] children = new int[type.fields.length];
		Arrays.fill(children, -1);
		contextChildren.add(children);
		int[] fieldLocations = new int[type.fields.length + 1];
		Arrays.fill(fieldLocations, -1);
		contextFieldLocations.add(fieldLocations);
		return contextOwners.size() - 1;
	}

	/** Field -1 denotes the value of a constant without fields, such as a string constant */
	private int fieldLocation(int context, Type type, int field) {
		int[] fieldLocations = contextFieldLocations.get(context);
		int id = fieldLocations[field + 1];
		if (id < 0) {
			String name = field < 0 ? NO_FIELD : type.fieldNames[field];
			id = fieldLocationId(contextOwners.get(context), join(contextPaths.get(context), name),
					contextConstant.get(context));
			fieldLocations[field + 1] = id;
		}
		return id;
	}

	private int fieldLocationId(String owner, String path, boolean constant) {
		String key = owner + '\0' + path + '\0' + constant;
		Integer id = fieldLocationIds.get(key);
		if (id == null) {
			id = fieldLocationOwners.size();
			fieldLocationOwners.add(owner);
			fieldLocationPaths.add(path);
			fieldLocationConstant.add(constant);
			fieldLocationIds.put(key, id);
		}
		return id;
	}

	private int referrerSetId(ConstantRecord constant) {
		if (constant.referrerCount == 0) {
			return 0;
		}
		if (constant.referrerCount == 1) {
			int fieldLocation = constant.referrers[0];
			if (fieldLocation >= singleReferrerSets.length) {
				int oldLength = singleReferrerSets.length;
				singleReferrerSets = Arrays.copyOf(singleReferrerSets, Math.max(fieldLocation + 1, oldLength * 2));
				Arrays.fill(singleReferrerSets, oldLength, singleReferrerSets.length, -1);
			}
			if (singleReferrerSets[fieldLocation] < 0) {
				singleReferrerSets[fieldLocation] = referrerSetId(constant.referrers, 1);
			}
			return singleReferrerSets[fieldLocation];
		}
		return referrerSetId(constant.referrers, constant.referrerCount);
	}

	private int referrerSetId(int[] referrers, int count) {
		List<String> names = new ArrayList<>(count);
		for (int i = 0; i < count; i++) {
			int fieldLocation = referrers[i];
			names.add(fieldLocationOwners.get(fieldLocation) + "." + fieldLocationPaths.get(fieldLocation));
		}
		Collections.sort(names);
		Integer id = referrerSetIds.get(names);
		if (id == null) {
			id = referrerSets.size();
			List<String> set = Collections.unmodifiableList(names);
			referrerSets.add(set);
			referrerSetIds.put(set, id);
		}
		return id;
	}

	private int locationId(int fieldLocation, int referrerSet) {
		long key = ((long) fieldLocation << 32) | referrerSet;
		Integer id = locationIds.get(key);
		if (id == null) {
			id = locations.size();
			locations.add(new StringLocation(fieldLocationOwners.get(fieldLocation),
					fieldLocationPaths.get(fieldLocation), fieldLocationConstant.get(fieldLocation),
					referrerSets.get(referrerSet)));
			locationIds.put(key, id);
		}
		return id;
	}

	private Type getPoolType(long typeId) throws IOException {
		Type type = types.getPoolType(typeId);
		if (type == null) {
			throw new IOException("Constant pool for undeclared type id " + typeId);
		}
		return type;
	}

	private static void checkEnd(RecordingStream stream, int end, Type type) throws IOException {
		if (stream.position() != end) {
			throw new IOException("Event " + type.name + " did not decode to its declared size");
		}
	}

	private static String join(String prefix, String name) {
		return prefix.isEmpty() ? name : prefix + "." + name;
	}

	static long readKey(RecordingStream stream, int keyKind) throws IOException {
		return switch (keyKind) {
		case ChunkTypes.KIND_VARINT -> stream.readVarint();
		case ChunkTypes.KIND_FIXED1 -> stream.read();
		case ChunkTypes.KIND_FIXED2 -> stream.readRawShort();
		case ChunkTypes.KIND_FIXED4 -> stream.readRawInt();
		case ChunkTypes.KIND_FIXED8 -> stream.readRawLong();
		default -> throw new IOException("Unsupported constant pool key kind " + keyKind);
		};
	}
}
