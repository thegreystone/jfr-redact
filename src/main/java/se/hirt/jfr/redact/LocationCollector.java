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
 * Rejects undeclared event types and malformed values encountered while collecting strings. Event
 * payloads without inline strings or references to folding constants are skipped; their constants
 * are collected separately.
 * <p>
 * A string is located at the field whose value it is. For a string inlined in an event or in the
 * constant of an entity, a constant pool type read as an object, that is the field storing it, and
 * for a constant the fields of other constants referring to the constant are its referrers. A
 * constant of a folding type, see {@link ChunkTypes.Type#folds}, is read by every reader as its one
 * value: the {@code java.lang.String} pool's entries, referred to through the encoding of a string
 * or, declared with a constant pool, with a key, and the constants of the types the metadata
 * declares simple, such as {@code jdk.types.Symbol} and {@code jdk.types.FrameType}. Its value is a
 * value of the fields referring to it, from events and from constants, and is located at those
 * fields, as an inline value of theirs would be, with the referrers of the constant holding the
 * field, through chains of folding constants. The references are kept as links on the folding
 * constant and resolved once the chunk is complete, see {@link #onChunkEnd()}; only a folding
 * constant no field of its chunk refers to is located at its own field, and a constant referred to
 * in one chunk and in none of another is located both ways.
 * <p>
 * The referrers of a constant are recorded only when its type stores strings itself, inline in its
 * constants, see {@link ChunkTypes.Type#containsStrings}: a reference to such a constant is a
 * referrer, and the constants of every other type, of {@code java.lang.Class},
 * {@code jdk.types.Method}, {@code jdk.types.Package}, {@code jdk.types.Module},
 * {@code jdk.types.ClassLoader} and {@code jdk.types.StackTrace} among HotSpot's, whose strings are
 * all folded from the symbols and pool entries they refer to, have none, however many constants
 * refer to them. Tracking those would mean decoding and deduplicating the method of every frame of
 * every stack trace, the bulk of a profiling recording's constants, for referrers no rule consumes,
 * so the key of such a reference is skipped, see {@link ChunkTypes.Type#locationFields}. The
 * constants of a chunk are tracked, in {@link ConstantTable records} holding their strings,
 * referrers and links, when they store strings or fold; a link from a field of a constant that is
 * not tracked carries no source, like a link from the field of an event, and resolves to the field
 * without referrers. The frames of the stack traces cost a cache lookup per frame type, see
 * {@link #isRecent}.
 */
final class LocationCollector implements ChunkParserListener {
	private static final String NO_FIELD = "value";
	/**
	 * The source of a link from the field of an event, or of a constant that is not tracked, which
	 * has no referrers and no record
	 */
	private static final int NO_SOURCE = -1;
	/**
	 * The recent references, a direct-mapped cache by pool, key and field, see {@link #isRecent}
	 */
	private static final int RECENT_BITS = 10;
	private static final long GOLDEN = 0x9E3779B97F4A7C15L;

	private final StringCountMap strings = new StringCountMap();
	private final StringDecoder decoder = new StringDecoder();
	private ChunkTypes types;
	private boolean legacy;
	private long chunkCount;

	/** Field locations: owner, path and whether in a constant, interned over the whole recording */
	private final Map<String, Integer> fieldLocationIds = new HashMap<>();
	private final List<String> fieldLocationOwners = new ArrayList<>();
	private final List<String> fieldLocationPaths = new ArrayList<>();
	private final List<Boolean> fieldLocationConstant = new ArrayList<>();

	/** Referrer sets, id 0 being the empty set */
	private final Map<List<String>, Integer> referrerSetIds = new HashMap<>();
	private final List<List<String>> referrerSets = new ArrayList<>();
	/** Referrer set ids of single referrers, by field location, -1 until computed */
	private int[] singleReferrerSets = new int[256];

	/**
	 * Locations: field location and referrer set. Looked up once per inline string of a constant
	 * and once per run of links resolving to the same field and referrer set, so without boxing.
	 */
	private final LongIntMap locationIds = new LongIntMap();
	private final List<StringLocation> locations = new ArrayList<>();
	/** The location of the field and referrer set last resolved, see {@link #pairStrings} */
	private int resolvedField = -1;
	private int resolvedReferrerSet = -1;
	private int resolvedLocation = -1;
	/**
	 * The chain of folding constants being followed while resolving the links of a constant, see
	 * {@link #locateThroughLinks}: the records, and per record the next link to follow
	 */
	private int[] chainRecords = new int[16];
	private int[] chainPositions = new int[16];
	/**
	 * Numbers the resolutions of the chunk, marking the records followed in the current one, so
	 * that a constant reached twice is followed once and a cycle, should a recording manage one,
	 * ends
	 */
	private int resolution;

	/** Distinct (string entry, location id) pairs */
	private final LongSet pairs = new LongSet(1 << 14);
	private final Set<String> metadataStrings = new HashSet<>();
	private int longestMetadataString;

	/** Per checkpoint, in recording order, the string entries stored in it */
	private int[] checkpointStarts = new int[1024];
	private int checkpointCount;
	private int[] checkpointStrings = new int[1 << 14];
	private int checkpointStringCount;

	/**
	 * Per chunk: struct nesting contexts, each an owner, path prefix and constant flag, with per
	 * field caches of the child contexts and field locations (-1 until computed).
	 */
	private final List<String> contextOwners = new ArrayList<>();
	private final List<String> contextPaths = new ArrayList<>();
	private final List<Boolean> contextConstant = new ArrayList<>();
	private final List<int[]> contextChildren = new ArrayList<>();
	/** Index 0 is for constants without fields, see {@link #fieldLocation(int, Type, int)} */
	private final List<int[]> contextFieldLocations = new ArrayList<>();
	/**
	 * Per event context and field, the location of a value of the field read from a constant, of
	 * the string pool or of another folding type, -1 until computed, see
	 * {@link #constantValueLocation(int, Type, int)}; null until the context's first reference to a
	 * folding constant, which most contexts never make, and always for the contexts of constants,
	 * whose field locations are constant already
	 */
	private final List<int[]> contextConstantValueLocations = new ArrayList<>();
	private int[] rootContexts;

	/**
	 * Per chunk: the strings of each tracked constant, the fields of other constants referring to
	 * it and, for a folding constant, the links from the fields whose value it is
	 */
	private final ConstantTable constants = new ConstantTable();
	/** The record of the constant being read, or null for one that is not tracked */
	private ConstantRecord currentConstant;
	/**
	 * The references seen recently, by pool, key and field, cleared per chunk: a repeated reference
	 * from an event, or from a constant that is not tracked, to a folding constant adds no link,
	 * and a repeated reference to an entity no referrer, so most references of a profiling
	 * recording, every frame of its stack traces referring to one of a few frame types, cost this
	 * lookup. Each slot holds the key and then the pool and field packed into one long, plus one so
	 * that 0 is empty, side by side in one cache line.
	 */
	private final long[] recent = new long[2 << RECENT_BITS];

	/**
	 * A tracked constant of the chunk: its strings with the fields holding them, the fields of
	 * other constants referring to it and, for a folding constant, the links from the fields whose
	 * value it is, see {@link LocationCollector#onChunkEnd()}
	 */
	private static final class ConstantRecord {
		/** The index of the record in the table, by which the links name their sources */
		int index;
		int[] entries = new int[2];
		int[] fieldLocations = new int[2];
		int count;
		int[] referrers = new int[1];
		int referrerCount;
		/** The id of the set of referrers, -1 until computed at chunk end */
		int referrerSet = -1;
		/**
		 * The links to a folding constant: the fields whose value it is, from events and from
		 * constants, and the records of the constants holding those fields, {@link #NO_SOURCE} for
		 * an event or a constant that is not tracked. Null until the first link, as most constants
		 * are entities, which no link reaches.
		 */
		int[] linkFields;
		int[] linkSources;
		int linkCount;
		/** The location the strings were last paired with while resolving the links */
		int lastLocation = -1;
		/**
		 * The resolution the links of this record were last followed in, see {@link #resolution}
		 */
		int visited;

		void reset() {
			count = 0;
			referrerCount = 0;
			referrerSet = -1;
			linkCount = 0;
			lastLocation = -1;
			visited = 0;
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

		/**
		 * A link from a field of a constant whose value this constant is. Only a repeat of the last
		 * link is skipped, which catches the elements of an array referring to the constant from
		 * the same field of the same source, such as the frames of a stack trace sharing a frame
		 * type, even when frames of another type come between, since those link to another
		 * constant: a repeat among the others resolves to the same location, which the pairs store
		 * once.
		 */
		void addLink(int fieldLocation, int source) {
			if (linkCount > 0 && linkSources[linkCount - 1] == source && linkFields[linkCount - 1] == fieldLocation) {
				return;
			}
			appendLink(fieldLocation, source);
		}

		/**
		 * A link from a field without a source, of an event or of a constant that is not tracked,
		 * which {@link LocationCollector#isRecent} mostly skips as a repeat: the few that reach the
		 * record are deduplicated exactly, so that a recording cannot grow the links by repeating
		 * references from a few fields, by a scan, since such links are few per constant
		 */
		void addFieldLink(int fieldLocation) {
			for (int i = 0; i < linkCount; i++) {
				if (linkFields[i] == fieldLocation && linkSources[i] == NO_SOURCE) {
					return;
				}
			}
			appendLink(fieldLocation, NO_SOURCE);
		}

		private void appendLink(int fieldLocation, int source) {
			if (linkFields == null) {
				linkFields = new int[2];
				linkSources = new int[2];
			} else if (linkCount == linkFields.length) {
				linkFields = Arrays.copyOf(linkFields, linkCount * 2);
				linkSources = Arrays.copyOf(linkSources, linkCount * 2);
			}
			linkFields[linkCount] = fieldLocation;
			linkSources[linkCount] = source;
			linkCount++;
		}
	}

	/**
	 * Open addressing map from (pool, key) to reusable constant records, numbered from 0 in the
	 * order they are first seen in. The slots hold the keys and, packed into one long, the pool and
	 * the number plus one, 0 being empty, so that a lookup reads two arrays, both the ones every
	 * reference to a constant touches.
	 */
	private static final class ConstantTable {
		private long[] slotKeys = new long[1 << 12];
		private long[] slotEntries = new long[1 << 12];
		private int mask = slotKeys.length - 1;
		private int size;
		private ConstantRecord[] records = new ConstantRecord[1 << 11];

		ConstantRecord get(int pool, long key) {
			int hash = hash(pool, key);
			for (int slot = hash & mask;; slot = (slot + 1) & mask) {
				long stored = slotEntries[slot];
				if (stored == 0) {
					return insert(pool, key, slot);
				}
				if (slotKeys[slot] == key && (int) (stored >>> 32) == pool) {
					return records[(int) stored - 1];
				}
			}
		}

		private ConstantRecord insert(int pool, long key, int slot) {
			int entry = size++;
			if (entry == records.length) {
				records = Arrays.copyOf(records, entry * 2);
			}
			ConstantRecord record = records[entry];
			if (record == null) {
				record = new ConstantRecord();
				records[entry] = record;
			} else {
				record.reset();
			}
			record.index = entry;
			slotKeys[slot] = key;
			slotEntries[slot] = packed(pool, entry);
			if (size * 2 > slotKeys.length) {
				long[] oldKeys = slotKeys;
				long[] oldEntries = slotEntries;
				slotKeys = new long[oldKeys.length * 2];
				slotEntries = new long[oldEntries.length * 2];
				mask = slotKeys.length - 1;
				for (int s = 0; s < oldEntries.length; s++) {
					long stored = oldEntries[s];
					if (stored != 0) {
						int moved = hash((int) (stored >>> 32), oldKeys[s]) & mask;
						while (slotEntries[moved] != 0) {
							moved = (moved + 1) & mask;
						}
						slotKeys[moved] = oldKeys[s];
						slotEntries[moved] = stored;
					}
				}
			}
			return record;
		}

		int size() {
			return size;
		}

		ConstantRecord record(int entry) {
			return records[entry];
		}

		void clear() {
			Arrays.fill(slotEntries, 0);
			size = 0;
		}

		private static long packed(int pool, int entry) {
			return ((long) pool << 32) | (entry + 1);
		}

		private static int hash(int pool, long key) {
			long h = (key ^ ((long) pool << 48)) * GOLDEN;
			return (int) (h ^ (h >>> 29) ^ (h >>> 47));
		}
	}

	/** Open addressing set of longs */
	private static final class LongSet {
		private long[] slots;
		private boolean containsMinusOne;
		private int size;

		LongSet(int capacity) {
			slots = new long[capacity];
		}

		/** Stored as value + 1, so that 0 means empty */
		void add(long value) {
			if (value == -1) {
				containsMinusOne = true;
				return;
			}
			long stored = value + 1;
			int mask = slots.length - 1;
			long h = stored * GOLDEN;
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

	/** Open addressing map from non-negative longs to non-negative ints */
	private static final class LongIntMap {
		private long[] keys = new long[1 << 10];
		private int[] values = new int[1 << 10];
		private int size;

		/**
		 * @return the value of the key, or -1 if absent. Keys are stored as key + 1, so that 0
		 *         means empty.
		 */
		int get(long key) {
			long stored = key + 1;
			int mask = keys.length - 1;
			long h = stored * GOLDEN;
			for (int slot = (int) (h ^ (h >>> 32)) & mask;; slot = (slot + 1) & mask) {
				if (keys[slot] == stored) {
					return values[slot];
				}
				if (keys[slot] == 0) {
					return -1;
				}
			}
		}

		/** Adds the key, which must be absent */
		void put(long key, int value) {
			if (++size * 2 > keys.length) {
				long[] oldKeys = keys;
				int[] oldValues = values;
				keys = new long[oldKeys.length * 2];
				values = new int[oldValues.length * 2];
				for (int i = 0; i < oldKeys.length; i++) {
					if (oldKeys[i] != 0) {
						insert(oldKeys[i], oldValues[i]);
					}
				}
			}
			insert(key + 1, value);
		}

		private void insert(long stored, int value) {
			int mask = keys.length - 1;
			long h = stored * GOLDEN;
			int slot = (int) (h ^ (h >>> 32)) & mask;
			while (keys[slot] != 0) {
				slot = (slot + 1) & mask;
			}
			keys[slot] = stored;
			values[slot] = value;
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

	long getChunkCount() {
		return chunkCount;
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
			if (occursInMetadata(strings.getString(i))) {
				result.get(i).add(StringLocation.METADATA);
			}
		}
		return result;
	}

	private boolean occursInMetadata(String value) {
		if (metadataStrings.contains(value)) {
			return true;
		}
		// Empty values only match actual empty metadata entries, not every string boundary.
		if (value.isEmpty() || value.length() >= longestMetadataString) {
			return false;
		}
		for (String metadata : metadataStrings) {
			if (metadata.contains(value)) {
				return true;
			}
		}
		return false;
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
		chunkCount++;
		this.types = types;
		this.legacy = types.legacy;
		types.prepareReferences();
		for (String s : types.getMetadataStrings()) {
			if (s != null) {
				metadataStrings.add(s);
				longestMetadataString = Math.max(longestMetadataString, s.length());
			}
		}
		contextOwners.clear();
		contextPaths.clear();
		contextConstant.clear();
		contextChildren.clear();
		contextFieldLocations.clear();
		contextConstantValueLocations.clear();
		rootContexts = new int[types.size() * 2];
		Arrays.fill(rootContexts, -1);
	}

	@Override
	public void onEvent(long typeId, RecordingStream stream, int payloadSize) throws IOException {
		Type type = types.getEventType(typeId);
		if (type == null) {
			throw new InvalidRecordingException(
					"Event of undeclared type " + typeId + ", cannot guarantee a complete redaction");
		}
		if (!type.containsStrings && !type.containsFoldingReferences) {
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
			throw new InvalidRecordingException("Checkpoint did not decode to its declared size");
		}
	}

	/**
	 * Pairs the strings of the chunk's constants with their locations, which are only complete now:
	 * the referrers of a constant, and the links to a folding constant from the fields whose value
	 * it is, which may arrive before or after the constant, since the string pool usually comes
	 * last, in the checkpoint ending the chunk, but first in a chunk with flushes. The strings of
	 * an entity are located at their fields with the entity's referrers; those of a folding
	 * constant are located through its links, see {@link #locateThroughLinks}, or at its own field
	 * when nothing links to it. A key referred to without a constant in the chunk, a dangling one,
	 * has no strings and locates nothing.
	 */
	@Override
	public void onChunkEnd() {
		for (int c = 0; c < constants.size(); c++) {
			ConstantRecord constant = constants.record(c);
			if (constant.count == 0) {
				continue; // No strings: an entity storing none, a link of a chain, or a dangling key
			}
			if (constant.linkCount > 0) {
				locateThroughLinks(constant); // Only folding constants are linked to
			} else {
				int referrerSet = referrerSetId(constant);
				for (int i = 0; i < constant.count; i++) {
					addPair(constant.entries[i], locationId(constant.fieldLocations[i], referrerSet));
				}
			}
		}
		constants.clear();
		resolution = 0;
		Arrays.fill(recent, 0);
	}

	/**
	 * Pairs the strings of a folding constant with the locations its links lead to: a link without
	 * a source locates the strings at the field, as a constant, without referrers; a link from an
	 * entity at the entity's field, with the entity's referrers; a link from another folding
	 * constant continues through that constant's links, and ends at its own field, the linking one,
	 * when it has none. The links follow the hierarchy of the folding types, see
	 * {@link ChunkTypes.Type#folds}, two or three deep, and the aliases of the string pool, entries
	 * referring to other entries, which chain to any depth, so the chain is kept on a stack of its
	 * own rather than the call stack. A folding constant reached twice in one resolution, through
	 * two of its referrers, is followed once, which also ends a cycle, should a recording manage to
	 * link one: the aliases of the pool cannot, as an entry holding a string refers to nothing.
	 */
	private void locateThroughLinks(ConstantRecord constant) {
		int stamp = ++resolution;
		constant.visited = stamp;
		ConstantRecord linked = constant; // The record whose links are being followed
		int l = 0; // The next of its links
		int depth = -1; // The records followed on the way to it, and where to resume each
		while (true) {
			if (l == linked.linkCount) {
				if (depth < 0) {
					return;
				}
				linked = constants.record(chainRecords[depth]);
				l = chainPositions[depth--];
				continue;
			}
			int source = linked.linkSources[l];
			int fieldLocation = linked.linkFields[l++];
			int referrerSet = 0;
			if (source != NO_SOURCE) {
				ConstantRecord holder = constants.record(source);
				if (holder.linkCount > 0) {
					if (holder.visited != stamp) {
						holder.visited = stamp;
						if (++depth == chainRecords.length) {
							chainRecords = Arrays.copyOf(chainRecords, depth * 2);
							chainPositions = Arrays.copyOf(chainPositions, depth * 2);
						}
						chainRecords[depth] = linked.index;
						chainPositions[depth] = l;
						linked = holder;
						l = 0;
					}
					continue;
				}
				referrerSet = referrerSetId(holder);
			}
			pairStrings(constant, fieldLocation, referrerSet);
		}
	}

	/**
	 * Pairs the strings of the constant with the location once per run of the same field and
	 * referrer set, which the links of a constant mostly are, as the hundreds of methods referring
	 * to the symbol of a common name, and once per location of the constant
	 */
	private void pairStrings(ConstantRecord constant, int fieldLocation, int referrerSet) {
		if (fieldLocation != resolvedField || referrerSet != resolvedReferrerSet) {
			resolvedField = fieldLocation;
			resolvedReferrerSet = referrerSet;
			resolvedLocation = locationId(fieldLocation, referrerSet);
		}
		if (constant.lastLocation != resolvedLocation) {
			constant.lastLocation = resolvedLocation;
			for (int i = 0; i < constant.count; i++) {
				addPair(constant.entries[i], resolvedLocation);
			}
		}
	}

	/**
	 * The constants of the types that store strings, so that they may have referrers, and of the
	 * types that fold, so that links reach them, are tracked; the others are only walked for their
	 * references, which need no record of theirs: a referrer is the field, and a link from a
	 * constant that is not tracked, which has no referrers, resolves like a link from an event
	 */
	private void readConstants(RecordingStream stream, Type type, int count) throws IOException {
		int context = rootContext(type, true);
		int[] fieldLocations = contextFieldLocations.get(context);
		boolean tracked = type.containsStrings || type.folds;
		for (int i = 0; i < count; i++) {
			long key = readKey(stream, type.keyKind);
			currentConstant = tracked ? constants.get(type.index, key) : null;
			if (type.isString) {
				readConstantString(stream, ChunkTypes.KIND_STRING, context, -1, type, fieldLocations);
			} else {
				walkConstant(stream, type, context, fieldLocations);
			}
		}
		currentConstant = null;
	}

	/**
	 * Walks the program with the references to folding constants, whose values are values of the
	 * referring fields, only for the types that have any: the walk of every other type stays as it
	 * is
	 */
	private void walkEvent(RecordingStream stream, Type type, int context) throws IOException {
		int[] fields = type.containsFoldingReferences ? type.locationFields : type.fields;
		for (int i = 0; i < fields.length; i++) {
			int op = fields[i];
			if ((op & ChunkTypes.ARRAY_FLAG) == 0) {
				readEventValue(stream, op, type, i, context);
			} else {
				int length = legacy ? stream.readRawInt() : (int) stream.readVarint();
				int kind = op & ChunkTypes.KIND_MASK;
				int fixedSize = ChunkTypes.fixedSize(kind);
				if (fixedSize > 0) {
					stream.skip(length * fixedSize);
				} else if (kind == ChunkTypes.KIND_STRUCT) {
					Type struct = types.getByIndex(op >>> ChunkTypes.TYPE_SHIFT);
					int child = childContext(context, type, i);
					for (int j = 0; j < length; j++) {
						walkEvent(stream, struct, child);
					}
				} else {
					for (int j = 0; j < length; j++) {
						readEventValue(stream, op, type, i, context);
					}
				}
			}
		}
	}

	private void readEventValue(RecordingStream stream, int op, Type type, int field, int context) throws IOException {
		int kind = op & ChunkTypes.KIND_MASK;
		switch (kind) {
		case ChunkTypes.KIND_FIXED1 -> stream.skip(1);
		case ChunkTypes.KIND_FIXED2 -> stream.skip(2);
		case ChunkTypes.KIND_FIXED4 -> stream.skip(4);
		case ChunkTypes.KIND_FIXED8 -> stream.skip(8);
		case ChunkTypes.KIND_VARINT -> stream.skipVarint();
		case ChunkTypes.KIND_STRING, ChunkTypes.KIND_UTF8, ChunkTypes.KIND_UTF16 -> {
			int result = decoder.read(stream, kind);
			if (result == StringDecoder.STRING) {
				int entry = strings.add(decoder.array, decoder.offset, decoder.length, StringScanner.INLINE);
				addPair(entry, locationId(fieldLocation(context, type, field), 0));
			} else if (result == StringDecoder.REFERENCE && types.stringTypeIndex >= 0) {
				addLink(types.stringTypeIndex, decoder.reference, constantValueLocation(context, type, field), null);
			}
		}
		case ChunkTypes.KIND_REF -> {
			// The value of a folding constant, a key into the string pool or a simple type such as the
			// state of a sample, is a value of the field, see walkEvent. A reference to an entity is
			// not a location of its strings, see StringLocation.getReferrers()
			Type pool = types.getByIndex(op >>> ChunkTypes.TYPE_SHIFT);
			long key = readKey(stream, pool.keyKind);
			if (pool.folds) {
				addLink(pool.index, key, constantValueLocation(context, type, field), null);
			}
		}
		case ChunkTypes.KIND_STRUCT -> {
			Type struct = types.getByIndex(op >>> ChunkTypes.TYPE_SHIFT);
			walkEvent(stream, struct, childContext(context, type, field));
		}
		default -> throw new InvalidRecordingException("Unexpected field kind " + kind);
		}
	}

	/**
	 * @param fieldLocations
	 *            the field locations of the context, see {@link #fieldLocation(int, Type, int)},
	 *            looked up once per constant and per array of structs, as every frame of a stack
	 *            trace refers to a method and a frame type
	 */
	private void walkConstant(RecordingStream stream, Type type, int context, int[] fieldLocations) throws IOException {
		int[] fields = type.locationFields;
		for (int i = 0; i < fields.length; i++) {
			int op = fields[i];
			if ((op & ChunkTypes.ARRAY_FLAG) == 0) {
				readConstantValue(stream, op, type, i, context, fieldLocations);
			} else {
				int length = legacy ? stream.readRawInt() : (int) stream.readVarint();
				int kind = op & ChunkTypes.KIND_MASK;
				int fixedSize = ChunkTypes.fixedSize(kind);
				if (fixedSize > 0) {
					stream.skip(length * fixedSize);
				} else if (kind == ChunkTypes.KIND_STRUCT) {
					Type struct = types.getByIndex(op >>> ChunkTypes.TYPE_SHIFT);
					int child = childContext(context, type, i);
					int[] childLocations = contextFieldLocations.get(child);
					for (int j = 0; j < length; j++) {
						walkConstant(stream, struct, child, childLocations);
					}
				} else {
					for (int j = 0; j < length; j++) {
						readConstantValue(stream, op, type, i, context, fieldLocations);
					}
				}
			}
		}
	}

	private void readConstantValue(
		RecordingStream stream, int op, Type type, int field, int context, int[] fieldLocations) throws IOException {
		int kind = op & ChunkTypes.KIND_MASK;
		switch (kind) {
		case ChunkTypes.KIND_FIXED1 -> stream.skip(1);
		case ChunkTypes.KIND_FIXED2 -> stream.skip(2);
		case ChunkTypes.KIND_FIXED4 -> stream.skip(4);
		case ChunkTypes.KIND_FIXED8 -> stream.skip(8);
		case ChunkTypes.KIND_VARINT -> stream.skipVarint();
		case ChunkTypes.KIND_STRING, ChunkTypes.KIND_UTF8, ChunkTypes.KIND_UTF16 ->
			readConstantString(stream, kind, context, field, type, fieldLocations);
		case ChunkTypes.KIND_REF -> {
			Type pool = types.getByIndex(op >>> ChunkTypes.TYPE_SHIFT);
			long key = readKey(stream, pool.keyKind);
			int location = fieldLocations[field + 1];
			if (location < 0) {
				location = fieldLocation(context, type, field);
			}
			if (pool.folds) {
				// The value of a folding constant is a value of the field: a link, see addLink
				addLink(pool.index, key, location, currentConstant);
			} else {
				addReference(pool.index, key, location);
			}
		}
		case ChunkTypes.KIND_STRUCT -> {
			Type struct = types.getByIndex(op >>> ChunkTypes.TYPE_SHIFT);
			int child = childContext(context, type, field);
			walkConstant(stream, struct, child, contextFieldLocations.get(child));
		}
		default -> throw new InvalidRecordingException("Unexpected field kind " + kind);
		}
	}

	private void readConstantString(
		RecordingStream stream, int kind, int context, int field, Type type, int[] fieldLocations) throws IOException {
		int result = decoder.read(stream, kind);
		if (result == StringDecoder.STRING) {
			int entry = strings.add(decoder.array, decoder.offset, decoder.length, StringScanner.CONSTANT_POOL);
			int location = fieldLocations[field + 1];
			if (location < 0) {
				location = fieldLocation(context, type, field);
			}
			currentConstant.add(entry, location);
			if (checkpointStringCount == checkpointStrings.length) {
				checkpointStrings = Arrays.copyOf(checkpointStrings, checkpointStringCount * 2);
			}
			checkpointStrings[checkpointStringCount++] = entry;
		} else if (result == StringDecoder.REFERENCE && types.stringTypeIndex >= 0) {
			int location = fieldLocations[field + 1];
			if (location < 0) {
				location = fieldLocation(context, type, field);
			}
			addLink(types.stringTypeIndex, decoder.reference, location, currentConstant);
		}
	}

	/**
	 * A reference from a field to a folding constant, whose value is thereby a value of the field:
	 * a link on the folding constant naming the field and the constant holding it, resolved at
	 * chunk end with that constant's referrers, see {@link #locateThroughLinks}. A link from a
	 * field of a tracked constant is kept as is, since each constant has referrers of its own; a
	 * link from a field of an event, or of a constant that is not tracked, has no source, and a
	 * repeat carries nothing new, so the recent ones are skipped. Key 0 into the string pool is
	 * null, as the scanner's reference counting takes it: HotSpot numbers the entries of its string
	 * pool from 1 and inlines a string whose number is not positive, and JMC's writer numbers from
	 * 1 as well, so no known writer refers to key 0, while the enumerations of HotSpot's simple
	 * types, the frame types among them, start at key 0.
	 *
	 * @param source
	 *            the record of the constant holding the field, or null for an event or a constant
	 *            that is not tracked
	 */
	private void addLink(int pool, long key, int fieldLocation, ConstantRecord source) {
		if (key == 0 && pool == types.stringTypeIndex) {
			return;
		}
		if (source != null) {
			constants.get(pool, key).addLink(fieldLocation, source.index);
		} else if (!isRecent(key, packed(pool, fieldLocation))) {
			constants.get(pool, key).addFieldLink(fieldLocation);
		}
	}

	/**
	 * The field of a constant referring to an entity storing strings, see
	 * {@link ChunkTypes.Type#containsStrings}: a referrer of the entity, whose record is made now
	 * if the entity's constant is yet to arrive, unless seen recently. Key 0 is null, as HotSpot
	 * writes a null class or thread. The entities storing no strings, such as classes and methods,
	 * are not referred to through this program, see {@link ChunkTypes.Type#locationFields}.
	 */
	private void addReference(int pool, long key, int sourceFieldLocation) {
		if (key != 0 && !isRecent(key, packed(pool, sourceFieldLocation))) {
			constants.get(pool, key).addReferrer(sourceFieldLocation);
		}
	}

	/**
	 * Whether the reference to the constant with the key from the field, the pool and the field
	 * packed by {@link #packed}, was seen recently, remembering it otherwise. The slot mixes the
	 * field and the pool into the key before the multiplication, so that references to one constant
	 * from different fields, as from the fields of an event referring to the same constant, keep
	 * slots of their own.
	 */
	private boolean isRecent(long key, long meta) {
		int slot = (int) (((key ^ (meta << 20)) * GOLDEN) >>> (64 - RECENT_BITS)) << 1;
		if (recent[slot] == key && recent[slot + 1] == meta) {
			return true;
		}
		recent[slot] = key;
		recent[slot + 1] = meta;
		return false;
	}

	/** The pool and the field of a reference packed into one long, plus one so that 0 is empty */
	private static long packed(int pool, int fieldLocation) {
		return (((long) pool << 32) | fieldLocation) + 1;
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
		contextFieldLocations.add(unknownFieldLocations(type.fields.length + 1));
		contextConstantValueLocations.add(null);
		return contextOwners.size() - 1;
	}

	private static int[] unknownFieldLocations(int count) {
		int[] fieldLocations = new int[count];
		Arrays.fill(fieldLocations, -1);
		return fieldLocations;
	}

	/** Field -1 denotes the value of a constant without fields, such as a string constant */
	private int fieldLocation(int context, Type type, int field) {
		int[] fieldLocations = contextFieldLocations.get(context);
		int id = fieldLocations[field + 1];
		if (id < 0) {
			id = fieldLocationId(contextOwners.get(context), fieldPath(context, type, field),
					contextConstant.get(context));
			fieldLocations[field + 1] = id;
		}
		return id;
	}

	/**
	 * The location of a value of the field of an event read from a constant, of the string pool or
	 * of another folding type: the field, as a constant, which is distinct from the location of its
	 * inline values. The context's cache is allocated on its first reference.
	 */
	private int constantValueLocation(int context, Type type, int field) {
		int[] fieldLocations = contextConstantValueLocations.get(context);
		if (fieldLocations == null) {
			fieldLocations = unknownFieldLocations(type.fields.length);
			contextConstantValueLocations.set(context, fieldLocations);
		}
		int id = fieldLocations[field];
		if (id < 0) {
			id = fieldLocationId(contextOwners.get(context), fieldPath(context, type, field), true);
			fieldLocations[field] = id;
		}
		return id;
	}

	/** The path of the field within the owner */
	private String fieldPath(int context, Type type, int field) {
		return join(contextPaths.get(context), field < 0 ? NO_FIELD : type.fieldNames[field]);
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

	/** The id of the constant's set of referrers, computed once per constant and chunk */
	private int referrerSetId(ConstantRecord constant) {
		int id = constant.referrerSet;
		if (id < 0) {
			id = computeReferrerSetId(constant);
			constant.referrerSet = id;
		}
		return id;
	}

	private int computeReferrerSetId(ConstantRecord constant) {
		int count = constant.referrerCount;
		if (count == 0) {
			return 0;
		}
		int[] referrers = constant.referrers;
		if (count == 1) {
			int fieldLocation = referrers[0];
			if (fieldLocation >= singleReferrerSets.length) {
				int oldLength = singleReferrerSets.length;
				singleReferrerSets = Arrays.copyOf(singleReferrerSets, Math.max(fieldLocation + 1, oldLength * 2));
				Arrays.fill(singleReferrerSets, oldLength, singleReferrerSets.length, -1);
			}
			if (singleReferrerSets[fieldLocation] < 0) {
				singleReferrerSets[fieldLocation] = referrerSetId(referrers, 1);
			}
			return singleReferrerSets[fieldLocation];
		}
		return referrerSetId(referrers, count);
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
		int id = locationIds.get(key);
		if (id < 0) {
			id = locations.size();
			locations.add(
					new StringLocation(fieldLocationOwners.get(fieldLocation), fieldLocationPaths.get(fieldLocation),
							fieldLocationConstant.get(fieldLocation), referrerSets.get(referrerSet)));
			locationIds.put(key, id);
		}
		return id;
	}

	private Type getPoolType(long typeId) throws IOException {
		Type type = types.getPoolType(typeId);
		if (type == null) {
			throw new InvalidRecordingException("Constant pool for undeclared type id " + typeId);
		}
		return type;
	}

	private static void checkEnd(RecordingStream stream, int end, Type type) throws IOException {
		if (stream.position() != end) {
			throw new InvalidRecordingException("Event " + type.name + " did not decode to its declared size");
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
		default -> throw new InvalidRecordingException("Unsupported constant pool key kind " + keyKind);
		};
	}
}
