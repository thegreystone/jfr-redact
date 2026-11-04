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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import se.hirt.jfr.redact.parser.ChunkReader;
import se.hirt.jfr.redact.parser.ChunkTypes;

/**
 * The flags {@link ChunkTypes} derives from the metadata for the location model: which types fold,
 * see {@link ChunkTypes.Type#folds}, which values refer to folding constants, and which references
 * the program locating strings follows. The declarations are written by hand, since the layouts the
 * flags tell apart, chains, arrays, structs, cycles and simple types without strings, are not
 * written by the JDK or by JMC's writer. The locations the flags lead to are the subject of
 * {@link SimpleTypeTest}.
 */
class ChunkTypesTest {
	/**
	 * A declared simple type folds when its one field, not an array, is a string, inline or a key
	 * into the string pool, or refers to a type that folds in turn, and the string pool folds by
	 * definition; a declared simple type over an array, a struct or a number, a member of a cycle,
	 * a type referring to itself, and a type with one string field but no declaration do not
	 */
	@Test
	void foldsTheDeclaredSimpleTypesReadAsOneString(@TempDir
	Path dir) throws Exception {
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declareSimple(100, "test.Word", "text:20");
		recording.declareSimple(101, "test.Keyed", "key:20:pool");
		recording.declareSimple(102, "test.Link", "word:100:pool");
		recording.declareSimple(103, "test.Chain", "link:102:pool");
		recording.declareSimple(104, "test.Texts", "texts:20:array");
		recording.declare(105, "test.Inner", "s:20");
		recording.declareSimple(106, "test.Wrap", "inner:105");
		recording.declareSimple(107, "test.Count", "count:1");
		recording.declareSimple(108, "test.A", "b:109:pool");
		recording.declareSimple(109, "test.B", "a:108:pool");
		recording.declareSimple(110, "test.Self", "self:110:pool");
		recording.declare(111, "test.Undeclared", "text:20");
		recording.declare(112, "test.Pair", "text:20", "count:1");
		Path file = recording.write(dir.resolve("types.jfr"));
		ChunkTypes types = typesOf(file);
		for (String folding : List.of("java.lang.String", "test.Word", "test.Keyed", "test.Link", "test.Chain")) {
			assertTrue(type(types, folding).folds, folding);
		}
		for (String entity : List.of("test.Texts", "test.Wrap", "test.Count", "test.A", "test.B", "test.Self",
				"test.Undeclared", "test.Pair", "test.Inner", "long")) {
			assertTrue(!type(types, entity).folds, entity);
		}
		assertEquals(List.of(), HandWrittenRecording.readValues(file, "none", "none"), "the JDK reads the metadata");
	}

	/**
	 * A value refers to folding constants when a field of it, or of a struct it inlines, is a key
	 * into the string pool or refers to a folding type; a reference to an entity, even one holding
	 * a folding constant's value, is none, and the entity itself does
	 */
	@Test
	void tellsTheValuesReferringToFoldingConstants(@TempDir
	Path dir) throws Exception {
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declareSimple(100, "test.Symbol", "string:20");
		recording.declare(101, "test.Class", "name:100:pool", "modifiers:1");
		recording.declare(102, "test.Frame", "type:100:pool", "line:1");
		recording.declare(103, "test.Trace", "frames:102:array");
		recording.declareEvent(104, "test.Sample", "state:100:pool");
		recording.declareEvent(105, "test.Keyed", "text:20:pool");
		recording.declareEvent(106, "test.Loaded", "clazz:101:pool", "count:1");
		recording.declareEvent(107, "test.Plain", "text:20", "count:1");
		Path file = recording.write(dir.resolve("types.jfr"));
		ChunkTypes types = typesOf(file);
		for (String referring : List.of("test.Class", "test.Frame", "test.Trace", "test.Sample", "test.Keyed")) {
			assertTrue(type(types, referring).containsFoldingReferences, referring);
		}
		for (String other : List.of("test.Symbol", "test.Loaded", "test.Plain", "java.lang.String")) {
			assertTrue(!type(types, other).containsFoldingReferences, other);
		}
		assertEquals(List.of(), HandWrittenRecording.readValues(file, "none", "none"), "the JDK reads the metadata");
	}

	/**
	 * The program locating strings follows the references to the constants storing strings, as the
	 * program counting references does, and also those to the folding types storing none, the
	 * chains of simple types, since their values are the values of the referring fields. The
	 * references to the other entities, a class whose name is a symbol or a method, are left as
	 * numbers to skip: their constants have no referrers, so the key of the method of a stack frame
	 * is never decoded, see {@link StringLocation#getReferrers()}.
	 */
	@Test
	void compilesTheReferencesTheLocationsFollow(@TempDir
	Path dir) throws Exception {
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declareSimple(100, "test.Symbol", "string:20");
		recording.declareSimple(101, "test.Link", "symbol:100:pool");
		recording.declare(102, "test.Class", "name:100:pool");
		recording.declare(103, "test.Thread", "name:20");
		recording.declare(104, "test.Method", "type:102:pool", "name:100:pool", "link:101:pool", "thread:103:pool",
				"count:1");
		recording.declare(105, "test.Frame", "method:104:pool", "line:1", "type:100:pool");
		Path file = recording.write(dir.resolve("types.jfr"));
		ChunkTypes types = typesOf(file);
		ChunkTypes.Type method = type(types, "test.Method");
		assertEquals(List.of(false, true, false, true, false), kinds(method.referenceFields, ChunkTypes.KIND_REF),
				"the symbol and the thread store strings; the class and the chain do not");
		assertEquals(List.of(false, true, true, true, false), kinds(method.locationFields, ChunkTypes.KIND_REF),
				"the chain folds into the field; the class, whose name is a symbol, has no referrers");
		ChunkTypes.Type frame = type(types, "test.Frame");
		assertEquals(List.of(false, false, true), kinds(frame.locationFields, ChunkTypes.KIND_REF),
				"the method of a frame is skipped, the frame type followed");
		assertEquals(List.of(), HandWrittenRecording.readValues(file, "none", "none"), "the JDK reads the metadata");
	}

	/** The compiled types of the recording's first chunk, with the references prepared */
	private static ChunkTypes typesOf(Path file) throws IOException {
		try (FileChannel channel = FileChannel.open(file)) {
			ChunkReader reader = new ChunkReader();
			reader.reset(channel);
			assertTrue(reader.next(), "a chunk");
			ChunkTypes types = reader.types();
			types.prepareReferences();
			return types;
		}
	}

	private static ChunkTypes.Type type(ChunkTypes types, String name) {
		for (int i = 0; i < types.size(); i++) {
			if (types.getByIndex(i).name.equals(name)) {
				return types.getByIndex(i);
			}
		}
		throw new AssertionError("No type " + name);
	}

	/** Per field of the program, whether it is of the kind */
	private static List<Boolean> kinds(int[] program, int kind) {
		List<Boolean> kinds = new java.util.ArrayList<>(program.length);
		for (int op : program) {
			kinds.add((op & ChunkTypes.KIND_MASK) == kind);
		}
		return kinds;
	}
}
