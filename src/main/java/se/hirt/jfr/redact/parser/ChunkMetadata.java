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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import se.hirt.jfr.redact.InvalidRecordingException;

/** The type declarations of a chunk, read from its metadata event. */
public final class ChunkMetadata {
	private final List<ClassElement> classes = new ArrayList<>();
	private final String[] strings;

	/** A type declaration */
	public static final class ClassElement {
		public long id;
		public String name;
		/**
		 * Declared {@code simpleType}: the JDK writes it for a type with exactly one field and no
		 * supertype, and its parser reads a constant of such a type as the value of that field
		 */
		public boolean simpleType;
		public final List<FieldElement> fields = new ArrayList<>();
	}

	/** A field declaration */
	public static final class FieldElement {
		public String name;
		public long typeId;
		public boolean constantPool;
		public int dimension;
	}

	ChunkMetadata(RecordingStream stream) throws IOException {
		stream.skipVarint(); // size
		long typeId = stream.readVarint();
		if (typeId != 0) {
			throw new InvalidRecordingException("Expected metadata event, found event type " + typeId);
		}
		stream.skipVarint(); // start time
		stream.skipVarint(); // duration
		stream.skipVarint(); // metadata id
		strings = new String[readLength(stream)];
		for (int i = 0; i < strings.length; i++) {
			strings[i] = readString(stream);
		}
		readElement(stream, strings, null);
	}

	/**
	 * @return the string table of the metadata: names, labels, descriptions and other annotation
	 *         values. May contain nulls.
	 */
	String[] getStrings() {
		return strings;
	}

	/**
	 * @return the type declarations in declaration order
	 */
	public List<ClassElement> getClasses() {
		return Collections.unmodifiableList(classes);
	}

	/**
	 * Elements form a tree (root, metadata, class, field, annotation, setting, region). Only
	 * classes and their direct field children are kept.
	 */
	private void readElement(RecordingStream stream, String[] strings, ClassElement parent) throws IOException {
		String elementName = strings[(int) stream.readVarint()];
		ClassElement classElement = null;
		FieldElement fieldElement = null;
		if ("class".equals(elementName)) {
			classElement = new ClassElement();
			classes.add(classElement);
		} else if ("field".equals(elementName) && parent != null) {
			fieldElement = new FieldElement();
			parent.fields.add(fieldElement);
		}

		int attributeCount = (int) stream.readVarint();
		for (int i = 0; i < attributeCount; i++) {
			String key = strings[(int) stream.readVarint()];
			String value = strings[(int) stream.readVarint()];
			if (classElement != null) {
				switch (key) {
				case "id" -> classElement.id = Long.parseLong(value);
				case "name" -> classElement.name = value;
				case "simpleType" -> classElement.simpleType = Boolean.parseBoolean(value);
				default -> {
				}
				}
			} else if (fieldElement != null) {
				switch (key) {
				case "name" -> fieldElement.name = value;
				case "class" -> fieldElement.typeId = Long.parseLong(value);
				case "constantPool" -> fieldElement.constantPool = Boolean.parseBoolean(value);
				case "dimension" -> fieldElement.dimension = Integer.parseInt(value);
				default -> {
				}
				}
			}
		}

		int childCount = (int) stream.readVarint();
		for (int i = 0; i < childCount; i++) {
			readElement(stream, strings, classElement);
		}
	}

	private static String readString(RecordingStream stream) throws IOException {
		byte encoding = stream.read();
		switch (encoding) {
		case 0:
			return null;
		case 1:
			return "";
		case 3:
		case 5: {
			int length = readLength(stream);
			int offset = stream.position();
			stream.skip(length);
			return new String(stream.array(), offset, length,
					encoding == 3 ? StandardCharsets.UTF_8 : StandardCharsets.ISO_8859_1);
		}
		case 4: {
			char[] chars = new char[readLength(stream)];
			for (int i = 0; i < chars.length; i++) {
				chars[i] = (char) stream.readVarint();
			}
			return new String(chars);
		}
		default:
			throw new InvalidRecordingException("Unexpected metadata string encoding " + encoding);
		}
	}

	/** Each string-table entry, byte or character needs at least one encoded byte. */
	private static int readLength(RecordingStream stream) throws IOException {
		long length = stream.readVarint();
		if (length < 0 || length > stream.limit() - stream.position()) {
			throw new InvalidRecordingException(
					"Invalid metadata length " + length + " at offset " + stream.position());
		}
		return (int) length;
	}
}
