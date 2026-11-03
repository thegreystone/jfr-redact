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
/**
 * Redacts strings in JDK Flight Recorder recordings.
 * <p>
 * {@link se.hirt.jfr.redact.JfrRedactor#redact(java.nio.file.Path, java.nio.file.Path, StringRedactor)}
 * writes a copy of a recording, with the strings replaced as decided by a {@link StringRedactor}.
 * The redactor is called once per distinct string, with all the {@link StringLocation locations} it
 * is stored at, and its decision applies to every occurrence, so no copy of a redacted string
 * remains. {@link RuleRedactor} covers simple cases without code:
 *
 * <pre>{@code
 * RedactionResult result = JfrRedactor.redact(Path.of("in.jfr"), Path.of("out.jfr"),
 * 		RuleRedactor.builder().renamePackage("java.util", "utilz").build());
 * }</pre>
 *
 * Note that class and package names are stored in their internal form in recordings, such as
 * {@code java/util/HashMap}, and also occur in method descriptors such as
 * {@code (Ljava/util/List;)V}: {@link RuleRedactor.Builder#renamePackage(String, String)} renames
 * every form, while patterns and regular expressions see the strings as stored.
 */
package se.hirt.jfr.redact;
