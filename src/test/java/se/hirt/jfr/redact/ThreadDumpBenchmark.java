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

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import java.util.function.Supplier;

/**
 * Measures how fast {@link RuleRedactor} rewrites thread dumps, and prints a digest of the output,
 * so that an optimization can be checked to keep the output unchanged. Not a test; run with
 * {@code java -cp target/classes:target/test-classes se.hirt.jfr.redact.ThreadDumpBenchmark}.
 */
public final class ThreadDumpBenchmark {
	private static final StringLocation THREAD_DUMP = new StringLocation("jdk.ThreadDump", "result", false, List.of());
	private static final byte[] KEY = "benchmark-key".getBytes(StandardCharsets.UTF_8);
	private static final String[] PACKAGES = {"java.lang", "java.util", "java.util.concurrent",
			"java.util.concurrent.locks", "com.acme.secret", "com.acme.secret.impl", "org.example.server",
			"org.example.server.http", "jdk.internal.misc", "sun.nio.ch"};
	private static final String[] CLASSES = {"Thread", "Worker", "Handler", "Dispatcher", "Pool", "Queue", "Lock$Sync",
			"Server$$Lambda/0x00007fb87c2252f8", "Selector", "Reader"};
	private static final String[] METHODS = {"run", "park", "await", "take", "handle", "dispatch", "lambda$run$0",
			"<init>", "select", "read"};

	private ThreadDumpBenchmark() {
	}

	public static void main(String[] args) throws Exception {
		List<String> real = TestRecordings.threadDumps(Path.of("src/test/resources/recordings/jdk21-jmc.jfr"));
		List<String> synthetic = new ArrayList<>();
		Random random = new Random(42);
		for (int i = 0; i < 20; i++) {
			synthetic.add(syntheticDump(random, 400, 40));
		}
		System.out.printf("real: %d dumps, %d chars; synthetic: %d dumps, %d chars%n", real.size(),
				real.stream().mapToInt(String::length).sum(), synthetic.size(),
				synthetic.stream().mapToInt(String::length).sum());

		run("unkeyed", () -> RuleRedactor.builder().hashThreadNames().hashClassNames("(.*)").hashMethodNames("(.*)")
				.renamePackage("java.util", "utilz").build(), real, synthetic);
		run("keyed", () -> RuleRedactor.builder().hashThreadNames(KEY).hashClassNames("com\\.acme\\.(.*)", KEY)
				.hashClassNames("(.*)", KEY).hashMethodNames("(handle.*)", KEY).build(), real, synthetic);
	}

	private static void run(String name, Supplier<RuleRedactor> redactors, List<String> real, List<String> synthetic)
			throws Exception {
		System.out.printf("%s: output %s%n", name, digest(redactors.get(), real, synthetic));
		for (int round = 0; round < 3; round++) {
			System.out.printf("%s round %d: real %.1f ms, synthetic %.1f ms%n", name, round, time(redactors, real, 20),
					time(redactors, synthetic, 3));
		}
	}

	/** @return the mean time in milliseconds of redacting all the dumps with a new redactor */
	private static double time(Supplier<RuleRedactor> redactors, List<String> dumps, int iterations) {
		long total = 0;
		int sink = 0;
		for (int i = 0; i < iterations; i++) {
			RuleRedactor redactor = redactors.get();
			long start = System.nanoTime();
			for (String dump : dumps) {
				sink += redactor.redact(dump, List.of(THREAD_DUMP)).length();
			}
			total += System.nanoTime() - start;
		}
		if (sink == 42) {
			System.out.println();
		}
		return total / 1e6 / iterations;
	}

	private static String digest(RuleRedactor redactor, List<String> real, List<String> synthetic) throws Exception {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		for (List<String> dumps : List.of(real, synthetic)) {
			for (String dump : dumps) {
				digest.update(redactor.redact(dump, List.of(THREAD_DUMP)).getBytes(StandardCharsets.UTF_8));
			}
		}
		return HexFormat.of().formatHex(digest.digest(), 0, 8);
	}

	private static String syntheticDump(Random random, int threads, int maxDepth) {
		StringBuilder dump = new StringBuilder();
		dump.append("2026-11-04 12:00:00\nFull thread dump OpenJDK 64-Bit Server VM (25+36 mixed mode):\n\n");
		for (int t = 0; t < threads; t++) {
			dump.append('"').append("worker-").append(random.nextInt(threads)).append(" (pool ")
					.append(random.nextInt(8)).append(")\" #").append(t).append(" daemon prio=5 os_prio=31 cpu=1.5ms")
					.append(" elapsed=12.3s tid=0x00007fb87c0").append(t).append(" nid=0x").append(t)
					.append(" waiting on condition\n   java.lang.Thread.State: WAITING (parking)\n");
			int depth = 1 + random.nextInt(maxDepth);
			for (int f = 0; f < depth; f++) {
				String pkg = PACKAGES[random.nextInt(PACKAGES.length)];
				String cls = CLASSES[random.nextInt(CLASSES.length)];
				String file = cls.contains("/") ? "" : cls.replaceAll("\\$.*", "") + ".java:" + random.nextInt(500);
				String location = pkg.startsWith("java") ? "java.base@25/" + file : file;
				dump.append("\tat ").append(pkg).append('.').append(cls).append('.')
						.append(METHODS[random.nextInt(METHODS.length)]).append('(')
						.append(location.isEmpty() ? "Unknown Source" : location).append(")\n");
				if (f == 0) {
					dump.append("\t- parking to wait for  <0x000000076b4d8f88> (a ").append(pkg).append('.')
							.append(cls.contains("/") ? "Queue" : cls).append(")\n");
				}
			}
			dump.append('\n');
		}
		return dump.toString();
	}
}
