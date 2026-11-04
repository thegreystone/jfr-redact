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

import static java.time.Duration.ofSeconds;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static se.hirt.jfr.redact.HandWrittenRecording.LONG;
import static se.hirt.jfr.redact.HandWrittenRecording.STRING;
import static se.hirt.jfr.redact.HandWrittenRecording.readValues;
import static se.hirt.jfr.redact.HandWrittenRecording.string;
import static se.hirt.jfr.redact.HandWrittenRecording.varint;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** The built-in rules: secrets, process arguments and the identity of the user */
class BuiltInRulesTest {
	private static final StringLocation CLASS_NAME = new StringLocation("java.lang.Class", "name", true, List.of());
	private static final StringLocation THREAD_DUMP = new StringLocation("jdk.ThreadDump", "result", false, List.of());
	private static final StringLocation DESCRIPTION = new StringLocation("jdk.types.OldObject", "description", true,
			List.of());
	private static final StringLocation THREAD_NAME = new StringLocation("java.lang.Thread", "javaName", true,
			List.of());
	private static final UserIdentity ALICE = new UserIdentity(Set.of("/home/alice", "C:\\Users\\Bob Smith"),
			Set.of("alice"), Set.of("box.corp.example", "box"));

	@ParameterizedTest
	@ValueSource(strings = {"DB_PASSWORD", "MYSQL_PWD", "PGPASSWORD", "javax.net.ssl.keyStorePassword", "DD_API_KEY",
			"JEV_KEY", "apiKey", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "SENTRY_DSN", "CI_JOB_JWT", "DOCKER_CREDS",
			"GITLAB_PAT", "NPM_CONFIG__AUTH", "AZURE_STORAGE_CONNECTION_STRING", "storepass", "client.secret",
			"session_cookie", "APIKey"})
	void recognizesSecretNames(String name) {
		assertEquals(true, Secrets.isSecretName(name), name);
	}

	@ParameterizedTest
	@ValueSource(strings = {"PWD", "OLDPWD", "SSH_AUTH_SOCK", "GIT_AUTHOR_NAME", "XAUTHORITY",
			"http.auth.digest.disabledAlgorithms", "jdk.http.auth.tunneling.disabledSchemes",
			"java.security.auth.login.config", "XDG_SESSION_TYPE", "DESKTOP_SESSION", "SESSIONNAME", "TERM_SESSION_ID",
			"CLAUDE_CODE_API_KEY_HELPER_TTL_MS", "BYPASS_PROXY", "COMPASS_HOME", "javax.net.ssl.keyStore",
			"javax.net.ssl.keyStoreType", "MONKEY", "KEYBOARD_LAYOUT", "java.home", "PATH", "AWS_ACCESS_KEY_ID"})
	void keepsOtherNames(String name) {
		assertEquals(false, Secrets.isSecretName(name), name);
	}

	@ParameterizedTest
	@CsvSource(delimiter = '|', quoteCharacter = '`', value = {"aws AKIAIOSFODNN7EXAMPLE x|aws <REDACTED> x",
			"token ghp_abcdefghijklmnopqrstuvwxyz0123456789|token <REDACTED>",
			"slack xoxb-1234567890-abcdefghij|slack <REDACTED>", "key sk-ant-abcdefghijklmnopqrstuvwxyz|key <REDACTED>",
			"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghij|jwt <REDACTED>",
			"Authorization: Bearer abc.def.ghi123|Authorization: Bearer <REDACTED>",
			"-XX:OnError=`curl -H 'Authorization: Basic dXNlcjpwYXNz'`|-XX:OnError=`curl -H 'Authorization: Basic <REDACTED>'`",
			"jdbc:postgresql://u:hunter2@db.local/x|jdbc:postgresql://u:<REDACTED>@db.local/x",
			"jdbc:mysql://db/x?user=a&password=hunter2&ssl=true|jdbc:mysql://db/x?user=a&password=<REDACTED>&ssl=true",
			"-Ddb.password=hunter2 -Dlog=x|-Ddb.password=<REDACTED> -Dlog=x",
			"--api-key=abc123 --verbose|--api-key=<REDACTED> --verbose",
			"mysql --password hunter2 --host db|mysql --password <REDACTED> --host db",
			"keytool -storepass changeit -list|keytool -storepass <REDACTED> -list",
			"Protocol=https;AccountName=a;AccountKey=abc123==;Suffix=net|Protocol=https;AccountName=a;AccountKey=<REDACTED>;Suffix=net",
			"-Ddd.api.key=`quoted value` x|-Ddd.api.key=`<REDACTED>` x"})
	void replacesTheSecretPartsOfCredentials(String text, String expected) {
		assertEquals(expected.replace('`', '"'), Secrets.redactFormats(text.replace('`', '"')));
	}

	@Test
	void replacesPrivateKeys() {
		assertEquals("a <REDACTED> b",
				Secrets.redactFormats("a -----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY----- b"));
		assertEquals("a <REDACTED>", Secrets.redactFormats("a -----BEGIN PRIVATE KEY-----\nMIIabc truncated"));
	}

	@ParameterizedTest
	@ValueSource(strings = {"java.util.HashMap", "task-123456789012345678901234", "-Duse.token=true",
			"ssh://git@github.com:22/acme/repo.git", "https://example.com:8443/path?q=1", "-----BEGIN CERTIFICATE-----",
			"a - b", "password", "--password"})
	void keepsTextWithoutSecrets(String text) {
		assertSame(text, Secrets.redactFormats(text));
	}

	@Test
	void scansLargeTextsInLinearTime() {
		String assignments = "a=b ".repeat(250_000);
		String options = "- x ".repeat(250_000);
		String at = "a@".repeat(250_000);
		assertTimeoutPreemptively(ofSeconds(5), () -> {
			Secrets.redactFormats(assignments);
			Secrets.redactFormats(options);
			Secrets.redactFormats("x".repeat(1_000_000));
			UserAnonymizer.replaceEmails(at);
			new UserAnonymizer(ALICE).anonymize("alicx ".repeat(200_000), List.of());
		});
	}

	@ParameterizedTest
	@CsvSource(delimiter = '|', value = {"/usr/bin/curl -H x|/usr/bin/curl <REDACTED>",
			"/Library/Application Support/JAMF/bin/jamfAgent|/Library/Application Support/JAMF/bin/jamfAgent",
			"/Applications/Foo - Bar.app/Contents/MacOS/Foo - Bar|/Applications/Foo - Bar.app/Contents/MacOS/Foo - Bar",
			"/Applications/G C.app/Contents/Frameworks/G C F.framework/Helpers/G C Helper (Renderer).app/Contents/MacOS/G C Helper (Renderer) --type=renderer"
					+ "|/Applications/G C.app/Contents/Frameworks/G C F.framework/Helpers/G C Helper (Renderer).app/Contents/MacOS/G C Helper (Renderer) <REDACTED>",
			"\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -contentproc|\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\" <REDACTED>",
			"C:\\Program Files (x86)\\Foo - Bar\\foo.exe /S|C:\\Program Files (x86)\\Foo - Bar\\foo.exe <REDACTED>",
			"python3 /Users/alice/script.py secret|python3 <REDACTED>",
			"/usr/bin/python3 script.py|/usr/bin/python3 <REDACTED>", "java -jar app.jar|java <REDACTED>",
			"[kworker/0:1H-events_highpri]|[kworker/0:1H-events_highpri]",
			"/Applications/Foo.app/Contents/MacOS/Foo|/Applications/Foo.app/Contents/MacOS/Foo",
			"Memory Compression|Memory Compression", "[System Process]|[System Process]"})
	void stripsTheArgumentsOfCommandLines(String commandLine, String expected) {
		assertEquals(expected, ProcessArguments.strip(commandLine));
	}

	@ParameterizedTest
	@CsvSource({"USER,1", "USERNAME,1", "LOGNAME,1", "user.name,1", "P4USER,1", "SUDO_USER,1", "PGUSER,1", "WLS_USER,1",
			"P4CLIENT,2", "CLIENTNAME,2", "LOGONSERVER,2", "USERDOMAIN,2", "USERDNSDOMAIN,2", "HOSTNAME,2", "HOST,2",
			"REMOTEHOST,2", "COMPUTERNAME,2", "SERVER_NAME,2", "java.rmi.server.hostname,2", "http.proxyHost,2",
			"SERVER_CLASS,0", "SERVER_PROFILE,0", "DOMAIN_HOME,0", "USER_MEM_ARGS,0", "HOSTTYPE,0", "ALLUSERSPROFILE,0",
			"USERDOMAIN_ROAMINGPROFILE,0", "__CF_USER_TEXT_ENCODING,0", "DERBY_CLIENT_CLASSPATH,0", "user.dir,0",
			"user.timezone,0", "PATH,0"})
	void tellsTheKeysNamingUsersAndHosts(String key, int kind) {
		assertEquals(kind, UserIdentity.kindOf(key), key);
	}

	@ParameterizedTest
	@CsvSource(delimiter = '|', nullValues = "null", value = {"alice|alice", "DESKTOP-4711|DESKTOP-4711",
			"\\\\HOST01|HOST01", "alice.desktop|alice.desktop", "box-1.corp.example|box-1.corp.example",
			"t3://adminhost:7001|adminhost", "https://user@ci.example.com/job|ci.example.com", "C:\\ProgramData|null",
			"/home/alice|null", "Europe/Stockholm|null", "120|null", "10.0.0.5 51234 22|null", "-Xmx1g|null",
			"Jörg|Jörg"})
	void takesOnlyValuesThatCanBeNames(String value, String name) {
		assertEquals(name, UserIdentity.nameIn(value), value);
	}

	@Test
	void dropsIdentitiesThatWouldDamageTheRecording() {
		UserIdentity identity = new UserIdentity(
				Set.of("/", "?", "/root", "/home/alice/", "C:\\Users\\Bob Smith", "/a"),
				Set.of("al", "root", "alice", "Oracle", " "), Set.of("localhost", "box.corp.example", "ab"));
		assertEquals(Set.of("/home/alice", "C:\\Users\\Bob Smith"), identity.homeDirectories());
		assertEquals(Set.of("alice"), identity.userNames());
		assertEquals(Set.of("box.corp.example"), identity.hostNames());
	}

	@ParameterizedTest
	@CsvSource(delimiter = '|', value = {"/home/alice/app.log|/home/user/app.log", "/home/alicex/a|/home/alicex/a",
			"/home/alice.old/a|/home/user.old/a", "PATH=/home/alice/bin:/usr/bin|PATH=/home/user/bin:/usr/bin",
			"/HOME/ALICE/x|/HOME/user/x", "C:/Users/Bob Smith/x|C:/Users/user/x",
			"file:/C:/Users/Bob%20Smith/x|file:/C:/Users/user/x",
			"C:\\\\Users\\\\Bob Smith\\\\x|C:\\\\Users\\\\user\\\\x", "alice-worker|user-worker", "malice|malice",
			"Alice's|user's", "box.corp.example:8080|host:8080", "box-1|host-1", "boxes|boxes",
			"mail alice@example.com now|mail <EMAIL> now", "java.base@25.0.4/Foo|java.base@25.0.4/Foo",
			"org.hibernate.orm.core@6.4.4.Final/Foo.java|org.hibernate.orm.core@6.4.4.Final/Foo.java",
			"git@github.com:acme/repo.git|git@github.com:acme/repo.git", "/a@b.com|/a@b.com",
			"user@host.example.org|<EMAIL>"})
	void anonymizesTheUser(String text, String expected) {
		assertEquals(expected, new UserAnonymizer(ALICE).anonymize(text, List.of(THREAD_NAME)));
	}

	@Test
	void keepsTheNamesOfCode() {
		UserAnonymizer anonymizer = new UserAnonymizer(ALICE);
		assertEquals("com/alice/Foo", anonymizer.anonymize("com/alice/Foo", List.of(CLASS_NAME)));
		assertEquals("\"user-worker\" #1 prio=5\n\tat com.alice.Foo.run(Foo.java:1)\n", anonymizer
				.anonymize("\"alice-worker\" #1 prio=5\n\tat com.alice.Foo.run(Foo.java:1)\n", List.of(THREAD_DUMP)));
		assertEquals("Thread Name: user-worker",
				anonymizer.anonymize("Thread Name: alice-worker", List.of(DESCRIPTION)));
		assertEquals("Class Name: com.alice.Foo",
				anonymizer.anonymize("Class Name: com.alice.Foo", List.of(DESCRIPTION)));
	}

	/** The built-in rules come last, whatever their order among the others */
	@Test
	void appliesTheBuiltInRulesAfterTheOthers() {
		RuleRedactor redactor = RuleRedactor.builder().anonymizeUser(ALICE).redactSecrets()
				.renamePackage("com.alice", "x").replace("*", "kept").build();
		assertEquals("x.Foo", redactor.redact("com.alice.Foo"), "the other rules see the original");
		StringLocation password = new StringLocation("jdk.InitialEnvironmentVariable", "value", false, List.of(),
				"DB_PASSWORD");
		assertEquals("<REDACTED>", redactor.redact("hunter2", List.of(password)), "the secret is replaced anyway");
		StringLocation unknown = new StringLocation("jdk.InitialEnvironmentVariable", "value", false, List.of(), null);
		assertEquals("<REDACTED>", redactor.redact("value", List.of(unknown)), "a value of an unknown key too");
		StringLocation flag = new StringLocation("jdk.InitialEnvironmentVariable", "value", false, List.of(),
				"USE_TOKEN");
		assertEquals("kept", redactor.redact("true", List.of(flag)), "a boolean is no secret");
	}

	/**
	 * The JDK 8 recording of a JavaFX application on Windows, whose identity was replaced with
	 * Alice's on HOST01, with the Perforce workspace alice.host01: the defaults find all of it in
	 * the JDK 7 and 8 environment variables and remove every copy
	 */
	@Test
	void anonymizesTheUserOfAJdk8RecordingOnWindows(@TempDir
	Path dir) throws Exception {
		Path input = FixtureTest.recording("jdk8-guimark.jfr");
		UserIdentity identity = UserIdentity.find(input);
		assertEquals(Set.of("C:\\Users\\Alice"), identity.homeDirectories());
		assertEquals(Set.of("Alice"), identity.userNames());
		assertEquals(Set.of("HOST01", "alice.host01"), identity.hostNames());
		Path output = dir.resolve("redacted.jfr");
		JfrRedactor.redact(input, output,
				RuleRedactor.builder().redactSecrets().stripProcessArguments().anonymizeUser(identity).build());
		TestRecordings.assertAbsent(output, "Alice", "alice", "ALICE", "HOST01", "host01");
	}

	@Test
	void redactsARecording(@TempDir
	Path dir) throws Exception {
		HandWrittenRecording recording = new HandWrittenRecording();
		recording.declareEvent(200, "jdk.InitialEnvironmentVariable", "key:" + STRING, "value:" + STRING);
		recording.declareEvent(201, "jdk.SystemProcess", "pid:" + LONG, "commandLine:" + STRING);
		recording.declareEvent(202, "jdk.JVMInformation", "jvmArguments:" + STRING);
		recording.event(200, string("HOME"), string("/home/alice"));
		recording.event(200, string("USER"), string("alice"));
		recording.event(200, string("DB_PASSWORD"), string("hunter2xyz"));
		recording.event(200, string("JAVA_TOOL_OPTIONS"), string("-Dapi.key=abc123xyz -Xmx1g"));
		recording.event(201, varint(42), string("/usr/bin/mysql -u alice -phunter2xyz"));
		recording.event(202, string("-Dlog=/home/alice/app.log -Dnotify=alice@example.com"));
		Path input = recording.write(dir.resolve("input.jfr"));

		UserIdentity identity = UserIdentity.find(input);
		assertEquals(Set.of("/home/alice"), identity.homeDirectories());
		assertEquals(Set.of("alice"), identity.userNames());
		Path output = dir.resolve("redacted.jfr");
		JfrRedactor.redact(input, output,
				RuleRedactor.builder().redactSecrets().stripProcessArguments().anonymizeUser(identity).build());

		assertEquals(List.of("/home/user", "user", "<REDACTED>", "-Dapi.key=<REDACTED> -Xmx1g"),
				readValues(output, "jdk.InitialEnvironmentVariable", "value"));
		assertEquals(List.of("/usr/bin/mysql <REDACTED>"), readValues(output, "jdk.SystemProcess", "commandLine"));
		assertEquals(List.of("-Dlog=/home/user/app.log -Dnotify=<EMAIL>"),
				readValues(output, "jdk.JVMInformation", "jvmArguments"));
		TestRecordings.assertAbsent(output, "alice", "hunter2xyz", "abc123xyz");
	}
}
