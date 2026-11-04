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
import java.nio.file.Path;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import se.hirt.jfr.redact.parser.StreamingChunkParser;
import se.hirt.jfr.redact.scan.StringCountMap;

/**
 * Who made a recording: the home directories, user names and host names that
 * {@link RuleRedactor.Builder#anonymizeUser(UserIdentity)} replaces. {@link #find(Path)} reads them
 * from a recording; they can also be given, for a recording that does not hold them.
 * <p>
 * Values that would damage a recording if replaced wherever they occur are dropped: a home
 * directory without a last path segment of at least two characters, such as {@code /}, or whose
 * last segment is a generic account name, such as {@code /root}, and user and host names shorter
 * than three characters or generic, such as {@code root}, {@code java}, {@code oracle} or
 * {@code localhost}. Generic account names name no person, and replacing them would rename the code
 * and the paths that share their names.
 */
public record UserIdentity(Set<String> homeDirectories, Set<String> userNames, Set<String> hostNames) {
	private static final Set<String> GENERIC_NAMES = Set.of("root", "admin", "administrator", "user", "users", "guest",
			"nobody", "daemon", "system", "default", "defaultuser0", "public", "shared", "java", "jdk", "app", "apps",
			"application", "service", "services", "server", "runner", "ubuntu", "ec2-user", "centos", "debian",
			"fedora", "alpine", "docker", "jenkins", "gradle", "maven", "build", "builder", "test", "tester", "dev",
			"developer", "oracle", "weblogic", "tomcat", "postgres", "mysql", "node", "www-data", "www", "http",
			"nginx", "apache", "bin", "sys", "sync", "mail", "ftp", "operator", "vagrant", "git", "home", "host",
			"localhost", "localdomain", "local", "nonexistent", "empty", "null", "unknown", "true", "false", "yes",
			"none", "off", "console", "workgroup");
	/** The environment variables and system properties naming a home directory */
	private static final Set<String> HOME_KEYS = Set.of("HOME", "USERPROFILE", "USER.HOME");
	/** The kinds of names a key can give, see {@link #kindOf(String)} */
	static final int NO_NAME = 0;
	static final int USER_NAME = 1;
	static final int HOST_NAME = 2;
	/** The endings of key segments naming a host, alone or followed by {@code name} */
	private static final List<String> HOST_TERMS = List.of("client", "server", "domain", "host", "computer");
	/**
	 * A value that can be a name: letters, digits, dots, underscores and dashes, starting with a
	 * letter or digit
	 */
	private static final Pattern NAME = Pattern.compile("[\\p{L}\\p{N}][\\p{L}\\p{N}._-]*");
	/** A URL, the host its first group */
	private static final Pattern URL = Pattern.compile("[A-Za-z][A-Za-z0-9+.-]*://(?:[^/@\\s]*@)?([^/:?#\\s]+).*");

	/** Drops the values that would damage a recording, see the class comment */
	public UserIdentity {
		homeDirectories = homes(homeDirectories);
		userNames = names(userNames);
		hostNames = names(hostNames);
	}

	/**
	 * Reads the identity from the environment variables and system properties of the recording:
	 * home directories from {@code HOME}, {@code USERPROFILE} and {@code user.home}; user names
	 * from the keys naming a user, such as {@code USER}, {@code USERNAME}, {@code LOGNAME},
	 * {@code user.name} or {@code P4USER}, and from the last segments of the home directories; and
	 * host names from the keys naming a client, server, domain or host, such as {@code P4CLIENT},
	 * {@code LOGONSERVER}, {@code USERDOMAIN}, {@code HOSTNAME}, {@code COMPUTERNAME} or
	 * {@code java.rmi.server.hostname}, each also without its domain, see {@link #kindOf(String)}.
	 * Only values that can be names are taken: of letters, digits, dots, underscores and dashes,
	 * starting with a letter or digit and with a letter, so not paths, lists, numbers, options or
	 * text; a value starting with {@code \\} without those, and of a URL its host. HotSpot, from
	 * JDK 7 to 25, records the environment variables, but of the system properties only those the
	 * JVM sets itself and those given on the command line, so {@code user.home} and
	 * {@code user.name}, which the class library sets, only when given there. Windows has no
	 * {@code HOME} and {@code USER}, macOS does not export {@code HOSTNAME}, and a recording may
	 * hold no environment variables at all, as those of WebLogic's diagnostic framework do, leaving
	 * nothing to find.
	 *
	 * @throws InvalidRecordingException
	 *             if the recording cannot be read, see {@link JfrRedactor#redact}
	 */
	public static UserIdentity find(Path recording) throws IOException {
		LocationCollector collector = new LocationCollector();
		new StreamingChunkParser().parse(recording, collector);
		StringCountMap strings = collector.getStrings();
		List<List<StringLocation>> locations = collector.getLocationsByEntry(false);
		Set<String> homes = new LinkedHashSet<>();
		Set<String> users = new LinkedHashSet<>();
		Set<String> hosts = new LinkedHashSet<>();
		for (int entry = 0; entry < strings.size(); entry++) {
			for (StringLocation location : locations.get(entry)) {
				String key = location.getKey();
				if (key == null) {
					continue;
				}
				if (!location.isEnvironmentVariableValue() && !location.isSystemPropertyValue()) {
					continue;
				}
				String value = strings.getString(entry);
				String name = key.toUpperCase(Locale.ROOT);
				if (HOME_KEYS.contains(name)) {
					homes.add(value);
					continue;
				}
				int kind = kindOf(key);
				String found = kind == NO_NAME ? null : nameIn(value);
				if (found != null) {
					(kind == USER_NAME ? users : hosts).add(found);
				}
			}
		}
		for (String home : homes(homes)) {
			users.add(lastSegment(home));
		}
		for (String host : List.copyOf(hosts)) {
			int dot = host.indexOf('.');
			if (dot > 0) {
				hosts.add(host.substring(0, dot));
			}
		}
		// A workspace name such as alice.desktop gives the user name as its first label
		hosts.removeIf(host -> users.stream().anyMatch(host::equalsIgnoreCase));
		return new UserIdentity(homes, users, hosts);
	}

	/**
	 * The kind of name the value of the key is, judged by the last segment of the key, split as
	 * {@link Secrets#segments(String)} does, without a trailing {@code name}: a user name if it
	 * ends with {@code user}, as {@code USER}, {@code USERNAME}, {@code P4USER} and
	 * {@code SUDO_USER} do, or is {@code LOGNAME}; a host name if it ends with {@code client},
	 * {@code server}, {@code domain}, {@code host} or {@code computer}, as {@code P4CLIENT},
	 * {@code CLIENTNAME}, {@code LOGONSERVER}, {@code USERDOMAIN}, {@code HOSTNAME},
	 * {@code REMOTEHOST}, {@code COMPUTERNAME} and {@code java.rmi.server.hostname} do; and if it
	 * is {@code name} alone, what the segment before it names, as in {@code user.name} or
	 * {@code SERVER_NAME}. A key with the term elsewhere names something else, as
	 * {@code SERVER_CLASS}, {@code DOMAIN_HOME}, {@code USER_MEM_ARGS} and {@code HOSTTYPE} do.
	 *
	 * @return {@link #USER_NAME}, {@link #HOST_NAME} or {@link #NO_NAME}
	 */
	static int kindOf(String key) {
		List<String> segments = Secrets.segments(key);
		if (segments.isEmpty()) {
			return NO_NAME;
		}
		String last = segments.getLast();
		if (last.equals("name") && segments.size() > 1) {
			return kindOfSegment(segments.get(segments.size() - 2));
		}
		return kindOfSegment(last);
	}

	private static int kindOfSegment(String segment) {
		String stem = segment.endsWith("name") ? segment.substring(0, segment.length() - 4) : segment;
		if (stem.endsWith("user") || segment.equals("logname")) {
			return USER_NAME;
		}
		for (String term : HOST_TERMS) {
			if (stem.endsWith(term)) {
				return HOST_NAME;
			}
		}
		return NO_NAME;
	}

	/**
	 * @return the name the value is, without a leading {@code \\}, or the host of a URL, or
	 *         {@code null} if the value cannot be a name
	 */
	static String nameIn(String value) {
		String candidate = value.strip();
		while (candidate.startsWith("\\")) {
			candidate = candidate.substring(1);
		}
		Matcher url = URL.matcher(candidate);
		if (url.matches()) {
			candidate = url.group(1);
		}
		return NAME.matcher(candidate).matches() && candidate.chars().anyMatch(Character::isLetter) ? candidate : null;
	}

	/** @return {@code true} if there is nothing to replace */
	public boolean isEmpty() {
		return homeDirectories.isEmpty() && userNames.isEmpty() && hostNames.isEmpty();
	}

	private static Set<String> homes(Collection<String> homes) {
		Set<String> kept = new LinkedHashSet<>();
		for (String home : homes) {
			String trimmed = home;
			while (trimmed.length() > 1 && (trimmed.endsWith("/") || trimmed.endsWith("\\"))) {
				trimmed = trimmed.substring(0, trimmed.length() - 1);
			}
			String last = lastSegment(trimmed);
			if (last.length() < trimmed.length() && last.length() >= 2 && !isGeneric(last)) {
				kept.add(trimmed);
			}
		}
		return Set.copyOf(kept);
	}

	private static Set<String> names(Collection<String> names) {
		Set<String> kept = new LinkedHashSet<>();
		for (String name : names) {
			String trimmed = name.strip();
			if (trimmed.length() >= 3 && trimmed.chars().anyMatch(Character::isLetter) && !isGeneric(trimmed)) {
				kept.add(trimmed);
			}
		}
		return Set.copyOf(kept);
	}

	private static boolean isGeneric(String name) {
		return GENERIC_NAMES.contains(name.toLowerCase(Locale.ROOT));
	}

	static String lastSegment(String path) {
		return path.substring(Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1);
	}
}
