#!/usr/bin/env bash
# Lists the most frequent strings in a JFR recording as a table.
#
# Usage: scripts/demo.sh [recording.jfr|-] [number of strings, default 30] [occurrences|references|inlined|length]
#        scripts/demo.sh [number of strings, default 30] [occurrences|references|inlined|length]
# Defaults to the included WebLogic (WLDF) MedRec recording, sorted by occurrences.
# Use - to select the included recording explicitly.
#
# Uses the native image (target/jfr-redact) if it has been built with `mvn -Pnative package`,
# otherwise the jar (target/jfr-redact-*.jar) with java, building it with `mvn package` if missing.

set -euo pipefail

if [[ $# -gt 3 ]]; then
    echo "Usage: $0 [recording.jfr|-] [number of strings, default 30] [occurrences|references|inlined|length]" >&2
    echo "       $0 [number of strings, default 30] [occurrences|references|inlined|length]" >&2
    exit 2
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RECORDING="${1:-}"
TOP="${2:-30}"
SORT="${3:-occurrences}"
if [[ $# -le 2 && "$RECORDING" =~ ^[0-9]+$ && ! -e "$RECORDING" ]]; then
    TOP="$RECORDING"
    SORT="${2:-occurrences}"
    RECORDING=""
fi
if [[ -z "$RECORDING" || "$RECORDING" == "-" ]]; then
    RECORDING="$PROJECT_DIR/src/test/resources/recordings/jdk9-weblogic-medrec.jfr"
fi
NATIVE="$PROJECT_DIR/target/jfr-redact"

if [[ -x "$NATIVE" ]]; then
    COMMAND=("$NATIVE")
else
    JAR="$(ls "$PROJECT_DIR"/target/jfr-redact-*.jar 2>/dev/null | head -n 1 || true)"
    if [[ -z "$JAR" ]]; then
        echo "No native image or jar found, building the jar..." >&2
        mvn -q -B -f "$PROJECT_DIR/pom.xml" -DskipTests package >&2
        JAR="$(ls "$PROJECT_DIR"/target/jfr-redact-*.jar | head -n 1)"
    fi
    COMMAND=(java -jar "$JAR")
fi

"${COMMAND[@]}" scan --table --top "$TOP" --sort "$SORT" "$RECORDING"
