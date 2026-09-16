#!/bin/bash
# Build payload_instrumentation.dex payload dex -> ../payload_instrumentation.dex
set -e

export JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"

SDK="${ANDROID_SDK:-$HOME/Library/Android/sdk}"
BT="$SDK/build-tools/35.0.0"
PLATFORM="$SDK/platforms/android-34/android.jar"
D8="$BT/d8"

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../payload_instrumentation.dex"
WORK="$HERE/build"

rm -rf "$WORK"
mkdir -p "$WORK/classes"

javac -source 8 -target 8 -bootclasspath "$PLATFORM" -d "$WORK/classes" \
    "$HERE/aaaaaaaaaaaa/ArchinomeInstrumentation.java"

"$D8" --lib "$PLATFORM" --output "$WORK" \
    "$WORK/classes/aaaaaaaaaaaa/ArchinomeInstrumentation.class"

cp "$WORK/classes.dex" "$OUT"
echo "BUILT: $OUT"
