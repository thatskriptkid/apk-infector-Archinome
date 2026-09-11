#!/bin/bash
# Build the encrypted-asset vector (option 8):
#   ../payload_assets.dex     - loader + triggers (factory / provider / receiver),
#                               injected into the APK as classesN.dex
#   ./dyn_payload.dex         - the hidden payload; the injector encrypts it into
#                               assets/archinome_payload.enc (never a classes*.dex)
set -e

export JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"

SDK="${ANDROID_SDK:-$HOME/Library/Android/sdk}"
BT="$SDK/build-tools/35.0.0"
PLATFORM="$SDK/platforms/android-34/android.jar"
D8="$BT/d8"

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../payload_assets.dex"
OUT_DYN="$HERE/dyn_payload.dex"
WORK="$HERE/build"

# --- 1. in-APK stub: AppComponentFactory is API 28, everything else is plain SDK
rm -rf "$WORK"; mkdir -p "$WORK/classes"
javac -source 8 -target 8 -bootclasspath "$PLATFORM" -d "$WORK/classes" \
    "$HERE/aaaaaaaaaaaa/AssetLoader.java" \
    "$HERE/aaaaaaaaaaaa/ArchinomeAppComponentFactory.java" \
    "$HERE/aaaaaaaaaaaa/ArchinomeProvider.java" \
    "$HERE/aaaaaaaaaaaa/ArchinomeReceiver.java"
"$D8" --min-api 28 --lib "$PLATFORM" --output "$WORK" \
    "$WORK"/classes/aaaaaaaaaaaa/*.class
cp "$WORK/classes.dex" "$OUT"
echo "BUILT: $OUT"

# --- 2. the payload that only exists encrypted inside assets/
rm -rf "$WORK/dyn" "$WORK/dynout"; mkdir -p "$WORK/dyn" "$WORK/dynout"
javac -source 8 -target 8 -bootclasspath "$PLATFORM" -d "$WORK/dyn" \
    "$HERE/dyn/dyn/Payload.java"
"$D8" --min-api 28 --lib "$PLATFORM" --output "$WORK/dynout" \
    "$WORK/dyn/dyn/Payload.class"
cp "$WORK/dynout/classes.dex" "$OUT_DYN"
echo "BUILT: $OUT_DYN"
