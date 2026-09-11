#!/bin/bash
# Build the legacy-style test target with aapt1 (not aapt2), which produces a
# UTF-8 string pool in AndroidManifest.xml - i.e. the opposite of what aapt2
# emits, and the shape most pre-2019 APKs in the wild have.
set -e

export JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"

SDK="${ANDROID_SDK:-$HOME/Library/Android/sdk}"
BT="$SDK/build-tools/34.0.0"          # still ships the legacy aapt1 binary
PLATFORM="$SDK/platforms/android-34/android.jar"
AAPT1="$BT/aapt"
D8="$BT/d8"

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$HERE/build"
rm -rf "$WORK"
mkdir -p "$WORK/classes"

find "$HERE/src" -name '*.java' > "$WORK/sources.txt"
javac -nowarn -source 8 -target 8 -bootclasspath "$PLATFORM" -d "$WORK/classes" @"$WORK/sources.txt" 2>/dev/null
find "$WORK/classes" -name '*.class' > "$WORK/classes.txt"
"$D8" --lib "$PLATFORM" --min-api 21 --output "$WORK" @"$WORK/classes.txt" >/dev/null

# aapt1 package: manifest + resources + assets in one go
"$AAPT1" package -f -M "$HERE/AndroidManifest.xml" -S "$HERE/res" -A "$HERE/assets" \
    -I "$PLATFORM" --min-sdk-version 21 --target-sdk-version 34 \
    -F "$WORK/legacy_raw.apk"

cd "$WORK"
"$AAPT1" add legacy_raw.apk classes.dex >/dev/null

"$BT/zipalign" -f -p 4 legacy_raw.apk aligned.apk
"$BT/apksigner" sign --ks "$HERE/../my-release-key.jks" --ks-key-alias my-key-alias-2 \
    --ks-pass env:KS_PASS --key-pass env:KS_PASS \
    --out "$HERE/legacyapp.apk" aligned.apk

echo "BUILT: $HERE/legacyapp.apk"
