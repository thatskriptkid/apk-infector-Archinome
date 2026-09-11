#!/bin/bash
# Build the native test app: minimal APK + lib/arm64-v8a/libnativetest.so (STORED, page-aligned).
set -e

export JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"

SDK="${ANDROID_SDK:-$HOME/Library/Android/sdk}"
BT="$SDK/build-tools/35.0.0"
NDK="${NDK:-$SDK/ndk/27.2.12479018}"
PLATFORM="$SDK/platforms/android-34/android.jar"
CC="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$HERE/build"
rm -rf "$WORK"
mkdir -p "$WORK/classes" "$WORK/res/values" "$WORK/lib/arm64-v8a"

cat > "$WORK/res/values/strings.xml" <<'EOF'
<resources>
    <string name="app_name">NativeTest</string>
</resources>
EOF

# --- native lib ---------------------------------------------------------------
"$CC" -shared -fPIC -O2 -o "$WORK/lib/arm64-v8a/libnativetest.so" "$HERE/jni/nativetest.c" -llog -landroid

# --- java ---------------------------------------------------------------------
javac -source 8 -target 8 -bootclasspath "$PLATFORM" -d "$WORK/classes" \
    "$HERE/src/com/example/nativetest/MainActivity.java"

"$BT/d8" --lib "$PLATFORM" --output "$WORK" "$WORK/classes/com/example/nativetest/MainActivity.class"
mv "$WORK/classes.dex" "$WORK/classes.dex.built"

"$BT/aapt2" compile --dir "$WORK/res" -o "$WORK/res.flata"
"$BT/aapt2" link -o "$WORK/base.apk" -I "$PLATFORM" \
    --manifest "$HERE/AndroidManifest.xml" \
    --min-sdk-version 24 --target-sdk-version 34 \
    "$WORK/res.flata"

# --- pack: dex + lib (STORED so it stays loadable straight from the APK) -------
cd "$WORK"
cp classes.dex.built classes.dex
zip -q -X base.apk classes.dex
zip -q -X -0 base.apk lib/arm64-v8a/libnativetest.so

"$BT/zipalign" -f -p 4 base.apk aligned.apk
"$BT/apksigner" sign --ks "$HERE/../my-release-key.jks" --ks-key-alias my-key-alias-2 \
    --ks-pass env:KS_PASS --key-pass env:KS_PASS \
    --out "$HERE/nativetest.apk" aligned.apk

echo "BUILT: $HERE/nativetest.apk"
unzip -l "$HERE/nativetest.apk" | grep -E "\.so|classes.dex"
