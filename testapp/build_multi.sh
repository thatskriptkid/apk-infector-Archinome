#!/bin/bash
# Build multi-launcher test APK (2 launcher activities + 2 launcher aliases).
set -e

export JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"

SDK="${ANDROID_SDK:-$HOME/Library/Android/sdk}"
BT="$SDK/build-tools/35.0.0"
PLATFORM="$SDK/platforms/android-34/android.jar"
AAPT2="$BT/aapt2"
D8="$BT/d8"
ZIPALIGN="$BT/zipalign"
APKSIGNER="$BT/apksigner"

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$HERE/build_multi"
rm -rf "$WORK"
mkdir -p "$WORK/classes" "$WORK/res/values"

cat > "$WORK/res/values/strings.xml" <<'EOF'
<resources>
    <string name="app_name">TestAppMulti</string>
</resources>
EOF

javac -source 8 -target 8 -bootclasspath "$PLATFORM" \
    -d "$WORK/classes" \
    "$HERE/src/com/example/testapp/MainActivity.java" \
    "$HERE/src/com/example/testapp/SecondActivity.java"

"$D8" --lib "$PLATFORM" --output "$WORK" \
    "$WORK/classes/com/example/testapp/MainActivity.class" \
    "$WORK/classes/com/example/testapp/SecondActivity.class"
mv "$WORK/classes.dex" "$WORK/classes.dex.tmp"

"$AAPT2" compile --dir "$WORK/res" -o "$WORK/res.flata"

"$AAPT2" link -o "$WORK/base.apk" \
    -I "$PLATFORM" \
    --manifest "$HERE/AndroidManifest_multi.xml" \
    --min-sdk-version 24 \
    --target-sdk-version 34 \
    "$WORK/res.flata"

cd "$WORK"
cp classes.dex.tmp classes.dex
zip -q base.apk classes.dex

"$ZIPALIGN" -f -p 4 base.apk aligned.apk
"$APKSIGNER" sign --ks "$HERE/../my-release-key.jks" --ks-key-alias my-key-alias-2 \
    --ks-pass env:KS_PASS --key-pass env:KS_PASS \
    --out "$HERE/testapp_multi.apk" aligned.apk

echo "BUILT: $HERE/testapp_multi.apk"
