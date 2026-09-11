#!/bin/bash
# Build minimal test APK (no custom Application class).
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
WORK="$HERE/build"
rm -rf "$WORK"
mkdir -p "$WORK/classes" "$WORK/res/values"

# minimal resource (a string, so resources.arsc exists)
cat > "$WORK/res/values/strings.xml" <<'EOF'
<resources>
    <string name="app_name">TestApp</string>
</resources>
EOF

# compile java
javac -source 8 -target 8 -bootclasspath "$PLATFORM" \
    -d "$WORK/classes" \
    "$HERE/src/com/example/testapp/MainActivity.java"

# dex
"$D8" --lib "$PLATFORM" --output "$WORK" "$WORK/classes/com/example/testapp/MainActivity.class"
mv "$WORK/classes.dex" "$WORK/classes.dex.tmp"

# compile resources
"$AAPT2" compile --dir "$WORK/res" -o "$WORK/res.flata"

# link (produces apk with manifest + resources)
"$AAPT2" link -o "$WORK/base.apk" \
    -I "$PLATFORM" \
    --manifest "$HERE/AndroidManifest.xml" \
    --min-sdk-version 24 \
    --target-sdk-version 34 \
    "$WORK/res.flata"

# add classes.dex into the apk
cd "$WORK"
cp classes.dex.tmp classes.dex
zip -q base.apk classes.dex

# align + sign
"$ZIPALIGN" -f -p 4 base.apk aligned.apk
"$APKSIGNER" sign --ks "$HERE/../my-release-key.jks" --ks-key-alias my-key-alias-2 \
    --ks-pass env:KS_PASS --key-pass env:KS_PASS \
    --out "$HERE/testapp.apk" aligned.apk

echo "BUILT: $HERE/testapp.apk"
