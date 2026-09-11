#!/bin/bash
# Build the Archinome native payload variants (arm64-v8a).
#
# Both variants carry ONE dependency with a long placeholder name
# (libarchinome_dependency_slot.so, 33 bytes). The injector rewrites that string
# in place - it is the same length-constrained operation as the DT_NEEDED edit it
# performs on the host library, so the payload can be re-pointed at the original
# library (stub mode) or at the dependency it displaces (chain mode) without a
# compiler and without growing the file.
set -e

SDK="${ANDROID_SDK:-$HOME/Library/Android/sdk}"
NDK="${NDK:-$SDK/ndk/27.2.12479018}"
CC="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"
READELF="${READELF:-/opt/homebrew/opt/llvm/bin/llvm-readelf}"

PLACEHOLDER="libarchinome_dependency_slot.so"

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/out/arm64-v8a}"
WORK="$HERE/build"
rm -rf "$WORK"; mkdir -p "$WORK" "$OUT"

# empty library used purely as a link-time dependency slot
printf 'int archinome_dependency_slot;\n' > "$WORK/slot.c"
"$CC" -shared -fPIC -o "$WORK/$PLACEHOLDER" "$WORK/slot.c"

build() { # build <out_name> <extra defines...>
    local out="$1"; shift
    "$CC" -shared -fPIC -O2 -fvisibility=default \
        -DARCHINOME_TAG="\"$(basename "$out")\"" \
        -DARCHINOME_FORWARD_JNI="\"$PLACEHOLDER\"" \
        "$@" \
        -o "$OUT/$out" "$HERE/archinome_native.c" -llog \
        -Wl,--no-as-needed -L"$WORK" -l:"$PLACEHOLDER"
}

# 1) plain payload - DT_NEEDED displacement (chain) and library substitution
build libarchin.so

# 2) payload + JNI symbol interposition (test app only)
build libarchin_hook.so -DARCHINOME_HOOK_TESTAPP

echo "BUILT into $OUT:"
for f in "$OUT/libarchin.so" "$OUT/libarchin_hook.so"; do
    echo "--- $(basename "$f") ($(stat -f%z "$f") bytes)"
    "$READELF" -d "$f" | grep -E "NEEDED|SONAME"
    echo "    placeholder occurrences: $(LC_ALL=C grep -c -o "$PLACEHOLDER" "$f" 2>/dev/null || \
        python3 -c "import sys;d=open('$f','rb').read();print(d.count(b'$PLACEHOLDER'))")"
done
