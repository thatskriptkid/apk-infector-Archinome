#!/bin/bash
# Build a drop-in replacement ("stub") for a renamed original library.
#
#   build_stub.sh <orig_dir> <orig_filename> <out_file> [--hook]
#
# The original file is used as a link input with --no-as-needed, which records it
# as DT_NEEDED of the stub: the platform opens our stub by name, the linker loads
# the renamed original as its dependency, and every JNI symbol of the original
# stays reachable through it.
set -e

SDK="${ANDROID_SDK:-$HOME/Library/Android/sdk}"
NDK="${NDK:-$SDK/ndk/27.2.12479018}"
CC="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"
READELF="/opt/homebrew/opt/llvm/bin/llvm-readelf"

ORIG_DIR="$1"; ORIG_FILE="$2"; OUT_FILE="$3"; HOOK="$4"
[ -n "$ORIG_DIR" ] && [ -n "$ORIG_FILE" ] && [ -n "$OUT_FILE" ] || {
    echo "usage: $0 <orig_dir> <orig_filename> <out_file> [--hook]" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
TAG="$(basename "$OUT_FILE")"
EXTRA=""
[ "$HOOK" = "--hook" ] && EXTRA="-DARCHINOME_HOOK_TESTAPP"

"$CC" -shared -fPIC -O2 -fvisibility=default \
    -DARCHINOME_TAG="\"$TAG\"" \
    -DARCHINOME_FORWARD_JNI="\"$ORIG_FILE\"" \
    $EXTRA \
    -o "$OUT_FILE" "$HERE/archinome_native.c" -llog \
    -Wl,--no-as-needed -L"$ORIG_DIR" -l:"$ORIG_FILE"

echo "BUILT stub: $OUT_FILE"
"$READELF" -d "$OUT_FILE" | grep -E "NEEDED|SONAME"
