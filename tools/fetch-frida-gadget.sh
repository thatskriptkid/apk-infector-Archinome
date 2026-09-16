#!/bin/sh
# Fetch the Frida Gadget binaries this PoC needs, from the upstream Frida
# release, instead of vendoring them in the repository.
#
# Why: the four gadget .so files are ~91 MiB in total, they are not this
# project's code, and they are licensed separately (Frida uses the wxWindows
# Library Licence). Keeping them out of the repository keeps a fresh clone
# small and keeps the licensing story simple.
#
# Usage:
#   tools/fetch-frida-gadget.sh [frida_gadget_dir]     # default: ./frida_gadget
#
# The script verifies every binary against the SHA-256 of the corresponding
# Frida 17.18.0 release asset before use; a mismatch is fatal.
set -eu

VERSION=17.18.0
DEST=${1:-frida_gadget}
BASE="https://github.com/frida/frida/releases/download/${VERSION}"

# name<TAB>sha256   (hashes of the ${VERSION} release assets; verified end-to-end
# for android-arm64 against a fresh download)
MANIFEST='frida-gadget-17.18.0-android-arm.so	596642689a2221f8fda5c15f887add936f20261a39ee0d6add3b1bc93af5c7d3
frida-gadget-17.18.0-android-arm64.so	c87c53efc10a9b6f2f4259b7b962d403cac729d6ee6f6a83f679489f92671a3a
frida-gadget-17.18.0-android-x86.so	9f590185d062a171aa46648abdfcf58b7cfa20c7df49390103c1c9b234cbfd3a
frida-gadget-17.18.0-android-x86_64.so	3b828b8fe5d97be4aeda0ae2e029fb2309343aea3db1a112459330e6b2e1a123'

mkdir -p "$DEST"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

printf '%s
' "$MANIFEST" | while IFS="$(printf '	')" read -r name want; do
    [ -n "$name" ] || continue
    printf 'fetching %s ...\n' "$name"
    curl -fsSL -o "$TMP/$name.xz" "$BASE/$name.xz"
    xz -dc "$TMP/$name.xz" > "$DEST/$name"
    got=$(sha256sum "$DEST/$name" 2>/dev/null || shasum -a 256 "$DEST/$name" | awk '{print $1}')
    got=${got%% *}
    if [ "$got" != "$want" ]; then
        printf 'SHA-256 mismatch for %s\n  want %s\n  got  %s\n' "$name" "$want" "$got" >&2
        rm -f "$DEST/$name"
        exit 1
    fi
    chmod 0644 "$DEST/$name"
done

printf 'gadgets ready in %s\n' "$DEST"
