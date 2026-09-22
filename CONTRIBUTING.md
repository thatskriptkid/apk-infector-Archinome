# Contributing

Thanks for looking. This is a proof-of-concept: it aims to be honest about what
works and what does not, and small, reviewable changes fit that goal better than
large ones.

## Build

Go 1.26 or newer (required by the `golang.org/x/text` version in `go.mod`).
Nothing else is needed to build the tool - the payload dex files
(`payload_*.dex`) are committed, and there is no `apktool`/Android SDK step:

```sh
go build -o archinome ./cmd/archinome
```

The Android SDK (`zipalign`, `apksigner`, `d8`, `aapt2`) is only needed to sign
a patched APK or to rebuild a payload class from its Java source under
`*_payload/`.

## Tests

```sh
go test ./...          # hermetic, no device, no network
```

The corpus round-trip fidelity sweep is env-gated because it needs real APKs:

```sh
ARCHINOME_CORPUS_DIR=/path/to/corpus go test ./pkg/dex/ -run TestCorpusRoundTripFidelity -v
```

That directory must contain `apk/*.apk`. Corpus runs against a device are
documented in `tools/corpus/README.md`; the matrix results live in
`docs/corpus-50-matrix.md`.

Live checks require a rooted device with Frida 17.18.0. Do not reboot the test
device as part of a change unless the change is about boot behaviour.

## Formatting and checks

- `gofmt` everything you touch; CI fails on unformatted files.
- `go vet ./...` must stay clean.
- Two files are Kaitai-compiler output and are excluded from the `gofmt` gate:
  `pkg/dex/kaitai_dex.go`, `pkg/dex/vlq_base128_le.go`. Do not reformat them by
  hand - regenerate from the `.ksy` source instead.

## Adding an injection vector

A new vector touches, at minimum:

1. `cmd/archinome/main.go` - register the option number and its help text.
2. `internal/utils/` - accept the number, reject unknown ones.
3. `internal/injector/` - the code path; manifest carriers go through
   `pkg/manifest`, dex carriers through `pkg/dex`.
4. `tools/corpus/matrix.py` - the log line that counts as success for the vector
   (and `tools/corpus/harness.sh` if it needs an external trigger).
5. `docs/detection-notes.md` - what a defender sees for this vector.
6. `README.md` - one line in the vector table.

Rules that are easy to get wrong:

- Manifest edits stay in **binary AXML form**: patch existing chunks and fix up
  sizes/offsets. Never pipe the manifest through a decode/rebuild cycle - the
  whole point of the tool is that there is no rebuild step.
- New attributes must be inserted at the position AXML requires: ascending
  **resolved resource id**, not insertion order and not string order.
- Dex edits go through the model + encoder in `pkg/dex` (`parse -> model ->
  encode`), never by hand-splicing bytes, and `class_defs` keep the source
  order (ART requires a superclass before its subclasses).
- Prefer a vector that leaves no new component behind. If a vector is not
  implemented for a host, say so in the matrix (`NA_*`) instead of reporting a
  pass.

## What must never be committed

- Keystores, passwords, tokens, `.env` files. Use
  `~/.android/debug.keystore` or your own key, and pass secrets through the
  environment (`KS_PASS`, `APKSIGNER_PASS`).
- APKs of third-party applications, and build artifacts generally
  (`archinome`, `payload_*.dex` are the exception: payload dex files are part
  of the tool).
- Binaries from other projects without an entry in `THIRD_PARTY_NOTICES.md`.
  Large vendored binaries are rejected in review on size alone.

## Pull requests

- One vector or one fix per PR.
- Say what you tested, on what device/corpus, and show the evidence
  (logcat line, `dexdump` output, matrix row counts). "It should work" is not
  evidence.
- Keep generated files out of the diff unless regeneration is the point.

## Conduct

Contributions are covered by the [Contributor
Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/)
v2.1. Report unacceptable behaviour through the same private channel as a
security report (`SECURITY.md`).
