# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities through **GitHub private vulnerability
reporting** on this repository (Security tab -> "Report a vulnerability"). That
keeps the report private until a fix is available. If you cannot use it, open a
minimal issue that says only that you have a security report and how to reach
you; do not put exploit details in a public issue.

Expect an acknowledgement within a week. This is a proof-of-concept maintained
on a best-effort basis: there is no bug bounty and no guaranteed fix deadline.

## Scope

In scope - defects in this repository's own code:

- Memory-safety or panics in the parsers/encoders driven by untrusted input:
  `pkg/manifest` (binary AXML), `pkg/dex` (dex parse/encode), `pkg/nativepatch`
  (ELF), `internal/injector` (zip read/repack).
- Output-integrity defects: an injected APK that is accepted by Android but
  behaves differently from what the tool reports (silent corruption of a
  `classes*.dex`, of the manifest, or of `resources.arsc`).
- Supply-chain issues in the build (workflow permissions, unpinned actions,
  dependency vulnerabilities reachable from the tool's own code).

Out of scope:

- The fact that the tool works. It is an offensive proof-of-concept; detection
  guidance lives in `docs/detection-notes.md`.
- Malicious use by third parties, and any APK that a user chose to modify.
- Vulnerabilities in vendored third-party components considered as upstream
  bugs (frida gadget, avast/apkparser-derived files, Kaitai-generated code):
  report those upstream, but tell us as well so we can bump or drop the copy.
  See `THIRD_PARTY_NOTICES.md`.

## Handling secrets

The corpus harness never needs a real signing key: use the Android debug
keystore (`~/.android/debug.keystore`) or your own, and keep passwords in the
environment (`KS_PASS`, `APKSIGNER_PASS`). No keystore, password, token, or
sample APK of a third-party application belongs in this repository's history -
if you find one, report it as a vulnerability.
