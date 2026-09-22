**Old article:**

https://www.orderofsixangles.com/en/2020/04/07/android-infection-the-new-way.html (EN)

https://www.orderofsixangles.com/ru/2020/07/04/Infecting-android-app-the-new-way.html (RU)

# Vectors

Fourteen carriers are defined, twelve of them ship as working vectors. All of them patch the APK in place: the binary
`AndroidManifest.xml` (AXML chunks: string pool, resource map, element chunks) and,
where needed, `classes*.dex` and `lib/<abi>/` — never through an `apktool`
decode/rebuild cycle.

| `-o` | Vector | What it does |
|---|---|---|
| 1 | custom payload | dex wrapper: `android:name` of `<application>` points at the injected `InjectedApp` (which extends the host Application class) and runs `payload_custom.dex` |
| 2 | frida gadget | same wrapper + `lib/<abi>/libfrida-gadget.so` (+ `.config.so`) — frida 17.18.0, listening on `127.0.0.1:27042` |
| 3 | content provider | `<provider android:name="aaaaaaaaaaaa.ArchinomeProvider" android:authorities="<pkg>.archinome.provider">` as the first child of `<application>` |
| 4 | trampoline | launcher activity is renamed to `aaaaaaaaaaaa.TrampolineActivity`, which runs the payload and then launches the real one |
| 5 | broadcast receiver | `<receiver>` with `BOOT_COMPLETED` / `MY_PACKAGE_REPLACED` filters + `RECEIVE_BOOT_COMPLETED` |
| 6 | appComponentFactory | `android:appComponentFactory="aaaaaaaaaaaa.ArchinomeAppComponentFactory"` (API 28+) |
| 7 | native | payload `lib/<abi>/libarchin.so` attached to a host library (`chain` — a `DT_NEEDED` slot, `replace` — host lib renamed to `*_orig.so`, `append`) |
| 8 | assets | the payload dex is sealed into `assets/archinome_payload.enc` (`ARCHN1` + AES-256-GCM) and decrypted at runtime |
| 9 | service code patch | manifest untouched: the `run()` call is spliced into `<clinit>` (else `<init>`) of every class the host declares as `<service android:name>` — right before the closing `return-*`; adds `classesN.dex` (`payload_service.dex`, `Laaaaaaaaaaaa/ServicePatch`). **Not implemented yet**: the learn step runs and reports the classes (`CODEPATCH_TARGETS`), the `code_item` splice is pending — see the design note in `pkg/dex/codepatch.go`; hosts are skipped with `NA_CODE_PATCH_PENDING` |
| 10 | native sideload | no dex is added: the host's own `System.loadLibrary("x")` calls are read, a name `libx.so` the host asks for but does not ship is picked, the payload is installed under that name in `lib/<abi>/` and its placeholder `DT_NEEDED` is re-pointed to `libc.so` |
| 11 | Application code patch | manifest untouched: the same call is spliced into `<clinit>`/`<init>` of the host Application class named by `<application android:name>`; adds `classesN.dex` (`payload_apppatch.dex`, `Laaaaaaaaaaaa/AppPatch`). **Not implemented yet**, same pending `code_item` splice as vector 9 |
| 12 | `<instrumentation>` | `<instrumentation android:name="aaaaaaaaaaaa.ArchinomeInstrumentation" android:targetPackage="<pkg>" android:functionalTest="true"/>` added as a child of `<manifest>` (before `<application>`); payload in the Instrumentation subclass `<init>` |
| 13 | `android:backupAgent` | `android:backupAgent="aaaaaaaaaaaa.ArchinomeBackupAgent"` added to `<application>` and `android:allowBackup` forced to `true` (an existing `false` is rewritten in place); payload in the BackupAgent subclass `<init>` |
| 14 | `android:zygotePreloadName` | `android:zygotePreloadName="aaaaaaaaaaaa.ArchinomeZygotePreload"` added to `<application>` plus a `<service android:name="aaaaaaaaaaaa.ArchinomeZygoteService" android:exported="true" android:isolatedProcess="true" android:useAppZygote="true"/>`; payload in `ZygotePreload.doPreload` |

Two things separate the new vectors from 1–8:

* **9 and 11 leave the manifest byte-for-byte as the developer wrote it** — no new
  component names, no attribute edits, nothing to diff against a reference
  manifest; the only traces are an extra `classesN.dex` and a rewritten method
  body. The cost is on the attacker's side: patching a `code_item` means recoding
  the host dex (checksums and offset tables are recomputed). That splice is the
  open work in this PoC: the vectors currently learn their targets and stop.
* **10 and 12–14 need an external trigger** rather than the ordinary app launch:
  10 fires from the host's own `loadLibrary` call, 12 from
  `am instrument -w <pkg>/aaaaaaaaaaaa.ArchinomeInstrumentation`, 13 from
  `bmgr backupnow <pkg>` (or `bmgr run`), 14 from
  `am start-service -n <pkg>/aaaaaaaaaaaa.ArchinomeZygoteService`.

Environment knobs:

```
ARCHINOME_ADD_INTERNET=1                 add android.permission.INTERNET to the manifest
ARCHINOME_GADGET_PORT=27043               listen port of the frida gadget (vector 2, default 27042)
                                         (vector 2 needs it on hosts that don't declare it)
ARCHINOME_ASSETS_VECTOR=appfactory|provider|receiver
                                         manifest carrier used by vector 8
ARCHINOME_ASSETS_KEY=<passphrase>        key for the sealed assets blob
ARCHINOME_ASSETS_DEX=<path.dex>          plain dex to seal into assets/
ARCHINOME_NATIVE_HOST=<libfoo.so>        host library to hook (vector 7)
ARCHINOME_NATIVE_MODE=chain|replace|append
ARCHINOME_NATIVE_ABI=<arm64-v8a|...>     ABI to inject for
ARCHINOME_NATIVE_LIB=<path.so>           payload .so (default native_payload/out/<abi>/libarchin.so)
ARCHINOME_NATIVE_NAME=<libfoo.so>        name the payload is installed under
```

Per-vector traces a defender can look for, and the applicability of each vector
over a 50-host corpus: `docs/detection-notes.md`, `docs/corpus-50-matrix.md`,
`docs/v7-host-lib-selection.md`. Corpus harness: `tools/corpus/README.md`.

# Build

Go 1.26 or newer (the only dependency, `golang.org/x/text@v0.42.0`, requires
it), and nothing else:

```sh
go build -o archinome ./cmd/archinome
./archinome input.apk output.apk -o 8
```

The payload dex files (`payload_*.dex`) are committed, so building the tool does
not involve `d8`, `javac` or an Android SDK. There is no `apktool` step anywhere:
the APK is read and written as a zip, the manifest is patched as binary AXML, and
`classes*.dex` is patched through the parser/encoder in `pkg/dex`.

# Prerequisite

Install and add to PATH - these are needed only to **sign or install** a patched
APK (or to rebuild a payload class from its Java source under `*_payload/`), not
to build or run the injector:

1. Android SDK
2. zipalign
3. apksigner 

# Usage

```
Usage:
main input.apk output.apk -o [option]
options:
        1 - custom payload
        2 - frida inject
        3 - provider inject
        4 - trampoline inject
        5 - receiver inject
        6 - app component factory inject
        7 - native payload (lib injection, see ARCHINOME_NATIVE_* env)
        8 - encrypted assets payload (dex in assets/, runtime DexClassLoader + reflection,
            trigger selectable via ARCHINOME_ASSETS_VECTOR=appfactory|provider|receiver)
        9 - code patch of the services the host declares (manifest untouched)
        10 - native sideload: payload under a library name the host asks for but does
            not ship (learned from the app's own loadLibrary calls)
        11 - code patch of the host Application class (manifest untouched)
        12 - <instrumentation> carrier (trigger: am instrument)
        13 - android:backupAgent carrier (trigger: bmgr backupnow / auto-backup)
        14 - android:zygotePreloadName carrier + app-zygote service (trigger: the
            isolated service is started)
```

# How this differs from other tools

Patching is done **in place, in the binary (AXML) form**: the tool walks the AXML
chunks (string pool, resource map, element chunks) and inserts/overwrites bytes in
them, fixing up chunk sizes and offsets. There is no `apktool` decode/rebuild step,
so `resources.arsc` and the resource XML files are never rewritten and cannot be
broken by a rebuild. Attributes are inserted at the position AXML requires —
sorted by **resolved resource id** — because the platform resolves attribute names
through the resource map and a misordered attribute is silently ignored at runtime
(`aapt2 dump xmltree` will happily print it anyway).
