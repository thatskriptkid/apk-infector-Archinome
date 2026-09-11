# TODO — новые вектора внедрения кода

## Tier 1 — закрывают главный гэп (нет Application-класса)

1. [x] **ContentProvider с `initOrder`** — `provider.onCreate()` вызывается раньше `Application.onCreate()`. Работает без Application-класса, не трогает `android:name`, не снимает `final`.
2. [x] **Trampoline / подмена entry-Activity** — прозрачная Activity: `onCreate` → payload → `finish()` → `startActivity(оригинальная)`.
3. [x] **BroadcastReceiver auto-start** — `BOOT_COMPLETED` / `MY_PACKAGE_REPLACED` / `USER_PRESENT`, payload без запуска приложения, переживает ребут/апдейт.

## Tier 2 — стелс / нативный слой

4. [x] **`AppComponentFactory` (API ≥ 28)** — перехват `instantiateApplication/Provider/ClassLoader`, подмена ClassLoader. Реализовано (оба хука: `instantiateApplication` + `instantiateClassLoader`), проверено на testapp и WhatsApp.
5. [x] **Native: JNI_OnLoad / подмена .so** — все три подхода реализованы: (a) подмена либы, которую приложение грузит по имени + интерпозиция JNI-символа; (b) DT_NEEDED-патчинг in-place (`chain`) и добавление записи (`append`); (c) подмена lib (rename + stub). Проверено на testapp и WhatsApp, без рута.
6. [x] **Assets + DexClassLoader** — payload в `assets/` (шифрованный), runtime-загрузка + reflection. Реализовано (`-o 8`), проверено на testapp и WhatsApp без рута.
7. [ ] **Instrumentation** — свой `Instrumentation`, `onCreate` + `callApplicationOnCreate`.

## Tier 3 — сложнее, максимальный стелс

8. [ ] **`<clinit>` / smali method injection** — `static{}` в загружаемый класс или `invoke-static` в `onCreate`. Требует полноценный DEX-редактор.
9. [ ] **Multi-dex merge** — склейка payload + стаб в существующий `classes.dex` (нужен dex-merger).

---

## Ход работ

- [x] **Пункт 1 (ContentProvider)** — реализован и проверен на рутованном Pixel 6a (SDK 37).
  - `pkg/manifest/provider_patch.go` — `PatchProvider()`: инъекция `<provider>` в бинарный манифест (string pool + resource map + element chunk).
  - `provider_payload/` — `ArchinomeProvider.java` + `payload.java` → `payload_provider.dex`.
  - option `3` в CLI (`main input.apk output.apk -o 3`); injector.go не трогает Application/dex-финал/frida для provider-пути.
  - Подтверждено: payload (`ARCHINOME: PROVIDER_PAYLOAD_EXECUTED`) сработал до `MainActivity.onCreate`, приложение без кастомного Application-класса, authority зарегистрирован и неэкспортируем.
  - Тест-харнес: `testapp/` (минимальный APK без Application) + `provider_payload/build.sh`.

- [x] **Пункт 3 (BroadcastReceiver auto-start)** — реализован и проверен на рутованном Pixel 6a (SDK 37), цель — WhatsApp 2.26.35.75.
  - `pkg/manifest/receiver_patch.go` — `PatchReceiver()`: инъекция `<receiver android:name="aaaaaaaaaaaa.ArchinomeReceiver" android:exported="false">` первым ребёнком `<application>` с `<intent-filter>` (3 action), + `<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>` перед `<application>` (ребёнок `<manifest>`).
  - `receiver_payload/` — `ArchinomeReceiver.java` (BroadcastReceiver: логирует action через `RECEIVER_ONRECEIVE:` + вызывает payload) + `payload.java` → `payload_receiver.dex`.
  - option `5` в CLI (`-o 5`); injector.go: provider/trampoline/receiver — один путь (только инъекция payload dex).
  - Манифест подтверждён `aapt2 dump xmltree`: receiver с `name/exported=false`, intent-filter c BOOT_COMPLETED/MY_PACKAGE_REPLACED/USER_PRESENT. Duplicate `RECEIVE_BOOT_COMPLETED` permission (у WhatsApp уже был) — безвредно.
  - **Проверено на устройстве:**
    - `MY_PACKAGE_REPLACED` реально сработал (переподпись+install-multiple как апдейт, разлоченный девайс): `RECEIVER_ONRECEIVE: MY_PACKAGE_REPLACED` + `RECEIVER_PAYLOAD_EXECUTED`; система подняла процесс в фоне (`Start proc ... for broadcast {com.whatsapp/aaaaaaaaaaaa.ArchinomeReceiver}`).
    - Симуляция всех 3 broadcast'ов из root (`su -c am broadcast … -f 0x20`) — payload исполнился по всем трём, `exported=false` принимает системные (protected) broadcast'ы.
  - **Ограничения (штатное поведение Android, не баг патча):**
    - *stopped-состояние:* `MY_PACKAGE_REPLACED`/`USER_PRESENT` не доставляются, пока приложение не запускалось ни разу (`stopped=true notLaunched=true`). Исключение — `BOOT_COMPLETED` (система шлёт с `FLAG_INCLUDE_STOPPED_PACKAGES`). Поэтому единственный триггер «из холода без запуска» — boot-broadcast'ы.
    - *залоченный девайс:* все три для `directBootAware=false` ресивера доставляются только после разблокировки (CE-хранилище).
    - **НЕ добавлять** `directBootAware=true` + `LOCKED_BOOT_COMPLETED` для срабатывания до первого анлока: процесс стартует в direct-boot-режиме, `Application.onCreate` целевого приложения падает (WhatsApp AppShell → `StackOverflowError`, `mkdir errno 126`) ДО вызова `onReceive` — payload не успевает, приложение крашится на каждом ребуте.
- [x] **Пункт 2 (Trampoline / подмена entry-Activity)** — реализован и проверен на рутованном Pixel 6a (SDK 37).
  - `pkg/manifest/trampoline_patch.go` — `PatchTrampoline()`: рекурсивный walk бинарного AXML, поиск launcher-Activity (MAIN+LAUNCHER), переименование её `android:name` в `aaaaaaaaaaaa.TrampolineActivity`, вставка `<meta-data android:name="archinome.target" android:value="<исходный FQN>"/>`, добавление новой non-launcher `<activity>` для исходного класса.
  - `trampoline_payload/` — `TrampolineActivity.java` (onCreate → payload → читает meta-data → startActivity(цель) → finish) + `payload.java` → `payload_trampoline.dex`.
  - option `4` в CLI (`-o 4`); injector.go: provider/trampoline — один путь (только инъекция payload dex, без Application-hijack/frida).
  - Подтверждено на устройстве: launcher резолвится на `TrampolineActivity` (одна иконка); logcat `TRAMPOLINE_PAYLOAD_EXECUTED` → `TRAMPOLINE_LAUNCHING_TARGET: com.example.testapp.MainActivity` → `MainActivity.onCreate fired` (тот же PID, +22 мс); трамплин finished (t-1), в back-stack только MainActivity; payload срабатывает при каждом холодном запуске через иконку.
  - Ограничение вектора: payload не срабатывает при тёплом возобновлении из recents (MainActivity уже на вершине стека) — выполняется только на холодном запуске по иконке.
  - **Множественные MAIN/LAUNCHER (доработка):** `findLauncherComponents` перебирает и `<activity>`, и `<activity-alias>`; каждый launcher-компонент перенаправляется на трамплин (activity: `android:name`; alias: `android:targetActivity` = 0x01010202), per-component `<meta-data archinome.target>` (payload читает цель через `getComponentName()`, поэтому для alias-запуска возвращается meta-data самого alias'а). Лишние launcher-`<activity>` конвертируются в `<activity-alias>` с **уникальным** именем (`<orig>+ArchinomeAlias`) — иначе коллизия с пере-объявленной activity → цикл трамплина. Пере-объявленная activity сохраняет исходные атрибуты (theme/label/exported/configChanges). Проверено на Pixel 6a: primary + 2 alias + конвертированный activity→alias — все корректно (без циклов).
  - **WhatsApp 2.26.35.75 (`why.apkm`):** base.apk + сплиты переподписаны своим ключом, `install-multiple` Success; launcher резолвится на `TrampolineActivity`; payload `TRAMPOLINE_PAYLOAD_EXECUTED` → `TRAMPOLINE_LAUNCHING_TARGET: com.whatsapp.Main` → WhatsApp реально стартовал (EULA/регистрация), процесс жив. 14 launcher-alias `AppIcon01–14` корректно перенаправлены (`targetActivity=TrampolineActivity`), но `enabled=false` в манифесте — поэтому не запускаются извне. Примечание: resmap дописывается в конец (не по возрастанию ID) — устройство парсит по индексу позиции корректно, но `aapt2 dump` может показать неверное имя атрибута для дописанного ID (косметика).

- [x] **Пункт 4 (AppComponentFactory, API ≥ 28)** — реализованы ОБА хука, проверено на testapp (ADD-путь) и WhatsApp 2.26.35.75 (REPOINT-путь). Ребут не делался.
  - `pkg/manifest/appfactory_patch.go` — `PatchAppComponentFactory()`. Атрибут `android:appComponentFactory` = **0x0101057a** (не 0x01010505 — это directBootAware).
    - **REPOINT-путь** (атрибут уже есть — так у любого androidx-приложения, у WhatsApp значение `androidx.core.app.CoreComponentFactory`): дописываем в конец string pool имя нашего класса и переподчиняем значение атрибута (`rawValue` @+8 и typed `data` @+16 = новый индекс строки, два overwrite по 4 байта). Манифест WhatsApp вырос всего на 92 байта; element/attrCount/resmap не трогаются.
    - **ADD-путь** (атрибута нет — testapp): дописываем строку-имя `appComponentFactory` + строку-значение, при необходимости расширяем resource map нулевым паддингом до нового индекса и кладём туда 0x0101057a, затем дописываем 20-байтный атрибут в `<application>` (`attrCount` @+28 +1, chunk size @+4 +20, вставка по `appStart+appSize`).
    - Реюз хелперов `findAttrByResID` / `firstTagStart` / `childElements` / `elementName` / `parseStringPool` / `encodeString`; логика роста пула — та же, что в provider/receiver.
  - `appfactory_payload/` — `ArchinomeAppComponentFactory.java` (extends `AppComponentFactory`) + `payload.java` → `payload_appfactory.dex`; **вложенный** `ArchinomeAppComponentFactory$ArchinomeClassLoader` и демо-класс `dyn.Payload` → `appfactory_payload/dyn_payload.dex` (вне APK).
  - option `6` в CLI (`-o 6`); `utils.AppComponentFactory_payload = 6`; injector.go: provider/trampoline/receiver/appfactory — один путь (только инъекция payload dex, без Application-hijack/frida).
  - **Порядок хуков подтверждён логом** (важно: фабрика — самый ранний хук, раньше `provider.onCreate`):
    `APPFACTORY_CTOR` → `APPFACTORY_INSTANTIATE_CLASSLOADER` → `APPFACTORY_INSTANTIATE_APPLICATION` → (потом `<provider>.onCreate` → `Application.onCreate` → receiver).
    - WhatsApp: `APPFACTORY_INSTANTIATE_APPLICATION com.whatsapp.AppShell` + `APPFACTORY_APPLICATION_READY com.whatsapp.AppShell`, процесс жив, crash-буфер пуст, UI поднялся. Приложение не ломается (AppShell создаётся штатно через `super`).
    - `instantiateClassLoader` (API 29+; в AOSP `LoadedApk.createOrUpdateClassLoaderLocked`, до `instantiateApplication`, требование — делегировать базовому загрузчику): подтверждён logcat `base=dalvik.system.PathClassLoader`.
  - **Подмена ClassLoader (демонстрация out-of-band payload):** фабрика возвращает `ArchinomeClassLoader` (parent = платформенный `PathClassLoader`, `findClass` → внешний `DexClassLoader`). Внешний `dyn_payload.dex` лежит ВНЕ APK; при старте WhatsApp: `APPFACTORY_DYN_DEX_FOUND /data/local/tmp/archinome_dyn.dex` → `DYN_PAYLOAD_EXECUTED_FROM_EXTERNAL_DEX pid=19152` — код из файла вне пакета исполнился внутри `com.whatsapp`. Приложение работает на подменённом загрузчике.
  - **Кандидаты пути внешнего dex:** `/data/local/tmp/archinome_dyn.dex`, затем `<ApplicationInfo.dataDir>/files/archinome_dyn.dex` (generic, через `info.dataDir`).
  - **Грабли (зафиксировать):**
    - **d8 получает ВСЕ `.class`, включая вложенные.** Перечисление только top-level `.class` (`payload.class ArchinomeAppComponentFactory.class`) молча не включает `Outer$Inner.class` → в dex класс есть лишь как тип-ссылка → рантайм `NoClassDefFoundError: ...$ArchinomeClassLoader`. Решение: `d8 ... "$WORK"/classes/<pkg>/*.class`. Проверка: `dexdump -f <dex> | grep "Class descriptor"` должен показать вложенный класс как **определение**.
    - **ART отвергает writable dex:** `SecurityException: Writable dex file '...' is not allowed` (файл был `-rw-rw-rw-`). Нужен не-writable файл: `su -c 'chmod 644 /data/local/tmp/archinome_dyn.dex'` (owner root/shell) либо путь в приватном каталоге приложения. Приложение при этом НЕ падает — срабатывает fallback на платформенный загрузчик.
    - **Возвращаемый ClassLoader обязан делегировать** платформенному (parent-first), иначе компоненты не резолвятся; при любой ошибке — вернуть исходный `base`, а не падать.
    - **REPOINT, а не перезапись поведения:** у большинства приложений атрибут уже занят `androidx.core.app.CoreComponentFactory`; наш класс не должен ломать его семантику — реплицируем `checkCompatWrapper` (reflection по `androidx.core.app.ComponentFactory$CompatWrapped` → `getWrapper()`), а остальные `instantiateActivity/Service/Receiver/Provider` делегируем `super`.
    - **Порядок старта в direct-boot:** фабрика исполняется ещё раньше провайдера, но `directBootAware`-краш AppShell в CE-locked всё равно происходит ПОСЛЕ нашего кода (см. anti-pattern в пункте 3) — pre-unlock бесплатно не даётся.
  - aapt2-проверка REPOINT: `A: ...:appComponentFactory(0x0101057a)="aaaaaaaaaaaa.ArchinomeAppComponentFactory"`.
  - Пайплайн теста (без ребута, девайс разлочен): inject (`-o 6`) → zipalign → apksigner (alias `my-key-alias-2`) → `adb install-multiple -r base + 5 сплитов` → push `dyn_payload.dex` + chmod 644 → force-stop → `am start`/monkey → `logcat -s ARCHINOME`.

- [x] **Пункт 5 (Native: JNI_OnLoad / подмена .so)** — реализованы все три подхода, проверено на testapp и WhatsApp 2.26.35.75. Ребут не делался, рут только для чтения логов/дампа (сам механизм рута не требует).
  - `pkg/elfpatch/` — ELF64/ELF32 reader + правка `DT_NEEDED` **in-place**, без роста файла:
    - `Open/Parse` → `Needed[]` (имя, слот в `.dynamic`, смещение в `.dynstr`, capacity) — вывод совпадает с `llvm-readelf -d` байт в байт.
    - `RewriteNeeded` — перезапись имени в слоте (NUL-паддинг, длина не может превышать исходную), `PickNeeded(n)` — выбор самого длинного подходящего слота.
    - `AddNeeded` — добавление зависимости: старый `DT_NULL` становится нашим `DT_NEEDED`, а следующий слот (уже занулённый) — валидным терминатором (`DT_NULL` == tag 0), поэтому достаточно **одного** свободного слота; имя пишется сразу за таблицей строк, `DT_STRSZ` увеличивается. Ограничение честно сообщается в ошибке.
    - `ReplaceBytes` — NUL-паддированная замена фиксированной строки (используется для placeholder'а payload'а).
    - Тесты: 10 герметичных (синтетический ELF), включая негативные (нет слота / нет места в строковой таблице / имя не влезает).
    - **Измеренный факт:** у либ, собранных clang/lld (WhatsApp `libs.so`/`libsuperpack.so`, тестовая либа), свободных слотов в `.dynamic` **нет** → `append` там недоступен, инструмент печатает причину; рабочие стратегии на реальных целях — `chain`/`replace`.
  - `pkg/nativepatch/` — три стратегии + выбор ABI/хоста/payload'а и переподчинение placeholder'а: `chain` (12-байтная правка `DT_NEEDED` хоста + наша либа дальше держит вытесненную зависимость), `replace` (оригинал → `<name>_orig.so`, payload встаёт под исходным именем), `append`. Тесты: 5 (в т.ч. на регресс «payload должен лечь под именем хоста»).
  - `native_payload/` — `archinome_native.c` + `build.sh` (NDK, arm64-v8a): payload в конструкторе (`__android_log_print` + запись proof-файла в data dir самого приложения), `JNI_OnLoad` с форвардом в оригинал (`dlopen`+`dlsym`), опциональная интерпозиция JNI-символа (`-DARCHINOME_HOOK_TESTAPP`).
    - **Один prebuilt payload на все режимы:** в либу зашита зависимость-заполнитель фиксированной длины `libarchinome_dependency_slot.so` (31 байт), которую инжектор переписывает in-place на реальное имя — компилятор на этапе инжекта не нужен.
  - CLI: `-o 7` + env `ARCHINOME_NATIVE_MODE|HOST|LIB|ABI|NAME`. Для `-o 7` манифест и dex не трогаются (это же делает возможным патч **split**-APK — парсер манифеста на них падает).
  - Тест-харнес `testapp_native/` — APK с настоящей JNI-либой (проверяет и сохранность оригинала, и интерпозицию).
  - **Проверено на устройстве (Pixel 6a, без рута):**
    - testapp `replace`: `ORIGINAL_LIB_CTOR` → `NATIVE_PAYLOAD_CTOR` → `NATIVE_JNI_ONLOAD` → `NATIVE_STUB_FORWARDING_JNI_ONLOAD` → `ORIGINAL_JNI_ONLOAD` → `NATIVE_HOOK_INTERCEPTED Java_com_example_nativetest_MainActivity_stringFromJNI` → приложение получило **нашу** строку, оригинальная реализация не вызывалась. Proof-файл создан в `/data/user/0/<pkg>/files/` (uid приложения).
    - testapp `chain`: наш ctor отрабатывает **раньше** ctor'а самой либы (инициализаторы зависимостей идут первыми), при этом поведение приложения не изменилось (`stringFromJNI -> ORIGINAL`).
    - WhatsApp, `chain` по `libsuperpack.so`: `nativeloader: Load .../split_config.arm64_v8a.apk!/lib/arm64-v8a/libsuperpack.so ... ok` → в ту же миллисекунду `NATIVE_PAYLOAD_CTOR tag=libarchin.so`, proof-файл в `/data/user/0/com.whatsapp/files/archinome_native.txt` (uid 10258); **воспроизводится на холодном старте**, FATAL нет, нативный стек WhatsApp грузится (36 либ), UI поднялся.
      - Технически важно: bionic разрешил нашу зависимость **изнутри APK-архива** (`extractNativeLibs=false`), а вытесненный `libandroid.so` остался в графе на один шаг дальше — приложение не заметило подмены.
    - WhatsApp, `replace` по `libs.so`: payload срабатывает, но **только при промахе кэша**: `libs.so` — это superpack-загрузчик, который распаковывает реальные либы в `files/decompressed/libs.spo/`; при валидном кэше система его вообще не грузит (на холодном старте строки о загрузке `libs.so` нет). Отсюда выбор мишени: `libsuperpack.so` надёжнее.
    - ART **не** вызвал `JNI_OnLoad` нашего stub'а для либ WhatsApp (они грузятся вне `Runtime.loadLibrary`-пути вызова `JNI_OnLoad`) — payload живёт в конструкторе, который отрабатывает всегда.
  - **Грабли (зафиксировать):**
    - Замена либы обязана лечь **под тем именем, которое приложение запрашивает** (`System.loadLibrary("x")` → `libx.so`); установка payload'а под его собственным именем = `UnsatisfiedLinkError`. Покрыто тестом.
    - `chain` требует, чтобы имя влезло в существующий `DT_NEEDED` (у WhatsApp `libandroid.so` = 13 байт ≥ `libarchin.so` = 12; `libc.so` = 7 не подходит). Инструмент сам выбирает самый длинный слот и внятно падает, если места нет.
    - Каталога `files/` в свежем data dir приложения может не быть (есть только `cache/`) → payload делает `mkdir` и падает обратно на `cache/`.
    - Добавленные `.so` обязаны быть **STORED + page-aligned** (`zipalign -p`): при `extractNativeLibs=false` либы мапятся прямо из APK.
- [x] **Пункт 6 (Assets + DexClassLoader: шифрованный payload в assets/)** — реализован, проверен на testapp (все три триггера) и WhatsApp, без рута.
  - `pkg/assetpayload/` — формат `ARCHN1 | nonce(12) | AES-256-GCM(ct||tag)`, ключ = `SHA-256(passphrase)`; `Seal/Open/EncryptFile/DecryptFile`. 8 герметичных тестов (round-trip, layout заголовка, неверный ключ, подмена байта, мусор, вывод ключа, отказ на не-dex).
  - `cmd/assetcrypt/` — `seal`/`open`/`info`; `info` печатает magic, nonce и **SHA-256 открытого dex** — по нему сверяется результат на устройстве.
  - `assets_payload/` — `AssetLoader.java` (чтение ассета → расшифровка → сброс dex в приватный каталог → `DexClassLoader` → reflection) + три тонких триггера (`ArchinomeAppComponentFactory`, `ArchinomeProvider`, `ArchinomeReceiver`) + `dyn/dyn/Payload.java`. Сборка: `payload_assets.dex` (стаб, он же — единственный dex вектора) и `dyn_payload.dex` (сам payload, в APK не попадает).
  - CLI `-o 8`; env `ARCHINOME_ASSETS_VECTOR` (`appfactory` по умолчанию | `provider` | `receiver`), `ARCHINOME_ASSETS_DEX`, `ARCHINOME_ASSETS_KEY`. Манифест-патч переиспользует существующие патчеры: вектор отличается только способом доставки payload, а не триггером.
  - **Два пути чтения ассета:** через `Context.getAssets()` (провайдер/receiver) и **напрямую из APK-архива** (`ZipFile(ApplicationInfo.sourceDir)`) — второе нужно, потому что `instantiateClassLoader` (API 29+) вызывается до создания Application, где Context ещё не существует; `dataDir`/`sourceDir` приходят в `ApplicationInfo`.
  - **Проверено на testapp (без рута):** триггер-фабрика (раньше Application: `ctx=false`, чтение из архива) — `ASSET_READ_FROM_APK 3642 -> ASSET_DECRYPTED 3608 -> ASSET_PAYLOAD_EXECUTED -> ASSET_PAYLOAD_INVOKED dyn.Payload.executePayload`; триггер-провайдер (`ctx=true`, чтение через AssetManager); триггер-receiver — payload сработал **по `MY_PACKAGE_REPLACED` без запуска приложения**.
  - **Проверено на WhatsApp:** фабрика REPOINT (`androidx.core.app.CoreComponentFactory` → наша), ассет прочитан из `base.apk`, payload исполнен внутри `com.whatsapp` (pid 22561), приложение живо, краша нет.
  - **Контроль качества (без рута):** payload логирует `ASSET_DEX_SHA256`; SHA-256 dex, сброшенного на устройстве, **совпал байт-в-байт** с SHA-256 исходного `assets_payload/dyn_payload.dex` на хосте (`ee226f5d…9e4f`). Плюс рядом с dex появляется каталог `oat/` — ART действительно его скомпилировал.
  - Статически в APK: `assets/archinome_payload.enc` (3642 Б) + стаб `classes2.dex`; строки payload в APK **не находятся** (`grep -c ASSET_PAYLOAD_EXECUTED` = 0). Утечка имён (`dyn.Payload`, `executePayload`, имя ассета) в стабе остаётся — это obfuscation, а не секретность: ключ выводится из константы в стабе.
  - Грабли:
    - **ART отвергает dex, который процесс может записать** (`SecurityException: Writable dex file ... is not allowed`). Проверка — `access(path, W_OK)` по реальному uid, поэтому для файла, **принадлежащего самому приложению**, не хватает и `0600`: нужен `0400` (снят и owner-write). Раньше (вектор 4) dex лежал в `/data/local/tmp` под `shell`, и там `0644` работало — та же проверка, другой владелец.
    - Перед перезаписью read-only dex его надо **удалить** (каталог writable, так что unlink разрешён) — иначе `FileOutputStream` падает на EACCES.
    - **Свежеустановленное приложение находится в состоянии *stopped*** и не получает широковещаний, пока его не запустят: `MY_PACKAGE_REPLACED` не пришёл, а `am force-stop` возвращает stopped-флаг обратно. Пришлось поднять версию (`versionCode` 2→4) и ставить обновление на уже запущенное приложение. `BOOT_COMPLETED` из shell отправить нельзя (`SecurityException`, uid 2000).
    - `Payload` получал `null` вместо Context в `provider`/`receiver`-путях (в `install()` Context не прокидывался) — исправлено, теперь `ctx=true`.

---

## Аудит универсальности (2026-09-11) — проверка «не заточено под WhatsApp/testapp»

**Метод.** Собрал враждебный корпус и прогнал вектора на нём без рута (рут — только чтение data-dir):
- `testapp_legacy/` (новый фикстур, legacy-aapt): **свой `Application`**, уже существующие `provider` **и** `receiver`, **два** launcher-`activity` + `<activity-alias>`, `assets/`, **нет** `lib/`;
- реальный сторонний APK: F-Droid 1.13.1 (два launcher-входа, один — скрытый «panic» с `enabled=0`, свой `FDroidApp`);
- split-APK: WhatsApp 2.26.35.75 (`install-multiple` — base + сплиты, **все** переподписаны одним ключом, иначе `signatures are inconsistent`);
- регресс на `testapp` и WhatsApp.

Проверка каждого вектора: инжект без паники → `adb install` → payload в logcat (фильтр **по pid**) → **свой код хоста жив** (`Application.onCreate`, существующий провайдер, реальная target-активити) → число launcher-записей (`aapt2 dump badging`) → md5 установленного APK == подписанному на хосте.

**Итог по векторам:**

| # | Вектор | Вердикт |
|---|--------|---------|
| 1 | Custom (Application hijack) | **сломан** — см. ниже |
| 2 | Frida gadget | не проверялся сквозным путём: нужен внешний `frida-gadget.so`, которого нет в репозитории |
| 3 | ContentProvider | универсален: legacy (свой Application + уже есть провайдер), F-Droid, WhatsApp, testapp |
| 4 | Trampoline | универсален **после переделки**: legacy (2 activity + alias), F-Droid (скрытый launcher), testapp, WhatsApp |
| 5 | BroadcastReceiver | универсален: legacy (receiver уже был), testapp, WhatsApp |
| 6 | AppComponentFactory | универсален: ADD (testapp, legacy — свой `MyApp` поднимается штатно), REPOINT (WhatsApp, F-Droid) |
| 7 | Native (.so) | не универсален **по природе цели**: нужен `lib/<abi>/` в APK (на legacy-фикстуре без либ — честный отказ), стратегия `append` недоступна на clang/lld-либах |
| 8 | Assets + DexClassLoader | универсален: legacy (триггеры appfactory/provider/receiver), F-Droid, WhatsApp (SHA-256 dex совпал) |

**Что починено в этом аудите**
- **Trampoline (вектор 4) не устанавливался на реальных приложениях.** `android:targetActivity` (0x01010202) обычно **отсутствует** в resource map хоста (aapt2 мапит только использованные имена), поэтому синтезированный `<activity-alias>` давал `INSTALL_PARSE_FAILED_MANIFEST_MALFORMED`. Переделано: трамплин **забирает единственный launcher** — переименование `android:name` хост-активити + **удаление** MAIN/LAUNCHER `<intent-filter>` у остальных компонентов (только удаления и перезапись значений, ни одного нового имени атрибута). Плюс: хост выбирается как первый **не**`enabled=0` launcher-activity (скрытые/«panic»-иконки включаются только в рантайме), и `<meta-data>` требует `android:value`, поэтому key-only схема отброшена.
- **Вектор 1 больше не выпускает «кирпич».** `dex.Patch()` правит `InjectedApp.dex` **in-place** и переименовывает placeholder-класс `z.z.z` в класс Application хоста; на текущем фикстуре переименование не попадает в строку, на которую ссылается суперкласс обёртки. Плюс относительное `android:name=".MyApp"` нормализовалось в несуществующий `L/MyApp;`. Итог: ART не может загрузить обёртку → приложение падает на старте с `ClassNotFoundException` (проверено на устройстве). Сейчас: `manifest.HostAppClassName()` даёт FQN, а `pkg/dex.Validate` + `ValidateSuperclass` **отказываются писать APK** с внятным сообщением (проверка структуры, наличия класса, сортировки `string_ids` — ART ищет строки бинарным поиском).

**Открытые вопросы**
- Вектор 1: нужен либо настоящий dex-writer (переименование класса с пересортировкой `string_ids`), либо обёртка-делегат (читает FQN хоста из meta-data; ломает приложения, которые кастуют `getApplication()`). Требует решения — какой путь брать.
- Вектор 1 не умеет ADD: без `android:name` в `<application>` патч паникует (`Application name wasn't found`) — нужен ADD-путь как в provider/appfactory.
- Тот же ресмап-риск остаётся в `receiver_patch.go` (добавляет `android:exported` через дописывание resmap) — на хостах без этого слота патч может дать неустановимый APK; стоит перенести правило «не расширять resmap для валидируемых атрибутов» на все патчеры.
- Вектор 2 (frida) и «холодные» триггеры receiver (ребут) сквозным путём не перепроверялись.
