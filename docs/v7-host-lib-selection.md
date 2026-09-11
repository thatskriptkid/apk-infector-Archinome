# Вектор 7 (нативный): почему payload срабатывает только в 3–5 из 20 приложений

Статический разбор (без устройства) отбора host-библиотеки и режимов инжекта,
с классификацией каждого отказа корпуса из 20 F-Droid приложений и
рекомендацией по эвристике выбора host-либы.

> Всё в этом документе получено **статически**: чтение кода, `llvm-readelf -d`,
> `dexdump -d`, `aapt2 dump xmltree`, разбор zip-структуры APK и локальный
> прогон самого инструмента (`./archinome ... -o 7`) на файлах корпуса.
> Устройство не использовалось, adb не вызывался, код инструмента не менялся.

---

## 1. Резюме

Причина «3 из 8» — не одна, а три независимых ограничителя, наложенных друг на друга.

| Причина | Приложений | Что именно |
|---|---|---|
| (а) в APK нет `lib/<abi>` под arm64-v8a (или только чужая ABI) | **7** | 6 приложений вообще без `lib/`; у `notesnook` в APK только `x86_64`, и сборки payload под x86_64 нет |
| (б) цепочка не влезает + подмена невозможна + append невозможен | **5** | самая длинная `DT_NEEDED` у host-либы 8–9 байт < 12 байт имени payload; новое имя для `replace` (33 байта) не влезает в 31-байтный слот плейсхолдера; свободных слотов после `DT_NULL` нет |
| (в) host-либа не загружается при старте (ленивая загрузка) | **3** | `syncthingfork` (загрузка в `SyncthingService`), `saracroche` (`libdatastore_shared_counter.so` вообще не упомянут в dex), `gallery` (host `libjxl.so` грузится только транзитивно, через `libjxlcoder.so`) |
| (г) установка падала до фикса | **4** | `extractNativeLibs="false"` + добавленный payload в ZIP был DEFLATE, а не STORED/page-aligned → `Failed to extract native libraries, res=-110`. **Уже исправлено** (коммит `32e6dc4`, «STORED .so») |

12 `INJECT_FAIL` = 7 (а) + 5 (б) — сходится ровно.
Оставшиеся `NO_PAYLOAD` — это 1 из matrix-прогона (`syncthingfork`) и ещё 2
(`saracroche`, `gallery`), которые стали видны только после фикса установки
(в matrix они маскировались `INSTALL_FAIL`).
Причина (б) целиком устраняется коротким именем payload (см. §7), причина (в) —
эвристикой «грузится ли эта либа приложением по имени» (см. §7).

---

## 2. Как инструмент выбирает host и режим (по коду)

Источники: `pkg/nativepatch/nativepatch.go`, `pkg/elfpatch/elfpatch.go`,
`internal/injector/inject_zip.go`.

**Выбор host.** `pickHost(libDir, want)`: если `ARCHINOME_NATIVE_HOST` не задан —
это **самая большая по размеру** `lib/<abi>/*.so`. Пользовательского ранжирования нет:
размер — единственный критерий.

**Набор ABI.** `abiDirs(root, ARCHINOME_NATIVE_ABI)`. При пустом `ABI` берутся **все**
подкаталоги `lib/`. Для каждой ABI нужен payload `native_payload/out/<abi>/libarchin.so`;
если его нет — ABI **молча пропускается** (`skipped`), а если пропущены все —
`no payload library available for <abi>`. Сборка payload есть только под `arm64-v8a`.
Важно: ошибка на **любой** ABI прерывает `Apply()` целиком (`return results, err`),
результаты по уже обработанным ABI не сохраняются.

**Цепочка режимов** задаётся вызывающей обвязкой (`/tmp/corpus/harness.sh`):
`for M in chain replace append; do ... if [ -s "$OUT" ]; then break; fi; done` —
то есть берётся **первый режим, который дал непустой APK**. Именно поэтому в
`INJECT_MSG` попадает сообщение **последней** (append) попытки, а не самой
информативной: у пяти приложений из (б) реально падают все три режима, но виден
только текст про `DT_NULL`.

**Ограничения режимов (проверено по коду и подтверждено на файлах корпуса):**

| Режим | Что делает | Жёсткое ограничение |
|---|---|---|
| `chain` | `PickNeeded(len(ourName))` — выбирает `DT_NEEDED` с максимальной ёмкостью и `Capacity >= len(ourName)`; payload кладётся под именем `libarchin.so` и получает `DT_NEEDED` = вытесненная либа | `len(ourName)` (12) ≤ ёмкость существующей строки. `Capacity == len(name)`, т.е. длина вытесняемой строки без NUL. `libc.so`=7, `libm.so`=7, `libdl.so`=8, `liblog.so`=9 — все **меньше 12** |
| `replace` | host → `<host>_orig.so`, payload встаёт под именем host | `writePayload` вызывает `ReplaceBytes(data, Placeholder, dep)`, где `Placeholder = "libarchinome_dependency_slot.so"` — **31 байт**. Значит новое имя `dep = <host>_orig.so` обязано быть ≤ 31. Порог: база имени host ≤ 23 байт |
| `append` | `AddNeeded()` — новая `DT_NEEDED` в слот `DT_NULL` + место под строку после `.dynstr` | Нужен (1) свободный слот сразу после терминатора, (2) нулевые байты в нём, (3) ≥ `len(name)+1` нулевых байт после конца `.dynstr` внутри mapped-сегмента. У clang/lld этого нет почти никогда |

Имя payload по умолчанию — `filepath.Base(payloadPath)` = `libarchin.so` (**12 байт**),
переопределяется `ARCHINOME_NATIVE_NAME`. Слоность: **12 байт — это и есть корень
проблемы (б)**, потому что подавляющее большинство `DT_NEEDED` в Android-библиотеках
короче.

---

## 3. Методика: что именно проверено

1. **Прогон лестницы режимов локально** (`chain → replace → append`, те же env, что в
   `harness.sh`, скрипт `/tmp/v7probe/ladder.sh`, лог `/tmp/v7probe/ladder.txt`).
   Результат **полностью совпал** с матрицей на устройстве: те же 8 «inject ok»
   и те же режимы (`replace` для torrserve/syncthingfork, `chain` для остальных шести),
   те же 12 отказов и те же тексты ошибок. То есть выбор режима воспроизводится статически.
   ⚠️ Текущий бинарник уже содержит фикс STORED, поэтому локальный прогон отражает
   **пост-фикс** состояние установки; на выбор режима фикс не влияет (сверено построчно).
2. **`llvm-readelf -d`** по каждой `lib/arm64-v8a/*.so` всех 20 APK → `DT_NEEDED`, `SONAME`, ёмкости слотов.
3. **`dexdump -d`** по всем `classes*.dex` → сайты `invoke-static Ljava/lang/System;->loadLibrary(...)` с классом-загрузчиком.
4. **`aapt2 dump xmltree`** → `android:extractNativeLibs` для всех 20 APK.
5. **Разбор zip** выходного APK (`zipalign -c -v 4`) → метод хранения и выравнивание добавленного payload.
6. Код: `pkg/nativepatch/nativepatch.go`, `pkg/elfpatch/elfpatch.go`, `internal/injector/inject_zip.go`,
   `internal/injector/ziprepack.go`; `git log` (только чтение).

---

## 4. Таблица по всем 20 приложениям

«Ёмкость» — максимальная ёмкость `DT_NEEDED` у host-либы (= длина самой длинной строки),
для `chain` нужно ≥ 12.

| # | Приложение | Что есть в `lib/` (arm64) | Выбрал инструмент | Ёмкость | Режим (итог) | Ожидается при старте (статика) | Вердикт прогона |
|---|---|---|---|---|---|---|---|
| 1 | `ru.yourok.torrserve` | `libconscrypt_jni.so` 2.1 МБ | он же (единственная) | 9 | chain ✗ → **replace** (24 ≤ 31) | **да** — `org/conscrypt/NativeCryptoJni` `loadLibrary("conscrypt_jni")`, TLS поднимается на старте | **PAYLOAD_OK** |
| 2 | `app.organicmaps` | `liborganicmaps.so` 15.8 МБ | он же | 13 (`libandroid.so`) | **chain** | **да** — `app/organicmaps/sdk/OrganicMaps` `loadLibrary("organicmaps")` | **PAYLOAD_OK** |
| 3 | `fm.helio` | `libjuce_jni.so` 13.7 МБ (только arm64+v7a) | он же | 13 (`libandroid.so`) | **chain** | **да** — `com/rmsl/juce/Java` `loadLibrary("juce_jni")` | **PAYLOAD_OK** |
| 4 | `dev.patrickgold.florisboard` | `libandroidx.graphics.path.so` 10 КБ + `libfl_native.so` 1.37 МБ | `libfl_native.so` (больше) | 13 (`libandroid.so`) | **chain** | **да** — `FlorisApplication` `loadLibrary("fl_native")` | PAYLOAD_OK после фикса `STORED` (в matrix — INSTALL_FAIL, причина г) |
| 5 | `me.knighthat.kreate` | `androidx.graphics.path` 10 КБ + `libsqliteJni.so` 1.31 МБ | `libsqliteJni.so` | 13 (`libandroid.so`) | **chain** | **да** — `BundledSQLiteDriver$NativeLibraryObject` `loadLibrary("sqliteJni")`, БД открывается на старте | PAYLOAD_OK после фикса (в matrix — INSTALL_FAIL) |
| 6 | `com.cbouvat.android.saracroche` | `libandroidx.graphics.path.so` 10096 Б + `libdatastore_shared_counter.so` 10360 Б | `libdatastore_shared_counter.so` (на 264 Б больше!) | 13 (`libandroid.so`) | **chain** | **нет** — строка `datastore_shared_counter` в dex **отсутствует**; `androidx.graphics.path` грузится только из `PathIteratorPreApi34Impl` | INSTALL_FAIL в matrix → **NO_PAYLOAD** после фикса |
| 7 | `com.github.catfriend1.syncthingfork` | `androidx.graphics.path` 10 КБ + `libsyncthingnative.so` 27.8 МБ | `libsyncthingnative.so` | 9 | chain ✗ → **replace** (26 ≤ 31) | **нет при старте** — имя либы используется в `com/nutomic/syncthingandroid/service/SyncthingService*` и `Constants`, т.е. в сервисе синхронизации, а не в launcher-активности | **NO_PAYLOAD** |
| 8 | `org.fossify.gallery` | 12 либ; крупнейшая `libjxl.so` 2.02 МБ (`androidx.graphics.path`, `libjxlcoder.so` 1.6 МБ, `libavif_android.so`, brotli*, `libNativeImageProcessor.so`, `libglide-webp.so`, `libpl_droidsonroids_gif.so`) | `libjxl.so` | 16 (`libbrotlicommon.so`) | **chain** | **нет** — `libjxl.so` не упомянут в dex вообще, он транзитивная зависимость `libjxlcoder.so`; в dex грузятся `jxlcoder`, `avif_android`, `glide-webp`, `pl_droidsonroids_gif`, `NativeImageProcessor` — все по требованию (кодеки) | INSTALL_FAIL в matrix → **NO_PAYLOAD** после фикса |
| 9 | `org.localsend.localsend_app` | `libapp.so` 14.5 МБ, `librust_lib_localsend_app.so` 16.7 МБ, `libflutter.so` 11.3 МБ, `libdartjni.so`, `libdatastore_shared_counter.so` | `librust_lib_localsend_app.so` (крупнейшая) | 9 | chain ✗ → replace ✗ (33 > 31) → append ✗ | — (инжект не состоялся) | **INJECT_FAIL** (б) |
| 10–13 | `com.kitsumed.shizucallrecorder`, `org.fossify.filemanager`, `io.github.rumcajs.offlinewebsearch`, `de.marmaro.krt.ffupdater` | **только** `libandroidx.graphics.path.so` 10096 Б (`DT_NEEDED`: `libm.so`,`libdl.so`,`libc.so`) | она же | **8** | chain ✗ → replace ✗ (33 > 31) → append ✗ | — | **INJECT_FAIL** (б) |
| 14 | `com.streetwriters.notesnook` | только `x86_64` (30 либ), **arm64 нет** | — | — | — | — | **INJECT_FAIL** (а): `no payload library available for x86_64`; оригинальный APK на устройстве тоже не ставится (`INSTALL_FAILED_NO_MATCHING_ABIS, res=-113`) |
| 15–20 | `com.chess.clock`, `com.foxdebug.acode`, `org.catrobat.paintroid`, `org.cryptomator.lite`, `org.vinaygopinath.launchchat`, `rak.pixellwp` | `lib/` отсутствует целиком | — | — | — | — | **INJECT_FAIL** (а): `no lib/<abi>/ directory` |

Сводка режимов: `chain` выбран в 6 случаях (organicmaps, helio, florisboard, kreate,
saracroche, gallery), `replace` — в 2 (torrserve, syncthingfork), `append` — **ни разу**
(недоступен ни для одного APK корпуса).

---

## 5. Разбор каждой группы отказов

### (а) Нет `lib/<abi>` под ABI устройства — 7 приложений
Проверено: 6 APK имеют пустой/отсутствующий `lib/` (проверено обходом zip),
`notesnook` содержит **ровно один** ABI — `x86_64` (30 библиотек), при этом payload
собирается только под `arm64-v8a` (`native_payload/out/arm64-v8a/libarchin.so`).
Формулировка в коде (`no payload library available for x86_64`) вводит в заблуждение:
проблема не в отсутствии payload, а в **отсутствии arm64-кода в самом APK** — даже
при наличии payload под x86_64 на Pixel 6a эта библиотека не загрузилась бы.
Для 6 приложений без `lib/` и без нативного кода нативный вектор неприменим
в принципе (ни цепочка, ни подмена, ни append).

### (б) Цепочка не влезает + подмена невозможна + append недоступен — 5 приложений
Единственная реально «починяемая» группа. Все три режима упираются в три разных лимита:

* `chain`: ёмкость самого широкого `DT_NEEDED` у host-либы равна **8** (`libdl.so` у
  `libandroidx.graphics.path.so`) или **9** (`liblog.so` у `libconscrypt_jni.so`,
  `librust_lib_localsend_app.so`), а имя payload — **12** байт (`libarchin.so`).
  8 < 12 и 9 < 12 → `PickNeeded` возвращает `nil`.
* `replace`: `renamed = <база host>_orig.so`. Для `libandroidx.graphics.path.so` и
  `librust_lib_localsend_app.so` это **33 байта** > 31-байтного `Placeholder` →
  `ReplaceBytes` отказывает («replacement ... is longer than ...»).
  Порог: база имени host ≤ 23 байт.
* `append`: `planAddNeeded` требует свободный слот после `DT_NULL` и нулевые байты
  после `.dynstr`. У clang/lld ни того, ни другого нет → «dynamic table has no free
  slots after the terminator».

Итог: `INJECT_FAIL` у этих 5 приложений — **не** «инструмент отказался», а честный
отказ всех трёх стратегий. Диагностика показывает только третью причину (лимит
обвязки harness), из-за чего картина выглядит как «инструмент сдался на DT_NULL».

### (в) Host-либа не загружается при старте — 3 приложения (главная причина NO_PAYLOAD)
`chain`/`replace` срабатывают только если host-либа реально попадает в процесс.
Payload либо становится её `DT_NEEDED` (chain), либо подменяет её файл (replace) —
и в обоих случаях точка входа `__attribute__((constructor))` выполнится **только в
момент загрузки host-либы**. Проверено по `dexdump -d`:

* `syncthingfork` — `libsyncthingnative.so` фигурирует в `Constants` и
  `SyncthingService`/`SyncthingService$1`. Это сервис синхронизации; при запуске
  launcher-активности через `monkey` он не поднимается. Загрузка → ленивая, NO_PAYLOAD.
* `saracroche` — host `libdatastore_shared_counter.so` (выбран лишь потому, что он на
  264 байта больше `libandroidx.graphics.path.so`). Строки `datastore_shared_counter`
  в dex **нет вообще**; путь `androidx.datastore` в dex есть, но обфусцирован и, судя
  по отсутствию строки, нативный счётчик вырезан R8. Либа лежит в APK, но приложение
  её не открывает **никогда**.
* `gallery` — host `libjxl.so` (крупнейшая). В dex **нет** `loadLibrary("jxl")`;
  `libjxl.so` подтягивается только как зависимость `libjxlcoder.so`, а тот грузится
  `com/awxkee/jxlcoder/*` по требованию (декодирование JXL-изображения). Никакая либа
  галереи не грузится безусловно на старте: `glide-webp`/`avif_android`/
  `pl_droidsonroids_gif`/`NativeImageProcessor` — все кодеки «по необходимости».

**Предположения (не проверено статически):** что именно `SyncthingService` вызывает
`loadLibrary` (в dex рядом с `libsyncthingnative.so` нет прямой пары
`const-string`+`invoke loadLibrary`, строка используется через `Constants`), и что
`androidx.graphics.path` при SDK 37 уходит в `PathIteratorImpl` (API≥34), который тоже
не вызывается на старте. Оба места помечены как гипотезы; вывод «при старте не
грузится» следует из отсутствия вызова на пути Application/launcher-активности.

### (г) Установка падала до фикса — 4 приложения (исправлено)
Точная корреляция (проверено `aapt2 dump xmltree`):

| APK | `extractNativeLibs` | Итог до фикса |
|---|---|---|
| florisboard, saracroche, kreate, gallery | **`false`** | `INSTALL_FAIL`, `Failed to extract native libraries, res=-110` |
| organicmaps (`true`), helio (не задан → `true`), torrserve (`true`), syncthingfork (`true`) | `true` | инжект и установка прошли |

Механизм: при `extractNativeLibs="false"` платформа маппит `.so` прямо из APK и
требует, чтобы **все** записи `lib/<abi>/*.so` были STORED и выровнены по странице.
Инжектор добавлял payload как DEFLATE → нарушение → `res=-110`. Совпадение 4/4 по
`extractNativeLibs=false` — сильный аргумент, что это и есть причина.
**Проверено, что фикс работает:** текущий бинарник для `dev.patrickgold.florisboard`
(chain) даёт добавленный `lib/arm64-v8a/libarchin.so` с `method=0` (STORED) и смещением
данных `14065664`, `14065664 % 4096 == 0`; `zipalign -c -v 4` → `Verification succesful`.
Коммит `32e6dc4` («потоковый репак, … STORED .so»).

---

## 6. Корневые причины (сводно)

1. **Имя payload «libarchin.so» = 12 байт** — длиннее почти всех `DT_NEEDED` в
   Android-библиотеках (`libc.so`=7, `libdl.so`=8, `liblog.so`=9). Это выключает `chain`
   на любой «типовой» либе и загоняет инструмент в `replace`.
2. **Плейсхолдер payload = 31 байт** — `replace` не работает для host-либ с базой
   имени > 23 байт. Это ровно те случаи, где `replace` был единственной альтернативой
   (имя `androidx.graphics.path` и `rust_lib_localsend_app` = 25 байт). Отсюда —
   двойной отказ (chain + replace) на 5 приложениях и на `localsend`.
3. **Ранжирование host по размеру не коррелирует с загрузкой на старте.**
   Самая большая либа — часто «тяжёлый» кодек или транзитивная зависимость
   (`libjxl.so`, `librust_lib_localsend_app.so`), которая может вообще не загружаться
   до востребования; при этом маленькая либа из `System.loadLibrary` в `Application`
   гарантировала бы срабатывание. Размер как прокси «грузится первой» неверен:
   у `localsend` крупнейшая `librust_lib_localsend_app.so` (16.7 МБ) не грузится
   кодом dex, а `libflutter.so` (11.3 МБ) грузится и **влезает в chain** (ёмкость 17).
4. **`libandroidx.graphics.path.so`** — маленькая (10 КБ) ленивая утилита, которую
   цепочка Maven всё чаще кладёт во все APK; она почти всегда оказывается
   единственной либой в тех приложениях, где нативного кода больше нет.
5. **Диагностика врёт**: harness берёт только последнюю попытку, а сам `Apply()`
   прерывается на первой ошибке ABI, поэтому пользователю видно одно (часто
   наименее информативное) сообщение из 3–9 фактических отказов.

---

## 7. Рекомендация: эвристика ранжирования host-либы

### 7.1 Что предпочитать (порядок приоритетов)

Ранжировать кандидатов по «гарантии загрузки в целевом процессе», а не по размеру:

1. **Либа, которую приложение само грузит по имени из кода, достигаемого на старте**
   (`System.loadLibrary("<base>")` в `Application.<init>/<clinit>/onCreate`, в
   `ContentProvider.onCreate`, в `androidx.startup`-провайдере или в `<clinit>`/`onCreate`
   launcher-активности). Примеры-эталоны: `libfl_native.so` (florisboard),
   `liborganicmaps.so`, `libjuce_jni.so`, `libflutter.so` (localsend), `libsqliteJni.so`.
2. **Либа, которую приложение грузит по имени где угодно** (даже лениво) — второй
   эшелон: сработает, если сценарий прогона дотянется до этого кода
   (`libconscrypt_jni.so` в torrserve, `libjxlcoder.so` в gallery).
3. **Либа, не упомянутая в dex ни одним `loadLibrary`** — как хост допустима, только
   если она является зависимостью (по `DT_NEEDED`) либы из п.1, т.е. «поедет» вместе
   с ней. Иначе — не выбирать.
4. **Чёрный список ленивых/утилитарных либ** (никогда не хост при наличии альтернатив):
   `libandroidx.graphics.path.so`, `libdatastore_shared_counter.so`, кодек-библиотеки
   (`libjxl*.so`, `libbrotli*.so`, `libavif_android.so`, `libglide-webp.so`,
   `libpl_droidsonroids_gif.so`, `libNativeImageProcessor.so`), `libdartjni.so`.

Практический эффект на этом корпусе:
* `localsend`: вместо `librust_lib_localsend_app.so` (ёмкость 9, chain невозможен) —
  `libflutter.so` (ёмкость 17, **chain проходит**, и она грузится на старте
  `FlutterLoader`). `INJECT_FAIL` → ожидаемый `PAYLOAD_OK`.
* `syncthingfork`, `saracroche`, `gallery`: корректный хост определить нельзя
  (единственная альтернатива тоже ленивая/неиспользуемая) — честный вердикт
  «вектор 7 для этого APK ненадёжен», а не молчаливый `NO_PAYLOAD` после установки.

### 7.2 Короткое имя payload — убирает причину (б) целиком

Главная победа по покрытию. Если имя payload ≤ 8 байт (например `liba.so` = 7,
`libach.so` = 8), то `PickNeeded(7)` находит слот в **любой** из пяти проблемных либ:

| host | самая длинная `DT_NEEDED` | `libarchin.so` (12) | `liba.so` (7) |
|---|---|---|---|
| `libandroidx.graphics.path.so` | `libdl.so` = 8 | ✗ | ✓ |
| `librust_lib_localsend_app.so` | `liblog.so` = 9 | ✗ | ✓ |
| `libconscrypt_jni.so` | `liblog.so` = 9 | ✗ | ✓ |
| `libsyncthingnative.so` | `liblog.so` = 9 | ✗ | ✓ |

Требуется: (1) собирать/раскладывать payload под коротким именем
(`ARCHINOME_NATIVE_NAME=liba.so`) и (2) **пропатчить `DT_SONAME` payload** на то же
имя in-place (12 → 7 байт с NUL-добивкой влезает), иначе загрузчик зарегистрирует
уже загруженную библиотеку под `SONAME`, отличным от запрошенного `DT_NEEDED`, что
приводит к повторной загрузке/неоднозначной резолюции зависимостей.
Замечание: `chain` в этом случае вытеснит ровно `libm.so`/`libdl.so` — payload
обязан сам прописать их в качестве своей `DT_NEEDED`, что `writePayload` уже делает.

Дополнительно: сделать режим **явным флагом**, а не лестницей «первый удавшийся».
`chain` предпочтительнее `replace`: он не меняет имя, по которому приложение просит
либу, и не зависит от порога в 31 байт.

### 7.3 Устранение причины (а)
Для APK без arm64-кода (`notesnook`, 6 приложений без `lib/`) — обязательный
предварительный гейт по инвентарю: если в APK нет `lib/arm64-v8a/*.so`, вектор 7
помечается «неприменим» **до** попыток инжекта (сейчас так и происходит, но текст
говорит про ABI payload, а не про ABI приложения — см. §8).

---

## 8. Что добавить в диагностику инструмента

Чтобы инструмент сам называл причину отказа (сейчас видно одно сообщение из трёх):

1. **Полная матрица попыток.** Печатать результат **каждого** режима отдельно
   (`chain: <причина>` / `replace: <причина>` / `append: <причина>`), а не только
   последний. Сейчас именно это скрывает двойной отказ на 5 приложениях.
2. **Предсказание «сработает ли payload»** сразу после выбора host — это самая
   ценная строка, потому что она ловит причину (в) до установки на устройство:
   * `host=<имя> size=<N>`
   * `chain: max DT_NEEDED capacity=<K>, need len("<ourName>")=<L> → fits|no-fit`
   * `replace: renamed="<base>_orig.so" len=<R>, placeholder capacity=31 → fits|no-fit`
   * `append: free_slot=<да/нет>, room_after_dynstr=<байт> → fits|no-fit`
   * `app-loads-host: <base> referenced by System.loadLibrary in <class>.<method> → yes|NO`
     (если NO — прямо писать: «payload, вероятно, не сработает: host не загружается
     кодом приложения; ожидайте NO_PAYLOAD»).
3. **Не прерывать `Apply()` на первой ABI.** Сейчас ошибка на любой ABI отменяет
   весь инжект, а пропуск ABI из-за отсутствия payload только добавляется в `skipped`;
   при ABI-only гейте различие «нет кода под arm64» vs «нет payload под x86_64»
   теряется. Полезно вернуть по-ABI отчёт: `arm64-v8a: patched` / `armeabi-v7a: no payload` /
   `x86_64: no payload`, и итоговый вердикт «приложение не содержит arm64-кода».
4. **Проверка применимости ZIP.** Для приложений с `extractNativeLibs="false"`
   печатать напоминание о требовании STORED + page-aligned для добавленного `.so`
   и предупреждать, если APK не был прогнан через `zipalign -p 4`.
5. **Различать «инструмент отказался» и «стратегия невозможна»** в тексте. Сейчас
   `dynamic table has no free slots after the terminator` читается как сбой; на деле
   это исчерпание append, о котором стоит говорить как «append недоступен; см. других
   кандидатов и полную матрицу».

---

## 9. Границы анализа

* Всё выше — результат статического разбора файлов и кода. **Никаких утверждений о
  поведении на устройстве, кроме тех, что зафиксированы в `matrix.tsv`/`verify*.log`.**
* Два пункта в §5(в) помечены как гипотезы: точный вызов загрузки в `SyncthingService`
  (строка проходит через `Constants`, прямой пары в dex нет) и ветка
  `PathIteratorImpl` vs `PathIteratorPreApi34Impl` на SDK 37.
* Вывод «`localsend` пройдёт на `libflutter.so`» получен по статике (ёмкость 17 у
  `DT_NEEDED` + `loadLibrary("flutter")` в `FlutterLoader`); живой проверки нет.
* Прогон лестницы режимов выполнен **текущим** бинарником (с фиксом STORED).
  На выбор режима фикс не влияет — сверено с `matrix.tsv` построчно по всем 20 строкам
  вектора 7.


## 10. Замер вместо эвристики (реализовано)

Статическая эвристика (§7) не может ответить на главный вопрос: загружает ли хост
выбранную либу **при холодном старте**. Из APK это не видно, а именно на этом
ломались 8 хостов из 19, где вектор 7 вообще применим. Ответ даёт замер:
`/proc/<pid>/maps` запущенного хоста.

Инструмент замера: `tools/corpus/learn-host-lib.sh <apk> <pkg>`

```
$ tools/corpus/learn-host-lib.sh apk/ru.yourok.torrserve.apk ru.yourok.torrserve
MEASURED=1
PID=5136
CANDIDATES=libconscrypt_jni.so
HOST_LIB=libconscrypt_jni.so
NOTE=загружено при холодном старте: libconscrypt_jni.so
```

Как это встроено в прогон: харнесс (`tools/corpus/harness.sh`, вектор 7) перед
инжектом ставит **оригинал**, запускает его, ждёт 6 с, снимает `maps` через `su`
(чтение `maps` чужого процесса требует root) и передаёт результат инжектору в
`ARCHINOME_NATIVE_HOST`. Если загруженных своих либ нет — это неприменимость, а не
сбой инжекта, и вердикт становится `NA_NO_LOADED_HOST_LIB` с причиной в `NA_NOTE`
(раньше такие хосты падали в общий `NO_PAYLOAD`, и отличить «не выбрал либу» от
«либа не грузится» было нельзя).

Что показал замер по корпусу (все 8 хостов, которые в прогоне 2 дали `NO_PAYLOAD`):

| Хост | Загруженные свои `lib/<abi>/*.so` |
| --- | --- |
| `app.chompass` | нет |
| `com.cbouvat.android.saracroche` | нет |
| `com.github.catfriend1.syncthingfork` | нет (и при `WAIT=25`) |
| `com.mardous.booming` | нет |
| `com.tnibler.cryptocam` | нет |
| `info.plateaukao.einkbro` | нет (и при `WAIT=25`) |
| `io.github.pastthepixels.freepaint` | нет |
| `org.fossify.gallery` | нет |
| контроль: `ru.yourok.torrserve` | `libconscrypt_jni.so` -> вектор 7 `PAYLOAD_OK` (режим `replace`) |

Вывод, который надо держать в голове: на этих восьми хостах цепляться при холодном
старте не за что — их нативные библиотеки грузятся только после навигации по UI
(проверено `WAIT=25`: на старте ноль своих либ). Для вектора 7 это граница
применимости, а не дефект; если хост нужен, сценарий надо менять (триггер после
взаимодействия), а не либу.

Ограничения замера: нужен root на тестовом устройстве и установка оригинала
(одна установка + запуск на каждый прогон вектора 7); замер смотрит только
холодный старт и первые секунды работы.
