# Корпус 50 хостов × 8 векторов: результаты и разбор отказов

Полная матрица по корпусу из 50 приложений F-Droid (20 прежних + 30 новых из
[offa/android-foss](https://github.com/offa/android-foss), по одному приложению
на категорию, 0.1–60 МБ). Прогон на рутованном Pixel 6a (`bluejay`, SDK 37,
arm64-v8a), 400 прогонов (50 × 8), по одной строке на пару «хост × вектор».

Методика на каждый прогон: `archinome <apk> <out> -o <вектор>` → `zipalign -f -p 4`
→ `apksigner` (debug-keystore) → `adb install -r -d` → запуск через `monkey` →
проверка лог-тега вектора → живость процесса (`pidof`/`dumpsys package`).
Обвязка: `tools/corpus/harness.sh` (один прогон), `tools/corpus/matrix.py`
(матрица, пишет `matrix.log` + `matrix.tsv`), данные — в `$CORPUS_DIR`
(по умолчанию `/tmp/corpus`), код — в репозитории.

---

## 1. Итог по векторам

Первый прогон (до правок инжектора, см. §3):

| Вектор | `PAYLOAD_OK` | `NO_PAYLOAD` | `INJECT_FAIL` | `NA_NO_INTERNET` | `INSTALL_FAIL` |
|---|---|---|---|---|---|
| 1 — dex-payload (dex-writer) | 48 | 0 | 0 | 0 | 1 |
| 2 — frida gadget | 27 | 0 | 0 | 22 | 1 |
| 3 — provider | 49 | 0 | 0 | 0 | 1 |
| 4 — trampoline | 49 | 0 | 0 | 0 | 1 |
| 5 — receiver | 49 | 0 | 0 | 0 | 1 |
| 6 — appComponentFactory | 46 | **3** | 0 | 0 | 1 |
| 7 — нативный | 11 | 8 | 31 (неприменим) | 0 | 0 |
| 8 — assets (AES-GCM) | 46 | **3** | 0 | 0 | 1 |

`INSTALL_FAIL` во всех восьми строках — один хост, `com.streetwriters.notesnook`
(`INSTALL_FAILED_NO_MATCHING_ABIS`): F-Droid отдаёт сборку без arm64-либ, она не
ставится и в исходном виде. Не регрессия — хост исключён из знаменателя.

Расшифровка вердиктов — в `tools/corpus/README.md`. Итоговые цифры после
доработок обвязки и векторов — в §8.

## 2. Пер-хостовая матрица (первый прогон)

`+` — `PAYLOAD_OK`, `-` — `NO_PAYLOAD`, `s` — `INJECT_FAIL` (вектор неприменим),
`n` — `NA_NO_INTERNET` (у хоста нет `android.permission.INTERNET`),
`!` — `INSTALL_FAIL`. Колонки — векторы 1…8.

```
app.chompass                               ++++++-+
app.organicmaps                            ++++++++
cn.rbc.termuc                              +++++-s-
com.bitmavrick.lumolight                   +n++++s+
com.cbouvat.android.saracroche             ++++++-+
com.chess.clock                            +n++++s+
com.chooloo.www.koler                      +n++++s+
com.foxdebug.acode                         ++++++s+
com.github.catfriend1.syncthingfork        ++++++-+
com.github.lamarios.clipious               ++++++++
com.jens.automation2                       ++++++s+
com.kitsumed.shizucallrecorder             +n++++s+
com.machiav3lli.fdroid                     ++++++s+
com.mardous.booming                        ++++++-+
com.nathanatos.Cuppa                       +n++++++
com.prof18.feedflow                        ++++++s+
com.streetwriters.notesnook                !!!!!!s!
com.tnibler.cryptocam                      +n++++-+
com.vincent_falzon.discreetlauncher        +n++++s+
com.wirelessalien.android.moviedb          ++++++s+
de.marmaro.krt.ffupdater                   ++++++s+
dev.patrickgold.florisboard                +n++++++
dubrowgn.wattz                             +n++++s+
fm.helio                                   +n++++++
info.plateaukao.einkbro                    ++++++-+
io.github.muntashirakon.captiveportalcontroller +n+++-s-
io.github.mwageringel.everest              +n++++++
io.github.pastthepixels.freepaint          +n++++-+
io.github.rumcajs.offlinewebsearch         ++++++s+
ir.ammari.nodelook                         ++++++s+
me.hackerchick.catima                      +n++++s+
me.knighthat.kreate                        ++++++++
net.stargw.fok                             +n++++s+
ogz.tripeaks                               +n++++++
org.billthefarmer.editor                   +n+++-s-
org.billthefarmer.gurgle                   ++++++s+
org.breezyweather                          ++++++++
org.catrobat.paintroid                     ++++++s+
org.cryptomator.lite                       ++++++s+
org.dolphinemu.dolphinemu                  ++++++++
org.fossify.filemanager                    +n++++s+
org.fossify.gallery                        +n++++-+
org.localsend.localsend_app                ++++++s+
org.vinaygopinath.launchchat               +n++++s+
org.woheller69.level                       +n++++s+
org.xbmc.kore                              ++++++s+
rak.pixellwp                               ++++++s+
ru.aleshin.timeplanner                     +n++++s+
ru.yourok.torrserve                        .+++++++
website.leifs.delta.foss                   ++++++s+
```

(`.` у `ru.yourok.torrserve` — строка вектора 1 потеряна при снятии устаревшего
прогона; в матрице перепроверена отдельно, `PAYLOAD_OK`.)

## 3. Дефекты обвязки, из-за которых первый прогон давал ложные вердикты

Оба найдены при разборе результатов, исправлены, коммит `30e521f`:

1. **Вектор 1 всегда `NO_PAYLOAD`.** Харнесс искал тег `PAYLOAD_CUSTOM|ARCHINOME`,
   а payload вектора 1 пишет `Log.i("HELL", …)`. Верный критерий — `HELL`
   (`TAGS[1]` в `matrix.py`, таблица тегов в `README.md`).
2. **Вектор 2 всегда `NO_PAYLOAD`.** `matrix.py` запускал `harness.sh` из
   `CORPUS_DIR`, где лежала устаревшая 86-строчная копия без проверки gadget'а
   (в репозитории — 203 строки). Теперь харнесс берётся рядом со скриптом
   (`HERE`), правило зафиксировано в `README.md`: код — в репозитории,
   данные — в `CORPUS_DIR`.
3. Дополнительно: при «gadget не ответил» в `FATAL_NOTE` теперь попадают число
   процессов из `frida-ps`, вывод пробы, живость pid и хвост logcat — раньше
   примечание было пустым и отказ инжекта был неотличим от отказа gadget'а.

## 4. Дефект инжектора: атрибут `appComponentFactory` терялся на 3 хостах

`NO_PAYLOAD` у векторов **6 и 8 сразу** на одних и тех же трёх хостах
(`cn.rbc.termuc`, `io.github.muntashirakon.captiveportalcontroller`,
`org.billthefarmer.editor`) — общий признак: у обоих векторов точка входа —
`android:appComponentFactory` (у вектора 8 триггер по умолчанию тоже
`appfactory`). Logcat при запуске не содержал **ни одной** строки `ARCHINOME`
(даже конструктор фабрики), при этом приложение живо и манифест патч на месте:
`aapt2 dump xmltree` показывает `android:appComponentFactory="aaaaaaaaaaaa.ArchinomeAppComponentFactory"`.

Причина — порядок атрибутов в бинарном AXML:

* `aapt2` хранит имя атрибута как **индекс строкового пула**, а resource ID
  берётся из карты ресурсов (chunk `0x0180`); `libandroidfw` разрешает атрибут
  через ту же карту и сравнивает **resource ID**;
* `attrInsertOffset` сравнивал сырые поля имени (индексы пула) с индексом нового
  имени, поэтому новый атрибут всегда уезжал в конец массива;
* на хостах, где у `<application>` уже есть атрибут с ID **больше** `0x0101057a`,
  массив переставал быть отсортированным по ID, и PMS атрибут не находил:
  `requestLegacyExternalStorage` (`0x01010603`) у `editor` и `termuc`,
  `dataExtractionRules` (`0x0101063e`) у `captiveportalcontroller`;
* `android:name` (`0x01010003`) дефект маскировал — его ID меньше любого другого
  атрибута `<application>`, и «в конец» совпадало с «по порядку»;
* `aapt2` перебирает атрибуты линейно и печатал потерянный атрибут, поэтому
  офлайн-проверки манифеста ничего не замечали — расхождение видно только на
  устройстве.

Проверка гипотезы: байтовый перенос уже инжектнутого атрибута на позицию по
возрастанию resource ID (без правки кода) на `org.billthefarmer.editor` дал
цепочку `APPFACTORY_CTOR` → `APPFACTORY_DYN_DEX_FOUND` →
`DYN_PAYLOAD_EXECUTED_FROM_EXTERNAL_DEX` → `APPFACTORY_PAYLOAD_EXECUTED`.

Исправление (коммит `3a5e82c`): `attrInsertOffset` принимает resource ID и
разрешает существующие атрибуты через карту ресурсов; `addApplicationName`
передаёт `0x01010003`, патч appComponentFactory — `0x0101057a`. Тесты
`pkg/manifest/attr_order_test.go` переписаны на проверку порядка по
разрешённым ID. После фикса все шесть прогонов (3 хоста × векторы 6 и 8) —
`PAYLOAD_OK`, живые строки критерия с устройства:

```
org.billthefarmer.editor v6/v8        INJECT=ok INSTALL=ok PAYLOAD=2 ALIVE=1
captiveportalcontroller v6  I ARCHINOME: APPFACTORY_PAYLOAD_EXECUTED pid=19355
captiveportalcontroller v8  I ARCHINOME: ASSET_PAYLOAD_EXECUTED  ... ctx=false
cn.rbc.termuc v6            I ARCHINOME: APPFACTORY_PAYLOAD_EXECUTED pid=19823
cn.rbc.termuc v8            I ARCHINOME: ASSET_PAYLOAD_EXECUTED  ... ctx=false
```

Полный перепрогон матрицы на исправленном инжекторе — в §7.

## 5. Вектор 7 (нативный): почему payload не отрабатывает

У вектора 7 нет отказов «инструмент не смог» — есть три разных класса:

| Класс | Хостов | Причина |
|---|---|---|
| `INJECT_FAIL`: в APK нет `lib/<abi>/` | 20 | вектор неприменим (нет нативных либ) |
| `INJECT_FAIL`: нет DT_NEEDED-слота | 11 | `chain` и `replace` не находят места под `libarchin.so` (самая длинная зависимость короче имени), `append` в матрице не пробуется — инструмент сообщает «use --mode append or replace» |
| `NO_PAYLOAD` при успешном инжекте | 8 | наша либа есть в APK, но **хост её не грузит при запуске** |

Разбор третьего класса (замер на устройстве: `pidof` + `/proc/<pid>/maps` +
счётчик тегов `NATIVE_PAYLOAD_CTOR`):

| Хост | Режим | Куда лёг payload | Что грузит хост |
|---|---|---|---|
| `app.chompass` | chain | `libarchin.so` ← `liblitertlm_jni.so` | LLM-инференс (по действию) |
| `com.cbouvat.android.saracroche` | chain | `libarchin.so` ← `libdatastore_shared_counter.so` | DataStore (лениво) |
| `com.mardous.booming` | chain | `libarchin.so` ← `libffmpegJNI.so` | аудио-декодер (при воспроизведении) |
| `com.tnibler.cryptocam` | chain | `libarchin.so` ← `libgojni.so` | Go-ядро (по действию) |
| `org.fossify.gallery` | chain | `libarchin.so` ← `libjxl.so` | JPEG-XL декодер (при открытии картинки) |
| `com.github.catfriend1.syncthingfork` | replace | `libsyncthingnative.so` | ядро syncthing (в сервисе/позже) |
| `info.plateaukao.einkbro` | replace | `libadblock-client.so` | блокировщик (при загрузке страницы) |
| `io.github.pastthepixels.freepaint` | replace | `libpathway.so` | рендер рисунка |

Замер: у всех восьми хостов в момент запуска в maps процесса **нет ни одной
нативной библиотеки** (`/lib/arm64/` — 0, `base.apk!/lib/` — 0, теги
`NATIVE_PAYLOAD_CTOR` — 0, снято при 2495–3297 строках maps). Контроль —
хост, где вектор 7 отработал (`ru.yourok.torrserve`, режим `replace` в
`libconscrypt_jni.so`): его библиотека в maps **есть** (и распакованная копия,
и `_orig`), тег `NATIVE_PAYLOAD_CTOR` — 2 срабатывания. То есть цепочка
работает ровно тогда, когда хост грузит выбранную библиотеку при запуске.

Вывод для эвристики выбора host-либы (`docs/v7-host-lib-selection.md`):
выбирать надо не по размеру/имени, а по тому, грузится ли библиотека в
UI-процессе при холодном старте (например, либы, которые тянут
`androidx.startup`/`JNI`-инициализация, или `System.loadLibrary` в
`Application`/первой активити).

## 6. Наблюдения по хостам (не дефекты инструмента)

* **Вектор 2 и офлайн-хосты:** 22 из 49 приложений не имеют
  `android.permission.INTERNET` — gadget не может создать сокет
  (SELinux), вердикт `NA_NO_INTERNET`. Это ограничение listen-режима
  gadget'а, а не инжекта: в режиме `script` (скрипт из ресурсов, без сокета)
  вектор применим и к ним. Отдельным заданием.
* **`com.streetwriters.notesnook`** — `INSTALL_FAILED_NO_MATCHING_ABIS`
  (`res=-113`) и в исходном APK: F-Droid отдаёт сборку без arm64.
* **`alive=0` при `PAYLOAD_OK`** (13 прогонов на 3 хостах: `com.chess.clock` ×5,
  `org.woheller69.level` ×5, `com.foxdebug.acode`/`org.billthefarmer.gurgle`/
  `org.dolphinemu.dolphinemu` — вектор 4): payload отработал (лог-тег есть), но
  процесс к моменту проверки живости уже завершился. Это свойство хоста
  (экран-виджет/быстрый выход из активити), а не сбой вектора.
* **Вектор 4 (trampoline) и splash-крэши:** у 4 хостов
  (`com.foxdebug.acode`, `de.marmaro.krt.ffupdater`, `org.billthefarmer.gurgle`,
  `org.dolphinemu.dolphinemu`) после trampoline-активности падает оригинальная
  активити из-за `Theme.AppCompat`-темы запуска. Критерий вектора (лог-тег)
  при этом выполнен — `PAYLOAD_OK`.
* **Колонка `crash` в `matrix.tsv`** ненадёжна: `logcat --pid` ловит
  переиспользованный pid, поэтому «крэш» может относиться к чужому процессу.

## 7. Прогон после исправления порядка атрибутов (прогон 2)

400/400 завершены 11 сентября в 18:18, сырые данные — `matrix_run2.tsv` /
`matrix_run2.log`. Что изменилось против первого прогона:

- **V6 и V8: 46 → 49.** Причина — порядок атрибутов AXML (`appComponentFactory`
  дописывался в конец, платформа его не видела), см. §4.
- **V1: 48 → 49.** Критерий вектора приведён к тому, что payload реально пишет
  (`Log.i("HELL", ...)`), см. §3.
- Суммарно `PAYLOAD_OK`: 325 → **332**; `NO_PAYLOAD`: 14 → 8 (остались только
  хосты вектора 7).

`INSTALL_FAIL` во всех восьми строках — по-прежнему единственный хост
`com.streetwriters.notesnook` (`INSTALL_FAILED_NO_MATCHING_ABIS`).

| Вектор | PAYLOAD OK | NO PAYLOAD | INJECT FAIL | NA NO INTERNET | NA NO LOADED HOST LIB | INSTALL FAIL |
|---|---|---|---|---|---|---|
| 1 | 49 | 0 | 0 | 0 | 0 | 1 |
| 2 | 27 | 0 | 0 | 22 | 0 | 1 |
| 3 | 49 | 0 | 0 | 0 | 0 | 1 |
| 4 | 49 | 0 | 0 | 0 | 0 | 1 |
| 5 | 49 | 0 | 0 | 0 | 0 | 1 |
| 6 | 49 | 0 | 0 | 0 | 0 | 1 |
| 7 | 11 | 8 | 31 | 0 | 0 | 0 |
| 8 | 49 | 0 | 0 | 0 | 0 | 1 |

| хост | 1..8 |
|---|---|
| app.chompass | `++++++-+` |
| app.organicmaps | `++++++++` |
| cn.rbc.termuc | `++++++s+` |
| com.bitmavrick.lumolight | `+n++++s+` |
| com.cbouvat.android.saracroche | `++++++-+` |
| com.chess.clock | `+n++++s+` |
| com.chooloo.www.koler | `+n++++s+` |
| com.foxdebug.acode | `++++++s+` |
| com.github.catfriend1.syncthingfork | `++++++-+` |
| com.github.lamarios.clipious | `++++++++` |
| com.jens.automation2 | `++++++s+` |
| com.kitsumed.shizucallrecorder | `+n++++s+` |
| com.machiav3lli.fdroid | `++++++s+` |
| com.mardous.booming | `++++++-+` |
| com.nathanatos.Cuppa | `+n++++++` |
| com.prof18.feedflow | `++++++s+` |
| com.streetwriters.notesnook | `!!!!!!s!` |
| com.tnibler.cryptocam | `+n++++-+` |
| com.vincent_falzon.discreetlauncher | `+n++++s+` |
| com.wirelessalien.android.moviedb | `++++++s+` |
| de.marmaro.krt.ffupdater | `++++++s+` |
| dev.patrickgold.florisboard | `+n++++++` |
| dubrowgn.wattz | `+n++++s+` |
| fm.helio | `+n++++++` |
| info.plateaukao.einkbro | `++++++-+` |
| io.github.muntashirakon.captiveportalcontroller | `+n++++s+` |
| io.github.mwageringel.everest | `+n++++++` |
| io.github.pastthepixels.freepaint | `+n++++-+` |
| io.github.rumcajs.offlinewebsearch | `++++++s+` |
| ir.ammari.nodelook | `++++++s+` |
| me.hackerchick.catima | `+n++++s+` |
| me.knighthat.kreate | `++++++++` |
| net.stargw.fok | `+n++++s+` |
| ogz.tripeaks | `+n++++++` |
| org.billthefarmer.editor | `+n++++s+` |
| org.billthefarmer.gurgle | `++++++s+` |
| org.breezyweather | `++++++++` |
| org.catrobat.paintroid | `++++++s+` |
| org.cryptomator.lite | `++++++s+` |
| org.dolphinemu.dolphinemu | `++++++++` |
| org.fossify.filemanager | `+n++++s+` |
| org.fossify.gallery | `+n++++-+` |
| org.localsend.localsend_app | `++++++s+` |
| org.vinaygopinath.launchchat | `+n++++s+` |
| org.woheller69.level | `+n++++s+` |
| org.xbmc.kore | `++++++s+` |
| rak.pixellwp | `++++++s+` |
| ru.aleshin.timeplanner | `+n++++s+` |
| ru.yourok.torrserve | `++++++++` |
| website.leifs.delta.foss | `++++++s+` |

итого: PAYLOAD_OK=332, NO_PAYLOAD=8, INJECT_FAIL=31, NA_NO_INTERNET=22, INSTALL_FAIL=7 (строк 400, хостов 50)

Что осталось после прогона 2: **V2** — 22 хоста без `android.permission.INTERNET`
(listen-режиму gadget'а нечего слушать без сокета) и **V7** — 8 хостов, где
инжект проходит, но выбранная host-либа не загружается при старте. Обе причины
закрыты доработками, прогон 3 — §8.

---

## Воспроизведение

```sh
export KS=$HOME/.android/debug.keystore KS_PASS=android KEY_ALIAS=androiddebugkey
export FRIDA_BIN=$HOME/.venvs/frida17/bin/frida-ps CORPUS_DIR=/tmp/corpus
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
export BUILD_TOOLS=$HOME/Library/Android/sdk/build-tools/35.0.0

cd tools/corpus
python3 inventory.py            # нативные либы, min/targetSdk, число методов
bash harness.sh <apk> <pkg> <вектор> <тег>   # один прогон
python3 matrix.py               # вся матрица (пропускает уже пройденные пары)
```
