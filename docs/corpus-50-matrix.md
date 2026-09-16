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

## 8. Прогон 3 и перепрогон вектора 2 (итоговые цифры)

Прогон 3 — та же матрица 50×8 (`400` ячеек), но одним харнессом с доработками §7:
opt-in `android.permission.INTERNET` для вектора 2 и выбор host-либы замером
`/proc/<pid>/maps` для вектора 7. Итог после перепрогона вектора 2 (см. ниже):

| Вектор | PAYLOAD OK | NO PAYLOAD | INJECT FAIL | NA NO LOADED HOST LIB | INSTALL FAIL |
|---|---|---|---|---|---|
| 1 dex-payload | 49 | 0 | 0 | 0 | 1 |
| 2 frida gadget | **49** | 0 | 0 | 0 | 1 |
| 3 provider | 49 | 0 | 0 | 0 | 1 |
| 4 trampoline | 49 | 0 | 0 | 0 | 1 |
| 5 receiver | 49 | 0 | 0 | 0 | 1 |
| 6 appComponentFactory | 49 | 0 | 0 | 0 | 1 |
| 7 нативный | 11 | 0 | 31 | 8 | 0 |
| 8 assets AES-GCM | 49 | 0 | 0 | 0 | 1 |

**354 `PAYLOAD_OK` из 400.** Семь векторов дают 49/50 — исполняется у всех хостов,
кроме одного, и этот один (`com.streetwriters.notesnook`) не устанавливается
вообще: `INSTALL_FAILED_NO_MATCHING_ABIS` в оригинале, без нашего вмешательства.
Единственный вектор с реальной границей применимости — нативный (11/50).

### 8.1 Вектор 2: 17 «NO_PAYLOAD» были недостоверны

В прогоне 3 вектор 2 дал 27 OK / 17 `NO_PAYLOAD` / 5 `NA_PORT_BUSY`. Причина
внешняя: на `27042` — порту, который `libfrida-gadget.config.so` занимает под
свой listen — сидел **чужой `frida-server`**. В заметке каждого из 17 прогонов это
записано прямым текстом: `на 27042 отвечает не gadget, а frida-server
(процессов 269)`. Занятый порт означает, что gadget не может принять соединение,
и честный `PAYLOAD_OK` вырождается в «payload не исполнен» — вердикт, который
неотличим от настоящего отказа.

Две подробности, которые стоит помнить:

- **Все 27 OK этого прогона подтверждены собственной строкой gadget'а в logcat,
  и ни один — портом.** Именно это и выдало причину: критерий по logcat
  (`Frida   : Listening on 127.0.0.1 TCP port 27042`) печатает gadget внутри
  процесса хоста и он сохраняется даже когда порт уже недоступен, поэтому хосты,
  которые успевают умереть за секунду, остались доказанными, а живые — нет.
- **Пять `NA_PORT_BUSY` — дефект обвязки, а не инжектора**: первая версия гарда
  стояла в момент проверки, когда `27042` держит уже сам gadget, то есть «порт
  занят» находил полезную нагрузку и выбрасывал результат. Гард перенесён туда,
  где он и должен быть — **до запуска хоста**.

После освобождения порта и переноса гарда вектор 2 даёт **49/50**.

### 8.2 Вектор 7: 11 OK, 31 неприменимо, 8 — граница применимости

- 11 OK, часть — с замером (`host-либа выбрана замером maps: libconscrypt_jni.so`,
  `liborganicmaps.so`);
- 31 `INJECT_FAIL` с внятной причиной неприменимости: в APK нет `lib/<abi>/` либо
  в host-либе нет слота `DT_NEEDED`, куда влезает имя (`libandroidx.graphics.path.so
  has no DT_NEEDED slot able to hold "libarchin.so" (longest dependency name is
  8 bytes)`);
- 8 `NA_NO_LOADED_HOST_LIB` — замер показал, что хост при холодном старте не
  загружает **ни одной** своей либы (проверено и с ожиданием 25 с):
  `app.chompass`, `com.cbouvat.android.saracroche`,
  `com.github.catfriend1.syncthingfork`, `com.mardous.booming`,
  `com.tnibler.cryptocam`, `info.plateaukao.einkbro`,
  `io.github.pastthepixels.freepaint`, `org.fossify.gallery`. Это не дефект
  выбора либы: нативный вектор здесь просто не достижим холодным стартом.

### 8.3 Порт gadget'а перестал быть константой

`27042` — одновременно дефолт Frida и дефолт `frida-server`, поэтому конфликт
неизбежен на любой машине, где рядом работает инструментация. Инжектор теперь
читает порт из `ARCHINOME_GADGET_PORT` (по умолчанию `27042`), а харнесс берёт
`GADGET_PORT` и использует один и тот же порт на всех трёх шагах: инжект
(`ARCHINOME_GADGET_PORT`), проброс (`adb forward`) и проверка (`frida-ps`).
Дополнительно гард освобождает порт до запуска хоста и делает это правильно:
`frida-server` называет процесс по имени файла (`frida-server-17.18.0`), поэтому
`pidof frida-server` его не находил и старый `kill` был пустышкой — теперь
`pkill -9 -f frida-server` с ожиданием до 10 с.

Проверено на устройстве в двух режимах:

| сценарий | результат |
|---|---|
| чужой `frida-server` на `27042`, прогон с `GADGET_PORT=27043` | `PAYLOAD_OK`, gadget слушает `27043`, сервер не тронут |
| чужой `frida-server` на `27042`, прогон по умолчанию | `FREED_27042=1`, `PAYLOAD_OK`, порт свободен после прогона |

---

## 9. Векторы 9–14: прогон 4 (250 ячеек)

Тот же корпус 50 приложений, пять новых векторов (`9,10,11,12,14` — вектор 13
исключён до починки измерения, см. §9.3), `250` ячеек, один харнесс с внешними
триггерами. Итог:

| Вектор | PAYLOAD OK | неприменимо на хосте | прочее |
|---|---|---|---|
| 9 service code patch | — | 36 `NA_CODE_PATCH_PENDING`, 14 `NA_NO_SERVICE_CLASS` | правка dex не реализована |
| 10 native sideload | **0** | 48 `NA_NO_UNSHIPPED_LIB` | 2 `NO_PAYLOAD` (оба применимых хоста) |
| 11 Application code patch | — | 34 `NA_CODE_PATCH_PENDING`, 16 `NA_NO_CUSTOM_APP_CLASS` | правка dex не реализована |
| 12 `<instrumentation>` | **49** | — | 1 `INSTALL_FAIL` (notesnook) |
| 14 zygotePreload + сервис | **47** | 2 `NA_TRIGGER_FAILED` (политика фонового старта) | 1 `INSTALL_FAIL` (notesnook) |

`96 PAYLOAD_OK` из 250, и оба `INSTALL_FAIL` — это `com.streetwriters.notesnook`,
который не ставится и в оригинале (`INSTALL_FAILED_NO_MATCHING_ABIS`): артефакт
корпуса, а не поведение вектора. Вектор 12 даёт **49/50** — ровно столько же,
сколько базовые 1–6 и 8 в §8.

### 9.1 Новые вердикты и что они значат

| Вердикт | Значит | Не значит |
|---|---|---|
| `NA_CODE_PATCH_PENDING` | вектор спроектирован, шаг обучения цели нашёл, сама правка `code_item` ещё не готова | «у хоста нет сервисов/своего Application» |
| `NA_NO_SERVICE_CLASS` | у хоста реально `declared services=0` | что-то не сломалось |
| `NA_NO_CUSTOM_APP_CLASS` | хост реально не объявляет свой Application | — |
| `NA_NO_UNSHIPPED_LIB` | брать нечего: хост не просит ни одной отсутствующей у него либы (в частном случае — вообще не поставляет нативных библиотек) | — |
| `NA_TRIGGER_FAILED` | внешний триггер не выстрелил; сырой ответ платформы лежит в `note` | «payload не отработал» |

Разделение введено после того, как первый прогон записал `NA_NO_SERVICE_CLASS`
и `NA_NO_CUSTOM_APP_CLASS` там, где причина была в отложенной правке dex: ярлык
«нет сервисов» на torrserve, где learn нашёл три сервиса, — это ложь, а не
измерение, поэтому такие ячейки были перепрогнаны с честным вердиктом.

### 9.2 Дефект измерения №1: окно logcat у внешних триггеров

Внешние триггеры (`am instrument`, `bmgr`, `am start-service`) поднимают процесс
сама платформа, и это медленнее, чем окно измерения: харнесс читал logcat через
`5` секунд после триггера, а `am instrument -w` под нагрузкой доходил до
`onCreate` позже. Симптом — **нестабильный вердикт на одном и том же хосте**:
`dubrowgn.wattz` в матрице получил `NA_TRIGGER_FAILED`, а при одиночном прогоне
сразу дал `INSTRUMENTATION_PAYLOAD_EXECUTED` и `PAYLOAD_OK`.

Это не гонка данных, а узкое окно, поэтому критерий не менялся: если тега в
первом чтении нет, харнесс ждёт `${EXTERNAL_RETRY_SETTLE_S:-30}` и читает
logcat повторно — те же строки, просто шире окно. Перепрогон 12 спорных ячеек
вектора 12 дал **12/12 `PAYLOAD_OK`**; ещё одна ячейка (вектор 14, moviedb) так
же оказалась `PAYLOAD_OK`. Все 13 расхождений дописаны в
`/tmp/corpus/matrix_new.tsv` с
пометкой `перепроверено с окном EXTERNAL_RETRY_SETTLE_S=30`.

### 9.3 Дефект измерения №2: `note` терял ответ платформы

Функции внешних триггеров печатали `TRIGGER_MSG=…` для парсера матрицы, но не
присваивали переменную, поэтому вердикт `NA_TRIGGER_FAILED` записывал в `note`
пустоту (`нет вывода`), хотя ответ платформы был. После правки заметка несёт
причину целиком:

```
TRIGGER_RC=255  TRIGGER_MSG=Starting service: Intent { cmp=…/ArchinomeZygoteService }
                Error: app is in background uid null
```

Именно из-за этого дефекта вектор 13 временно исключён из прогона: без текста
`bmgr` вердикт по нему не разобрать. Его триггер (`bmgr backup` + локальный
транспорт, подкоманды `backupnow` в Android 17 нет) уже переписан, измерение —
следующий шаг.

### 9.4 Почему вектор 14 упирается ровно в 2 хоста

У `com.chess.clock` и `org.woheller69.level` ответ одинаков: `TRIGGER_RC=255`,
`Error: app is in background uid null`. Android 17 не даёт стартовать сервис
приложению из фона — даже после того, как харнесс выводит хост на передний план.
У остальных 47 хостов изолированный сервис стартовал, `ZYGOTE_PRELOAD_EXECUTED`
дошёл до logcat и вердикт — `PAYLOAD_OK`. Это граница платформы, а не дефект
вектора: вектор применим там, где хост дают поднять.

### 9.5 Вектор 10: механика работает, но срабатывания нет

Шаг обучения читает dex хоста и собирает вызовы `System.loadLibrary` — на 50
хостах их **93**. Вектор применим там, где хост просит библиотеку, которой сам не
поставляет, и таких хостов **2 из 50**:

| Хост | Просит | Зовущий | Почему не сработало |
|---|---|---|---|
| `ru.yourok.torrserve` | `libconscrypt_gmscore_jni.so` | `Lorg/conscrypt/NativeCryptoJni;->coroutineBoundary` | вызов лежит в ленивой ветке coroutine-обвязки conscrypt, холодный старт до неё не доходит |
| `com.github.lamarios.clipious` | `libffmpegkit_armv7a_neon.so` | `Lcom/antonkarpenko/ffmpegkit/NativeLoader;->b` | запрошен **armv7**-вариант имени, на arm64-устройстве он не загружается никогда |

Механика при этом проверена: имя занято, payload поставлен под ним (лог
`--arm64-v8a: added lib<имя>.so … placeholder dependency re-pointed at libc.so`),
но хост до вызова не доходит — отсюда честные `NO_PAYLOAD`. Отсюда вывод про сам
вектор: у него **два уровня применимости** — (а) хост просит непоставляемую
библиотеку, (б) исполнение действительно доходит до этого вызова. Харнесс
проверяет только (а); (б) требует своего триггера под конкретный хост. Ещё один
частный случай — `org.cryptomator.lite`: либу он просит, но нативных библиотек не
поставляет вообще, поэтому вердикт `NA_NO_UNSHIPPED_LIB` (брать нечего), а причина
в `note` — `no lib/<abi>/ directory`.

### 9.6 Что осталось

- **9 и 11** — довести правку `code_item` (примитив спроектирован: дописать новый
  `class_data`+`code_item` в конец dex и поправить `class_data_off`, чтобы ни один
  существующий offset не сдвинулся; вставляемый `invoke-static` обязан ссылаться
  на уже существующий id — на 25 из 50 хостов таких свободных ссылок 183).
- **13** — прогнать по матрице после того, как заметка начнёт нести ответ `bmgr`.
- **10** — при желании добавить отбор по достижимости вызова на старте.

---

## 10. Векторы 9 и 11: правка `code_item`, прогон 5 (100 ячеек)

Векторы 9 (service code patch) и 11 (Application code patch) доведены до рабочего состояния: инжектор добавляет в хостовый dex id'ы payload-класса и вставляет `invoke-static` в НАЧАЛО целевого метода (`<clinit>` в приоритете, иначе `<init>`), сдвигая адреса try-блоков и обработчиков на 3 code unit'а. Манифест остаётся байт-в-байт как у разработчика, новых компонентов нет — payload-класс приходит отдельным `classesN.dex`.

Прежде чем гонять векторы, верность энкодера измерена по всему корпусу (`docs/dex-roundtrip-fidelity.md`): 50 хостов, 79 dex'ов, ~2.1 млн строк и ~74 млн инструкций, 0 расхождений. Замер нашёл пять дефектов (порядок операнда 35c, пересортировка `class_defs`, чтение MUTF-8, правило сортировки строк, знаковое расширение `char`), каждый из которых до правки делал прогон бессмысленным.

| # | вектор | `PAYLOAD_OK` | `NO_PAYLOAD` | неприменимо | применим / сработал |
|---|---|---|---|---|---|
| 9 | service code patch | 13 | 17 | 20 `NA_NO_SERVICE_CLASS` | 30 / 13 (43%) |
| 11 | Application code patch | 26 | 0 | 23 `NA_NO_CUSTOM_APP_CLASS` + 1 `INSTALL_FAIL` | 27 / 26 (96%) |

Единственный `INSTALL_FAIL` — `com.streetwriters.notesnook` (`INSTALL_FAILED_NO_MATCHING_ABIS`, не ставится и в оригинале) — артефакт корпуса, как и в прогонах 1-4.

### 10.1 Вектор 11: срабатывает на всех применимых хостах

26 `PAYLOAD_OK` из 27 ячеек, дошедших до установки; отказов по существу нет. Живая проверка на `com.machiav3lli.fdroid`: инжектор правит `Lcom/machiav3lli/fdroid/NeoApp;-><clinit>`, `dexdump -d` показывает первой инструкцией метода `invoke-static {}, Laaaaaaaaaaaa/AppPatch;.run:()V`, `dexdump` верифицирует файл, на устройстве в logcat `I/ARCHINOME: APP_PATCH_EXECUTED`.

### 10.2 Вектор 9: 13 из 30 — упор в загрузку класса сервиса

17 `NO_PAYLOAD` — хосты, у которых патченные классы сервисов при обычном запуске не загружаются. Разбор целей: срабатывания приходятся на инфраструктурные сервисы, которые хост поднимает сам при старте (`androidx/work/...SystemJobService` — 5, `androidx/room/MultiInstanceInvalidationService` — 5, `SystemForegroundService` — 4, `SystemAlarmService` — 3), а отказы — на сервисы, грузящиеся только при определённом сценарии (`FlorisImeService`, `InCallService`, tile- и sync-сервисы XBMC/Kore, Dolphin). Вывод: у вектора 9, как и у вектора 10, два уровня применимости — «класс сервиса есть в dex» и «хост реально грузит этот класс при запуске»; инжектор проверяет только первое. Ранжирование целей по признаку «грузится при старте» (аналог `learn-host-lib.sh` у нативного вектора) осталось за рамками прогона: 43% — это оценка снизу, а не предел вектора.

### 10.3 Что осталось за рамками

- Вектор 13 (`android:backupAgent`) — механизм подтверждён, измерение в харнессе дефектно, из таблицы исключён (§9.3).
- Вектор 10 (sideload) — 0 срабатываний из 2 фактически прогнанных хостов (§9.5).
- Цели вектора 9 не ранжируются по признаку «загружается при старте» (§10.2).
- `NA_NO_SERVICE_CLASS` / `NA_NO_CUSTOM_APP_CLASS` — честная неприменимость: у хоста нет собственных `<service>` или своего класса `Application`.

## Воспроизведение

```sh
export KS=$HOME/.android/debug.keystore KS_PASS=android KEY_ALIAS=androiddebugkey
export FRIDA_BIN=$HOME/.venvs/frida17/bin/frida-ps CORPUS_DIR=/tmp/corpus
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
export BUILD_TOOLS=$HOME/Library/Android/sdk/build-tools/35.0.0
# внешние триггеры (12..14): окно повторного чтения logcat, если payload в первое
# чтение не попал; критерий тот же, меняется только ширина окна, см. §9.2
export EXTERNAL_RETRY_SETTLE_S=30
# подпись: по умолчанию харнесс берёт релизный keystore (my-release-key.jks,
# alias my-key-alias-2). Для прогона под отладочным ключом задай ВСЕ ТРИ явно,
# иначе каждая ячейка кончится SIGN_FAIL «keystore password was incorrect»
export KS=$HOME/.android/debug.keystore
export KEY_ALIAS=androiddebugkey
export KS_PASS=<пароль keystore и ключа: только через env, литералов в репо нет>

cd tools/corpus
python3 inventory.py            # нативные либы, min/targetSdk, число методов
bash harness.sh <apk> <pkg> <вектор> <тег>   # один прогон
# вся матрица (пропускает уже пройденные пары);
# GADGET_PORT=27043 — если 27042 занят чужим frida-server
python3 matrix.py
```
