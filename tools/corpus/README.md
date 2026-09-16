# tools/corpus — тестовый корпус для Archinome

Переиспользуемая обвязка для прогона **всех векторов внедрения Archinome по всем
сторонним APK** на подключённом (рутованном) устройстве. Изначально это был
одноразовый тест 20 приложений из `offa/android-foss` × 8 векторов (160 прогонов),
живший в `/tmp`; здесь он приведён к виду воспроизводимого инструмента.

Что внутри:

| Файл | Назначение |
| --- | --- |
| `dl.sh` | скачивает APK корпуса с f-droid.org в `apk/` |
| `targets.tsv` | список корпуса: `package<TAB>versionCode<TAB>size` (20 приложений) |
| `sample30.txt` | расширенный список кандидатов (29 пакетов) — задел на больший корпус |
| `meta.tsv` | метаданные по кандидатам (pkg/versionCode/size) из F-Droid API |
| `inventory.py` | структурный инвентарь APK → `inventory.json` (aapt2 badging + xmltree + zip) |
| `harness.sh` | **один** прогон «инжект → align → sign → install → launch → logcat» |
| `matrix.py` | **драйвер матрицы**: все приложения × все векторы, возобновляемый |
| `README.md` | этот файл |

Сами APK (400+ МиБ) в git не хранятся — их всегда качает `dl.sh`.

**Код живёт в репозитории, данные — в `CORPUS_DIR`.** `matrix.py` запускает `harness.sh`
рядом с собой (репозиторный файл), а не тот, что лежит в `CORPUS_DIR`: устаревшая копия
харнесса там однажды подменила логику и тихо выдала `NO_PAYLOAD` на векторе 2 (в старой
86-строчной копии не было проверки gadget'а вообще). Правишь обвязку — правь в репозитории.

## Требования

* macOS (используются `gtimeout`/`timeout`, `curl`), Android SDK `build-tools`
  (aapt2, zipalign, apksigner, d8) и JDK — по умолчанию:
  * `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`
  * `BUILD_TOOLS=$HOME/Library/Android/sdk/build-tools/35.0.0`
* собранный бинарь `archinome` (путь задаётся через `ARCH_BIN`, по умолчанию
  `<repo>/archinome`);
* keystore с ключом подписи (по умолчанию `<repo>/my-release-key.jks`, alias
  `my-key-alias-2`);
* подключённое по ADB рутованное устройство.

## Переменные окружения

| Переменная | Назначение | Значение по умолчанию |
| --- | --- | --- |
| `ARCH_BIN` | путь к собранному бинарю `archinome` | `<repo>/archinome` |
| `KS` | путь к keystore | `<repo>/my-release-key.jks` |
| `KS_PASS` | **обязательно**: пароль keystore и ключа | — (без него прогон не стартует) |
| `KEY_ALIAS` | alias ключа в keystore | `my-key-alias-2` |
| `JAVA_HOME` | JDK для apksigner | homebrew openjdk@21 |
| `BUILD_TOOLS` | каталог build-tools (aapt2/zipalign/apksigner/d8) | `~/Library/Android/sdk/build-tools/35.0.0` |
| `CORPUS_DIR` | каталог **данных** корпуса: `targets.tsv`, `meta.tsv`, `apk/`, `work/`, `matrix.tsv` | каталог самого скрипта |

**Пароль приходит только из окружения.** Литеральных паролей в репозитории нет:
если `KS_PASS` не задан, `harness.sh` печатает `RESULT=SETUP_FAIL` и выходит с
кодом 1. apksigner получает пароль через `env:KS_PASS`, а не аргументом в
командной строке, поэтому он не светится ни в `git`, ни в `ps`.

```bash
export KS_PASS='ваш-пароль'          # либо: KS_PASS='...' bash tools/corpus/harness.sh ...
```

## 1. Собрать корпус

```bash
cd tools/corpus
bash dl.sh                 # скачает APK из targets.tsv в ./apk/ (параллельно, JOBS=4)
# JOBS=2 CORPUS_DIR=/tmp/c bash dl.sh     # другой каталог / меньше параллелизма
```

`dl.sh` собирает URL как `https://f-droid.org/repo/<package>_<versionCode>.apk`
и пропускает уже скачанные файлы. Проверить, что корпус полный:

```bash
python3 - <<'PY'
import os
for line in open("targets.tsv"):
    pkg = line.split("\t")[0]
    p = f"apk/{pkg}.apk"
    print(("OK  " if os.path.exists(p) else "MISS"), pkg, os.path.getsize(p) if os.path.exists(p) else "")
PY
```

При желании — структурный инвентарь (какие у приложений Application, alias-ы,
resmap-атрибуты, `lib/`, dex-и):

```bash
python3 inventory.py            # BUILD_TOOLS=... CORPUS_DIR=... при необходимости
# -> inventory.json + таблица в stdout
```

## 2. Один прогон

```bash
export KS_PASS='...'
bash harness.sh <apk> <package> <vector> <tag-regex> [reinstall]
```

Например:

```bash
ARCH_BIN=./archinome bash harness.sh apk/com.chess.clock.apk com.chess.clock 4 TRAMPOLINE_PAYLOAD_EXECUTED
bash harness.sh apk/org.organicmaps.apk app.organicmaps 7 NATIVE_PAYLOAD_CTOR
bash harness.sh apk/com.foxdebug.acode.apk com.foxdebug.acode 5 RECEIVER_PAYLOAD_EXECUTED 1
```

Что делает `harness.sh`:
1. внедряет payload выбранного вектора (`archinome <apk> <out> -o <vector>`);
2. `zipalign -p 4` и `apksigner sign`;
3. `adb install -r -d` (с откатом на чистую установку при `UPDATE_INCOMPATIBLE`);
4. запускает приложение (`monkey`), ждёт, читает `logcat` по pid;
5. при `reinstall=1` дополнительно переустанавливает APK поверх живого (нужно для
   `MY_PACKAGE_REPLACED`, вектор 5);
6. печатает `KEY=VALUE`, всегда завершается кодом 0 — **результат читается из
   строк, а не из кода возврата**.

Векторы (`-o N`):

| V | Вектор | Тег-маркер |
| --- | --- | --- |
| 1 | custom payload | `HELL` (payload печатает `Log.i("HELL", …)`) |
| 2 | frida gadget | `GADGET_CHECK` — не тег, а интерфейс gadget'а (`frida-ps` → `Gadget`) |
| 3 | provider | `PROVIDER_PAYLOAD_EXECUTED` |
| 4 | trampoline | `TRAMPOLINE_PAYLOAD_EXECUTED` |
| 5 | receiver | `RECEIVER_PAYLOAD_EXECUTED` |
| 6 | appfactory | `APPFACTORY_PAYLOAD_EXECUTED` |
| 7 | native | `NATIVE_PAYLOAD_CTOR` |
| 8 | assets | `ASSET_PAYLOAD_EXECUTED` |
| 9 | service code patch | **не реализовано**: learn-шаг печатает цели (`CODEPATCH_TARGETS`), `code_item`-патч в разработке → `NA_CODE_PATCH_PENDING` |
| 10 | native sideload | `NATIVE_PAYLOAD_CTOR` — обычный запуск (хост сам зовёт `loadLibrary`); dex не добавляется |
| 11 | Application code patch | **не реализовано**, как и 9 → `NA_CODE_PATCH_PENDING` |
| 12 | `<instrumentation>` | `INSTRUMENTATION_PAYLOAD_EXECUTED` — триггер внешний: `am instrument -w <pkg>/aaaaaaaaaaaa.ArchinomeInstrumentation` |
| 13 | `android:backupAgent` | `BACKUPAGENT_PAYLOAD_EXECUTED` — триггер внешний: `bmgr backup <pkg>` (подкоманды `bmgr backupnow` в Android 17 нет), при `Backup is not enabled`/`Transport not initialized` — `bmgr enable true` + `bmgr transport com.android.localtransport/.LocalTransport` и повтор, затем откат на `bmgr run`. Механизм подтверждён на устройстве отдельным триггером (`bash smoke_new.sh <pkg> 13`), но через сам харнесс тот же хост даёт ложный `NO_PAYLOAD` — открытый дефект измерения (не вектора) |
| 14 | `zygotePreloadName` + isolated service | `ZYGOTE_PRELOAD_EXECUTED` — триггер внешний: `am start-service -n <pkg>/aaaaaaaaaaaa.ArchinomeZygoteService` |

Векторы 9 и 11 не трогают манифест: патчится тело метода (`<clinit>`, иначе
`<init>`) классов, которые хост и так объявил (`<service android:name>` / класс из
`<application android:name>`), поэтому статического следа в манифесте нет. Вектор 10
вообще не добавляет dex — payload занимает имя библиотеки, которую хост запрашивает
через `System.loadLibrary`, но сам не поставляет. Векторы 12–14 активируются только
внешним триггером (см. таблицу); обычный запуск приложения их не включает.

Инжектор печатает по новым векторам: `SIDELOAD_TARGET=<lib>` и
`SIDELOAD_CALLER=<класс>-><метод>` (10), `CODEPATCH_TARGETS=<...>` и
`CODEPATCH_COUNT=<n>` (9/11). Вектор структурно неприменим к хосту там, где
патчить нечего (нет сервисов, нет собственного Application-класса, нет
непоставленной библиотеки) — это `rc 3` (SKIP) инжектора и вердикт `NA_*`, а не
`NO_PAYLOAD`.

Каждый шаг внешнего триггера идёт под таймаутом
(`TRIGGER_TIMEOUT_INSTRUMENT`/`TRIGGER_TIMEOUT_BACKUP`/`TRIGGER_TIMEOUT_BMGR`/
`TRIGGER_TIMEOUT_SERVICE`, секунды; без coreutils `timeout` работает портативный
запасной путь фон+опрос) — иначе зависший `am instrument -w` съел бы весь прогон
(matrix.py убивает прогон на 900 с и пишет `HARNESS_TIMEOUT`). Сырой ответ
триггера (первые 200 символов, одной строкой) попадает в `note`; `TRIGGER_OK=0`
при отсутствии payload даёт `NA_TRIGGER_FAILED`, а не `NO_PAYLOAD`.

Вектор 7 перебирает нативные режимы `chain → replace → append` и возвращает
`NATIVE_MODE=<режим>|none`; причина отказа при этом собирается по **всем**
попыткам, а не только по последней. Перед инжектом вектор 7 замеряет
`/proc/<pid>/maps` оригинала (`learn-host-lib.sh`) и подставляет найденную либу в
`ARCHINOME_NATIVE_HOST` — статически узнать, какую свою либу хост грузит при
старте, нельзя. Ключи `LEARN_HOST_LIB`/`LEARN_CANDIDATES`/`LEARN_NA`/`LEARN_NOTE`
попадают в вывод прогона; если замер не нашёл ни одной загруженной либы, вердикт —
`NA_NO_LOADED_HOST_LIB` (неприменимость), а не `NO_PAYLOAD` (см. §5).

Вектор 2 требует `android.permission.INTERNET` (listen-режим gadget'а не может
создать сокет без него). Харнесс смотрит разрешения оригинала и, если их нет,
включает `ARCHINOME_ADD_INTERNET=1` — тогда инжектор дописывает
`<uses-permission>` в бинарный манифест, а в выводе появляется
`ADDED_INTERNET_PERMISSION=1`. Вердикт при этом считается по-прежнему по gadget'у:
порт 27042 (`frida-ps -H 127.0.0.1:27042` → один `Gadget`) **или** собственная строка
gadget'а в logcat (`Frida: Listening on 127.0.0.1 TCP port 27042`) для хостов,
которые завершают процесс раньше, чем мы стучимся в порт.

## 3. Прогнать матрицу

```bash
export KS_PASS='...'
python3 matrix.py
```

Корпус в `targets.tsv` — 50 приложений; `matrix.py` перебирает все векторы
инжектора (1–14), по одному прогону на пару `(package, vector)`. Числа прогонов
смотрите в `matrix.tsv`.
**Возобновляемо**: пара
`(package, vector)`, уже присутствующая в `matrix.tsv`, пропускается — после
обрыва просто запустите `matrix.py` снова. Прогресс виден в stdout и в
`matrix.log`.

Артефакты прогона (`work/<pkg>_v<N>.apk` и подписанный) удаляются для успешных
прогонов и сохраняются для неуспешных — чтобы было что разбирать.

## 4. Выходные файлы

### `matrix.tsv`

TSV, первая строка — заголовок, по строке на прогон:

| # | Колонка | Смысл |
| --- | --- | --- |
| 1 | `timestamp` | время окончания прогона, ISO |
| 2 | `package` | пакет |
| 3 | `vector` | номер вектора (1–14) |
| 4 | `verdict` | вердикт (см. ниже) |
| 5 | `inject_ok` | `INJECT=ok/fail` от harness |
| 6 | `install_ok` | `INSTALL=ok/fail` |
| 7 | `payload_ok` | сколько раз тег найден в logcat |
| 8 | `alive` | `APP_ALIVE=1/0` — процесс жив после запуска |
| 9 | `crash` | сколько фатальных строк в logcat |
| 10 | `natmode` | нативный режим для вектора 7 (`chain`/`replace`/`append`/пусто) |
| 11 | `pid` | pid запущенного процесса (`none` если не поднялся) |
| 12 | `note` | **причина** для не-успешного вердикта (см. ниже) |
| 13 | `duration` | длительность прогона |

### `matrix.log`

По строке на прогон: время, `i/total`, пакет, вектор, вердикт, payload/alive/crash,
длительность и — для не-успешных прогонов — `note=<текст причины>`.

### Колонка `note`

Содержит человекочитаемую причину, а не только флаг: переводы строк заменены
пробелами, значение обрезано до 400 символов. Источник зависит от вердикта:

* `INJECT_FAIL` → `INJECT_MSG` — **весь** текст инжектора (stdout+stderr);
* `INSTALL_FAIL` → `INSTALL_MSG` — вывод `adb install`;
* `NO_PAYLOAD` → `FATAL_NOTE`/`PAYLOAD_LINES` — фатальные строки logcat;
* `SIGN_FAIL`/`ALIGN_FAIL`/`SETUP_FAIL` → `SIGN_MSG`/`INJECT_MSG`;
* `NA_NO_LOADED_HOST_LIB` → `NA_NOTE` (что именно замерил `learn-host-lib.sh`).
* Для вектора 2 в `note` дописывается провенанс: `харнесс добавил
  android.permission.INTERNET (у хоста его нет)` / `gadget подтверждён по своей
  строке в logcat (порт уже не отвечал)`; для вектора 7 — `host_lib=<lib>`.

## 5. Как читать вердикты

| Вердикт | Что значит |
| --- | --- |
| `PAYLOAD_OK` | payload внедрён, APK подписан и установлен, приложение запустилось и его тег виден в logcat — вектор сработал. |
| `NO_PAYLOAD` | APK установился и запустился, но тега payload в logcat нет — внедрение формально прошло, а код не выполнился. |
| `INJECT_FAIL` | `archinome` не создал выходной APK. Причина в `note` (`INJECT_MSG`). |
| `INSTALL_FAIL` | APK внедрён, но не ставится на устройство. Причина в `note` (`INSTALL_MSG`). |
| `NA_PORT_BUSY` | порт gadget'а (`GADGET_PORT`, по умолчанию 27042) занят чужим слушателем и освободить его не удалось. |
| `NA_NO_INTERNET` | хост не заявил `android.permission.INTERNET`, а listen-режим gadget'а (вектор 2) без него не поднимается. |
| `NA_NO_LOADED_HOST_LIB` | замер `maps` на оригинале не нашёл ни одной загруженной `lib/<abi>/*.so` — вектору 7 не за что цепляться при холодном старте. |
| `NA_NO_SERVICE_CLASS` | у хоста нет собственных объявленных `<service>` — вектору 9 нечего патчить. |
| `NA_NO_UNSHIPPED_LIB` | хост не зовёт `loadLibrary` ни для одной библиотеки, которой нет в APK, — вектору 10 не за что зацепиться. |
| `NA_NO_CUSTOM_APP_CLASS` | у хоста нет собственного Application-класса (стоит платформенный `android.app.Application`) — вектору 11 нечего патчить. |
| `NA_CODE_PATCH_PENDING` | вектор 9/11 нашёл цели по манифесту, но правка `code_item` в чужом dex ещё не реализована — хост пропущен не из-за неприменимости. |
| `NA_TRIGGER_FAILED` | внешний триггер векторов 12–14 не отработал: `am` вернул ошибку (текст ответа лежит в `note`), сервис не стартовал, у `bmgr` нет транспорта или пакет не участвует |

Внешние триггеры поднимают процесс сама платформа, и под нагрузкой это медленнее
первого чтения logcat: если тега в нём нет, харнесс ждёт `EXTERNAL_RETRY_SETTLE_S`
(по умолчанию 30 с) и читает logcat повторно. Критерий при этом не меняется —
расширяется только окно; без этого один и тот же хост давал то `PAYLOAD_OK`, то
ложный `NA_TRIGGER_FAILED`.
| `ALIGN_FAIL` / `SIGN_FAIL` | не удалось выровнять или подписать APK (для `SIGN_FAIL` причина в `note`). |
| `SETUP_FAIL` | не задан обязательный `KS_PASS` и т.п. |
| `HARNESS_ERROR` | `harness.sh` не напечатал `RESULT` (например, скрипта нет на месте) — вывод harness целиком уходит в `note`. |
| `HARNESS_TIMEOUT` (`matrix.py`) | прогон не уложился в 900 с. |

Историческая матрица (20×8, до переноса в репо) дала:
`94 PAYLOAD_OK / 52 INJECT_FAIL / 13 INSTALL_FAIL / 1 NO_PAYLOAD`.
Провалы `INJECT_FAIL` по векторам 1/2 — `panic: stub dex superclass mismatch`,
по вектору 7 — `SKIP: native vector not applicable: …` (нет `lib/<abi>/`,
нет свободного слота в `DT_NEEDED`, нет payload-библиотеки под ABI).

## Заметки

* `harness.sh` обращается к устройству через `adb` — на машине без устройства
  матрицу не прогнать; синтаксис проверяется без него (`bash -n`, `py_compile`).
* Проверить обвязку без устройства можно, подсунув фальшивый инжектор: он падает
  до обращения к `adb`, а причина отказа всё равно должна доехать до `note`:
  ```bash
  printf '#!/bin/bash\necho "boom: no such manifest"\nexit 3\n' > /tmp/fake-arch
  chmod +x /tmp/fake-arch
  KS_PASS=dummy ARCH_BIN=/tmp/fake-arch CORPUS_DIR=/tmp/c ./harness.sh apk/<pkg>.apk <pkg> 1 ARCHINOME
  ```
* Всё, что попадает в git, — это скрипты, tsv/csv-списки и этот README. APK,
  журналы, `matrix.tsv`, `inventory.json` и `work/` исключены через `.gitignore`.
* Рабочий каталог `work/` создаётся автоматически рядом с корпусом.
