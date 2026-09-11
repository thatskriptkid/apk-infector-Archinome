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

Вектор 7 перебирает нативные режимы `chain → replace → append` и возвращает
`NATIVE_MODE=<режим>|none`; причина отказа при этом собирается по **всем**
попыткам, а не только по последней.

## 3. Прогнать матрицу

```bash
export KS_PASS='...'
python3 matrix.py
```

20 приложений × 8 векторов = 160 прогонов. **Возобновляемо**: пара
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
| 3 | `vector` | номер вектора (1–8) |
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
* `SIGN_FAIL`/`ALIGN_FAIL`/`SETUP_FAIL` → `SIGN_MSG`/`INJECT_MSG`.

## 5. Как читать вердикты

| Вердикт | Что значит |
| --- | --- |
| `PAYLOAD_OK` | payload внедрён, APK подписан и установлен, приложение запустилось и его тег виден в logcat — вектор сработал. |
| `NO_PAYLOAD` | APK установился и запустился, но тега payload в logcat нет — внедрение формально прошло, а код не выполнился. |
| `INJECT_FAIL` | `archinome` не создал выходной APK. Причина в `note` (`INJECT_MSG`). |
| `INSTALL_FAIL` | APK внедрён, но не ставится на устройство. Причина в `note` (`INSTALL_MSG`). |
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
