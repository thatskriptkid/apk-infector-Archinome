#!/bin/bash
# Один прогон (APK, вектор) на подключённом устройстве.
#
#   harness.sh <apk> <package> <vector> <tag-regex> [reinstall]
#
# Печатает строки "KEY=VALUE" в stdout и ВСЕГДА завершается кодом 0:
# результат прогона передаётся именно в этих строках, а не в коде возврата.
#
# Ключевые строки вывода:
#   APP, VECTOR, INJECT_RC, INJECT(ok|fail), NATIVE_MODE
#   INJECT_MSG    текст, который вернул инжектор. Для INJECT_FAIL это ПРИЧИНА
#                 отказа: вывод целиком (stdout+stderr), переводы строк
#                 заменены пробелами, обрезано до 400 символов. Если причина
#                 не уместилась в обрезку — она всё равно начинается с начала.
#   INSTALL_MSG   последние строки вывода `adb install`
#   SIGN_MSG      текст ошибки apksigner (при RESULT=SIGN_FAIL)
#   PID, APP_ALIVE, PAYLOAD, PAYLOAD_LINES, CRASH, FATAL_NOTE
#   SIDELOAD_TARGET, SIDELOAD_CALLER      вектор 10: какую библиотеку хост просит
#                 и не поставляет (её имя занял payload) и в каком методе он её
#                 просит — то, что инструмент узнал сам из dex хоста
#   CODEPATCH_TARGETS, CODEPATCH_COUNT    векторы 9/11: какие именно методы хоста
#                 переписаны (cls->method,cls->method,…)
#   TRIGGER_OK, TRIGGER_RC, TRIGGER_MSG   внешний триггер векторов 12..14; у
#                 вектора 13 к ним добавляются TRIGGER_MSG_ENABLE/
#                 TRIGGER_MSG_TRANSPORT/TRIGGER_RC_RETRY/TRIGGER_MSG3 (повтор
#                 после `bmgr enable` + локальный транспорт) и
#                 TRIGGER_RC_RUN/TRIGGER_MSG2 (откат на `bmgr run`)
#   RESULT        PAYLOAD_OK | NO_PAYLOAD | INJECT_FAIL | INSTALL_FAIL |
#                 ALIGN_FAIL | SIGN_FAIL | SETUP_FAIL | NA_NO_INTERNET |
#                 NA_NO_LOADED_HOST_LIB | NA_NO_SERVICE_CLASS |
#                 NA_NO_UNSHIPPED_LIB | NA_NO_CUSTOM_APP_CLASS |
#                 NA_TRIGGER_FAILED
#
# Векторы 9..14 — та же обвязка, что у 1..8 (инжект → zipalign → apksigner →
# install → триггер → критерий по logcat → живость), отличие только в триггере и
# в том, что часть векторов структурно неприменима к хосту и отвечает кодом 3
# (SKIP), а не сбоем:
#   9  service code patch      критерий SERVICE_PATCH_EXECUTED; триггер — обычный
#                              запуск; rc 3 -> NA_NO_SERVICE_CLASS (у хоста нет
#                              собственных <service>, патчить нечего)
#   10 native sideload         критерий NATIVE_PAYLOAD_CTOR; триггер — обычный
#                              запуск; dex не добавляется, payload занимает имя
#                              библиотеки, которую хост просит, но не поставляет;
#                              rc 3 -> NA_NO_UNSHIPPED_LIB
#   11 Application code patch  критерий APP_PATCH_EXECUTED; триггер — обычный
#                              запуск; rc 3 -> NA_NO_CUSTOM_APP_CLASS
#   12 <instrumentation>       критерий INSTRUMENTATION_PAYLOAD_EXECUTED; триггер
#                              внешний: `am instrument -w <pkg>/<класс>` под
#                              таймаутом; ошибка am -> NA_TRIGGER_FAILED
#   13 android:backupAgent     критерий BACKUPAGENT_PAYLOAD_EXECUTED; триггер
#                              внешний: `bmgr backup <pkg>` (подкоманды
#                              `bmgr backupnow` в Android 17 нет), при «Backup is
#                              not enabled»/«Transport not initialized» —
#                              `bmgr enable true` + `bmgr transport
#                              com.android.localtransport/.LocalTransport` и
#                              повтор, затем откат на `bmgr run`; нет транспорта/
#                              пакет не участник -> NA_TRIGGER_FAILED
#   14 zygotePreload + сервис  критерий ZYGOTE_PRELOAD_EXECUTED; триггер внешний:
#                              `am start-service -n <pkg>/<класс>` (сервис объявлен
#                              exported=true специально); сервис не стартовал ->
#                              NA_TRIGGER_FAILED
#
# Вектор 2 (frida) проверяется не по лог-тегу, а по интерфейсу самого gadget'а:
# frida-ps -H 127.0.0.1:<порт gadget'а> должен показать ровно один процесс Gadget
# (27042 по умолчанию, GADGET_PORT — если 27042 занят чужим frida-server).
# ВАЖНО: frida-server по умолчанию слушает тот же 27042 — перед прогоном вектора 2
# уведи его (frida-server -l 127.0.0.1:27099), иначе проверка попадёт в сервер.
# Если у хоста нет android.permission.INTERNET, listen-режим gadget'а не может
# создать сокет (SELinux), приложение падает по abort — такой прогон получает
# вердикт NA_NO_INTERNET, а не NO_PAYLOAD.
#
# Переменные окружения:
#   ARCH_BIN     путь к собранному бинарю archinome (по умолчанию <repo>/archinome)
#   KS           путь к keystore (по умолчанию <repo>/my-release-key.jks)
#   KS_PASS      ОБЯЗАТЕЛЬНО: пароль keystore И ключа. Литеральных паролей в
#                репозитории нет — пароль приходит только из окружения.
#   KEY_ALIAS    alias ключа в keystore (по умолчанию my-key-alias-2)
#   FRIDA_BIN    frida-ps для проверки вектора 2 (по умолчанию из PATH; нужен
#                frida-tools 17.x — та же мажорная.минорная, что у gadget'а)
#   JAVA_HOME    JDK для apksigner (по умолчанию homebrew openjdk@21)
#   BUILD_TOOLS  каталог build-tools (aapt2/zipalign/apksigner/d8)
#   CORPUS_DIR   каталог корпуса, в нём же создаётся work/ (по умолчанию
#                каталог самого скрипта)
#   GADGET_PORT  порт gadget'а вектора 2 (по умолчанию 27042). Уводить нужно тогда,
#                когда 27042 занят чужим frida-server: он слушает там по умолчанию.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$HERE/../.." && pwd)}"
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home}"
export PATH="$JAVA_HOME/bin:$PATH"
B="${BUILD_TOOLS:-$HOME/Library/Android/sdk/build-tools/35.0.0}"
ARCH="${ARCH_BIN:-$REPO/archinome}"
KS="${KS:-$REPO/my-release-key.jks}"
KEY_ALIAS="${KEY_ALIAS:-my-key-alias-2}"
C="${CORPUS_DIR:-$HERE}"
W="$C/work"; mkdir -p "$W"

# Порт gadget'а (вектор 2). 27042 — дефолт Frida и ОДНОВРЕМЕННО дефолт
# frida-server: если на устройстве уже поднят сервер (его запускает соседний
# инструмент, а бывает и «зависший» экземпляр, который слушает, но по протоколу
# не отвечает), gadget не примет соединение, и честный OK вырождается в
# «payload не исполнен». Поэтому порт один и тот же на всех трёх шагах —
# инжект (ARCHINOME_GADGET_PORT), проброс (adb forward) и проверка (frida-ps) —
# и его можно увести от чужого сервера: GADGET_PORT=27043 bash harness.sh ...
GPORT="${GADGET_PORT:-27042}"
export ARCHINOME_GADGET_PORT="$GPORT"

# Пароль — ТОЛЬКО из окружения. Не задан -> выходим с явной ошибкой, чтобы
# прогон нельзя было принять за настоящий результат.
if [ -z "${KS_PASS:-}" ]; then
  echo "RESULT=SETUP_FAIL"
  echo "INJECT_MSG=KS_PASS не задан: пароль keystore/ключа передаётся только через переменную окружения (KS_PASS=... bash harness.sh ...); литеральных паролей в репозитории нет"
  exit 1
fi
export KS_PASS

# Приводим любой текст к одной строке: CR/NL -> пробел, схлопываем пробелы,
# обрезаем. Используется для note-полей (INJECT_MSG/INSTALL_MSG/SIGN_MSG).
sanitize() {
  tr -d '\r' | tr '\n' ' ' | tr -s '[:space:]' ' ' | sed -e 's/^ //' -e 's/ $//' | cut -c1-400
}

# ---- внешние триггеры векторов 12..14 ---------------------------------------
# Эти векторы не запускаются launcher'ом: процесс поднимает сама платформа по
# команде с устройства (`am instrument`, `bmgr`, `am start-service`). Каждая
# такая команда — под таймаутом: `am instrument -w` ждёт завершения
# инструментации, а payload её не завершает, поэтому без таймаута команда висит
# до 900-секундного лимита matrix.py и прогон выглядит как сбой харнесса.
if command -v gtimeout >/dev/null; then TIMEOUT_BIN="gtimeout"
elif command -v timeout >/dev/null; then TIMEOUT_BIN="timeout"
else TIMEOUT_BIN=""; fi

# tmo <секунды> <команда...>: код команды, 124 — если она не уложилась. Без
# coreutils timeout работает портативный запасной путь (фон + опрос), иначе на
# macOS зависший `am instrument` съел бы весь прогон.
tmo() {
  local secs="$1"; shift
  if [ -n "$TIMEOUT_BIN" ]; then "$TIMEOUT_BIN" "$secs" "$@"; return $?; fi
  "$@" & local cpid=$!
  local i=0
  while kill -0 "$cpid" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -ge "$secs" ]; then
      kill -9 "$cpid" 2>/dev/null
      wait "$cpid" 2>/dev/null
      return 124
    fi
    sleep 1
  done
  wait "$cpid"; return $?
}

# inj_line <KEY>: значение машиночитаемой строки KEY=... из вывода инжектора
# (SIDELOAD_TARGET, CODEPATCH_TARGETS, ...). Инжектор печатает их с начала
# строки, поэтому матч строгий — в отладочном тексте таких строк не бывает.
inj_line() {
  printf '%s\n' "$INJ" | sed -n "s/^$1=//p" | head -1
}

# Вектор 12: <instrumentation> из манифеста. Ошибка am (SecurityException,
# «Unable to find instrumentation», пустой вывод) означает, что триггер не
# выстрелил: это неприменимость вектора на хосте, а не отсутствие payload.
# Различает их критерий по logcat — TRIGGER_OK только сужает вердикт.
trigger_instrumentation() {
  local out rc
  out=$(tmo "${TRIGGER_TIMEOUT_INSTRUMENT:-45}" adb shell am instrument -w \
        "$1/aaaaaaaaaaaa.ArchinomeInstrumentation" 2>&1); rc=$?
  TRIGGER_RC="$rc"; TRIGGER_MSG="$(printf '%s' "$out" | sanitize)"
  echo "TRIGGER_RC=$TRIGGER_RC"
  echo "TRIGGER_MSG=$TRIGGER_MSG"
  [ "$rc" -eq 0 ] || return 1
  [ -n "$out" ] || return 1
  if printf '%s' "$out" | grep -qaiE 'SecurityException|Unable to find instrumentation|INSTRUMENTATION_FAILED|does not exist|not found'; then
    return 1
  fi
  return 0
}

# brief: тот же sanitize, но короче — сырые ответы bmgr/am в note должны быть
# одной короткой строкой, а не вытеснять собой всю причину прогона.
brief() { sanitize | cut -c1-200; }

# bmgr_bad: ответ bmgr, означающий «бэкап не поедет» (пакет не участник, команда
# не понята, ошибка, бэкап выключен, транспорт не поднят). Именно это делает
# вектор неприменимым на хосте. «not enabled»/«transport not initialized» здесь
# тоже плохие: после того как харнесс включил бэкап и перевёл менеджер на
# локальный транспорт, такой ответ означает, что меры не помогли.
bmgr_bad() {
  printf '%s' "$1" | grep -qaiE 'error|unable|cannot|not eligible|not allowed|unknown package|no backup transport|transport not initialized|not enabled|not participating|does not support backup|does not exist|usage:'
}

# bmgr_needs_enable: bmgr отказал ровно из-за выключенного бэкапа или неподнятого
# транспорта — есть что включить и что переключить, после чего повторить.
bmgr_needs_enable() {
  printf '%s' "$1" | grep -qaiE 'backup is not enabled|backup not enabled|transport not initialized'
}

# Вектор 13: android:backupAgent. Подкоманды `bmgr backupnow` в Android 17 нет:
# сам bmgr печатает usage с `bmgr backup PACKAGE`. Порядок, проверенный на
# устройстве: `bmgr backup <pkg>` -> если «Backup is not enabled»/«Transport not
# initialized», `bmgr enable true` и перевод менеджера на локальный транспорт
# (google-транспорт в лаборатории может быть не готов) -> повтор `bmgr backup`
# -> при пустом/отказном ответе `bmgr run`. Сырой вывод каждого шага уходит в
# note: без него вердикт не разобрать. Каждый шаг под таймаутом.
trigger_backup() {
  local out rc
  # Локальный транспорт и включённый bmgr — сразу: google-транспорт в лаборатории
  # не инициализирован, без перевода запрос до агента не доходит вовсе.
  tmo "${TRIGGER_TIMEOUT_BMGR:-60}" adb shell bmgr enable true >/dev/null 2>&1
  tmo "${TRIGGER_TIMEOUT_BMGR:-60}" adb shell bmgr transport com.android.localtransport/.LocalTransport >/dev/null 2>&1
  out=$(tmo "${TRIGGER_TIMEOUT_BACKUP:-180}" adb shell bmgr backup "$1" 2>&1); rc=$?
  TRIGGER_RC="$rc"; TRIGGER_MSG="$(printf '%s' "$out" | brief)"
  echo "TRIGGER_RC=$TRIGGER_RC"
  echo "TRIGGER_MSG=$TRIGGER_MSG"
  if bmgr_needs_enable "$out"; then
    local en tr
    en=$(tmo "${TRIGGER_TIMEOUT_BMGR:-60}" adb shell bmgr enable true 2>&1)
    TRIGGER_MSG_ENABLE="$(printf '%s' "$en" | brief)"
    echo "TRIGGER_MSG_ENABLE=$TRIGGER_MSG_ENABLE"
    tr=$(tmo "${TRIGGER_TIMEOUT_BMGR:-60}" adb shell bmgr transport com.android.localtransport/.LocalTransport 2>&1)
    TRIGGER_MSG_TRANSPORT="$(printf '%s' "$tr" | brief)"
    echo "TRIGGER_MSG_TRANSPORT=$TRIGGER_MSG_TRANSPORT"
    out=$(tmo "${TRIGGER_TIMEOUT_BACKUP:-180}" adb shell bmgr backup "$1" 2>&1); rc=$?
    TRIGGER_RC_RETRY="$rc"; TRIGGER_MSG3="$(printf '%s' "$out" | brief)"
    echo "TRIGGER_RC_RETRY=$TRIGGER_RC_RETRY"
    echo "TRIGGER_MSG3=$TRIGGER_MSG3"
  fi
  # `bmgr backup PACKAGE` часто отвечает молча: это запрос, а не результат.
  # rc=0 без ошибки = запрос принят. Затем `bmgr run`: транспорт обрабатывает
  # очередь по своему расписанию, а без принудительного прогона агент не
  # поднимается вовсе (проверено на устройстве: с одним `bmgr backup` payload не
  # исполнялся, с последующим `bmgr run` — исполнялся).
  if [ "$rc" -eq 0 ] && ! bmgr_bad "$out"; then
    tmo "${TRIGGER_TIMEOUT_BMGR:-60}" adb shell bmgr run >/dev/null 2>&1
    return 0
  fi
  local run rrc
  run=$(tmo "${TRIGGER_TIMEOUT_BMGR:-60}" adb shell bmgr run 2>&1); rrc=$?
  TRIGGER_RC_RUN="$rrc"; TRIGGER_MSG2="$(printf '%s' "$run" | brief)"
  echo "TRIGGER_RC_RUN=$TRIGGER_RC_RUN"
  echo "TRIGGER_MSG2=$TRIGGER_MSG2"
  # Молчаливый `bmgr run` (rc 0, ноль вывода) успехом не считается: этот вывод
  # ничего не доказывает, а вердикт при отсутствии payload обязан быть честным —
  # NA_TRIGGER_FAILED, а не NO_PAYLOAD. PAYLOAD_OK всё равно решает logcat.
  if [ "$rrc" -eq 0 ] && [ -n "$run" ] && ! bmgr_bad "$run"; then return 0; fi
  return 1
}

# Вектор 14: app-zygote-сервис (объявлен exported=true именно под этот триггер).
# Пустой ответ `am start-service` — норма, в отличие от am instrument: о старте
# судим по критерию в logcat, а не по тексту am.
trigger_zygote_service() {
  local out rc
  # Изолированный сервис у фонового приложения система стартовать не даёт
  # («app is in background uid null»): сначала поднимаем приложение на передний
  # план тем же способом, что и лончерные векторы, иначе триггер проверял бы не
  # вектор, а политику фоновых запусков.
  adb shell monkey -p "$1" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
  sleep "${ZYGOTE_PRELIFT_S:-3}"
  out=$(tmo "${TRIGGER_TIMEOUT_SERVICE:-30}" adb shell am start-service -n \
        "$1/aaaaaaaaaaaa.ArchinomeZygoteService" 2>&1); rc=$?
  TRIGGER_RC="$rc"; TRIGGER_MSG="$(printf '%s' "$out" | sanitize)"
  echo "TRIGGER_RC=$TRIGGER_RC"
  echo "TRIGGER_MSG=$TRIGGER_MSG"
  [ "$rc" -eq 0 ] || return 1
  if printf '%s' "$out" | grep -qaiE 'Error|Exception|not found|does not exist|Unable'; then
    return 1
  fi
  return 0
}

APK="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; PKG="$2"; V="$3"
TAG="${4:-ARCHINOME}"; REINSTALL="${5:-0}"
if command -v gtimeout >/dev/null; then TO="gtimeout 300"; elif command -v timeout >/dev/null; then TO="timeout 300"; else TO=""; fi
OUT="$W/${PKG}_v${V}.apk"; SIGNED="$W/${PKG}_v${V}_signed.apk"
INS_RAW="$W/ins_raw.txt"
echo "APP=$PKG"; echo "VECTOR=$V"

# ---- inject ----------------------------------------------------------------
cd "$REPO" || exit 1
rm -f "$OUT"
INJ=""; NMODE=""; INJECT_RC=1
if [ "$V" = "7" ]; then
  # Нативный вектор цепляется за библиотеку, которую хост реально грузит. Какая
  # это либа - из APK не видно: замер /proc/<pid>/maps на оригинале (learn)
  # отвечает на вопрос фактом. Без замера используется старая эвристика
  # («самая большая либа»), но тогда прогон помечается отдельным признаком.
  HOST_LIB=""; LEARN_NOTE=""; LEARN_CAND=""
  if [ -x "$HERE/learn-host-lib.sh" ]; then
    LEARN=$("$HERE/learn-host-lib.sh" "$APK" "$PKG" 2>/dev/null)
    HOST_LIB=$(printf '%s\n' "$LEARN" | sed -n 's/^HOST_LIB=//p' | head -1)
    LEARN_CAND=$(printf '%s\n' "$LEARN" | sed -n 's/^CANDIDATES=//p' | head -1)
    LEARN_NOTE=$(printf '%s\n' "$LEARN" | sed -n 's/^NOTE=//p' | head -1)
    LEARN_MEASURED=$(printf '%s\n' "$LEARN" | sed -n 's/^MEASURED=//p' | head -1)
    echo "LEARN_CANDIDATES=${LEARN_CAND:-none}"
    echo "LEARN_HOST_LIB=${HOST_LIB:-none}"
    echo "LEARN_MEASURED=${LEARN_MEASURED:-0}"
    LEARN_HOST_LIB="${HOST_LIB:-none}"
    # Разделяем два разных «HOST_LIB пуст»: замер сделан и хост действительно
    # ничего не грузит (вектор неприменим) vs замер не удался (maps закрыт, нет
    # root) — во втором случае остаёмся на эвристике инжектора и NA не объявляем.
    [ "$LEARN_MEASURED" = "1" ] && [ -z "$HOST_LIB" ] && LEARN_NA=1 || LEARN_NA=0
    echo "LEARN_NA=$LEARN_NA"
    echo "LEARN_NOTE=$(printf '%s' "$LEARN_NOTE" | sanitize)"
  fi
  # chain-режиму нативного вектора нужен свободный слот в DT_NEEDED, а он есть
  # не у каждой хостовой библиотеки; откатываемся к replace/append. Собираем
  # вывод ВСЕХ попыток, чтобы причина отказа не потерялась за последней.
  for M in chain replace append; do
    rm -f "$OUT"
    if [ -n "$HOST_LIB" ]; then
      M_OUT=$(ARCHINOME_NATIVE_MODE=$M ARCHINOME_NATIVE_HOST="$HOST_LIB" $TO "$ARCH" "$APK" "$OUT" -o 7 2>&1); MRC=$?
    else
      M_OUT=$(ARCHINOME_NATIVE_MODE=$M $TO "$ARCH" "$APK" "$OUT" -o 7 2>&1); MRC=$?
    fi
    INJECT_RC=$MRC
    INJ="${INJ}${INJ:+$'\n'}[native-mode=$M rc=$MRC] ${M_OUT}"
    if [ -s "$OUT" ]; then NMODE=$M; break; fi
  done
  echo "NATIVE_MODE=${NMODE:-none}"
elif [ "$V" = "8" ]; then
  INJ=$(ARCHINOME_ASSETS_VECTOR=${ARCHINOME_ASSETS_VECTOR:-appfactory} $TO "$ARCH" "$APK" "$OUT" -o 8 2>&1); INJECT_RC=$?
else
  # Вектор 2 (frida gadget, listen-режим) требует android.permission.INTERNET:
  # без него платформа не даёт создать сокет, и прогон вырождается в NA. Половина
  # реальных приложений это разрешение не объявляет, поэтому харнесс (не сам
  # инжектор) добавляет его явным флагом — и печатает, что именно он изменил.
  if [ "$V" = "2" ] && ! "$B/aapt2" dump permissions "$APK" 2>/dev/null | grep -qa 'android.permission.INTERNET'; then
    export ARCHINOME_ADD_INTERNET=1
    echo "ADDED_INTERNET_PERMISSION=1"
  else
    echo "ADDED_INTERNET_PERMISSION=0"
  fi
  INJ=$($TO "$ARCH" "$APK" "$OUT" -o "$V" 2>&1); INJECT_RC=$?
fi
echo "INJECT_RC=$INJECT_RC"

# Код 3 — это SKIP, а не сбой: вектор структурно неприменим к этому хосту
# (у 9 — в манифесте нет собственных <service>, у 10 — хост не просит ни одной
# библиотеки, которой у него нет, у 11 — нет собственного Application-класса).
# Такой прогон обязан быть отличим от INJECT_FAIL, поэтому вердикт выносится
# здесь, до install/launch: выходного APK у SKIP нет by design.
if [ "$INJECT_RC" = "3" ]; then
  NAV=""
  case "$V" in
    9)  NAV=NA_NO_SERVICE_CLASS ;;
    10) NAV=NA_NO_UNSHIPPED_LIB ;;
    11) NAV=NA_NO_CUSTOM_APP_CLASS ;;
  esac
  # Векторы 9/11 сначала учатся по манифесту и только потом патчат тело метода в
  # чужом dex. Если learn-шаг классы нашёл, а патч ещё не реализован, вердикт
  # "нет сервисов/нет своего Application" был бы ложью: причина другая, и вызывающий
  # её должен видеть.
  case "$V" in
    9|11) case "$INJ" in
            *"code-item patch not implemented"*) NAV=NA_CODE_PATCH_PENDING ;;
          esac ;;
  esac
  if [ -n "$NAV" ]; then
    SKIP_NOTE="$(printf '%s' "$INJ" | sanitize)"
    [ -z "$SKIP_NOTE" ] && SKIP_NOTE="инжектор вернул SKIP (rc=3) без текста причины"
    echo "INJECT=skip"
    echo "INJECT_MSG=$SKIP_NOTE"
    echo "NA_NOTE=$SKIP_NOTE"
    echo "RESULT=$NAV"
    exit 0
  fi
fi

if [ ! -s "$OUT" ]; then
  echo "INJECT=fail"
  # ВАЖНО: причина отказа уходит наружу целиком и без фильтра по ключевым
  # словам — старый вариант с grep терял нестандартные ошибки и оставлял
  # отказы (например 12 отказов вектора 7) недиагностируемыми.
  NOTE="$(printf '%s' "$INJ" | sanitize)"
  [ -z "$NOTE" ] && NOTE="(инжектор не вернул диагностического текста; rc=$INJECT_RC, apk=$(basename "$APK"))"
  echo "INJECT_MSG=$NOTE"
  echo "RESULT=INJECT_FAIL"
  exit 0
fi
echo "INJECT=ok"
echo "INJECT_MSG=$(printf '%s' "$INJ" | grep -aE 'Skipped|native vector|Done!|error|Failed|OK' | sanitize)"
# Провенанс новых векторов: строки, по которым видно, что именно сделал
# инструмент (какую библиотеку угнал, какие методы переписал, сколько их).
# В INJECT_MSG они не попадают — там фильтр по ключевым словам, — а для разбора
# прогона нужны целиком, поэтому печатаются отдельными KEY=VALUE и уходят в note
# (см. note_for в matrix.py).
for K in SIDELOAD_TARGET SIDELOAD_CALLER CODEPATCH_TARGETS CODEPATCH_COUNT; do
  KV="$(inj_line "$K")"
  [ -n "$KV" ] && echo "$K=$KV"
done

# ---- align + sign ----------------------------------------------------------
"$B/zipalign" -f -p 4 "$OUT" "$W/al.apk" >/dev/null 2>&1 || "$B/zipalign" -f 4 "$OUT" "$W/al.apk" >/dev/null 2>&1
if [ ! -s "$W/al.apk" ]; then echo "RESULT=ALIGN_FAIL"; exit 0; fi
# Пароль передаётся apksigner через env:KS_PASS, а не литералом в командной
# строке — так он не светится ни в репозитории, ни в `ps`.
SIGN_ERR=$("$B/apksigner" sign --ks "$KS" --ks-key-alias "$KEY_ALIAS" \
  --ks-pass env:KS_PASS --key-pass env:KS_PASS --out "$SIGNED" "$W/al.apk" 2>&1)
if [ ! -s "$SIGNED" ]; then
  echo "SIGN_MSG=$(printf '%s' "$SIGN_ERR" | sanitize)"
  echo "RESULT=SIGN_FAIL"
  exit 0
fi

# ---- install (exit code is the only reliable signal: big APKs use the
# incremental installer and stream progress instead of a single Success line) --
adb uninstall "$PKG" >/dev/null 2>&1
sleep 1
adb install -r -d "$SIGNED" >"$INS_RAW" 2>&1; IRC=$?
if [ $IRC -ne 0 ] && grep -qa 'INSTALL_FAILED_UPDATE_INCOMPATIBLE' "$INS_RAW"; then
  adb uninstall "$PKG" >/dev/null 2>&1; sleep 1
  adb install -d "$SIGNED" >"$INS_RAW" 2>&1; IRC=$?
fi
echo "INSTALL_MSG=$(sanitize < "$INS_RAW")"
if [ $IRC -eq 0 ] && ! grep -qa 'Failure' "$INS_RAW"; then echo "INSTALL=ok"; else
  echo "INSTALL=fail"; echo "RESULT=INSTALL_FAIL"; exit 0; fi

# ---- launch + observe ------------------------------------------------------
# Вектор 2: порт 27042 принадлежит самому gadget'у (libfrida-gadget.config.so,
# on_port_conflict=fail). Если его уже занял чужой frida-server — его поднимает
# соседний инструмент, и в этом окружении он появлялся сам, в том числе
# «зависший» экземпляр, который слушает, но по протоколу не отвечает, — gadget
# не примет соединение, и честный OK вырождается в NO_PAYLOAD. Освобождаем порт
# ДО запуска хоста: после запуска на 27042 висит уже сам gadget, и проверка
# «порт занят» стала бы ложной (проверено: ложные NA_PORT_27042_BUSY на 4 хостах).
if [ "$TAG" = "GADGET_CHECK" ]; then
  P27042=$(adb shell "ss -ltn 2>/dev/null | grep -c \":${GPORT} \"" | tr -d '\r')
  if [ "${P27042:-0}" -gt 0 ]; then
    # frida-server называет процесс по имени файла (frida-server-17.18.0), поэтому
    # pidof frida-server его не находит и старый kill был пустышкой: берём процесс
    # по полной командной строке. Сокет освобождается не мгновенно — ждём до 10 с.
    adb shell 'su -c "pkill -9 -f frida-server"' >/dev/null 2>&1
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      P27042=$(adb shell "ss -ltn 2>/dev/null | grep -c \":${GPORT} \"" | tr -d '\r')
      [ "${P27042:-0}" -eq 0 ] && break
      sleep 1
    done
    echo "FREED_${GPORT}=$([ "${P27042:-0}" -eq 0 ] && echo 1 || echo 0)"
    if [ "${P27042:-0}" -gt 0 ]; then
      echo "INJECT_MSG=порт $GPORT занят чужим слушателем и не освободился: проверка вектора 2 недостоверна, повтори с GADGET_PORT=<свободный порт>"
      echo "RESULT=NA_PORT_BUSY"
      exit 0
    fi
  fi
fi
adb shell am force-stop "$PKG" >/dev/null 2>&1
adb logcat -c >/dev/null 2>&1
# Векторы 12..14 поднимает не launcher, а системная команда: monkey здесь только
# мешал бы (лишний процесс и лишние строки в logcat), поэтому у них свой триггер.
# TRIGGER_OK читается вердиктом ниже: он различает «payload не исполнился» и
# «триггер не выстрелил» — это разные вещи и разные вердикты.
case "$V" in
  12|13|14)
    TRIGGER_OK=1
    if [ "$V" = "12" ]; then trigger_instrumentation "$PKG" || TRIGGER_OK=0
    elif [ "$V" = "13" ]; then trigger_backup "$PKG" || TRIGGER_OK=0
    else trigger_zygote_service "$PKG" || TRIGGER_OK=0
    fi
    echo "TRIGGER_OK=$TRIGGER_OK"
    ;;
  *)
    adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
    ;;
esac
# Внешний триггер вектора 13 асинхронный: `bmgr backup` только просит транспорт,
# агент поднимается в отдельном процессе уже после ответа — пяти секунд на это не
# хватает, и честный OK вырождался в NO_PAYLOAD.
if [ "$V" = "13" ]; then
  sleep "${TRIGGER_SETTLE_BACKUP_S:-20}"
else
  sleep 5
fi
# Внешний триггер (12..14) поднимает процесс сама платформа, и под нагрузкой это
# медленнее, чем окно чтения logcat: один и тот же хост давал PAYLOAD_OK при
# отдельном прогоне и NA_TRIGGER_FAILED в матрице. Критерий НЕ меняется (строка
# payload в logcat) — расширяется только окно: если тега в первом чтении нет,
# ждём и читаем logcat повторно, приписывая второе чтение к первому. Тег в первом
# чтении есть (или уже найден payload) — повтор не нужен.
EXTRA_SETTLE=""
case "$V" in 12|13|14) EXTRA_SETTLE="${EXTERNAL_RETRY_SETTLE_S:-30}";; esac
PID=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')
echo "PID=${PID:-none}"
if [ "$REINSTALL" = "1" ]; then
  # MY_PACKAGE_REPLACED срабатывает только при замене уже установленного пакета
  adb install -r -d "$SIGNED" >/dev/null 2>&1
  sleep 5
  PID=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')
fi
LOG=$(adb logcat -d 2>/dev/null)
if [ -n "$EXTRA_SETTLE" ] && ! printf '%s' "$LOG" | grep -qa "$TAG"; then
  sleep "$EXTRA_SETTLE"
  LOG2=$(adb logcat -d 2>/dev/null)
  echo "EXTERNAL_RETRY_SETTLE=${EXTRA_SETTLE}s"
  LOG="$LOG
$LOG2"
fi

# ---- vector 2 (frida gadget): his own interface, not a log tag --------------
# The injected wrapper only calls System.loadLibrary("frida-gadget"); nothing
# logs anything, and a gadget that cannot create its socket aborts the host on
# the spot. The only honest check is the gadget itself: frida-server compatible,
# a single process named Gadget, listening on the gadget port (27042 by default,
# GADGET_PORT otherwise). That needs the host to hold
# android.permission.INTERNET - the platform denies socket creation to app
# domains without it, which is exactly how the gadget dies. The harness therefore
# sets ARCHINOME_ADD_INTERNET=1 during injection whenever the host does not
# declare it (see ADDED_INTERNET_PERMISSION above), so this branch now only fires
# if that edit itself failed on this manifest.
if [ "$TAG" = "GADGET_CHECK" ]; then
  if ! "$B/aapt2" dump permissions "$SIGNED" 2>/dev/null | grep -qa 'android.permission.INTERNET'; then
    echo "PAYLOAD=na"
    echo "FATAL_NOTE=signed APK declares no android.permission.INTERNET: a listen-mode gadget cannot open its socket (harness requested the permission: ADDED_INTERNET_PERMISSION=${ADDED_INTERNET_PERMISSION:-?})"
    echo "APP_ALIVE=$([ -n "$PID" ] && [ "$PID" != none ] && echo 1 || echo 0)"
    echo "RESULT=NA_NO_INTERNET"
    adb shell am force-stop "$PKG" >/dev/null 2>&1
    exit 0
  fi
  adb forward "tcp:$GPORT" "tcp:$GPORT" >/dev/null 2>&1
  GADGET_LINES=$("${FRIDA_BIN:-frida-ps}" -H "127.0.0.1:$GPORT" 2>/dev/null | tr '\n' '|' | cut -c1-200)
  GADGET_HITS=$("${FRIDA_BIN:-frida-ps}" -H "127.0.0.1:$GPORT" 2>/dev/null | awk 'NR>1 {print $2}' | grep -c '^Gadget$')
  # frida-server тоже по умолчанию слушает 27042: если на порту он, ответ содержит
  # (проверка ловит это и при выбранном GADGET_PORT)
  # весь список процессов устройства, и вердикт нельзя выдавать как «gadget не встал»
  GADGET_OTHER=$("${FRIDA_BIN:-frida-ps}" -H "127.0.0.1:$GPORT" 2>/dev/null | awk 'NR>1' | wc -l | tr -d ' ')
  adb forward --remove "tcp:$GPORT" >/dev/null 2>&1
  # Процесс хоста может умереть раньше, чем мы постучимся в порт: часть хостов
  # падает в собственных потоках через секунду после старта (com.chess.clock -
  # SIGILL в NDK MediaCodec_), часть является виджет-приложениями. Тогда порта
  # уже нет, хотя gadget успел подняться. Собственная строка gadget'а в logcat
  # «Frida   : Listening on 127.0.0.1 TCP port 27042» доказывает, что он
  # исполнился в процессе хоста, и это не слабее проверки порта: её печатает
  # gadget внутри приложения, а не frida-server (у того свой процесс и своя
  # область logcat). Без этого различия честный OK уходил в NO_PAYLOAD.
  GADGET_LISTENED=$(echo "$LOG" | grep -acE "Frida *: *Listening on 127\.0\.0\.1 TCP port ${GPORT}")
  echo "PAYLOAD=$GADGET_HITS"
  echo "GADGET_LISTENED=$GADGET_LISTENED"
  echo "PAYLOAD_LINES=$GADGET_LINES"
  echo "CRASH=$(echo "$LOG" | grep -acE 'Failed to start|Abort message')"
  if [ "$GADGET_HITS" -eq 0 ] && [ "${GADGET_OTHER:-0}" -gt 2 ]; then
    echo "FATAL_NOTE=на $GPORT отвечает не gadget, а frida-server (процессов $GADGET_OTHER): проверь, что gadget слушает именно $GPORT (ARCHINOME_GADGET_PORT), и повтори"
  elif [ "$GADGET_HITS" -eq 0 ]; then
    # gadget не ответил: без этого текста прогон неотличим от «инжект не сработал»
    ALIVE_NOTE=нет
    [ -n "$PID" ] && [ "$PID" != none ] && ALIVE_NOTE=да
    echo "FATAL_NOTE=gadget не ответил на $GPORT: процессов в frida-ps=${GADGET_OTHER:-?}, ответ='${GADGET_LINES:-пусто}', процесс жив=$ALIVE_NOTE; logcat=$(echo "$LOG" | grep -aiE 'frida|gadget|Abort message|Failed to start' | head -2 | tr '\n' '|' | cut -c1-220)"
  else
    echo "FATAL_NOTE=$(echo "$LOG" | grep -aE 'Failed to start|Abort message' | head -2 | tr '\n' '|' | cut -c1-300)"
  fi
  echo "APP_ALIVE=$([ -n "$PID" ] && [ "$PID" != none ] && echo 1 || echo 0)"
  if [ "$GADGET_HITS" -gt 0 ]; then
    echo "RESULT=PAYLOAD_OK"
  elif [ "${GADGET_LISTENED:-0}" -gt 0 ]; then
    echo "NA_NOTE=процесс хоста завершился до проверки порта, но gadget поднялся: в logcat его собственная строка 'Frida: Listening on 127.0.0.1 TCP port 27042'"
    echo "RESULT=PAYLOAD_OK"
  else
    echo "RESULT=NO_PAYLOAD"
  fi
  adb shell am force-stop "$PKG" >/dev/null 2>&1
  exit 0
fi

echo "PAYLOAD=$(echo "$LOG" | grep -acE "$TAG")"
echo "PAYLOAD_LINES=$(echo "$LOG" | grep -aE "$TAG" | head -3 | tr '\n' '|' | cut -c1-400)"
echo "CRASH=$(echo "$LOG" | grep -acE 'FATAL EXCEPTION|ClassNotFoundException|Unable to instantiate application')"
echo "FATAL_NOTE=$(echo "$LOG" | grep -aE 'FATAL EXCEPTION|Unable to instantiate|ClassNotFoundException' | head -2 | tr '\n' '|' | cut -c1-300)"
if [ -n "$PID" ] && [ "$PID" != "none" ]; then echo "APP_ALIVE=1"; else echo "APP_ALIVE=0"; fi
if [ "$(echo "$LOG" | grep -acE "$TAG")" -gt 0 ]; then
  echo "RESULT=PAYLOAD_OK"
elif [ "$V" = "7" ] && [ "${LEARN_NA:-0}" = "1" ]; then
  # Инжект мог быть технически корректен, но цепляться не за что: замер maps на
  # оригинале показал, что при холодном старте хост не грузит ни одной своей
  # lib/<abi>/*.so. Это неприменимость вектора на таком хосте, а не сбой, и
  # вердикт обязан быть отличим от NO_PAYLOAD.
  echo "NA_NOTE=вектор 7: при холодном старте хост не загрузил ни одной lib/<abi>/*.so (замер /proc/<pid>/maps на оригинале); NATIVE_MODE=${NMODE:-none}"
  echo "RESULT=NA_NO_LOADED_HOST_LIB"
elif { [ "$V" = "12" ] || [ "$V" = "13" ] || [ "$V" = "14" ]; } && [ "${TRIGGER_OK:-1}" = "0" ]; then
  # payload не появился и триггер не выстрелил. Это неприменимость вектора на
  # хосте, а не сбой инжекта, поэтому NA_* — отличный от NO_PAYLOAD вердикт.
  # Сырой вывод триггера идёт в note: без него причину с устройства не разобрать.
  TRIG_NOTE="${TRIGGER_MSG:-нет вывода}"
  [ -n "${TRIGGER_MSG3:-}" ] && TRIG_NOTE="$TRIG_NOTE; повтор после enable+transport: $TRIGGER_MSG3"
  [ -n "${TRIGGER_MSG2:-}" ] && TRIG_NOTE="$TRIG_NOTE; bmgr run: $TRIGGER_MSG2"
  echo "NA_NOTE=внешний триггер вектора $V не сработал: $TRIG_NOTE"
  echo "RESULT=NA_TRIGGER_FAILED"
else
  echo "RESULT=NO_PAYLOAD"
fi
adb shell am force-stop "$PKG" >/dev/null 2>&1
exit 0
