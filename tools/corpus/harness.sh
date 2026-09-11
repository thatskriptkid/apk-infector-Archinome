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
#   RESULT        PAYLOAD_OK | NO_PAYLOAD | INJECT_FAIL | INSTALL_FAIL |
#                 ALIGN_FAIL | SIGN_FAIL | SETUP_FAIL | NA_NO_INTERNET
#
# Вектор 2 (frida) проверяется не по лог-тегу, а по интерфейсу самого gadget'а:
# frida-ps -H 127.0.0.1:27042 должен показать ровно один процесс Gadget.
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
  # chain-режиму нативного вектора нужен свободный слот в DT_NEEDED, а он есть
  # не у каждой хостовой библиотеки; откатываемся к replace/append. Собираем
  # вывод ВСЕХ попыток, чтобы причина отказа не потерялась за последней.
  for M in chain replace append; do
    rm -f "$OUT"
    M_OUT=$(ARCHINOME_NATIVE_MODE=$M $TO "$ARCH" "$APK" "$OUT" -o 7 2>&1); MRC=$?
    INJECT_RC=$MRC
    INJ="${INJ}${INJ:+$'\n'}[native-mode=$M rc=$MRC] ${M_OUT}"
    if [ -s "$OUT" ]; then NMODE=$M; break; fi
  done
  echo "NATIVE_MODE=${NMODE:-none}"
elif [ "$V" = "8" ]; then
  INJ=$(ARCHINOME_ASSETS_VECTOR=${ARCHINOME_ASSETS_VECTOR:-appfactory} $TO "$ARCH" "$APK" "$OUT" -o 8 2>&1); INJECT_RC=$?
else
  INJ=$($TO "$ARCH" "$APK" "$OUT" -o "$V" 2>&1); INJECT_RC=$?
fi
echo "INJECT_RC=$INJECT_RC"

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
adb shell am force-stop "$PKG" >/dev/null 2>&1
adb logcat -c >/dev/null 2>&1
adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 5
PID=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')
echo "PID=${PID:-none}"
if [ "$REINSTALL" = "1" ]; then
  # MY_PACKAGE_REPLACED срабатывает только при замене уже установленного пакета
  adb install -r -d "$SIGNED" >/dev/null 2>&1
  sleep 5
  PID=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')
fi
LOG=$(adb logcat -d 2>/dev/null)

# ---- vector 2 (frida gadget): his own interface, not a log tag --------------
# The injected wrapper only calls System.loadLibrary("frida-gadget"); nothing
# logs anything, and a gadget that cannot create its socket aborts the host on
# the spot. The only honest check is the gadget itself: frida-server compatible,
# a single process named Gadget, listening on 27042. That needs the host to hold
# android.permission.INTERNET - the platform denies socket creation to app
# domains without it, which is exactly how the gadget dies.
if [ "$TAG" = "GADGET_CHECK" ]; then
  if ! "$B/aapt2" dump permissions "$SIGNED" 2>/dev/null | grep -qa 'android.permission.INTERNET'; then
    echo "PAYLOAD=na"
    echo "FATAL_NOTE=host has no android.permission.INTERNET: a listen-mode gadget cannot create a socket"
    echo "APP_ALIVE=$([ -n "$PID" ] && [ "$PID" != none ] && echo 1 || echo 0)"
    echo "RESULT=NA_NO_INTERNET"
    adb shell am force-stop "$PKG" >/dev/null 2>&1
    exit 0
  fi
  adb forward tcp:27042 tcp:27042 >/dev/null 2>&1
  GADGET_LINES=$("${FRIDA_BIN:-frida-ps}" -H 127.0.0.1:27042 2>/dev/null | tr '\n' '|' | cut -c1-200)
  GADGET_HITS=$("${FRIDA_BIN:-frida-ps}" -H 127.0.0.1:27042 2>/dev/null | awk 'NR>1 {print $2}' | grep -c '^Gadget$')
  # frida-server тоже по умолчанию слушает 27042: если на порту он, ответ содержит
  # весь список процессов устройства, и вердикт нельзя выдавать как «gadget не встал»
  GADGET_OTHER=$("${FRIDA_BIN:-frida-ps}" -H 127.0.0.1:27042 2>/dev/null | awk 'NR>1' | wc -l | tr -d ' ')
  adb forward --remove tcp:27042 >/dev/null 2>&1
  echo "PAYLOAD=$GADGET_HITS"
  echo "PAYLOAD_LINES=$GADGET_LINES"
  echo "CRASH=$(echo "$LOG" | grep -acE 'Failed to start|Abort message')"
  if [ "$GADGET_HITS" -eq 0 ] && [ "${GADGET_OTHER:-0}" -gt 2 ]; then
    echo "FATAL_NOTE=на 27042 отвечает не gadget, а frida-server (процессов $GADGET_OTHER): уведи сервер на другой порт (frida-server -l 127.0.0.1:27099) и повтори"
  elif [ "$GADGET_HITS" -eq 0 ]; then
    # gadget не ответил: без этого текста прогон неотличим от «инжект не сработал»
    ALIVE_NOTE=нет
    [ -n "$PID" ] && [ "$PID" != none ] && ALIVE_NOTE=да
    echo "FATAL_NOTE=gadget не ответил на 27042: процессов в frida-ps=${GADGET_OTHER:-?}, ответ='${GADGET_LINES:-пусто}', процесс жив=$ALIVE_NOTE; logcat=$(echo "$LOG" | grep -aiE 'frida|gadget|Abort message|Failed to start' | head -2 | tr '\n' '|' | cut -c1-220)"
  else
    echo "FATAL_NOTE=$(echo "$LOG" | grep -aE 'Failed to start|Abort message' | head -2 | tr '\n' '|' | cut -c1-300)"
  fi
  echo "APP_ALIVE=$([ -n "$PID" ] && [ "$PID" != none ] && echo 1 || echo 0)"
  if [ "$GADGET_HITS" -gt 0 ]; then echo "RESULT=PAYLOAD_OK"; else echo "RESULT=NO_PAYLOAD"; fi
  adb shell am force-stop "$PKG" >/dev/null 2>&1
  exit 0
fi

echo "PAYLOAD=$(echo "$LOG" | grep -acE "$TAG")"
echo "PAYLOAD_LINES=$(echo "$LOG" | grep -aE "$TAG" | head -3 | tr '\n' '|' | cut -c1-400)"
echo "CRASH=$(echo "$LOG" | grep -acE 'FATAL EXCEPTION|ClassNotFoundException|Unable to instantiate application')"
echo "FATAL_NOTE=$(echo "$LOG" | grep -aE 'FATAL EXCEPTION|Unable to instantiate|ClassNotFoundException' | head -2 | tr '\n' '|' | cut -c1-300)"
if [ -n "$PID" ] && [ "$PID" != "none" ]; then echo "APP_ALIVE=1"; else echo "APP_ALIVE=0"; fi
if [ "$(echo "$LOG" | grep -acE "$TAG")" -gt 0 ]; then echo "RESULT=PAYLOAD_OK"; else echo "RESULT=NO_PAYLOAD"; fi
adb shell am force-stop "$PKG" >/dev/null 2>&1
exit 0
