#!/usr/bin/env bash
# learn-host-lib.sh - какой .so хост реально грузит при холодном старте.
#
# Зачем: нативный вектор (archinome -o 7) делает так, чтобы линковщик загрузил
# payload, цепляясь за уже загружаемую библиотеку хоста (DT_NEEDED) или занимая
# её имя. Поэтому весь вектор упирается в один вопрос, которого нельзя решить,
# глядя на APK: какую из lib/<abi>/*.so процесс действительно откроет при
# старте. Статическая эвристика «самая большая либа» на корпусе из 50 F-Droid
# приложений даёт 11 попаданий из 19 применимых хостов: у 8 хостов выбранная
# библиотека при холодном старте не грузится вообще (в /proc/<pid>/maps ноль
# нативных либ), и прогон уходил в NO_PAYLOAD, хотя инжект был корректен.
#
# Скрипт отвечает на этот вопрос замером: ставит ОРИГИНАЛЬНЫЙ APK, запускает
# его, читает /proc/<pid>/maps и возвращает те .so из lib/<abi>/, которые
# процесс реально загрузил - в порядке загрузки.
#
# Использование:
#   ./learn-host-lib.sh <путь к оригинальному APK> <package> [serial]
#
# Вывод (машиночитаемый, последние строки):
#   CANDIDATES=liba.so libb.so
#   HOST_LIB=liba.so          <- первый загруженный, кандидат для
#                                ARCHINOME_NATIVE_HOST (пусто = ни одна либа
#                                при холодном старте не грузится: вектор 7 на
#                                этом хосте неприменим, это NA, а не сбой)
#
# Переменные окружения:
#   BUILD_TOOLS  каталог build-tools (нужен aapt2 для ABI-списка)
#   LAUNCH_WAIT  сколько секунд ждать после запуска (по умолчанию 6)
set -u

APK="$1"; PKG="$2"; SERIAL="${3:-}"
ADB="adb"; [ -n "$SERIAL" ] && ADB="adb -s $SERIAL"
B="${BUILD_TOOLS:-$(dirname "$(command -v aapt2 2>/dev/null || echo /nonexistent/aapt2)")}"
WAIT="${LAUNCH_WAIT:-6}"

[ -s "$APK" ] || { echo "HOST_LIB="; echo "NOTE=apk not found: $APK"; exit 0; }

# ABI, для которых в APK есть lib/: именно из них выбирает инжектор
ABIS=$("$B/aapt2" dump badging "$APK" 2>/dev/null | sed -n "s/^native-code: '\(.*\)'$/\1/p" | tr -d "'" | tr ' ' '\n' | sed '/^$/d')
[ -n "$ABIS" ] || ABIS="arm64-v8a armeabi-v7a"
# на устройстве почти всегда arm64-v8a; для замера берём первую объявленную ABI
PRIMARY_ABI=$(echo "$ABIS" | head -1)

# какие .so вообще лежат в APK (только они годятся как host). ABI не сужаем:
# в maps может быть загружен и armeabi-v7a вариант, если он объявлен первым.
ENTRIES=$(unzip -Z1 "$APK" 2>/dev/null | grep -E "^lib/[^/]+/.*\.so$")
if [ -z "$ENTRIES" ]; then
  echo "MEASURED=1"
  echo "CANDIDATES="; echo "HOST_LIB="
  echo "NOTE=в APK нет lib/<abi>/*.so (вектор 7 структурно неприменим)"
  exit 0
fi

$ADB uninstall "$PKG" >/dev/null 2>&1
sleep 1
if ! $ADB install -r -d "$APK" >/dev/null 2>&1; then
  echo "MEASURED=0"
  echo "CANDIDATES="; echo "HOST_LIB="
  echo "NOTE=оригинальный APK не установился, замер невозможен"
  exit 0
fi

$ADB shell am force-stop "$PKG" >/dev/null 2>&1
$ADB shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep "$WAIT"
PID=$($ADB shell pidof "$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')

# /proc/<pid>/maps чужого процесса на Android 10+ закрыт SELinux: читается
# только под root. Это лабораторный замер, а не часть инжекта, поэтому root
# здесь допустим; без него честнее сказать «замер невозможен» (MEASURED=0),
# чем выдать пустой список за «хост ничего не грузит».
MAPS_RAW=""
if [ -n "$PID" ]; then
  MAPS_RAW=$($ADB shell "su -c 'cat /proc/$PID/maps'" 2>/dev/null | tr -d '\r')
  [ -n "$MAPS_RAW" ] || MAPS_RAW=$($ADB shell cat "/proc/$PID/maps" 2>/dev/null | tr -d '\r')
fi
MEASURED=1
[ -n "$MAPS_RAW" ] || MEASURED=0

# Загруженные .so хоста: и распакованные (/lib/arm64-v8a/libX.so), и внутри APK
# (base.apk!/lib/arm64-v8a/libX.so). Порядок в maps = порядок загрузки.
CANDIDATES=""
if [ -n "$MAPS_RAW" ]; then
  CANDIDATES=$(printf '%s\n' "$MAPS_RAW" \
    | sed -n 's#.*[/!]lib/[a-z0-9_-]*/\(lib[^/ ]*\.so\).*#\1#p' \
    | awk '!seen[$0]++')
fi

# оставляем только то, что реально лежит в APK (инжектору нужен файл в lib/<abi>/)
LISTED=""
for c in $CANDIDATES; do
  echo "$ENTRIES" | grep -q "/$c$" && LISTED="$LISTED $c"
done
LISTED=$(echo $LISTED)

FIRST=$(echo "$LISTED" | awk '{print $1}')
echo "MEASURED=$MEASURED"
echo "PID=${PID:-none}"
echo "ABI=$PRIMARY_ABI"
echo "CANDIDATES=$LISTED"
echo "HOST_LIB=${FIRST:-}"
if [ "$MEASURED" = "0" ]; then
  echo "NOTE=не удалось прочитать /proc/<pid>/maps (нужен root на устройстве, PID=${PID:-нет}): замер не сделан, host-либа остаётся на эвристике инжектора"
elif [ -z "$FIRST" ]; then
  echo "NOTE=при холодном старте хост не загрузил ни одной своей lib/<abi>/*.so; нативный вектор здесь неприменим (NA)"
else
  echo "NOTE=первая загруженная библиотека хоста: $FIRST"
fi

$ADB shell am force-stop "$PKG" >/dev/null 2>&1
exit 0
