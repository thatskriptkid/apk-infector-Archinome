#!/bin/bash
# Скачивает APK корпуса с f-droid.org в каталог apk/ рядом со скриптом.
#
# Источник — targets.tsv (package<TAB>versionCode<TAB>size): URL собирается как
#   https://f-droid.org/repo/<package>_<versionCode>.apk
# versionCode взят из suggestedVersionCode F-Droid API, то есть это те же самые
# сборки, что использовались в матрице.
#
# Сами APK в git не попадают (см. .gitignore) — их всегда качает этот скрипт.
#
# Использование:
#   bash dl.sh                 # скачать в ./apk
#   JOBS=2 bash dl.sh          # ограничить параллелизм (по умолчанию 4)
#   CORPUS_DIR=/tmp/c bash dl.sh   # другой каталог корпуса
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C="${CORPUS_DIR:-$HERE}"
DEST="$C/apk"
JOBS="${JOBS:-4}"
mkdir -p "$DEST"

dl() {
  local pkg="$1" vc="$2"
  local url="https://f-droid.org/repo/${pkg}_${vc}.apk"
  local out="$DEST/${pkg}.apk"
  local tmp="$out.part"
  if [ -s "$out" ]; then echo "skip $pkg (уже скачан)"; return 0; fi
  rm -f "$tmp"
  echo "get  $pkg <- $url"
  if curl -fsSL --retry 3 --retry-delay 2 --max-time 300 -o "$tmp" "$url"; then
    mv "$tmp" "$out"; echo "ok   $pkg ($(wc -c < "$out" | tr -d ' ') bytes)"
  else
    rm -f "$tmp"; echo "FAIL $pkg <- $url"
  fi
}

n=0
while IFS=$'\t' read -r pkg vc _rest; do
  [ -z "${pkg:-}" ] && continue
  [ "$pkg" = "package" ] && continue
  dl "$pkg" "$vc" &
  n=$((n + 1))
  if [ $((n % JOBS)) -eq 0 ]; then wait; fi
done < "$C/targets.tsv"
wait

echo DL_DONE
ls -la "$DEST" | tail -25
