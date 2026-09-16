#!/usr/bin/env python3
"""Прогоняет все векторы внедрения по всем APK корпуса.

Возобновляемо: пара (package, vector), уже присутствующая в matrix.tsv,
пропускается — можно спокойно перезапускать после обрыва.
Пишет по одной TSV-строке на прогон и дублирует прогресс в matrix.log.

Входные файлы (рядом со скриптом, см. README.md):
  targets.tsv   package<TAB>versionCode<TAB>size
  apk/<package>.apk   — сами APK, их скачивает dl.sh

Выходные файлы:
  matrix.tsv    колонки: timestamp  package  vector  verdict  inject_ok
                install_ok  payload_ok  alive  crash  natmode  pid  note
                duration  (первая строка — заголовок)
  matrix.log    журнал прогресса; для неуспешных прогонов в строку включён
                текст причины из колонки note

Колонка note — причина для не-успешного вердикта: для INJECT_FAIL это текст,
который вернул инжектор (stdout+stderr), для INSTALL_FAIL — вывод adb install,
для NO_PAYLOAD — фатальные строки logcat. Переводы строк заменены пробелами,
значение обрезано (см. NOTE_MAX).

Переменные окружения:
  CORPUS_DIR   каталог корпуса (по умолчанию — каталог этого скрипта)
"""
import os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
W = os.environ.get("CORPUS_DIR", HERE)

TAGS = {
    # вектор 1 ничего не логирует под своим именем: payload_custom.dex пишет
    # Log.i("HELL", "Hello, I'm a malicious payload")
    1: "HELL",
    # вектор 2 не логирует: инжектор только вызывает System.loadLibrary, поэтому
    # критерий — интерфейс самого gadget'а (frida-ps -> один процесс Gadget)
    2: "GADGET_CHECK",
    3: "PROVIDER_PAYLOAD_EXECUTED",
    4: "TRAMPOLINE_PAYLOAD_EXECUTED",
    5: "RECEIVER_PAYLOAD_EXECUTED",
    6: "APPFACTORY_PAYLOAD_EXECUTED",
    7: "NATIVE_PAYLOAD_CTOR",
    8: "ASSET_PAYLOAD_EXECUTED",
    # 9 и 11 — code patch: payload вызывается из тела метода, который хост
    # исполняет сам (<clinit>/<init> сервиса или Application-класса), поэтому
    # триггер — обычный запуск приложения
    9: "SERVICE_PATCH_EXECUTED",
    # 10 — native sideload: payload, как и у вектора 7, это библиотека (.dex в
    # APK не добавляется), критерий тот же — конструктор .so под тегом
    # ARCHINOME_NATIVE. Имя библиотеки инструмент узнаёт сам из loadLibrary()
    # хостового dex (см. SIDELOAD_TARGET в note)
    10: "NATIVE_PAYLOAD_CTOR",
    11: "APP_PATCH_EXECUTED",
    # 12..14 — внешний триггер: процесс поднимает платформа по команде с
    # устройства (`am instrument` / `bmgr` / `am start-service`), launcher не
    # участвует. Если триггер не выстрелил, вердикт — NA_TRIGGER_FAILED
    12: "INSTRUMENTATION_PAYLOAD_EXECUTED",
    13: "BACKUPAGENT_PAYLOAD_EXECUTED",
    14: "ZYGOTE_PRELOAD_EXECUTED",
}
REINSTALL = {5}          # MY_PACKAGE_REPLACED срабатывает только при живой замене
VECTORS = sorted(TAGS)
# ONLY_VECTORS=9,10,11 — прогон подмножества (например, только новых векторов,
# чтобы не переигрывать уже проверенные). Пусто = все известные векторы.
if os.environ.get("ONLY_VECTORS"):
    want = {v.strip() for v in os.environ["ONLY_VECTORS"].split(",") if v.strip()}
    VECTORS = [v for v in VECTORS if str(v) in want]

NOTE_MAX = 400
HEADER = ["timestamp", "package", "vector", "verdict", "inject_ok", "install_ok",
          "payload_ok", "alive", "crash", "natmode", "pid", "note", "duration"]


def sanitize(s):
    """Одна строка без табов/переводов строк, обрезанная до NOTE_MAX."""
    if not s:
        return ""
    s = s.replace("\t", " ").replace("\n", " ").replace("\r", " ")
    return " ".join(s.split())[:NOTE_MAX]


def note_for(d, v=None):
    """Причина прогона — то, что реально нужно, чтобы разобрать отказ.

    Плюс провенанс для двух векторов, где вердикт зависит от того, что харнесс
    изменил по ходу дела: у вектора 2 хост без INTERNET получает разрешение
    (иначе gadget в listen-режиме физически не может создать сокет), у вектора 7
    host-либа выбирается замером /proc/<pid>/maps на оригинале, а не эвристикой.
    Без этого «PAYLOAD_OK» в матрице не отличить от «повезло с эвристикой».
    """
    extra = ""
    if v == 2 and d.get("ADDED_INTERNET_PERMISSION") == "1":
        extra += "харнесс добавил android.permission.INTERNET (у хоста его нет); "
    if v == 2 and d.get("GADGET_LISTENED", "0") not in ("", "0"):
        gport = os.environ.get("GADGET_PORT", "27042")
        extra += f"gadget подтверждён своей строкой в logcat (порт {gport} уже не отвечал); "
    if v == 2 and d.get("FREED_27042") == "1":
        extra += "харнесс освободил порт 27042 от чужого frida-server; "
    if v == 7 and d.get("LEARN_HOST_LIB", "none") not in ("", "none"):
        extra += f"host-либа выбрана замером maps: {d['LEARN_HOST_LIB']}; "
    # Векторы 9..14: у 9/11 важно, какой именно класс/метод пропатчен (иначе
    # PAYLOAD_OK не отличить от «пропатчен не тот класс»), у 10 — какую
    # библиотеку хост просит и не поставляет, у 13 — пришлось ли включать бэкап
    # и переводить менеджер на локальный транспорт.
    if v in (9, 11) and d.get("CODEPATCH_TARGETS", ""):
        extra += (f"пропатчено методов {d.get('CODEPATCH_COUNT', '?')}: "
                  f"{d['CODEPATCH_TARGETS']}; ")
    if v == 10 and d.get("SIDELOAD_TARGET", ""):
        extra += f"угнано имя {d['SIDELOAD_TARGET']}"
        if d.get("SIDELOAD_CALLER", ""):
            extra += f" (зовущий {d['SIDELOAD_CALLER']})"
        extra += "; "
    if v == 13 and d.get("TRIGGER_MSG_ENABLE", ""):
        extra += ("bmgr: бэкап был выключен/транспорт не поднят — харнесс включил "
                  "его и перевёл менеджер на локальный транспорт; ")
    return extra + reason(d)


def reason(d):
    verdict = d.get("RESULT", "")
    if verdict == "INJECT_FAIL":
        return sanitize(d.get("INJECT_MSG", ""))
    if verdict == "INSTALL_FAIL":
        return sanitize(d.get("INSTALL_MSG", "") or d.get("INJECT_MSG", ""))
    if verdict == "NO_PAYLOAD":
        return sanitize(d.get("FATAL_NOTE", "") or d.get("PAYLOAD_LINES", ""))
    if verdict in ("ALIGN_FAIL", "SIGN_FAIL", "SETUP_FAIL"):
        return sanitize(d.get("SIGN_MSG", "") or d.get("INJECT_MSG", ""))
    if verdict == "NA_NO_INTERNET":
        return ("в подписанном APK нет android.permission.INTERNET, хотя харнесс "
                "просил его добавить: listen-режим gadget'а не может создать сокет")
    if verdict == "NA_NO_LOADED_HOST_LIB":
        return sanitize(d.get("NA_NOTE", "")) or (
            "хост не грузит ни одной своей lib/<abi>/*.so при холодном старте: "
            "нативному вектору не за что зацепиться")
    # Неприменимость новых векторов: инжектор вернул SKIP (rc=3) и вышел, не
    # создав APK. Это не INJECT_FAIL — хосту просто нечего патчить/подменять.
    if verdict == "NA_NO_SERVICE_CLASS":
        return sanitize(d.get("NA_NOTE", "")) or (
            "в манифесте хоста нет собственных <service>: вектору 9 нечего патчить")
    if verdict == "NA_NO_UNSHIPPED_LIB":
        return sanitize(d.get("NA_NOTE", "")) or (
            "хост не просит через loadLibrary ни одной библиотеки, которой у него "
            "нет: вектору 10 нечего подменять")
    if verdict == "NA_NO_CUSTOM_APP_CLASS":
        return sanitize(d.get("NA_NOTE", "")) or (
            "у хоста нет собственного Application-класса: вектору 11 нечего патчить")
    # Внешний триггер (am instrument / bmgr / am start-service) не выстрелил:
    # инжект и установка прошли, но процесс под нашу точку входа платформа не
    # подняла. Сырой ответ триггера лежит в NA_NOTE (TRIGGER_MSG*).
    if verdict == "NA_TRIGGER_FAILED":
        return sanitize(d.get("NA_NOTE", "")) or (
            "внешний триггер вектора не сработал: процесса под точку входа нет, "
            "payload не получал шанса исполниться")
    if verdict == "HARNESS_TIMEOUT":
        return "прогон не уложился в таймаут (900 с)"
    return sanitize(d.get("INJECT_MSG", ""))


def load_apps():
    rows = []
    with open(os.path.join(W, "targets.tsv")) as fh:
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 2 and p[0] and p[0] != "package":
                rows.append((p[0], os.path.join(W, "apk", f"{p[0]}.apk")))
    return rows


def done():
    s = set()
    path = os.path.join(W, "matrix.tsv")
    if os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                p = line.split("\t")
                if len(p) > 2 and p[0] != "timestamp":
                    s.add((p[1], p[2]))
    return s


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(os.path.join(W, "matrix.log"), "a") as fh:
        fh.write(line + "\n")


def main():
    tsv = os.path.join(W, "matrix.tsv")
    if not os.path.exists(tsv) or os.path.getsize(tsv) == 0:
        with open(tsv, "a") as fh:
            fh.write("\t".join(HEADER) + "\n")
    harness = os.path.join(HERE, "harness.sh")
    apps = load_apps()
    already = done()
    todo = [(a, v) for a in apps for v in VECTORS if (a[0], str(v)) not in already]
    log(f"matrix start: {len(apps)} apps x {len(VECTORS)} vectors, {len(todo)} runs to do")
    for i, ((pkg, path), v) in enumerate(todo, 1):
        t0 = time.time()
        rc = None
        try:
            out = subprocess.run(
                ["bash", harness, path, pkg, str(v), TAGS[v], "1" if v in REINSTALL else "0"],
                capture_output=True, text=True, timeout=900)
            rc = out.returncode
            txt = out.stdout + out.stderr
        except subprocess.TimeoutExpired as e:
            partial = e.stdout or ""
            if isinstance(partial, bytes):
                partial = partial.decode("utf-8", "replace")
            txt = partial + "\nRESULT=HARNESS_TIMEOUT"
        d = {}
        for line in txt.splitlines():
            if "=" in line and not line.startswith(" "):
                k, _, val = line.partition("=")
                d[k.strip()] = val.strip()
        if "RESULT" not in d:
            # harness не напечатал RESULT (например, его нет на месте) — не теряем
            # вывод, иначе строка матрицы окажется недиагностируемой
            d["RESULT"] = "HARNESS_ERROR"
            d["INJECT_MSG"] = sanitize(txt) or f"harness не вернул RESULT (exit={rc})"
        row = [time.strftime("%Y-%m-%dT%H:%M:%S"), pkg, str(v), d.get("RESULT", "?"),
               d.get("INJECT", "?"), d.get("INSTALL", "?"), d.get("PAYLOAD", "?"),
               d.get("APP_ALIVE", "?"), d.get("CRASH", "?"), d.get("NATIVE_MODE", ""),
               sanitize(d.get("PID", "")), note_for(d, v), f"{time.time()-t0:.0f}s"]
        with open(tsv, "a") as fh:
            fh.write("\t".join(sanitize(x) for x in row) + "\n")
        line = (f"{i}/{len(todo)} {pkg} v{v} -> {row[3]} (payload={row[6]} "
                f"alive={row[7]} crash={row[8]}) {row[12]}")
        if row[3] not in ("PAYLOAD_OK",) and row[11]:
            # причина отказа обязана попасть и в журнал, иначе прогон не разобрать
            line += f" note={row[11]}"
        log(line)
        # артефакты держим только когда что-то пошло не так — /tmp не бесконечный
        for f in (os.path.join(W, "work", "al.apk"),):
            if os.path.exists(f):
                os.remove(f)
        if row[3] == "PAYLOAD_OK":
            for f in (os.path.join(W, "work", f"{pkg}_v{v}.apk"),
                      os.path.join(W, "work", f"{pkg}_v{v}_signed.apk")):
                if os.path.exists(f):
                    os.remove(f)
    log("matrix done")


if __name__ == "__main__":
    main()
