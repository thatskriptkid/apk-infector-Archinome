#!/usr/bin/env python3
"""Сводка прогона матрицы: таблицы для docs/ из matrix.tsv.

Использование:
  python3 summarize.py [matrix.tsv]

Печатает markdown-таблицу вердиктов по векторам и пер-хостовую матрицу
(`+` PAYLOAD_OK, `-` NO_PAYLOAD, `s` INJECT_FAIL, `n` NA_NO_INTERNET,
`L` NA_NO_LOADED_HOST_LIB, `!` INSTALL_FAIL, `?` строки нет).
"""
import collections
import sys

ORDER = ["PAYLOAD_OK", "NO_PAYLOAD", "INJECT_FAIL", "NA_NO_INTERNET",
         "NA_NO_LOADED_HOST_LIB", "INSTALL_FAIL"]
CODE = {
    "PAYLOAD_OK": "+",
    "NO_PAYLOAD": "-",
    "INJECT_FAIL": "s",
    "NA_NO_INTERNET": "n",
    "NA_NO_LOADED_HOST_LIB": "L",
    "INSTALL_FAIL": "!",
}


def main(path):
    rows = [r.split("\t") for r in open(path).read().splitlines()[1:] if r.strip()]
    per: dict[int, collections.Counter] = collections.defaultdict(collections.Counter)
    hosts: dict[str, dict[int, str]] = collections.defaultdict(dict)
    for r in rows:
        pkg, vec, verdict = r[1], int(r[2]), r[3]
        per[vec][verdict] += 1
        hosts[pkg][vec] = verdict

    print("| Вектор | " + " | ".join(v.replace("_", " ") for v in ORDER) + " |")
    print("|---|" + "---|" * len(ORDER))
    for vec in sorted(per):
        cells = [str(per[vec][v]) if per[vec][v] else "0" for v in ORDER]
        print(f"| {vec} | " + " | ".join(cells) + " |")
    print()
    print("| хост | 1..8 |")
    print("|---|---|")
    for pkg in sorted(hosts):
        line = "".join(CODE.get(hosts[pkg].get(v, ""), "?") for v in range(1, 9))
        print(f"| {pkg} | `{line}` |")
    print()
    total = collections.Counter(r[3] for r in rows)
    print("итого:", ", ".join(f"{k}={total[k]}" for k in ORDER if total[k]),
          f"(строк {len(rows)}, хостов {len(hosts)})")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "matrix.tsv")
