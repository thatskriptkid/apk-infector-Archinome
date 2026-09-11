#!/usr/bin/env python3
"""Структурный инвентарь корпуса: что вообще есть в каждом APK.

Для каждого apk/<pkg>.apk собирает через aapt2 badging + xmltree и по zip:
package/versionCode/minSdk/targetSdk/label, списки launchable-activity и abi,
число provider/receiver/activity/activity-alias/service, наличие
appComponentFactory, extractNativeLibs, android:name у <application>,
наличие resmap-атрибутов (exported/targetActivity/value/enabled), список
classes*.dex, список lib/** и число assets/**.

Результат: inventory.json рядом со скриптом + таблица в stdout.

Переменные окружения:
  CORPUS_DIR    каталог корпуса (по умолчанию — каталог этого скрипта)
  BUILD_TOOLS   каталог build-tools с aapt2
"""
import subprocess, os, json, re, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
C = os.environ.get("CORPUS_DIR", HERE)
BT = os.environ.get("BUILD_TOOLS", os.path.expanduser("~/Library/Android/sdk/build-tools/35.0.0"))
AAPT = os.path.join(BT, "aapt2")

out = {}
for fn in sorted(os.listdir(os.path.join(C, "apk"))):
    if not fn.endswith(".apk"): continue
    p = os.path.join(C, "apk", fn); d = {"apk": fn, "size": os.path.getsize(p)}
    bg = subprocess.run([AAPT, "dump", "badging", p], capture_output=True, text=True, timeout=180).stdout
    for k, pat in [("package", r"package: name='([^']+)'"), ("vercode", r"versionCode='([^']+)'"),
                   ("minSdk", r"minSdkVersion:'([^']+)'"), ("targetSdk", r"targetSdkVersion:'([^']+)'"),
                   ("label", r"application-label:'([^']+)'")]:
        m = re.search(pat, bg)
        if m: d[k] = m.group(1)
    d["launchable"] = re.findall(r"launchable-activity: name='([^']+)'", bg)
    d["abis"] = re.findall(r"native-code: '([^']+)'", bg)
    if not d["abis"]:
        m = re.search(r"native-code: (.+)", bg)
        if m: d["abis"] = [x.strip().strip("'") for x in m.group(1).split("' '")]
    xt = subprocess.run([AAPT, "dump", "xmltree", "--file", "AndroidManifest.xml", p], capture_output=True, text=True, timeout=300).stdout
    d["providers"] = len(re.findall(r"^\s*E: provider", xt, re.M))
    d["receivers"] = len(re.findall(r"^\s*E: receiver", xt, re.M))
    d["activities"] = len(re.findall(r"^\s*E: activity ", xt, re.M))
    d["aliases"] = len(re.findall(r"^\s*E: activity-alias", xt, re.M))
    d["services"] = len(re.findall(r"^\s*E: service ", xt, re.M))
    d["has_acf"] = bool(re.search(r"appComponentFactory", xt))
    m = re.search(r"extractNativeLibs\(0x[0-9a-f]+\)=\(type 0x12\)0x([01])", xt)
    d["extractNativeLibs"] = m.group(1) if m else "?"
    blk = re.search(r"^\s*E: application.*?(?=^\s*E: |\Z)", xt, re.M | re.S)
    d["app_name"] = None
    if blk:
        m = re.search(r'android:name\(0x[0-9a-f]+\)="([^"]*)"\s*\(Raw: "([^"]*)"\)', blk.group(0))
        if m: d["app_name"], d["app_name_raw"] = m.group(1), m.group(2)
        m = re.search(r'android:name\(0x[0-9a-f]+\)="([^"]*)"(?!\s*\(Raw)', blk.group(0))
        if not d["app_name"] and m: d["app_name"] = m.group(1)
    d["resmap_exported"] = bool(re.search(r":exported\(0x01010010\)", xt))
    d["resmap_targetActivity"] = bool(re.search(r":targetActivity\(0x01010202\)", xt))
    d["resmap_value"] = bool(re.search(r":value\(0x01010024\)", xt))
    d["resmap_enabled"] = bool(re.search(r":enabled\(0x0101000e\)", xt))
    with zipfile.ZipFile(p) as z:
        names = z.namelist()
        d["dex"] = sorted(n for n in names if re.match(r"classes\d*\.dex$", n))
        d["libs"] = sorted(n for n in names if n.startswith("lib/"))
        d["libabis"] = sorted(set(n.split("/")[1] for n in names if n.startswith("lib/")))
        d["assets"] = len([n for n in names if n.startswith("assets/")])
    out[fn] = d
json.dump(out, open(os.path.join(C, "inventory.json"), "w"), indent=1)
print(f"{'package':40s} {'vc':>9s} sdk    app_name                              prov recv act alias svc dex libs extr acf launc resmap(exp/tA/val/en)")
for fn, d in out.items():
    rm = f"{int(d['resmap_exported'])}{int(d['resmap_targetActivity'])}{int(d['resmap_value'])}{int(d['resmap_enabled'])}"
    print(f"{d.get('package','?'):40s} {d.get('vercode','?'):>9s} {d.get('minSdk','?')}->{d.get('targetSdk','?'):<3s} {str(d.get('app_name'))[:36]:36s} {d['providers']:4d} {d['receivers']:4d} {d['activities']:3d} {d['aliases']:5d} {d['services']:3d} {len(d['dex']):3d} {len(d['libs']):4d} {d['extractNativeLibs']:>4s} {str(d['has_acf'])[0]}    {len(d['launchable']):2d}   {rm}")
