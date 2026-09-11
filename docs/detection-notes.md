# Следы векторов: что видно защитнику

Артефакты всех восьми векторов — что остаётся в APK и что появляется на устройстве.
Сверено с кодом (`pkg/manifest/*.go`, `internal/injector/*.go`,
`assets_payload/`, `appfactory_payload/`, `native_payload/`) и с прогонами корпуса
50 хостов × 8 векторов (`corpus-50-matrix.md`) на живом устройстве
(Pixel 6a, Android 17).

## Общий слой: это всегда переупаковка

| Артефакт | Почему появляется | Чем ловится |
|---|---|---|
| Заменённая подпись APK | любой вектор меняет zip (новый `classesN.dex`, `.so`, assets) → APK подписывается заново нашим ключом | сверка с подписью магазина/эталоном — единственный универсальный признак, 400/400 прогонов; ловит точно так же objection, apk.sh, apkinjector, ACVPatcher |
| Новый `classesN.dex` | payload-классы едут отдельным dex-файлом; имя = первый свободный индекс после хостовых `classes*.dex` (векторы 1–6, 8) | инвентарь zip: `classes2.dex`+ в хосте, где его не было |
| Переписанный бинарный манифест | строки в string pool, элемент/атрибут, пересчёт размеров чанков | diff манифеста против эталона (см. таблицу ниже) |
| `resources.arsc` и resource-XML **не тронуты** | правка идёт по байтам в существующих чанках, без `apktool` decode/rebuild | это не след, а наоборот: детекты, которые ищут «следы пересборки ресурсов», молчат |

## По векторам

| `-o` | Вектор | Статика в APK | Динамика на устройстве |
|---|---|---|---|
| 1 | custom payload | `<application android:name="aaaaaaaa.aaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaa.InjectedApp">`; `classesN.dex` (`payload_custom.dex`) | logcat `HELL` (наш PoC-стаб; нагрузка подменяемая) |
| 2 | frida gadget | тот же `android:name`; `lib/<abi>/libfrida-gadget.so` + `lib/<abi>/libfrida-gadget.config.so`; при `ARCHINOME_ADD_INTERNET=1` — `<uses-permission android:name="android.permission.INTERNET"/>` | `Frida: Listening on 127.0.0.1 TCP port 27042` в logcat приложения; сам порт 27042 в процессе хоста; строки `frida`/`frida-gadget` в `.so` |
| 3 | content provider | `<provider android:name="aaaaaaaaaaaa.ArchinomeProvider" android:authorities="<pkg>.archinome.provider">` первым ребёнком `<application>` | `PROVIDER_PAYLOAD_EXECUTED` (tag `ARCHINOME`); срабатывает в том числе при обращении из чужого процесса |
| 4 | trampoline | лончер-`<activity>` переименована в `aaaaaaaaaaaa.TrampolineActivity`; у остальных MAIN/LAUNCHER снят `<intent-filter>`; цель сохранена в meta-data с **ключом** `archinome.target:<fqcn>` | `TRAMPOLINE_PAYLOAD_EXECUTED`, затем стартует настоящая активити |
| 5 | broadcast receiver | `<receiver android:name="aaaaaaaaaaaa.ArchinomeReceiver">` с фильтрами `BOOT_COMPLETED`/`MY_PACKAGE_REPLACED`/`USER_PRESENT`, `exported=false`; `<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>` | `RECEIVER_PAYLOAD_EXECUTED` после перезагрузки / обновления / разблокировки |
| 6 | appComponentFactory | `android:appComponentFactory="aaaaaaaaaaaa.ArchinomeAppComponentFactory"` (API 28+); `classesN.dex` | `APPFACTORY_PAYLOAD_EXECUTED` — исполняется раньше `Application.onCreate` |
| 7 | native | `lib/<abi>/libarchin.so`; правка хостовой либы: `chain` — имя payload'а дописано в её `DT_NEEDED`, `replace` — хост переименован в `<host>_orig.so`, а payload занял его имя, `append` — payload отдельной либой; в chain-режиме рядом лежит placeholder `libarchinome_dependency_slot.so` | тег `ARCHINOME_NATIVE`, строка `NATIVE_PAYLOAD_CTOR`; наш `.so` в `/proc/<pid>/maps`; лишняя или переписанная `DT_NEEDED` |
| 8 | assets | `assets/archinome_payload.enc` — `ARCHN1` + nonce(12) + AES-256-GCM(payload dex); loader как `classesN.dex`; манифестный носитель задаётся `ARCHINOME_ASSETS_VECTOR` (appfactory/provider/receiver) | `ASSET_PAYLOAD_EXECUTED`, `ASSET_DEX_DROPPED <path> (N bytes)`: расшифрованный dex пишется в приватный каталог приложения с правами `0400` и грузится `DexClassLoader`; дальше `DYN_PAYLOAD_EXECUTED_FROM_EXTERNAL_DEX` |

## Порядок проверки

1. **Подпись** — сверка с подписью магазина/эталоном. Это единственный признак,
   который срабатывает всегда (все 400 прогонов) и не зависит от того, какой носитель
   выбран.
2. **Состав zip** — неожиданные `classesN.dex`; `lib/<abi>/*.so` в STORED-виде,
   особенно `libarchin.so`, `libfrida-gadget*.so`, `*_orig.so`;
   `assets/archinome_payload.enc` с magic `ARCHN1`.
3. **Бинарный манифест** — `android:appComponentFactory`, `android:name` у
   `<application>`, `<provider>` с `archinome.provider` в authorities, `<receiver>`
   с `BOOT_COMPLETED` + `RECEIVE_BOOT_COMPLETED`, переименование лончер-активити,
   meta-data `archinome.target:*`. Имена видны в string pool: `aapt2 dump xmltree`
   или `strings AndroidManifest.xml`.
4. **Рантайм** — logcat-теги из таблицы, открытый порт 27042 в процессе хоста,
   dex-файл с правами `0400` в приватном каталоге приложения, строки `frida` в
   памяти процесса.

## Чего эти признаки не дают (ограничения)

- Имена `aaaaaaaa*`, теги `ARCHINOME*`/`HELL` и `archinome.*` — подпись PoC, а не
  свойство техники: и пакет, и классы, и теги переименовываются в одну строку
  константы, после чего пункт 3 почти полностью вырождается в «сверь манифест с
  эталоном».
- `aapt2 dump xmltree` показывает и те атрибуты, которые платформа не увидит:
  она резолвит имя через resource map и ищет по возрастанию resource id, а aapt2
  идёт по массиву атрибутов линейно. Дамп — не доказательство, что атрибут работает
  (см. разбор в `corpus-50-matrix.md`, §3).
- Вектор 2 требует `android.permission.INTERNET`: у 22 из 50 хостов корпуса его нет,
  и без него listen-режим gadget'а не поднимается. Если разрешение добавлено
  (`ARCHINOME_ADD_INTERNET=1`), это ещё один видимый артефакт — новый
  `<uses-permission>` в манифесте.
- Вектор 7 в режиме `replace` не оставляет «лишней» либы под своим именем —
  вместо неё появляется `<host>_orig.so`; проверка «в lib/ есть .so, которого не
  было» должна искать и этот суффикс.
- Вектор 7 неприменим там, где хост вообще не загружает свои `lib/<abi>/*.so` при
  холодном старте (8 из 50 хостов корпуса) — разбор в `v7-host-lib-selection.md`.
- Все проверки выше — про репак на уровне манифеста/dex/zip. Ни одна из них не
  ловит нагрузку после запуска (что именно исполняется, зависит от payload'а,
  который в PoC — заглушка).
