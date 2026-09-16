# Следы векторов: что видно защитнику

Артефакты всех четырнадцати векторов — что остаётся в APK и что появляется на устройстве.
Сверено с кодом (`pkg/manifest/*.go`, `internal/injector/*.go`,
`assets_payload/`, `appfactory_payload/`, `native_payload/`,
`service_payload/`, `apppatch_payload/`, `instrumentation_payload/`,
`backupagent_payload/`, `zygote_payload/`) и с прогонами корпуса
50 хостов × все векторы (`corpus-50-matrix.md`) на живом устройстве
(Pixel 6a, Android 17).

## Общий слой: это всегда переупаковка

| Артефакт | Почему появляется | Чем ловится |
|---|---|---|
| Заменённая подпись APK | любой вектор меняет zip (новый `classesN.dex`, `.so`, assets) → APK подписывается заново нашим ключом | сверка с подписью магазина/эталоном — единственный универсальный признак, срабатывает во всех прогонах корпуса; ловит точно так же objection, apk.sh, apkinjector, ACVPatcher |
| Новый `classesN.dex` | payload-классы едут отдельным dex-файлом; имя = первый свободный индекс после хостовых `classes*.dex` (векторы 1–6, 8; у 9/11 — ещё и переписанное тело метода хоста, у 10 dex не добавляется вовсе) | инвентарь zip: `classes2.dex`+ в хосте, где его не было |
| Переписанный бинарный манифест | строки в string pool, элемент/атрибут, пересчёт размеров чанков (векторы 3–6, 8, 12–14; у 9/11 манифест не меняется вовсе) | diff манифеста против эталона (см. таблицу ниже) |
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
| 9 | service code patch | **не реализовано**: learn-шаг (список классов из `<service android:name>`) работает и печатает `CODEPATCH_TARGETS`, сама правка тела метода в разработке — хост пропускается с `NA_CODE_PATCH_PENDING`. Как только патч появится, след такой: **манифест байт-в-байт как у разработчика** — новых имён компонентов и правок атрибутов нет; виден лишний `classesN.dex` (`payload_service.dex`) и изменённое тело метода у классов-`<service>` хоста: вызов `invoke-static {}, Laaaaaaaaaaaa/ServicePatch;->run()V` в `<clinit>` (иначе `<init>`) перед завершающей `return-*` | `SERVICE_PATCH_EXECUTED` (tag `ARCHINOME`) при обычном старте — хост сам поднимает свой сервис (`startService`/`bindService`); если в хосте нет ни одного объявленного `<service>` — неприменимо (SKIP, `NA_NO_SERVICE_CLASS`) |
| 10 | native sideload | dex **не добавляется**; в `lib/<abi>/` появляется `lib<name>.so` под именем, которое хост запрашивает (`System.loadLibrary("<name>")`), но сам не поставляет; у payload-либы плейсхолдерная `DT_NEEDED`-строка переуказана на `libc.so` (`nativepatch` ModeSideload) | `NATIVE_PAYLOAD_CTOR` (tag `ARCHINOME`) в конструкторе либы — срабатывает тем же вызовом `loadLibrary`, который раньше давал ошибку; инжектор печатает `SIDELOAD_TARGET=lib<name>.so` и `SIDELOAD_CALLER=L<class>;-><method>`; если хост не просит ни одной непоставленной либы — SKIP / `NA_NO_UNSHIPPED_LIB` |
| 11 | Application code patch | **не реализовано** (тот же отложенный `code_item`-патч): learn-шаг находит класс из `<application android:name>` и печатает его, хост пропускается с `NA_CODE_PATCH_PENDING`. Целевой след: **манифест байт-в-байт как у разработчика**; лишний `classesN.dex` (`payload_apppatch.dex`) + изменённое тело метода в классе из `<application android:name>` | `APP_PATCH_EXECUTED` при обычном старте (экземпляр Application создаётся всегда); у хоста нет собственного Application-класса — SKIP / `NA_NO_CUSTOM_APP_CLASS`; инжектор печатает `CODEPATCH_TARGETS=... CODEPATCH_COUNT=n` |
| 12 | `<instrumentation>` | `<instrumentation android:name="aaaaaaaaaaaa.ArchinomeInstrumentation" android:targetPackage="<pkg>" android:functionalTest="true"/>` добавлен ребёнком `<manifest>` перед `<application>`; `classesN.dex` (`payload_instrumentation.dex`) | `INSTRUMENTATION_PAYLOAD_EXECUTED` — payload в `<init>` самого Instrumentation; триггер **внешний**: `am instrument -w <pkg>/aaaaaaaaaaaa.ArchinomeInstrumentation` (ошибка am → `NA_TRIGGER_FAILED`) |
| 13 | `android:backupAgent` | в `<application>` дописан `android:backupAgent="aaaaaaaaaaaa.ArchinomeBackupAgent"` (resID `0x0101027f`), `android:allowBackup` приведён к `true` (был `false` — правка на месте, resID `0x01010280`); `classesN.dex` (`payload_backupagent.dex`) | `BACKUPAGENT_PAYLOAD_EXECUTED` — payload в `<init>` BackupAgent (`onBackup`/`onRestore` — no-op); триггер **внешний**: `bmgr backup <pkg>`, затем `bmgr run` (в Android 17 подкоманды `backupnow` нет; нужен включённый транспорт — в лаборатории `com.android.localtransport`); нет транспорта или пакет не участник → `NA_TRIGGER_FAILED` |
| 14 | `android:zygotePreloadName` | в `<application>` дописан `android:zygotePreloadName="aaaaaaaaaaaa.ArchinomeZygotePreload"` (resID `0x0101059d`) и внутрь добавлен `<service android:name="aaaaaaaaaaaa.ArchinomeZygoteService" android:exported="true" android:isolatedProcess="true" android:useAppZygote="true"/>`; `classesN.dex` (`payload_zygote.dex`) | `ZYGOTE_PRELOAD_EXECUTED` — payload в `ZygotePreload.doPreload`; триггер **внешний**: `am start-service -n <pkg>/aaaaaaaaaaaa.ArchinomeZygoteService` (сервис не стартовал → `NA_TRIGGER_FAILED`) |

## Порядок проверки

1. **Подпись** — сверка с подписью магазина/эталоном. Это единственный признак,
   который срабатывает всегда (во всех прогонах корпуса) и не зависит от того, какой
   носитель выбран.
2. **Состав zip** — неожиданные `classesN.dex`; `lib/<abi>/*.so` в STORED-виде,
   особенно `libarchin.so`, `libfrida-gadget*.so`, `*_orig.so`,
   а для вектора 10 — любая `lib<name>.so`, которую хост запрашивает
   (`System.loadLibrary`), но в оригинале не поставлял;
   `assets/archinome_payload.enc` с magic `ARCHN1`.
3. **Бинарный манифест** — `android:appComponentFactory`, `android:name` у
   `<application>`, `<provider>` с `archinome.provider` в authorities, `<receiver>`
   с `BOOT_COMPLETED` + `RECEIVE_BOOT_COMPLETED`, переименование лончер-активити,
   meta-data `archinome.target:*`, а также `<instrumentation>` (12),
   `android:backupAgent` вместе с `android:allowBackup="true"` (13) и
   `android:zygotePreloadName` вместе с isolated `<service>` (14). Имена видны
   в string pool: `aapt2 dump xmltree` или `strings AndroidManifest.xml`.
4. **Байт-код методов хоста** — для векторов 9 и 11 манифест чист, поэтому
   единственная статика — сверка тела методов классов из манифеста с эталоном:
   лишний `invoke-static {}, Laaaaaaaaaaaa/{ServicePatch,AppPatch}->run()V` перед
   `return-*` в `<clinit>`/`<init>`. Нужен дизассемблер, а не `aapt2`.
5. **Рантайм** — logcat-теги из таблицы, открытый порт 27042 в процессе хоста,
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
- Векторы 9 и 11 — **самые тихие из всех**: манифест остаётся байт-в-байт как у
  разработчика, новых имён компонентов и правок атрибутов нет, diff манифеста
  молчит; видно только лишний `classesN.dex` и изменённое тело метода (п. 4).
  Цена — на стороне атакующего: правка `code_item` требует перекодировки dex
  хоста (пересчёт контрольных сумм, переиндексация таблиц).
- Вектор 10 прячет либу под именем, которое уже есть в самом хосте (в его
  `loadLibrary`-вызовах), поэтому «подозрительное имя» тут не ловится: помогает
  только сверка состава `lib/<abi>/` с эталоном — та же логика, что для
  `*_orig.so` у вектора 7.
- У векторов 12–14 статический след в APK есть, но payload активируется только
  **внешним** триггером (`am instrument` / `bmgr` / `am start-service`): обычный
  запуск приложения их не задействует, так что тишина в logcat при обычном старте
  — не доказательство, что патча нет.
- Атрибуты в бинарном AXML обязаны идти **по возрастанию resolved resource id**,
  а не по индексу строки (см. разбор в `corpus-50-matrix.md`, §3). Патчи 12–14
  соблюдают это: список атрибутов остаётся отсортированным по resID. Ресурс-иды
  сняты с устройства (Pixel 6a, Android 17): `targetPackage=0x01010021`,
  `functionalTest=0x01010023`, `exported=0x01010010`, `backupAgent=0x0101027f`,
  `allowBackup=0x01010280`, `isolatedProcess=0x010103a9`, `useAppZygote=0x01010597`,
  `zygotePreloadName=0x0101059d`.
- Все проверки выше — про репак на уровне манифеста/dex/zip. Ни одна из них не
  ловит нагрузку после запуска (что именно исполняется, зависит от payload'а,
  который в PoC — заглушка).
