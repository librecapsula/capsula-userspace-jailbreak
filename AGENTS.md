# AGENTS.md — инструкция для LLM-агентов: разработка

Инструкция по прошивке колонки для конечного пользователя — отдельный
файл `resources/packaging/AGENTS.md`; он же кладётся в релизные
архивы. Этот файл — о работе над репозиторием.

## Сборка и тесты

- `cargo build --release` — нужен Rust и C-компилятор (lwext4
  собирается через `cc`).
- `cargo test --workspace` — тесты userdata гоняют настоящий lwext4 на
  синтетических образах и сериализованы общим мьютексом (у lwext4
  глобальное состояние); протокольные тесты работают на MockTransport,
  без железа и без сети.
- Подписанный лоадер (`resources/loader/loader.bin`, из OTA Capsule-14
  44.90) — единственный бинарник прошивки в репозитории (хранение
  разрешено); вшивается в бинарник jb-core и проверяется обычным
  тестом (`jb_core::loader`). Сеть инструмент не использует: скачивания
  OTA с VK CDN больше нет (модули `ota`/`rkfw` удалены).

## Архитектура бэкендов

main (jb-cli) — только входная точка: разбор аргументов и выбор
платформенного бэкенда **по USB-устройству на шине** (`pick_backend`:
платформы различаются по VID:PID, опрос — через `Backend::present`).
Контракт — `jb-cli/src/backend.rs` (`jailbreak` / `backup` / `present`
/ `wait_hint`); реализация rockchip — `jb-cli/src/rockchip.rs`
(весь сценарий, WinUSB-драйверы win-drv, монитор шины), домен — jb-core.
Будущая платформа = новый модуль-бэкенд в jb-cli по контракту + строка
в `main::backends()`; rockchip-модуль при этом трогать не нужно.

## Первое поколение (подарочные колонки)

Колонки первого поколения определяются по серийнику стокового u-boot
(`jb_core::firstgen`: первые 4 знака не цифры — первое поколение).
Их BootROM залочен и отклоняет наш usbplug, поэтому полного бэкапа на
них нет; сценарий идёт через **стоковый rockusb-лоадер** (`2207:330d` с
«подарочным» серийником): GPT читается с LBA1, запись userdata —
штатный WRITE_LBA. Признак `firstgen` живёт в стейте сессии
(`bring_up` возвращает `BroughtUp { session, serial, firstgen }`),
джейлбрейк-сценарий один на оба пути (`write_userdata` в jb-cli
выбирает источник образа по флагу; `attach_stock_loader` — jb-core).
Замерено на живом железе (log/firstgen-stock-loader-diag-*.txt):

- стоковый лоадер отвечает chip_info («8033»), flash_detect (218 MiB
  NAND) и читает GPT целиком — таблица совпадает с Capsule-14,
  userdata 166 463 секторов на LBA 280 992;
- у стокового лоадера ЕСТЬ та же маска чтения 0xCC: всё выше LBA 0x10000
  (32 МиБ) читается как 0xCC — включая содержимое userdata (его ext2-
  суперблок виден как 0xcccc). Полный бэкап через стоковый лоадер тоже
  невозможен; читаемы только разделы ниже 32 МиБ (uboot, trust, misc,
  boot_a, начало boot_b);
- Read-only диагностика такой колонки:
  `cargo run -p jb-core --example stock_diag --release`.

Особенности, которые нельзя ломать:

- **fastboot (18d1:d00d) не поддерживается и не детектируется**:
  стоковый u-boot впадает в этот режим только при сбое; инструмент
  устройство под чужим VID не видит и просто ждёт режим лоадера.
  Fastboot-сценарии не добавлять: измерено на живом железе —
  брошенная на полпути DATA-фаза клинит гаджет намертво, до
  передёргивания питания. Исследовательский дамп getvar этого
  состояния — `log/firstgen-fastboot-getvar-all-*.txt`.
- userdata на первом поколении всегда собирается с нуля: чистый ext2,
  `/overlay/upper` с файлами и **пустой** `/overlay/work`
  (overlayfs требует существующий пустой workdir — S23overlayfs.sh его
  не создаёт).
- Windows: пакета win-drv под 18d1:d00d нет и не нужно (fastboot не
  поддерживается; процедура пакета — resources/drivers/winusb/
  README.md, если когда-нибудь понадобится).

## Ограничения, которые нельзя ломать

- `.cargo/config.toml` резервирует 8 МиБ стека главного потока на
  Windows-таргетах (`/STACK:8388608`) — с запасом под рекурсивные
  парсеры (исторически предел ставил рекурсивный парсинг
  OTA-манифеста, требовавший больше дефолтных для MSVC-линкера 1 МиБ).
  Конфиг не удалять и не занижать.
- `BULK_IN_MAX` в `rockusb/src/transport.rs` (1 МиБ) — потолок одного
  bulk-IN запроса на Windows: nusb включает RAW_IO, и WinUSB не дробит
  RAW_IO-запросы — всё выше maximum transfer size хост-стека (замерено:
  2 МиБ проходит, 3 МиБ падает с `usb: unknown (error 1)`) отклоняется
  мгновенно. Проверить потолок на новом железе:
  `cargo run -p jb-core --example readsize --release`.
- Файлы в `resources/drivers/winusb/` (INF+CAT+CER) — подписанные
  артефакты Zadig/libwdi: каталог подписывает ровно этот INF, поэтому
  их нельзя переименовывать и править (включая DriverVer). Новый PID =
  новый пакет против живого устройства — процедура в
  `resources/drivers/winusb/README.md`.

## win-drv (Windows-драйверы)

Крейт `crates/win-drv` держит плату на WinUSB без ручного Zadig: пакеты
зашиты в бинарник, сертификаты ставятся в **машинные**
Root/TrustedPublisher (`CertOpenStore(CERT_SYSTEM_STORE_LOCAL_MACHINE)`;
`CertOpenSystemStore` здесь ошибка — он пишет в хранилища текущего
пользователя и вешает процесс на модальном диалоге Windows), привязка —
`UpdateDriverForPlugAndPlayDevices` с FORCE (тот же newdev API, что у
Zadig), сессия следит за шиной и перевязывает узлы, перехваченные
вендорским Rockusb. Повышение — манифестом requireAdministrator,
вшитым ресурсом через `embed-resource` в jb-cli (путь через
`/MANIFESTUAC` в rustflags не работает — link.exe не принимает его в
этой форме). Живой тест: удалить libwdi-пакеты (`pnputil
/delete-driver oemNN.inf /uninstall /force`) и сертификаты (`certutil
-delstore Root/TrustedPublisher <thumbprint>`), запустить
`capsula-jb backup` из непривилегированного контекста — сценарий должен
сам дойти до «reading GPT» и полного дампа.

## Бэкапы по серийнику

Бэкапы лежат в `backup/<серийник>/`. Серийник читается **ровно один
раз** — при распознавании персоны лоадера (330d, u-boot chipid, тот же
номер, что System Profiler) — и живёт всю сессию; остальные персоны его
не перечитывают (BootROM-гаджет рапортует нули — именно затирание
серийника нулями в MaskRom-ветке когда-то ломало ключ). Если каталог с
валидным бэкапом уже есть (SUCCESS.txt + SHA256 сходятся:
`BackupStore::exists_verified`), дамп пропускается и сценарий сразу
идёт к записи userdata; в `capsula-jb backup` при этом печатается
«nothing to do». Нюансы:

- `--no-backup` (CLI) пропускает и проверку, и съём дампа: userdata
  всегда собирается с нуля, каталог `backup/` не читается вовсе —
  крайний случай (например, битый каталог); с подкомандой `backup`
  флаг несовместим и отвергается с ошибкой;
- колонка вошла без персоны лоадера (MaskROM напрямую, живой usbplug от
  прошлого прогона, нечитаемый серийник 330d) → серийник неизвестен, и
  `bring_up` **отказывается работать** с такой персоной: путь выбрать
  нельзя (ни кеш бэкапа, ни сценарий первого поколения), инструмент
  просит перезапустить колонку в режим лоадера и ждёт именно 330d
  (`refuse_unknown_identity` в session.rs; флоу `backup/unknown`
  удалён);
- старый плоский `backup/*.img` новыми версиями не читается.

## adbd

Оверлейный `adbd` собирается герметично в контейнере (Debian bullseye,
кросс-тулчейн, стоковый ABI glibc ≤ 2.33 / libcrypto 1.1):

```sh
docker build -t capsula-adbd docker/adbd
docker run --rm -v docker/adbd:/work capsula-adbd /work/build.sh
```

## Релизы

Тег `v*` запускает `.github/workflows/release.yml`: сборка adbd в
Docker → матрица из 5 платформ → публикация GitHub Release.

- В Windows-архив вкладываются `RockchipUSBDriver.zip` (вендорский
  драйвер Rockusb для официальных утилит) и `zadig-2.9.exe` (перевод
  платы на WinUSB для capsula-jb). Оба пинуются SHA256 в env
  воркфлоу: при обновлении upstream обновляйте пин, при изменении
  суммы сборка падает, а не катит непроверенный бинарник.
- В каждый архив кладутся `resources/packaging/QUICKSTART.txt`,
  `resources/packaging/AGENTS.md` (инструкция для агентов по прошивке)
  и, для Windows, `resources/packaging/windows-DRIVER-SETUP.txt`.
- Изменения упаковки проверяйте локально: `TARGET=... ARCHIVE=...
  TAG=vX.Y.Z bash .github/scripts/package.sh` после сборки.
