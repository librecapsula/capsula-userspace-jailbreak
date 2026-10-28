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
  без железа. Единственный тест с реальными данными скачивает OTA с
  VK CDN в момент запуска и выключен по умолчанию (см. tests/README.md).
- Бинарные образцы прошивок в репозитории не хранятся и не
  распространяются.

## Первое поколение (подарочные колонки)

Колонки первого поколения определяются по серийнику стокового u-boot
(`jb_core::firstgen`: первые 4 знака не цифры — первое поколение).
Их BootROM залочен и отклоняет наш usbplug, поэтому полного бэкапа на
них нет; сценарий идёт через **стоковый rockusb-лоадер** (`2207:330d` с
«подарочным» серийником): GPT читается с LBA1, запись userdata —
штатный WRITE_LBA (`firstgen_stock_flow` в jb-cli, `attach_stock_loader`
в jb-core). Замерено на живом железе (log/firstgen-stock-loader-diag-*.txt):

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

- **fastboot (18d1:d00d) — аварийное состояние**, не рабочий канал:
  стоковый u-boot впадает в него только при сбое. Инструмент обязан
  отказываться работать с этим гаджетом и просить передёрнуть питание
  (см. раннюю классификацию в `dump_all_once`). Не добавляйте fastboot-
  сценарии: измерено на живом железе — брошенная на полпути DATA-фаза
  клинит гаджет намертво, до передёргивания питания. Исследовательский
  дамп getvar этого состояния — `log/firstgen-fastboot-getvar-all-*.txt`.
- userdata на первом поколении всегда собирается с нуля: чистый ext2,
  `/overlay/upper` с файлами и **пустой** `/overlay/work`
  (overlayfs требует существующий пустой workdir — S23overlayfs.sh его
  не создаёт).
- Windows: у win-drv нет подписанного пакета под 18d1:d00d — и не нужно:
  этот режим не рабочий (процедура пакета — resources/drivers/winusb/
  README.md, если когда-нибудь понадобится).

## Ограничения, которые нельзя ломать

- `.cargo/config.toml` резервирует 8 МиБ стека главного потока на
  Windows-таргетах (`/STACK:8388608`). Парсинг OTA-манифеста рекурсивен
  и требует больше дефолтного для MSVC-линкера 1 МиБ — конфиг не
  удалять и не занижать.
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

- колонка вошла без персоны лоадера (MaskROM напрямую, живой usbplug от
  прошлого прогона) → серийник неизвестен, дамп идёт в `backup/unknown`
  и кешем не становится (`session::is_identifying`: пустые и нулевые
  серийники — не идентичность);
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
