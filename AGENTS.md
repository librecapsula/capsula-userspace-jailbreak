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
