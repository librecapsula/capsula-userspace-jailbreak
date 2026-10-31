//! Amlogic-бэкенд (A113X, Capsula Mini поздних ревизий, плата MRC02B):
//! весь специфичный для платформы сценарий — ловля короткого
//! download-окна стокового u-boot (1b8e:c003 поднимается на каждое
//! включение примерно на полсекунды), полный чекпоинт-захват NAND по
//! окнам (как flasher.sh: окно исчерпано — просим передёрнуть питание,
//! ждём плату на шине, докачиваем), сборка образа раздела data с
//! оверлеем adbd, запись кусками «в ОЗУ → nand write» между окнами,
//! перезагрузка. Платформа опознаётся по USB-устройству VID 1b8e PID
//! c003 (BootROM и burning-гаджет u-boot неразличимы на шине — стадию
//! сообщает identify).
//!
//! Протокол — крейт `amlogic`; домен (захват, окружение, оверлей) —
//! jb-core. Этот модуль привязывает их к CLI-контракту
//! `crate::backend::Backend`.
//!
//! Отличия от rockchip-пути, измеренные на живом железе (ветка
//! feature/amlogic-mini): окно короткое — опрос шины быстрее, чем
//! rockchip-каденс; identify шлётся немедленно после открытия (он же
//! держит сессию); первый bulkcmd сессии — жертвенный `echo` (prime).
//! WinUSB-пакета под 1b8e:c003 нет: на Windows плату нужно один раз
//! перевести на WinUSB вручную (Zadig) — см. DRIVER-SETUP.txt.

use crate::backend::Backend;
use crate::progress::CliProgress;
use crate::util::{hexdump, humansize, utc_now_iso};
use anyhow::{bail, Context};
use jb_core::aml::backup::Pass;
use jb_core::aml::WriteState;
use jb_core::config::Config;
use jb_core::session::Progress;
use jb_core::{aml, userdata};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Каденс опроса в цикле ловли окна: окно u-boot ~450 мс, опрос шины
/// должен уверенно попасть внутрь (rockchip ждёт с каденсом 50 мс —
/// здесь тот же).
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Пауза между попытками открытия в горячем цикле (флэшер-референс
/// крутит 10 мс).
const RETRY_PAUSE: Duration = Duration::from_millis(10);
/// Сколько подряд неудачных open/identify терпим прежде, чем признать
/// проблему (обычно драйвер на Windows), прежде чем looping forever.
const MAX_OPEN_FAILURES: u32 = 10;
/// Сколько ждём ухода колонки с шины после команды reset.
const REBOOT_WAIT: Duration = Duration::from_secs(30);
/// Настенные часы одного окна: измеренная стена здоровой платы
/// 250–350 мс от открытия сессии; берём с запасом вниз. Полевой
/// эксперимент — AML_WINDOW_BUDGET_MS.
const WINDOW_BUDGET: Duration = Duration::from_millis(250);
/// Сколько окон подряд без прироста байт терпим, прежде чем признать
/// устойчивую проблему (кабель/драйвер/плата) и выйти.
const MAX_STALLED_WINDOWS: u32 = 3;

fn window_budget() -> Duration {
    std::env::var("AML_WINDOW_BUDGET_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(WINDOW_BUDGET)
}

/// Байт захвата на диске (для детекции топтания на месте).
fn captured_bytes(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| {
                    let n = e.file_name();
                    let n = n.to_string_lossy();
                    n.ends_with(".bin") || n.ends_with(".partial") || n == "env.txt"
                })
                .filter_map(|e| e.metadata().ok().map(|m| m.len()))
                .sum()
        })
        .unwrap_or(0)
}

/// После исчерпания окна — две попытки. Первая: рецепт стека
/// `reenter_download_window` — вложенный `run try_auto_burn`
/// (fire-and-forget) + 300 мс + port reset; если гаджет поднимается на
/// тёплом цикле, новое окно ловится без передёргивания питания.
/// Вторая (если рецепт не сработал — гаджет уже мёртв или тёплый цикл
/// его не поднимает): просьба передёрнуть питание и ожидание платы
/// (flasher.sh `poll_for_device`).
fn reconnect_window(
    mut s: amlogic::AmlogicSession<amlogic::NusbTransport>,
    progress: &dyn Fn(Progress),
) -> anyhow::Result<amlogic::AmlogicSession<amlogic::NusbTransport>> {
    // рецепт стека имеет смысл, только пока сессия жива: если окно
    // умерло раньше нас (transfer cancelled), в мёртвый гаджет стрелять
    // нечем и незачем
    if amlogic::present().unwrap_or(false) {
        let _ = s.send_bulk_cmd("run try_auto_burn");
        std::thread::sleep(Duration::from_millis(300));
        let _ = s.reset();
    }
    match bring_up(Some(Duration::from_secs(20)), progress) {
        Ok(fresh) => {
            log::info!("новое окно поймано без переподключения");
            Ok(fresh)
        }
        Err(e) => {
            log::info!("auto-cycle не сработал ({e}) — ручное переподключение");
            manual_reconnect(progress)
        }
    }
}

/// Ручной перезаход: просим передёрнуть питание колонки, ждём ухода
/// платы с шины (умирающий гаджет ещё висит и ломает open-бюджет
/// bring_up), затем ловим свежее окно.
fn manual_reconnect(
    progress: &dyn Fn(Progress),
) -> anyhow::Result<amlogic::AmlogicSession<amlogic::NusbTransport>> {
    log::info!(
        "Выключите и снова включите питание колонки — USB-кабель не \
         трогайте; я поймаю её на шине."
    );
    let mut reminder = Instant::now();
    while amlogic::present().unwrap_or(false) {
        if reminder.elapsed() >= Duration::from_secs(30) {
            log::warn!("...плата всё ещё на шине: выдерните питание колонки и вставьте обратно");
            reminder = Instant::now();
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    bring_up(None, progress)
}

/// Чекпоинт-цикл захвата: окна по очереди до полного дампа; каждое
/// исчерпанное окно — просьба переподключить плату и ожидание её на
/// шине.
fn capture_all_windows(
    session: amlogic::AmlogicSession<amlogic::NusbTransport>,
    parent: &Path,
    progress: &dyn Fn(Progress),
) -> anyhow::Result<(
    aml::backup::BackupReport,
    amlogic::AmlogicSession<amlogic::NusbTransport>,
)> {
    let dir = aml::backup::start(parent).context("каталог захвата Amlogic")?;
    let mut s = session;
    let mut last = captured_bytes(&dir);
    let mut stalls = 0u32;
    loop {
        match aml::backup::capture_pass(&mut s, &dir, progress, window_budget())
            .context("проход захвата Amlogic")?
        {
            Pass::Done(report) => return Ok((report, s)),
            Pass::Interrupted(reason) => {
                let now = captured_bytes(&dir);
                stalls = if now > last { 0 } else { stalls + 1 };
                last = last.max(now);
                if stalls >= MAX_STALLED_WINDOWS {
                    bail!(
                        "окна идут, а захват стоит на месте ({now} байт): {reason}\n  \
                         проверьте кабель/плату; окно ловится, но данные не идут"
                    );
                }
                log::info!("{reason}");
                s = reconnect_window(s, progress)
                    .context("перезаход в окно после исчерпания")?;
            }
        }
    }
}

/// Реализация бэкенда для Amlogic. Драйверная сессия win-drv здесь не
/// нужна: подписанных WinUSB-пакетов под 1b8e:c003 нет (новый PID —
/// новый пакет против живого устройства, см. resources/drivers/winusb/
/// README.md), привязка на Windows — вручную через Zadig.
pub struct Amlogic {
    config: Config,
}

impl Amlogic {
    pub fn new() -> Self {
        Amlogic {
            config: Config::embedded(),
        }
    }
}

impl Default for Amlogic {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for Amlogic {
    fn name(&self) -> &'static str {
        "amlogic"
    }

    fn present(&self) -> anyhow::Result<bool> {
        match amlogic::present() {
            Ok(p) => Ok(p),
            // мгновенный сбой перечисления (узел в середине перепривязки
            // на Windows) не должен ронять ожидание
            Err(e) => {
                log::warn!("перечисление USB не удалось ({e}) — попробую снова");
                Ok(false)
            }
        }
    }

    fn wait_hint(&self) -> Option<&str> {
        Some(&self.config.hint.amlogic_text)
    }

    fn jailbreak(
        &mut self,
        yes: bool,
        format_userdata: bool,
        no_backup: bool,
        wait: Option<Duration>,
    ) -> anyhow::Result<()> {
        let p = CliProgress::new();
        let progress = |ev: Progress| p.handle(ev);
        let mut s = bring_up(wait, &progress)?;

        // шаг 1: полный чекпоинт-захват по окнам (каждый запуск — свежий
        // каталог; серийника, по которому кешировать бэкап, у amlogic-мин
        // нет)
        let base = if no_backup {
            log::info!(
                "--no-backup: бэкап не снимаю — data будет собран с нуля, \
                 текущее содержимое теряется"
            );
            None
        } else {
            let (report, session) =
                capture_all_windows(s, Path::new("backup"), &progress)?;
            s = session;
            match report.status {
                aml::backup::Status::Complete => {
                    log::info!("готово: захват {} — полный", report.path.display());
                    Some(report.path.join("data.bin"))
                }
                aml::backup::Status::Warnings => {
                    // коротким мог стать любой файл; для базы образа важен
                    // только data — он публикуется как data.bin только
                    // полным
                    if report.path.join("data.bin").is_file() {
                        log::info!(
                            "готово: захват {} — с укороченными разделами \
                             (бед-блоки), раздел data полный",
                            report.path.display()
                        );
                        Some(report.path.join("data.bin"))
                    } else {
                        bail!(
                            "раздел data прочитан не полностью (бед-блоки) — \
                             строить образ поверх неполного дампа нельзя. \
                             Повторите запуск (бед-блок может уйти с перечётом \
                             логической ёмкости) или используйте \
                             --format-userdata/--no-backup"
                        );
                    }
                }
                other => bail!("неожиданный статус захвата: {other:?}"),
            }
        };

        // шаг 2: размеры и база образа
        let logical = s
            .partition_readable_size("data")
            .context("запрос логического размера data (store size)")? as u64;
        let fresh = format_userdata || no_backup;
        let base: Option<&Path> = match (&base, fresh) {
            (Some(path), false) => Some(path.as_path()),
            _ => None,
        };
        confirm_write(base.is_some(), fresh, no_backup, yes, logical)?;

        // шаг 3: сборка образа (та же доменная процедура, что и на rockchip)
        let marker = format!("capsula-jb userspace {}\n", utc_now_iso());
        let out = PathBuf::from("work").join("userdata.img");
        userdata::build_image(
            base.unwrap_or(Path::new("")),
            &out,
            base.is_none(),
            logical,
            &userdata::overlay_files(marker),
            &print_step,
        )
        .context("не удалось собрать образ раздела data с оверлеем")?;

        // шаг 4: запись кусками «в ОЗУ → nand write» между окнами —
        // один download store весь раздел в окно здоровой платы не
        // помещается так же, как и захват
        let image_len = std::fs::metadata(&out)?.len() as usize;
        let mut image = std::fs::File::open(&out)?;
        let data_off = amlogic::partition("data")
            .map(|(_, off, _)| off)
            .ok_or_else(|| anyhow::anyhow!("в карте разделов нет data"))?;
        log::info!(
            "запись data: {} ({})",
            humansize(image_len as u64),
            out.display()
        );
        progress(Progress::TransferStart {
            name: "data".into(),
            bytes: image_len as u64,
        });
        let mut st = WriteState::fresh();
        let mut last = 0usize;
        let mut stalls = 0u32;
        loop {
            let done = aml::write_data_pass(
                &mut s,
                &mut image,
                data_off,
                image_len,
                &mut st,
                &|done| {
                    progress(Progress::TransferProgress {
                        name: "data".into(),
                        done: done as u64,
                        total: image_len as u64,
                    });
                },
                window_budget(),
            )
            .context("проход записи data")?;
            if done {
                break;
            }
            stalls = if st.written > last { 0 } else { stalls + 1 };
            last = last.max(st.written);
            if stalls >= MAX_STALLED_WINDOWS {
                bail!(
                    "окна идут, а запись стоит на месте ({}/{}): \
                     проверьте кабель/плату",
                    humansize(st.written as u64),
                    humansize(image_len as u64)
                );
            }
            log::info!(
                "записано {} из {} — нужно свежее окно",
                humansize(st.written as u64),
                humansize(image_len as u64)
            );
            s = reconnect_window(s, &progress)
                .context("перезаход в окно после исчерпания записи")?;
        }
        progress(Progress::TransferDone {
            name: "data".into(),
        });

        // шаг 5: перезагрузка (u-boot reset; гаджет умрёт посреди статуса —
        // это ожидаемо) и ожидание ухода с шины
        log::info!("перезагружаю колонку...");
        let _ = s.bulk_cmd("reset");
        let start = Instant::now();
        while amlogic::present().unwrap_or(false) {
            if start.elapsed() >= REBOOT_WAIT {
                log::warn!(
                    "колонка не ушла с шины за {} с — проверьте её состояние",
                    REBOOT_WAIT.as_secs()
                );
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        log::info!(
            "готово: data прошит оверлеем adbd. Дождитесь загрузки колонки и \
             проверьте `adb devices` (PID живого Linux-гаджета amlogic-мин \
             инструмент не знает — следим только за 1b8e:c003)."
        );
        Ok(())
    }

    fn backup(&mut self, wait: Option<Duration>) -> anyhow::Result<()> {
        let p = CliProgress::new();
        let progress = |ev: Progress| p.handle(ev);
        let s = bring_up(wait, &progress)?;
        let (report, _) = capture_all_windows(s, Path::new("backup"), &progress)
            .context("полный захват Amlogic")?;
        match report.status {
            aml::backup::Status::Complete => log::info!(
                "готово: полный захват {} (на колонку не писалось)",
                report.path.display()
            ),
            aml::backup::Status::Warnings => log::info!(
                "готово: захват {} — с укороченными разделами (бед-блоки; \
                 см. manifest.json и файлы .partial; на колонку не писалось)",
                report.path.display()
            ),
            other => bail!("неожиданный статус захвата: {other:?}"),
        }
        Ok(())
    }
}

/// Поднять сессию: ловим окно 1b8e:c003 (открываем устройство напрямую на
/// каждом проходе — одна энумерация шины на попытку, без проверки
/// presence), identify немедленно, prime (жертвенный `echo`), требуем
/// стадию TPL (burning-команды есть только у u-boot-гаджета; BootROM на
/// мини залочен паролем и для сценария бесполезен). «Устройство не
/// найдено» = пустая шина; прочие ошибки копятся в бюджет — устойчивый
/// сбой (обычно драйвер) surfaced вместо вечного цикла.
pub(crate) fn bring_up(
    deadline: Option<Duration>,
    progress: &dyn Fn(Progress),
) -> anyhow::Result<amlogic::AmlogicSession<amlogic::NusbTransport>> {
    let start = Instant::now();
    let mut open_failures = 0u32;
    let mut seen = false;
    let mut hint_shown = false;
    loop {
        match open_and_identify(progress) {
            Ok((session, soc)) => {
                require_tpl(&soc)?;
                return Ok(session);
            }
            Err(amlogic::Error::DeviceNotFound) => {
                if seen {
                    log::info!("usb: 1b8e:c003 пропал (+{}мс)", start.elapsed().as_millis());
                    seen = false;
                    if !hint_shown {
                        log::info!(
                            "окно download-режима закрылось — выключите и снова \
                             включите подключённую колонку, я поймаю следующее"
                        );
                        hint_shown = true;
                    }
                }
                std::thread::sleep(RETRY_PAUSE);
            }
            Err(e @ amlogic::Error::MultipleDevices) => {
                bail!("{e}: подключите ровно одну колонку");
            }
            Err(e) => {
                if !seen {
                    log::info!(
                        "usb: 1b8e:c003 появился (+{}мс)",
                        start.elapsed().as_millis()
                    );
                    seen = true;
                }
                open_failures += 1;
                if open_failures >= MAX_OPEN_FAILURES {
                    bail!(
                        "устройство Amlogic на шине есть, но не открывается: {e}.\n  \
                         на Windows переведите 1b8e:c003 на WinUSB вручную (Zadig, \
                         см. DRIVER-SETUP.txt); macOS/Linux — проверьте права \
                         (udev-правило из архива)"
                    );
                }
                log::warn!(
                    "open/identify не удался ({e}) (+{}мс); пробую ещё",
                    start.elapsed().as_millis()
                );
            }
        }
        if let Some(d) = deadline {
            if start.elapsed() >= d {
                bail!("колонка Amlogic не появилась на шине (--wait)");
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn open_and_identify(
    progress: &dyn Fn(Progress),
) -> amlogic::Result<(
    amlogic::AmlogicSession<amlogic::NusbTransport>,
    amlogic::SocId,
)> {
    let t = Instant::now();
    let mut s = amlogic::AmlogicSession::open()?;
    let opened = t.elapsed();
    // Identify до любых пауз: prime сам ретраит кратко недоступный bulk-
    // канал, а у BootROM burning-канала нет вовсе. Первый bulkcmd сессии
    // может потерять первые байты (flasher.sh prime_bulk) — жертуем
    // командой, которая никому не нужна; её провал = мёртвая труба,
    // продолжать бессмысленно (сессия умрёт на первом же статусе).
    let soc = s.identify_and_prime()?;
    log::info!("amlogic: open +{opened:?}, identify +{:?}", t.elapsed());
    progress(Progress::Step(format!("amlogic download device: {soc}")));
    Ok((s, soc))
}

/// Burning-команды (store/download/upload/env) есть только у u-boot
/// гаджета; BootROM отвечает на bulkcmd молчанием.
fn require_tpl(soc: &amlogic::SocId) -> anyhow::Result<()> {
    if soc.stage() != amlogic::Stage::Tpl {
        bail!(
            "устройство в стадии {} — storage-команды доступны только из \
             u-boot-гаджета; передёрните питание колонки, чтобы поймать её \
             download-окно",
            soc.stage().label()
        );
    }
    Ok(())
}

/// Подтверждение записи (пропускается с --yes). На этот момент на колонку
/// ничего не записано — отказ безопасен.
fn confirm_write(
    has_base: bool,
    fresh: bool,
    no_backup: bool,
    yes: bool,
    part_size: u64,
) -> anyhow::Result<()> {
    if yes {
        return Ok(());
    }
    let mode = if no_backup {
        "оверлей adbd на чистый ext2 (--no-backup: бэкап не снимался, \
         текущее содержимое теряется)"
    } else if fresh {
        "оверлей adbd на чистый ext2 (--format-userdata, содержимое теряется)"
    } else if has_base {
        "оверлей adbd поверх полного захвата, содержимое сохраняется"
    } else {
        unreachable!("без базы и не fresh запись не запускается")
    };
    log::info!("запись data ({}): {mode}", humansize(part_size));
    log::info!("продолжить? [y/N]");
    crate::ask_yes()
}

fn print_step(ev: Progress) {
    if let Progress::Step(msg) = ev {
        log::info!("{msg}");
    }
}

/// `capsula-jb aml "<cmd>"...`: диагностика — identify платы и пасстру
/// u-boot burning-команд в рамках одного пойманного окна. `upload mem
/// <addr> normal <size>` вычитывает память и печатает hexdump; `sleep
/// <ms>` — хостовая пауза; `id` — одиночный identify (кандидат в
/// keepalive).
pub(crate) fn passthrough(wait: Option<Duration>, cmds: &[String]) -> anyhow::Result<()> {
    let p = CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    let (s, soc) = match open_and_identify(&progress) {
        Ok(pair) => pair,
        Err(amlogic::Error::DeviceNotFound) => {
            // пустая шина — ловим окно как обычно
            let mut s = bring_up(wait, &progress)?;
            let soc = s.identify()?;
            require_tpl(&soc)?;
            (s, soc)
        }
        Err(e) => return Err(e).context("открытие amlogic-устройства"),
    };
    require_tpl(&soc)?;
    if cmds.is_empty() {
        log::info!("{soc}");
        return Ok(());
    }
    let mut s = s;
    let t0 = Instant::now();
    for c in cmds {
        // "cycle <n>": n полных циклов перезахода в окно БЕЗ
        // передёргивания питания — вложенный `run try_auto_burn`
        // реинициализирует гаджет, затем port reset гасит узел
        // принудительно (рецепт стека reenter_download_window; тест
        // 18:08 без reset не дал переэнумерации за 30 с). Ловим
        // переэнумерацию и стримим 4 МиБ из каждой новой сессии.
        if let Some(n) = c.strip_prefix("cycle ") {
            let n: u32 = n.parse().context("cycle <n>: не число")?;
            for i in 1..=n {
                log::info!("cycle {i}/{n}: убиваю окно (run try_auto_burn + port reset)...");
                let _ = s.send_bulk_cmd("run try_auto_burn");
                std::thread::sleep(Duration::from_millis(300));
                let _ = s.reset();
                let caught = Instant::now();
                s = bring_up(Some(Duration::from_secs(30)), &progress)
                    .context(format!("cycle {i}: новое окно не поймано за 30 с"))?;
                log::info!(
                    "cycle {i}/{n}: новое окно за {} мс — стримлю 4 МиБ...",
                    caught.elapsed().as_millis()
                );
                let st = Instant::now();
                let data = s
                    .upload_read(amlogic::RAM_SCRATCH, 0x400_000)
                    .context(format!("cycle {i}: стрим не прошёл"))?;
                log::info!(
                    "cycle {i}/{n}: {} байт за {} мс (окно живо)",
                    data.len(),
                    st.elapsed().as_millis()
                );
            }
            continue;
        }
        // "sleep <ms>": хостовая пауза, ничего не отправляется
        if let Some(ms) = c.strip_prefix("sleep ") {
            let ms: u64 = ms.parse().context("sleep <ms>: не число")?;
            log::info!("пауза {ms}мс (ничего не отправляется)...");
            std::thread::sleep(Duration::from_millis(ms));
            continue;
        }
        // "id": одиночный identify — кандидат в keepalive (вендорский
        // инструмент идентифицирует перед каждой операцией)
        if c == "id" {
            let soc = s.identify()?;
            log::info!("id -> {soc} (+{}мс)", t0.elapsed().as_millis());
            continue;
        }
        // "dlmem <size>": probe-download в DRAM (флеш не трогается):
        // arm через TPL-канал (AM_REQ_TPL_CMD, как вендорский update) +
        // media-пакеты с синтетическим паттерном + финальный
        // `download get_status` (bulkcmd, как вендорский mwrite). Затем
        // `upload mem` читает записанное обратно и сравнивает: на живом
        // железе это проверяет, что media-флоу вендора доезжает до DRAM.
        if let Some(size) = c.strip_prefix("dlmem ") {
            let size = usize::from_str_radix(size.trim_start_matches("0x"), 16)
                .context("dlmem <size>: не hex-число")?;
            anyhow::ensure!(
                size > 0 && size <= 4 << 20,
                "dlmem <size>: 1..=0x400000"
            );
            let armed = s.tpl_cmd(&format!(
                "download mem {:#x} normal {size:#x}",
                amlogic::RAM_SCRATCH
            ))?;
            log::info!(
                "dlmem {size:#x}: arm -> {armed} (+{}мс)",
                t0.elapsed().as_millis()
            );
            // паттерн без нулевых прогонов: нулевую память не спутать
            // с незаписанной
            let data: Vec<u8> = (0..size).map(|i| ((i % 251) + 1) as u8).collect();
            s.write_media_all(&data)
                .context("dlmem: media-поток не принят")?;
            let st = s
                .bulk_cmd("download get_status")
                .context("dlmem: get_status не отработал")?;
            log::info!(
                "dlmem {size:#x}: get_status -> {st} (+{}мс), читаю обратно...",
                t0.elapsed().as_millis()
            );
            let back = s
                .upload_read(amlogic::RAM_SCRATCH, size)
                .context("dlmem: обратное чтение не удалось")?;
            let diff = back
                .iter()
                .zip(&data)
                .filter(|(a, b)| a != b)
                .count();
            if diff == 0 && back.len() == size {
                log::info!(
                    "dlmem {size:#x}: сверка сошлась, все {size:#x} байт на месте (+{}мс)",
                    t0.elapsed().as_millis()
                );
            } else {
                bail!(
                    "dlmem {size:#x}: сверка НЕ сошлась: {} байт отличаются, \
                     прочитано {:#x} из {size:#x}",
                    diff,
                    back.len()
                );
            }
            continue;
        }
        let r = if let Some((addr, size)) = parse_upload_cmd(c) {
            log::info!("читаю {size:#x} байт с {addr:#x}...");
            s.upload_read(addr, size).map(|data| {
                // большой поток — только начало + итог; hexdump 8 МиБ
                // никому не нужен
                let head = data.len().min(4096);
                hexdump(&data[..head], addr);
                format!(
                    "готово: {} байт (+{}мс)",
                    data.len(),
                    t0.elapsed().as_millis()
                )
            })
        } else {
            s.bulk_cmd(c)
                .map(|st| format!("{st} (+{}мс)", t0.elapsed().as_millis()))
        };
        match r {
            Ok(status) => log::info!("{c} -> {status}"),
            Err(e) => {
                let on_bus = amlogic::present().unwrap_or(false);
                bail!(
                    "команда {c:?} не удалась на +{}мс ({e}); устройство {}",
                    t0.elapsed().as_millis(),
                    if on_bus {
                        "ещё на шине (проблема передачи)"
                    } else {
                        "пропало с шины (download-окно закрылось посреди команды)"
                    }
                );
            }
        }
    }
    Ok(())
}

/// Разобрать пасстру-команду `upload mem <addr> normal <size>`.
fn parse_upload_cmd(c: &str) -> Option<(u32, usize)> {
    let t: Vec<&str> = c.split_whitespace().collect();
    if t.len() != 5 || t[0] != "upload" || t[1] != "mem" || t[3] != "normal" {
        return None;
    }
    let addr = u32::from_str_radix(t[2].trim_start_matches("0x"), 16).ok()?;
    let size = usize::from_str_radix(t[4].trim_start_matches("0x"), 16).ok()?;
    if size == 0 || size > 0x80_0000 {
        return None;
    }
    Some((addr, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_commands_reject_bootrom_spl_and_unknown_stages() {
        for stage in [0, 8, 5] {
            let soc = amlogic::SocId::parse(&[0, 7, 0, stage]).unwrap();
            assert!(require_tpl(&soc).is_err());
        }
        for major in [0, 1] {
            let soc = amlogic::SocId::parse(&[0, 7, major, 16]).unwrap();
            assert!(require_tpl(&soc).is_ok());
        }
    }

    #[test]
    fn upload_passthrough_parses_only_wellformed_mem_reads() {
        assert_eq!(
            parse_upload_cmd("upload mem 0x1080000 normal 0x100"),
            Some((0x108_0000, 0x100))
        );
        // без 0x — всё равно hex, как у флэшер-референса
        assert_eq!(
            parse_upload_cmd("upload mem 1080000 normal 40"),
            Some((0x108_0000, 0x40))
        );
        assert_eq!(parse_upload_cmd("upload store data normal 0x100"), None);
        assert_eq!(parse_upload_cmd("upload mem 0x0 normal 0x800001"), None);
        assert_eq!(parse_upload_cmd("printenv"), None);
    }
}
