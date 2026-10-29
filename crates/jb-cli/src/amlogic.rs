//! Amlogic-бэкенд (A113X, Capsula Mini поздних ревизий, плата MRC02B):
//! весь специфичный для платформы сценарий — ловля короткого
//! download-окна стокового u-boot (1b8e:c003 поднимается на каждое
//! включение примерно на полсекунды), полный однопроходный захват NAND,
//! сборка образа раздела data с оверлеем adbd, запись через
//! `download store`, перезагрузка. Платформа опознаётся по USB-устройству
//! VID 1b8e PID c003 (BootROM и burning-гаджет u-boot неразличимы на
//! шине — стадию сообщает identify).
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

        // шаг 1: полный захват (каждый запуск — свежий каталог; серийника,
        // по которому кешировать бэкап, у amlogic-мин нет)
        let base = if no_backup {
            println!(
                "--no-backup: бэкап не снимаю — data будет собран с нуля, \
                 текущее содержимое теряется"
            );
            None
        } else {
            let report = aml::backup::backup(&mut s, Path::new("backup"), &progress)
                .context("полный захват Amlogic")?;
            match report.status {
                aml::backup::Status::Complete => {
                    println!("готово: захват {} — полный", report.path.display());
                    Some(report.path.join("data.bin"))
                }
                aml::backup::Status::Warnings => {
                    // коротким мог стать любой файл; для базы образа важен
                    // только data — он публикуется как data.bin только
                    // полным
                    if report.path.join("data.bin").is_file() {
                        println!(
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

        // шаг 4: запись через download store + media-пакеты
        let image_len = std::fs::metadata(&out)?.len() as usize;
        let mut image = std::fs::File::open(&out)?;
        println!(
            "запись data: {} ({})",
            humansize(image_len as u64),
            out.display()
        );
        progress(Progress::TransferStart {
            name: "data".into(),
            bytes: image_len as u64,
        });
        s.write_store("data", image_len, &mut image, &|done| {
            progress(Progress::TransferProgress {
                name: "data".into(),
                done: done as u64,
                total: image_len as u64,
            });
        })
        .context("запись раздела data")?;
        progress(Progress::TransferDone {
            name: "data".into(),
        });

        // шаг 5: перезагрузка (u-boot reset; гаджет умрёт посреди статуса —
        // это ожидаемо) и ожидание ухода с шины
        println!("перезагружаю колонку...");
        let _ = s.bulk_cmd("reset");
        let start = Instant::now();
        while amlogic::present().unwrap_or(false) {
            if start.elapsed() >= REBOOT_WAIT {
                println!(
                    "колонка не ушла с шины за {} с — проверьте её состояние",
                    REBOOT_WAIT.as_secs()
                );
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        println!(
            "готово: data прошит оверлеем adbd. Дождитесь загрузки колонки и \
             проверьте `adb devices` (PID живого Linux-гаджета amlogic-мин \
             инструмент не знает — следим только за 1b8e:c003)."
        );
        Ok(())
    }

    fn backup(&mut self, wait: Option<Duration>) -> anyhow::Result<()> {
        let p = CliProgress::new();
        let progress = |ev: Progress| p.handle(ev);
        let mut s = bring_up(wait, &progress)?;
        let report = aml::backup::backup(&mut s, Path::new("backup"), &progress)
            .context("полный захват Amlogic")?;
        match report.status {
            aml::backup::Status::Complete => println!(
                "готово: полный захват {} (на колонку не писалось)",
                report.path.display()
            ),
            aml::backup::Status::Warnings => println!(
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
                        println!(
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
    println!("запись data ({}): {mode}", humansize(part_size));
    print!("продолжить? [y/N] ");
    crate::ask_yes()
}

fn print_step(ev: Progress) {
    if let Progress::Step(msg) = ev {
        println!("{msg}");
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
    let (mut s, soc) = match open_and_identify(&progress) {
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
        println!("{soc}");
        return Ok(());
    }
    let mut s = s;
    let t0 = Instant::now();
    for c in cmds {
        // "cycle <n>": n полных циклов перезахода в окно БЕЗ перезагрузки
        // платы — вложенный `run try_auto_burn` реинициализирует гаджет
        // (свежий бюджет окна), ловим переэнумерацию и стримим 4 МиБ из
        // каждой новой сессии. Ответ вложенной команды теряется (гаджет
        // роняет трубы) — шлём без ожидания статуса.
        if let Some(n) = c.strip_prefix("cycle ") {
            let n: u32 = n.parse().context("cycle <n>: не число")?;
            for i in 1..=n {
                println!("cycle {i}/{n}: убиваю окно (run try_auto_burn)...");
                let _ = s.send_bulk_cmd("run try_auto_burn");
                std::thread::sleep(Duration::from_millis(300));
                let caught = Instant::now();
                s = bring_up(Some(Duration::from_secs(30)), &progress)
                    .context(format!("cycle {i}: новое окно не поймано за 30 с"))?;
                println!(
                    "cycle {i}/{n}: новое окно за {} мс — стримлю 4 МиБ...",
                    caught.elapsed().as_millis()
                );
                let st = Instant::now();
                let data = s
                    .upload_read(amlogic::RAM_SCRATCH, 0x400_000)
                    .context(format!("cycle {i}: стрим не прошёл"))?;
                println!(
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
            println!("пауза {ms}мс (ничего не отправляется)...");
            std::thread::sleep(Duration::from_millis(ms));
            continue;
        }
        // "id": одиночный identify — кандидат в keepalive (вендорский
        // инструмент идентифицирует перед каждой операцией)
        if c == "id" {
            let soc = s.identify()?;
            println!("id -> {soc} (+{}мс)", t0.elapsed().as_millis());
            continue;
        }
        // "dlmem <size>": probe-download в DRAM (флеш не трогается):
        // arm через TPL-канал (AM_REQ_TPL_CMD, как вендорский update) +
        // media-пакеты + финальный TPL-статус. Проверка гипотезы, что
        // download-передача переводит гаджет в состояние «burning идёт»
        // и таймер update-окна перестаёт работать.
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
            println!(
                "dlmem {size:#x}: arm -> {armed} (+{}мс)",
                t0.elapsed().as_millis()
            );
            let data = vec![0u8; size];
            s.write_media_all(&data)?;
            // финальный статус — из TPL-канала; общий буфер ответа сперва
            // отдаёт склейки ack-ов (OK!!ess), поэтому ждём настоящий
            // success терпеливо, а не падаем на первом мусоре
            let mut st = String::new();
            for _ in 0..100 {
                match s.tpl_stat() {
                    Ok(text) if text.starts_with("success") => {
                        st = text;
                        break;
                    }
                    Ok(text) => st = text,
                    Err(e) => {
                        st = format!("<tpl_stat: {e}>");
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            println!(
                "dlmem {size:#x}: done -> {st} (+{}мс)",
                t0.elapsed().as_millis()
            );
            continue;
        }
        let r = if let Some((addr, size)) = parse_upload_cmd(c) {
            println!("читаю {size:#x} байт с {addr:#x}...");
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
            Ok(status) => println!("{c} -> {status}"),
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
