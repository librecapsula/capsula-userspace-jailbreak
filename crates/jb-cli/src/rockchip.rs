//! Rockchip-бэкенд (RK3308): весь специфичный для платформы сценарий —
//! подключение (лоадер/MaskROM, первое поколение), полный дамп, оверлей
//! userdata, запись, перезагрузка, ожидание ADB-гаджета, монитор шины и
//! WinUSB-драйверы Windows. Платформа опознаётся по USB-устройству:
//! VID 2207 (лоадер/MaskROM/usbplug/Linux-гаджет) и аварийный fastboot
//! 18d1:d00d.
//!
//! Транспорт и протоколы — крейт rockusb; доменная логика (GPT, дамп,
//! оверлей, вшитый лоадер) — jb-core. Этот модуль привязывает их к
//! CLI-контракту `crate::backend::Backend`.

use crate::backend::Backend;
use crate::progress::CliProgress;
use anyhow::{bail, Context};
use jb_core::backup_store::BackupStore;
use jb_core::config::Config;
use jb_core::session::{bring_up, BringUpError, Progress};
use jb_core::{backup, flash, userdata};
use rockusb::loader::RESET_SUBCODE_NORMAL;
use rockusb::NusbTransport;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The gadget must stay on the bus this long to be considered alive:
/// the stock firmware blinks 0006 for under a second.
const GADGET_STABLE: Duration = Duration::from_secs(10);

/// The live device as the flow sees it (after bring-up). The `firstgen`
/// flag selects the path inside the shared flow: first generation works
/// over the stock loader and has no backup.
struct Device {
    session: rockusb::LoaderSession<NusbTransport>,
    serial: String,
    /// First generation: the stock u-boot rockusb loader (330d) with a
    /// gift serial — no backup possible, userdata is built from scratch.
    firstgen: bool,
    /// A fresh backup was taken this run (false = a verified backup for
    /// this serial already existed, or first generation).
    dumped: bool,
}

/// Реализация бэкенда для Rockchip. Держит драйверную сессию Windows
/// (win-drv) живой на весь сценарий: супервизор обязан перевязывать
/// плату на WinUSB и во время записи userdata.
pub struct Rockchip {
    config: Config,
    drivers: win_drv::Session,
}

impl Rockchip {
    pub fn new() -> Self {
        Rockchip {
            config: Config::embedded(),
            drivers: win_drv::Session::new(),
        }
    }
}

impl Default for Rockchip {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for Rockchip {
    fn name(&self) -> &'static str {
        "rockchip"
    }

    fn present(&self) -> anyhow::Result<bool> {
        Ok(rockusb::current_mode()?.is_some())
    }

    fn wait_hint(&self) -> Option<&str> {
        Some(&self.config.hint.text)
    }

    fn jailbreak(
        &mut self,
        yes: bool,
        format_userdata: bool,
        wait: Option<Duration>,
    ) -> anyhow::Result<()> {
        let mut dev = dump_all(wait, &mut self.drivers)?;
        write_userdata(&mut dev, yes, format_userdata, wait)
    }

    fn backup(&mut self, wait: Option<Duration>) -> anyhow::Result<()> {
        let dev = dump_all(wait, &mut self.drivers)?;
        if dev.firstgen {
            bail!(
                "первое поколение: полный дамп невозможен (BootROM залочен). \
                 Запустите инструмент без подкоманды — он прошьёт оверлей adbd \
                 без бэкапа"
            );
        }
        let where_ = backup_dir(&dev.serial).display().to_string();
        if dev.dumped {
            println!(
                "готово: дампы {} — в {where_} (на колонку не писалось)",
                dev.serial
            );
        } else {
            println!(
                "валидный бэкап {} уже есть в {where_} — делать нечего \
                 (удалите каталог, чтобы снять дамп заново)",
                dev.serial
            );
        }
        Ok(())
    }

    fn monitor(&mut self) -> anyhow::Result<()> {
        monitor()
    }
}

/// Backup directory for a column: backup/<sanitized serial>.
fn backup_dir(serial: &str) -> PathBuf {
    Path::new("backup").join(BackupStore::dir_name(serial))
}

/// Steps 1-3 (loader, device, full dump into backup/) for regular
/// columns; for first-generation personas the same session mechanics,
/// but no backup — that hardware cannot run our usbplug.
///
/// On Windows the board hops between devnodes (330d loader, 330e
/// MaskROM/usbplug) and a fresh devnode may be grabbed by a vendor
/// Rockusb driver before our WinUSB package gets it; when that
/// happens the session rebinds the node and the bring-up — which is a
/// re-entrant state machine over the current bus state — is retried.
fn dump_all(wait: Option<Duration>, drivers: &mut win_drv::Session) -> anyhow::Result<Device> {
    if win_drv::any_rockchip_node_misbound() {
        println!("устройство Rockchip без WinUSB — ставлю драйвер");
        start_or_wait_drivers(drivers, Duration::from_secs(180));
    }

    const ATTEMPTS: u32 = 5;
    for attempt in 1..=ATTEMPTS {
        match dump_all_once(wait) {
            Ok(s) => return Ok(s),
            Err(e) => {
                if attempt < ATTEMPTS && win_drv::chain_is_binding_error(&e) {
                    println!(
                        "узел перехвачен чужим драйвером (попытка {attempt}/{ATTEMPTS}) — перевязываю"
                    );
                    start_or_wait_drivers(drivers, Duration::from_secs(120));
                    continue;
                }
                if win_drv::chain_is_binding_error(&e) {
                    // the driver supervisor could not win in ATTEMPTS tries
                    return Err(e.context(format!(
                        "драйвер WinUSB не установился; лог: {}\n\
                         ручной путь: DRIVER-SETUP.txt (Zadig)",
                        drivers.log_path().display()
                    )));
                }
                return Err(e);
            }
        }
    }
    unreachable!("the retry loop always returns")
}

/// Make sure the driver supervisor is running, then wait for the board
/// to actually settle on WinUSB. The process is elevated from the very
/// start (UAC manifest), so this is pure install time: certificates,
/// the driver package import and the devnode restart take a few seconds
/// on a first run.
fn start_or_wait_drivers(drivers: &mut win_drv::Session, settle: Duration) {
    match drivers.ensure_supervision() {
        Ok(()) => {
            println!("ставлю драйвер WinUSB (до {} с)...", settle.as_secs());
            if !win_drv::wait_until_bound(settle) {
                println!(
                    "драйвер не установился за {} с (лог: {})",
                    settle.as_secs(),
                    drivers.log_path().display()
                );
            }
        }
        Err(e) => {
            println!(
                "не удалось запустить драйверную сессию: {e}\n  \
                 ручной путь: DRIVER-SETUP.txt (Zadig)\n  лог: {}",
                drivers.log_path().display()
            );
        }
    }
}

/// One bring-up + dump attempt (no retries). The first-generation
/// classification lives in bring_up (jb-core): the returned `firstgen`
/// flag drives everything downstream.
fn dump_all_once(wait: Option<Duration>) -> anyhow::Result<Device> {
    let config = Config::embedded();
    let loader = jb_core::loader::embedded().context("не удалось разобрать вшитый лоадер")?;
    let p = CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    let up = match bring_up(&config, &loader, wait, &progress) {
        Ok(v) => v,
        Err(BringUpError::LoaderRejected) => bail!(
            "usbplug не запустился: BootROM отклонил лоадер (неподдерживаемая \
             плата или первое поколение в MaskROM — отпустите Recovery и \
             войдите в режим лоадера заново)"
        ),
        Err(e) => return Err(e.into()),
    };

    // First generation: no backup on that hardware — straight to the
    // userdata write.
    if up.firstgen {
        return Ok(Device {
            session: up.session,
            serial: up.serial,
            firstgen: true,
            dumped: false,
        });
    }

    let serial = up.serial;
    let mut s = up.session;
    println!("серийник колонки: {serial}");
    let dir = backup_dir(&serial);
    // A verified backup of THIS column exists -> skip the dump
    // and go straight to the userdata write.
    let dumped = if BackupStore::exists_verified(&dir) {
        println!(
            "валидный бэкап уже есть в {} — дамп пропускаю (удалите \
             каталог, чтобы снять заново)",
            dir.display()
        );
        false
    } else {
        backup::backup(&mut s, &config, &dir, &progress)?;
        let _ = std::fs::write(dir.join("serial.txt"), &serial);
        true
    };
    Ok(Device {
        session: s,
        serial,
        firstgen: false,
        dumped,
    })
}

/// Steps 4-6, one shared flow for both paths: build the userdata image
/// (on top of the backup dump, or from scratch — first generation
/// always, `--format-userdata` by request), flash it, reboot and wait
/// for ADB. The only path difference is the image source; `fresh`
/// selects it.
fn write_userdata(
    dev: &mut Device,
    yes: bool,
    format_userdata: bool,
    wait: Option<Duration>,
) -> anyhow::Result<()> {
    let s = &mut dev.session;
    if dev.firstgen {
        println!(
            "первое поколение {} (стоковый лоадер): полный бэкап НЕВОЗМОЖЕН.",
            dev.serial
        );
    }

    let p = CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    // The GPT gives the partition size and the flash address on both
    // paths (the dump file is exactly the GPT sector count, so the
    // sizes agree).
    let gpt =
        jb_core::session::read_gpt(s, &progress).context("не удалось прочитать GPT колонки")?;
    let part = gpt
        .find("userdata")
        .context("в GPT колонки нет раздела userdata")?;
    let part_size = part.sectors * 512;
    if dev.firstgen {
        println!("раздел userdata: {} (из GPT колонки)", humansize(part_size));
    }

    // step 4: the image base — the dump from backup/ (regular column),
    // or nothing when building from scratch.
    let fresh = dev.firstgen || format_userdata;
    let dump = if fresh {
        None
    } else {
        // dump_all has just taken or verified this backup; re-check it
        // so a broken dump never becomes the base of the only copy.
        let store = BackupStore::open(&backup_dir(&dev.serial))
            .context("нет валидного бэкапа этой колонки — запустите инструмент ещё раз")?;
        store
            .verify()
            .context("бэкап не прошёл проверку SHA256 — снимите дамп заново")?;
        Some(
            store
                .find("userdata")
                .context("в бэкапе нет раздела userdata")?
                .to_path_buf(),
        )
    };

    if !yes {
        let mode = if dev.firstgen {
            "оверлей adbd на чистый ext2 — бэкапа на первом поколении нет, \
             текущее содержимое теряется"
        } else if fresh {
            "оверлей adbd на чистый ext2 (--format-userdata, содержимое теряется)"
        } else {
            "оверлей adbd поверх дампа, содержимое сохраняется"
        };
        println!("запись userdata ({}): {mode}", humansize(part_size));
        print!("продолжить? [y/N] ");
        crate::ask_yes()?;
    }

    let marker = format!("capsula-jb userspace {}\n", utc_now_iso());
    let out = PathBuf::from("work").join("userdata.img");
    userdata::build_image(
        dump.as_deref().unwrap_or(Path::new("")),
        &out,
        fresh,
        part_size,
        &userdata::overlay_files(marker),
        &print_step,
    )
    .context("не удалось собрать образ userdata с оверлеем")?;

    // step 5: flash the partition (the same session, ours or stock)
    flash::write_partition_padded(s, &gpt, "userdata", &out, &progress)?;

    // step 6: reboot and wait for the ADB gadget
    reboot_and_wait(s, wait)
}

/// The shared tail of every flow: reboot the device and wait for the ADB
/// gadget to come up and stay.
fn reboot_and_wait(
    s: &mut rockusb::LoaderSession<NusbTransport>,
    wait: Option<Duration>,
) -> anyhow::Result<()> {
    println!("перезагружаю колонку...");
    let _ = s.reset(RESET_SUBCODE_NORMAL);
    wait_for_adb_gadget(wait)
}

fn wait_for_adb_gadget(wait: Option<Duration>) -> anyhow::Result<()> {
    println!(
        "жду ADB-гаджет (2207:0006; должен продержаться {} с)...",
        GADGET_STABLE.as_secs()
    );
    rockusb::monitor::wait_gadget_stable(GADGET_STABLE, wait)
        .context("ADB-гаджет не поднялся (или мигнул и пропал) — проверьте загрузку колонки")?;
    println!("готово: ADB поднят — adb shell даёт root без авторизации");
    Ok(())
}

fn print_step(ev: Progress) {
    if let Progress::Step(msg) = ev {
        println!("{msg}");
    }
}

/// Live log of 2207:* bus events.
fn monitor() -> anyhow::Result<()> {
    let mut m = rockusb::DeviceMonitor::new();
    println!("Монитор USB 2207:* (Ctrl-C — выход).");
    m.poll()?;
    if let Some(best) = rockusb::transport::DeviceMode::best(m.modes()) {
        println!("сейчас на шине: {}", best.label());
    }
    loop {
        for ev in m.poll()? {
            match ev {
                rockusb::monitor::MonitorEvent::Appeared(mode) => {
                    println!(
                        "[{}] появился 2207:{:04x} ({})",
                        ts(),
                        mode.pid(),
                        mode.label()
                    )
                }
                rockusb::monitor::MonitorEvent::Disappeared(mode) => {
                    println!(
                        "[{}] пропал   2207:{:04x} ({})",
                        ts(),
                        mode.pid(),
                        mode.label()
                    )
                }
            }
        }
        std::thread::sleep(rockusb::monitor::POLL_INTERVAL);
    }
}

fn ts() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| {
            let secs = d.as_secs() % 86400;
            format!(
                "{:02}:{:02}:{:02}",
                secs / 3600,
                (secs / 60) % 60,
                secs % 60
            )
        })
        .unwrap_or_default()
}

fn humansize(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// Current UTC time as 2026-10-26T12:34:56Z.
fn utc_now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, m, s) = (rem / 3600, (rem / 60) % 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}
