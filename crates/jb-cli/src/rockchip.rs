//! Rockchip-бэкенд (RK3308): весь специфичный для платформы сценарий —
//! подключение (лоадер/MaskROM, первое поколение), полный дамп, оверлей
//! userdata, запись, перезагрузка, ожидание ADB-гаджета, монитор шины и
//! WinUSB-драйверы Windows. Платформа опознаётся по USB-устройству:
//! VID 2207 (лоадер/MaskROM/usbplug/Linux-гаджет).
//!
//! Транспорт и протоколы — крейт rockusb; доменная логика (GPT, дамп,
//! оверлей, вшитый лоадер) — jb-core. Этот модуль привязывает их к
//! CLI-контракту `crate::backend::Backend`.

use crate::backend::Backend;
use crate::progress::CliProgress;
use crate::util::{humansize, utc_now_iso};
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
/// flag selects the path inside the shared flow: first generation and
/// --no-backup runs work over the stock loader (330d); on first
/// generation the backup is NOT intact (0xCC above the 32 MiB read
/// mask) and userdata is always built from scratch.
struct Device {
    session: rockusb::LoaderSession<NusbTransport>,
    serial: String,
    /// First generation: the stock u-boot rockusb loader (330d) with a
    /// gift serial — the dump above the 32 MiB read mask is 0xCC,
    /// userdata is built from scratch.
    firstgen: bool,
    /// A fresh backup was taken this run (false = a verified backup for
    /// this serial already existed, or --no-backup).
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
        match rockusb::current_mode() {
            Ok(m) => Ok(m.is_some()),
            // a transient enumeration failure (a devnode mid-rebind on
            // Windows) must not abort the wait — report "not present"
            Err(e) => {
                log::warn!("перечисление USB не удалось ({e}) — попробую снова");
                Ok(false)
            }
        }
    }

    fn wait_hint(&self) -> Option<&str> {
        Some(&self.config.hint.text)
    }

    fn jailbreak(
        &mut self,
        yes: bool,
        format_userdata: bool,
        no_backup: bool,
        wait: Option<Duration>,
    ) -> anyhow::Result<()> {
        let mut dev = dump_all(wait, &self.config, &mut self.drivers, no_backup)?;
        write_userdata(&mut dev, yes, format_userdata, no_backup, wait)
    }

    fn backup(&mut self, wait: Option<Duration>) -> anyhow::Result<()> {
        let dev = dump_all(wait, &self.config, &mut self.drivers, false)?;
        let where_ = backup_dir(&dev.serial).display().to_string();
        if dev.firstgen {
            println!(
                "первое поколение: полный дамп невозможен (BootROM залочен) — \
                 читаемы только разделы ниже 32 МиБ, дамп НЕцелостный"
            );
        }
        if dev.dumped {
            println!(
                "готово: дампы {} — в {where_} (на колонку не писалось)",
                dev.serial
            );
        } else {
            println!(
                "бэкап {} уже есть в {where_} — делать нечего (удалите \
                 каталог, чтобы снять дамп заново)",
                dev.serial
            );
        }
        Ok(())
    }
}

/// Backup directory for a column: backup/<sanitized serial>.
fn backup_dir(serial: &str) -> PathBuf {
    Path::new("backup").join(BackupStore::dir_name(serial))
}

/// Steps 1-3 (loader, device, dump into backup/) — one flow for regular
/// columns and first generation; --no-backup skips the dump entirely.
/// On a regular column the session runs our usbplug with the read-limit
/// patch (fully readable dump); on first generation it stays on the
/// stock loader (330d) and the dump is NOT intact: everything above
/// the 32 MiB read mask reads back as 0xCC.
///
/// On Windows the board hops between devnodes (330d loader, 330e
/// MaskROM/usbplug) and a fresh devnode may be grabbed by a vendor
/// Rockusb driver before our WinUSB package gets it; when that
/// happens the session rebinds the node and the bring-up — which is a
/// re-entrant state machine over the current bus state — is retried.
fn dump_all(
    wait: Option<Duration>,
    config: &Config,
    drivers: &mut win_drv::Session,
    no_backup: bool,
) -> anyhow::Result<Device> {
    if win_drv::any_rockchip_node_misbound() {
        println!("устройство Rockchip без WinUSB — ставлю драйвер");
        start_or_wait_drivers(drivers, Duration::from_secs(180));
    }

    const ATTEMPTS: u32 = 5;
    for attempt in 1..=ATTEMPTS {
        match dump_all_once(wait, config, no_backup) {
            Ok(s) => return Ok(s),
            Err(e) => {
                let binding_error = win_drv::chain_is_binding_error(&e);
                if binding_error && attempt < ATTEMPTS {
                    println!(
                        "узел перехвачен чужим драйвером (попытка {attempt}/{ATTEMPTS}) — перевязываю"
                    );
                    start_or_wait_drivers(drivers, Duration::from_secs(120));
                    continue;
                }
                if binding_error {
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
    Err(anyhow::anyhow!("перебор попыток перевязки драйвера"))
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
fn dump_all_once(
    wait: Option<Duration>,
    config: &Config,
    no_backup: bool,
) -> anyhow::Result<Device> {
    let loader = jb_core::loader::embedded().context("не удалось разобрать вшитый лоадер")?;
    let p = CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    let mut bus = jb_core::session::UsbBus;
    let up = match bring_up(&mut bus, config, &loader, wait, no_backup, &progress) {
        Ok(v) => v,
        Err(BringUpError::LoaderRejected) => bail!(
            "usbplug не запустился: BootROM отклонил лоадер (неподдерживаемая \
             плата или первое поколение в MaskROM — отпустите Recovery и \
             войдите в режим лоадера заново)"
        ),
        Err(e) => return Err(e.into()),
    };

    let serial = up.serial;
    let firstgen = up.firstgen;
    let mut s = up.session;
    println!("серийник колонки: {serial}");
    let dir = backup_dir(&serial);
    // A verified backup of THIS column exists -> skip the dump
    // and go straight to the userdata write. On the stock loader
    // (first generation) the dump is NOT intact: everything above
    // the 32 MiB read mask goes in as 0xCC — backup() says so itself.
    let dumped = if no_backup {
        println!(
            "--no-backup: бэкап не проверяю и не снимаю — userdata будет \
             собран с нуля, текущее содержимое теряется"
        );
        false
    } else if BackupStore::exists_verified(&dir) {
        println!(
            "бэкап уже есть в {} — дамп пропускаю (удалите каталог, чтобы \
             снять заново)",
            dir.display()
        );
        false
    } else {
        backup::backup(&mut s, config, &dir, &progress, firstgen)
            .with_context(|| format!("колонка {serial}: дамп"))?;
        let _ = std::fs::write(dir.join("serial.txt"), &serial);
        true
    };
    Ok(Device {
        session: s,
        serial,
        firstgen,
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
    no_backup: bool,
    wait: Option<Duration>,
) -> anyhow::Result<()> {
    if dev.firstgen {
        println!(
            "первое поколение {} (стоковый лоадер): бэкап нецелостный \
             (маска 0xCC выше 32 МиБ), userdata будет собран с нуля",
            dev.serial
        );
    }

    let p = CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    // The GPT gives the partition size and the flash address on both
    // paths (the dump file is exactly the GPT sector count, so the
    // sizes agree).
    let (gpt, _) = jb_core::session::read_gpt(&mut dev.session, &progress)
        .context("не удалось прочитать GPT колонки")?;
    let part = gpt
        .find("userdata")
        .context("в GPT колонки нет раздела userdata")?;
    let part_size = part.sectors * 512;
    if dev.firstgen {
        println!("раздел userdata: {} (из GPT колонки)", humansize(part_size));
    }

    let fresh = dev.firstgen || format_userdata || no_backup;
    let dump = image_base(dev, fresh)?;
    confirm_write(dev.firstgen, fresh, no_backup, yes, part_size)?;

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
    flash::write_partition_padded(&mut dev.session, &gpt, "userdata", &out, &progress)
        .with_context(|| format!("колонка {}: запись userdata", dev.serial))?;

    // step 6: reboot and wait for the ADB gadget
    reboot_and_wait(&mut dev.session, wait)
}

/// The base of the new userdata image: the verified dump of this column
/// (regular path), or nothing when building from scratch. Re-opens and
/// re-verifies the backup so a broken dump never becomes the base of
/// the only copy.
fn image_base(dev: &Device, fresh: bool) -> anyhow::Result<Option<PathBuf>> {
    if fresh {
        return Ok(None);
    }
    let store = BackupStore::open(&backup_dir(&dev.serial))
        .context("нет валидного бэкапа этой колонки — запустите инструмент ещё раз")?;
    store
        .verify()
        .context("бэкап не прошёл проверку SHA256 — снимите дамп заново")?;
    Ok(Some(
        store
            .find("userdata")
            .context("в бэкапе нет раздела userdata")?
            .to_path_buf(),
    ))
}

/// Ask for the write confirmation (skipped with --yes). Nothing has
/// been written at this point, so a refusal is safe.
fn confirm_write(
    firstgen: bool,
    fresh: bool,
    no_backup: bool,
    yes: bool,
    part_size: u64,
) -> anyhow::Result<()> {
    if yes {
        return Ok(());
    }
    let mode = if firstgen {
        "оверлей adbd на чистый ext2 — бэкап первого поколения нецелостный \
         (0xCC выше 32 МиБ), userdata собирается с нуля, содержимое \
         теряется"
    } else if no_backup {
        "оверлей adbd на чистый ext2 (--no-backup: бэкап не снимался, \
         текущее содержимое теряется)"
    } else if fresh {
        "оверлей adbd на чистый ext2 (--format-userdata, содержимое теряется)"
    } else {
        "оверлей adbd поверх дампа, содержимое сохраняется"
    };
    println!("запись userdata ({}): {mode}", humansize(part_size));
    print!("продолжить? [y/N] ");
    crate::ask_yes()
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
