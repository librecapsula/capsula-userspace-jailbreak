//! The rockchip [`jb_core::backend::Backend`] and
//! [`jb_core::scenario::Platform`] implementation. The scenario
//! skeleton (jb-core) drives the hooks; this module owns everything
//! device-specific: the Windows driver supervisor, the loader-persona
//! bring-up with the driver-rebind retries, the full dump, the ext4
//! image build and the WRITE_LBA write.
//!
//! On Windows the board hops between devnodes (330d loader, 330e
//! MaskROM/usbplug) and a fresh devnode may be grabbed by a vendor
//! Rockusb driver before our WinUSB package gets it; when that happens
//! the session rebinds the node and the bring-up — a re-entrant state
//! machine over the current bus state — is retried.

use jb_core::backend::Backend;
use jb_core::backup_store::BackupStore;
use jb_core::config::Config;
use jb_core::format::humansize;
use jb_core::overlay::OverlayFile;
use jb_core::progress::ProgressFn;
use jb_core::scenario::{self, Params, Platform, Prepared};
use anyhow::{anyhow, bail, Context, Result};
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

/// The rockchip platform. Holds the Windows driver session alive for
/// the whole scenario: the supervisor must rebind the board to WinUSB
/// during the userdata write as well.
pub struct Rockchip {
    config: Config,
    drivers: win_drv::Session,
    device: Option<Device>,
    gpt: Option<crate::gpt::Gpt>,
    wait: Option<Duration>,
}

impl Rockchip {
    pub fn new() -> Self {
        Rockchip {
            config: Config::embedded(),
            drivers: win_drv::Session::new(),
            device: None,
            gpt: None,
            wait: None,
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

    fn present(&self) -> Result<bool> {
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
        params: &Params,
        confirm: jb_core::scenario::Confirm,
        progress: ProgressFn,
    ) -> Result<()> {
        scenario::jailbreak(self, params, confirm, progress)
    }

    fn backup(&mut self, wait: Option<Duration>, progress: ProgressFn) -> Result<()> {
        scenario::backup(self, wait, progress)
    }

    fn restore(
        &mut self,
        wait: Option<Duration>,
        confirm: jb_core::scenario::Confirm,
        progress: ProgressFn,
    ) -> Result<()> {
        scenario::restore(self, wait, confirm, progress)
    }
}

impl Platform for Rockchip {
    fn prepare(
        &mut self,
        no_backup: bool,
        wait: Option<Duration>,
        progress: ProgressFn,
    ) -> Result<Prepared> {
        self.wait = wait;
        self.gpt = None;
        let dev = self.dump_all(wait, no_backup, progress)?;
        let dir = backup_dir(&dev.serial);
        if dev.firstgen {
            log::info!(
                "первое поколение {} (стоковый лоадер): бэкап нецелостный \
                 (маска 0xCC выше 32 МиБ), userdata будет собран с нуля",
                dev.serial
            );
        }
        let complete = !dev.firstgen;
        let dumped = dev.dumped;
        // The base of the new userdata image: the verified dump of this
        // column (regular path), or nothing when building from scratch.
        // Re-opens and re-verifies the backup so a broken dump never
        // becomes the base of the only copy.
        let base = if no_backup || dev.firstgen {
            None
        } else {
            image_base(&dir)?
        };
        self.device = Some(dev);
        Ok(Prepared {
            base,
            dumped,
            dir: if no_backup { None } else { Some(dir) },
            complete,
        })
    }

    fn data_size(&mut self, progress: ProgressFn) -> Result<u64> {
        let dev = self
            .device
            .as_mut()
            .ok_or_else(|| anyhow!("устройство не поднято"))?;
        // The GPT gives the partition size and the flash address (the
        // dump file is exactly the GPT sector count, so the sizes
        // agree).
        let (gpt, _) = crate::session::read_gpt(&mut dev.session, progress)
            .context("не удалось прочитать GPT колонки")?;
        let part = gpt
            .find("userdata")
            .context("в GPT колонки нет раздела userdata")?;
        let size = part.sectors * 512;
        if dev.firstgen {
            log::info!("раздел userdata: {} (из GPT колонки)", humansize(size));
        }
        self.gpt = Some(gpt);
        Ok(size)
    }

    fn data_partition(&self) -> &'static str {
        "userdata"
    }

    fn describe_write(&self, fresh: bool, no_backup: bool) -> String {
        let firstgen = self.device.as_ref().map(|d| d.firstgen).unwrap_or(false);
        if firstgen {
            "оверлей adbd на чистый ext2 — бэкап первого поколения нецелостный \
             (0xCC выше 32 МиБ), userdata собирается с нуля, содержимое \
             теряется"
                .into()
        } else if no_backup {
            "оверлей adbd на чистый ext2 (--no-backup: бэкап не снимался, \
             текущее содержимое теряется)"
                .into()
        } else if fresh {
            "оверлей adbd на чистый ext2 (--format-userdata, содержимое теряется)"
                .into()
        } else {
            "оверлей adbd поверх дампа, содержимое сохраняется".into()
        }
    }

    fn describe_restore(&self) -> String {
        "userdata из верифицированного дампа — оверлей джейлбрейка и всё, \
         что записано после дампа, будет затёрто".into()
    }

    fn build_data_image(
        &self,
        base: Option<&Path>,
        out: &Path,
        size: u64,
        files: &[OverlayFile],
        progress: ProgressFn,
    ) -> Result<()> {
        crate::userdata::build_image(
            base.unwrap_or(Path::new("")),
            out,
            base.is_none(),
            size,
            files,
            progress,
        )
        .context("не удалось собрать образ userdata с оверлеем")
    }

    fn write_data_image(&mut self, image: &Path, progress: ProgressFn) -> Result<()> {
        let dev = self
            .device
            .as_mut()
            .ok_or_else(|| anyhow!("устройство не поднято"))?;
        let gpt = self
            .gpt
            .as_ref()
            .ok_or_else(|| anyhow!("GPT не прочитан"))?;
        crate::flash::write_partition_padded(&mut dev.session, gpt, "userdata", image, progress)
            .with_context(|| format!("колонка {}: запись userdata", dev.serial))
    }

    fn finish(&mut self, _progress: ProgressFn) -> Result<()> {
        let dev = self
            .device
            .as_mut()
            .ok_or_else(|| anyhow!("устройство не поднято"))?;
        log::info!("перезагружаю колонку...");
        let _ = dev.session.reset(RESET_SUBCODE_NORMAL);
        wait_for_adb_gadget(self.wait)
    }

    fn report_backup(&self, prepared: &Prepared) {
        if !prepared.complete {
            log::info!(
                "первое поколение: полный дамп невозможен (BootROM залочен) — \
                 читаемы только разделы ниже 32 МиБ, дамп НЕцелостный"
            );
        }
        let serial = self
            .device
            .as_ref()
            .map(|d| d.serial.as_str())
            .unwrap_or("");
        let dir = prepared
            .dir
            .as_deref()
            .map(|d| d.display().to_string())
            .unwrap_or_default();
        if prepared.dumped {
            log::info!("готово: дампы {serial} — в {dir} (на колонку не писалось)");
        } else {
            log::info!(
                "бэкап {serial} уже есть в {dir} — делать нечего (удалите \
                 каталог, чтобы снять дамп заново)"
            );
        }
    }
}

/// Backup directory for a column: backup/<sanitized serial>.
fn backup_dir(serial: &str) -> PathBuf {
    Path::new("backup").join(BackupStore::dir_name(serial))
}

impl Rockchip {
    /// Bring-up + dump with the driver-rebind retries (steps 1–3 of the
    /// scenario); --no-backup skips the dump entirely. On a regular
    /// column the session runs our usbplug with the read-limit patch
    /// (fully readable dump); on first generation it stays on the stock
    /// loader (330d) and the dump is NOT intact: everything above the
    /// 32 MiB read mask reads back as 0xCC.
    fn dump_all(
        &mut self,
        wait: Option<Duration>,
        no_backup: bool,
        progress: ProgressFn,
    ) -> Result<Device> {
        if win_drv::any_rockchip_node_misbound() {
            log::info!("устройство Rockchip без WinUSB — ставлю драйвер");
            self.start_or_wait_drivers(Duration::from_secs(180));
        }

        const ATTEMPTS: u32 = 5;
        for attempt in 1..=ATTEMPTS {
            match self.dump_all_once(wait, no_backup, progress) {
                Ok(s) => return Ok(s),
                Err(e) => {
                    let binding_error = win_drv::chain_is_binding_error(&e);
                    if binding_error && attempt < ATTEMPTS {
                        log::warn!(
                            "узел перехвачен чужим драйвером (попытка {attempt}/{ATTEMPTS}) — перевязываю"
                        );
                        self.start_or_wait_drivers(Duration::from_secs(120));
                        continue;
                    }
                    if binding_error {
                        // the driver supervisor could not win in ATTEMPTS tries
                        return Err(e.context(format!(
                            "драйвер WinUSB не установился; лог: {}\n\
                             ручной путь: DRIVER-SETUP.txt (Zadig)",
                            self.drivers.log_path().display()
                        )));
                    }
                    return Err(e);
                }
            }
        }
        bail!("перебор попыток перевязки драйвера")
    }

    /// Make sure the driver supervisor is running, then wait for the board
    /// to actually settle on WinUSB. The process is elevated from the very
    /// start (UAC manifest), so this is pure install time: certificates,
    /// the driver package import and the devnode restart take a few seconds
    /// on a first run.
    fn start_or_wait_drivers(&mut self, settle: Duration) {
        match self.drivers.ensure_supervision() {
            Ok(()) => {
                log::info!("ставлю драйвер WinUSB (до {} с)...", settle.as_secs());
                if !win_drv::wait_until_bound(settle) {
                    log::warn!(
                        "драйвер не установился за {} с (лог: {})",
                        settle.as_secs(),
                        self.drivers.log_path().display()
                    );
                }
            }
            Err(e) => {
                log::warn!(
                    "не удалось запустить драйверную сессию: {e}\n  \
                     ручной путь: DRIVER-SETUP.txt (Zadig)\n  лог: {}",
                    self.drivers.log_path().display()
                );
            }
        }
    }

    /// One bring-up + dump attempt (no retries). The first-generation
    /// classification lives in bring_up (session.rs): the returned
    /// `firstgen` flag drives everything downstream.
    fn dump_all_once(
        &mut self,
        wait: Option<Duration>,
        no_backup: bool,
        progress: ProgressFn,
    ) -> Result<Device> {
        let loader = crate::loader::embedded().context("не удалось разобрать вшитый лоадер")?;
        let mut bus = crate::session::UsbBus;
        let up = match crate::session::bring_up(&mut bus, &self.config, &loader, wait, no_backup, progress)
        {
            Ok(v) => v,
            Err(crate::session::BringUpError::LoaderRejected) => bail!(
                "usbplug не запустился: BootROM отклонил лоадер (неподдерживаемая \
                 плата или первое поколение в MaskROM — отпустите Recovery и \
                 войдите в режим лоадера заново)"
            ),
            Err(e) => return Err(e.into()),
        };

        let serial = up.serial;
        let firstgen = up.firstgen;
        let mut s = up.session;
        log::info!("серийник колонки: {serial}");
        let dir = backup_dir(&serial);
        // A verified backup of THIS column exists -> skip the dump
        // and go straight to the userdata write. On the stock loader
        // (first generation) the dump is NOT intact: everything above
        // the 32 MiB read mask goes in as 0xCC — backup() says so itself.
        let dumped = if no_backup {
            log::info!(
                "--no-backup: бэкап не проверяю и не снимаю — userdata будет \
                 собран с нуля, текущее содержимое теряется"
            );
            false
        } else if BackupStore::exists_verified(&dir) {
            log::info!(
                "бэкап уже есть в {} — дамп пропускаю (удалите каталог, чтобы \
                 снять заново)",
                dir.display()
            );
            false
        } else {
            crate::backup::backup(&mut s, &self.config, &dir, progress, firstgen)
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
}

/// The verified dump of this column (regular path), re-verified before
/// it becomes the base of the only copy.
fn image_base(dir: &Path) -> Result<Option<PathBuf>> {
    let store = BackupStore::open(dir)
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

/// The shared tail of the flow: reboot the device and wait for the ADB
/// gadget to come up and stay.
fn wait_for_adb_gadget(wait: Option<Duration>) -> Result<()> {
    log::info!(
        "жду ADB-гаджет (2207:0006; должен продержаться {} с)...",
        GADGET_STABLE.as_secs()
    );
    rockusb::monitor::wait_gadget_stable(GADGET_STABLE, wait)
        .context("ADB-гаджет не поднялся (или мигнул и пропал) — проверьте загрузку колонки")?;
    log::info!("готово: ADB поднят — adb shell даёт root без авторизации");
    Ok(())
}
