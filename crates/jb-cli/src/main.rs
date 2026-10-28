//! capsula-jb — jailbreak CLI for VK Capsula speakers (Rockchip RK3308).
//!
//! Method: userspace overwrite. The userdata partition is not signed and
//! can be rewritten by the user freely; no other partition is modified.
//!
//! Default scenario (no subcommand):
//!   1. fetch the Capsule-14 OTA, extract the loader into ota/ (cached;
//!      one loader for all supported boards)
//!   2. wait for the device in rockchip loader mode, start our usbplug
//!      in RAM
//!   3. patch the read limit over USB (0xCC bypass), dump all partitions
//!      into backup/
//!   4. build the adbd overlay on top of the userdata dump
//!   5. flash userdata back
//!   6. reboot and wait for the ADB gadget (2207:0006) to come up

mod progress;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use jb_core::backup_store::BackupStore;
use jb_core::config::Config;
use jb_core::firstgen::is_first_generation;
use jb_core::session::{
    attach_stock_loader, bring_up, BringUpError, BroughtUp, Progress,
};
use jb_core::{backup, flash, ota, userdata};
use rockusb::loader::RESET_SUBCODE_NORMAL;
use rockusb::{DeviceMode, LoaderContainer, NusbTransport};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The gadget must stay on the bus this long to be considered alive:
/// the stock firmware blinks 0006 for under a second.
const GADGET_STABLE: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(
    name = "capsula-jb",
    version,
    about = "VK Capsula (Rockchip RK3308) userspace jailbreak: dump -> adbd overlay in userdata -> ADB"
)]
struct Cli {
    /// Timeout for waiting for the device on USB, seconds (0 = forever)
    #[arg(long, value_name = "SEC", default_value = "0")]
    wait: u64,

    /// Do not ask for confirmation before writing userdata (scripts)
    #[arg(long)]
    yes: bool,

    /// Format userdata as a clean ext2 instead of patching the dump
    /// (existing userdata content is lost)
    #[arg(long)]
    format_userdata: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Dump all partitions into backup/ only (nothing is written to the device)
    Backup,
    /// Live log of 2207:* USB events
    Monitor,
}

fn main() -> anyhow::Result<()> {
    // An elevated relaunch (Windows UAC manifest) may start in
    // C:\Windows\System32; the tool writes ota/backup/work relative to
    // the CWD, so move next to the executable in that case.
    if let Some(cwd) = win_drv::fix_cwd_if_system32() {
        eprintln!("working directory: {}", cwd.display());
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let wait = if cli.wait == 0 {
        None
    } else {
        Some(Duration::from_secs(cli.wait))
    };
    let result = match cli.command {
        None => run_jailbreak(wait, cli.yes, cli.format_userdata),
        Some(Command::Backup) => run_backup(wait),
        Some(Command::Monitor) => monitor(),
    };
    // Launched from a normal console, Windows elevates the tool into a
    // NEW console window (see the UAC manifest note in .cargo/config.toml);
    // keep that window open so the output is readable. A shared terminal
    // or a redirected/none console gets no pause.
    win_drv::pause_if_own_console();
    result
}

fn print_step(ev: Progress) {
    if let Progress::Step(msg) = ev {
        println!("{msg}");
    }
}

/// Prepare the loader: ota/loader.bin from cache or a fresh OTA download.
fn ensure_loader(config: &Config) -> anyhow::Result<LoaderContainer> {
    let (container, version) =
        ota::ensure_loader(Path::new("ota"), &config.ota.platform, &|step| match step {
            ota::Step::Cached(path) => println!("loader: using cached {path}"),
            ota::Step::Fetching(code) => println!("querying latest firmware for {code}..."),
            ota::Step::Unpacking(path) => println!("extracting loader from OTA package {path}"),
            ota::Step::Saved { path, version } => {
                println!("loader saved: {path} (OTA {version})")
            }
        })
        .context("failed to prepare the loader from the OTA")?;
    if let Some(v) = version {
        println!("loader OTA version: {v}");
    }
    Ok(container)
}

/// The live device as the CLI flows see it (after bring-up).
enum Device {
    /// Our usbplug in RAM. `dumped`: a fresh backup was taken this run
    /// (false = a verified backup for this serial already existed).
    Ours {
        session: rockusb::LoaderSession<NusbTransport>,
        serial: String,
        dumped: bool,
    },
    /// First generation: the stock u-boot rockusb loader (330d) with a
    /// gift serial — no backup possible, userdata flashes through it.
    StockLoader {
        session: rockusb::LoaderSession<NusbTransport>,
        serial: String,
    },
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
fn dump_all(
    wait: Option<Duration>,
    drivers: &mut win_drv::Session,
) -> anyhow::Result<Device> {
    if win_drv::any_rockchip_node_misbound() {
        println!("a Rockchip device is present without WinUSB — installing the driver");
        start_or_wait_drivers(drivers, Duration::from_secs(180));
    }

    const ATTEMPTS: u32 = 5;
    for attempt in 1..=ATTEMPTS {
        match dump_all_once(wait) {
            Ok(s) => return Ok(s),
            Err(e) => {
                if attempt < ATTEMPTS && win_drv::chain_is_binding_error(&e) {
                    println!(
                        "device node caught a non-WinUSB driver (attempt {attempt}/{ATTEMPTS}) — rebinding and retrying"
                    );
                    start_or_wait_drivers(drivers, Duration::from_secs(120));
                    continue;
                }
                if win_drv::chain_is_binding_error(&e) {
                    // the driver supervisor could not win in ATTEMPTS tries
                    return Err(e.context(format!(
                        "the WinUSB driver did not settle; session log: {}\n\
                         manual fallback: see DRIVER-SETUP.txt (Zadig)",
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
            println!(
                "installing the WinUSB driver if needed (up to {} s)...",
                settle.as_secs()
            );
            if !win_drv::wait_until_bound(settle) {
                println!(
                    "warning: the driver did not settle in {} s (session log: {})",
                    settle.as_secs(),
                    drivers.log_path().display()
                );
            }
        }
        Err(e) => {
            println!(
                "warning: {e}\n  manual fallback: see DRIVER-SETUP.txt (Zadig)\n  \
                 session log: {}",
                drivers.log_path().display()
            );
        }
    }
}

/// One bring-up + dump attempt (no retries).
fn dump_all_once(wait: Option<Duration>) -> anyhow::Result<Device> {
    let config = Config::embedded();

    // Classify what is already on the bus before the OTA download: the
    // loader cache is pointless on a first-generation column (our
    // usbplug never runs on it), and the emergency fastboot state is a
    // hard stop with a clear instruction. The loader serial read here
    // is THE session identity — bring_up will not read it again.
    let mut known_serial: Option<String> = None;
    match rockusb::current_mode().context("USB bus")? {
        Some(DeviceMode::Fastboot) => bail!(
            "the device is in its EMERGENCY fastboot state (18d1:d00d): \
             power-cycle it and re-enter loader mode (recovery button), \
             then run the tool again"
        ),
        Some(DeviceMode::Loader) => {
            let serial =
                rockusb::device_serial(&DeviceMode::Loader).unwrap_or_default();
            if is_first_generation(&serial) {
                let p = progress::CliProgress::new();
                let session = attach_stock_loader(&|ev| p.handle(ev))
                    .context("first-generation stock loader")?;
                return Ok(Device::StockLoader { session, serial });
            }
            known_serial = Some(serial);
        }
        _ => {}
    }

    let loader = ensure_loader(&config)?;
    let p = progress::CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    let (up, serial) = match bring_up(&config, &loader, wait, &progress, known_serial) {
        Ok(v) => v,
        Err(BringUpError::LoaderRejected) => bail!(
            "usbplug did not start: BootROM rejected the loader signature \
             (unsupported board? a first-generation column in MaskROM — \
             release the recovery button and re-enter download mode)"
        ),
        Err(e) => return Err(e.into()),
    };
    match up {
        BroughtUp::Ours(mut s) => {
            if jb_core::session::is_identifying(&serial) {
                println!("column serial: {serial}");
            } else {
                println!(
                    "warning: the column did not show up as 330d, its serial is \
                     unknown — the backup goes to {} and will NOT be reused as \
                     a cache; re-enter loader mode (recovery button) to key it \
                     by the column serial",
                    backup_dir(&serial).display()
                );
            }
            let dir = backup_dir(&serial);
            // A verified backup of THIS column exists -> skip the dump
            // and go straight to the userdata write. Only an identifying
            // serial (read from the loader persona) may unlock the cache.
            let dumped =
                if jb_core::session::is_identifying(&serial) && BackupStore::exists_verified(&dir)
                {
                    println!(
                        "backup {} already exists and verifies — skipping the dump \
                         (delete it to force a fresh one)",
                        dir.display()
                    );
                    false
                } else {
                    backup::backup(&mut s, &config, &dir, &progress)?;
                    if jb_core::session::is_identifying(&serial) {
                        let _ = std::fs::write(dir.join("serial.txt"), &serial);
                    }
                    true
                };
            Ok(Device::Ours {
                session: s,
                serial,
                dumped,
            })
        }
        BroughtUp::FirstGenStockLoader(session) => Ok(Device::StockLoader { session, serial }),
    }
}

/// `capsula-jb backup`: dump only.
fn run_backup(wait: Option<Duration>) -> anyhow::Result<()> {
    let mut drivers = win_drv::Session::new();
    match dump_all(wait, &mut drivers)? {
        Device::Ours { serial, dumped, .. } => {
            let where_ = backup_dir(&serial).display().to_string();
            if dumped {
                if jb_core::session::is_identifying(&serial) {
                    println!("done: dumps for {serial} are in {where_} (nothing was written to the device)");
                } else {
                    println!("done: dumps are in {where_} (nothing was written to the device)");
                }
            } else {
                println!(
                    "a verified backup of {serial} already exists in {where_} — \
                     nothing to do (delete it to force a fresh dump)"
                );
            }
            Ok(())
        }
        Device::StockLoader { .. } => bail!(
            "first-generation column: its BootROM is locked and refuses our \
             usbplug, so a full dump is not possible. Run the default command \
             to flash the adbd overlay without a backup."
        ),
    }
}

/// Full jailbreak scenario (steps 1-6).
fn run_jailbreak(wait: Option<Duration>, yes: bool, format_userdata: bool) -> anyhow::Result<()> {
    let mut drivers = win_drv::Session::new();
    match dump_all(wait, &mut drivers)? {
        Device::Ours { mut session, serial, .. } => {
            full_flow(&mut session, &serial, yes, format_userdata, wait)
        }
        Device::StockLoader { mut session, serial } => {
            firstgen_stock_flow(&mut session, &serial, yes, wait)
        }
    }
}

/// Steps 4-6 over our usbplug: overlay on top of the dump, flash, reboot.
fn full_flow(
    s: &mut rockusb::LoaderSession<NusbTransport>,
    serial: &str,
    yes: bool,
    format_userdata: bool,
    wait: Option<Duration>,
) -> anyhow::Result<()> {
    // step 4: overlay on top of the userdata dump (per-serial directory;
    // the dump was just taken or found valid by dump_all)
    let store = BackupStore::open(&backup_dir(serial))
        .context("no valid backup for this column — run the default command again")?;
    store
        .verify()
        .context("backup failed SHA256 verification — run backup again")?;
    let dump = store
        .find("userdata")
        .context("no userdata partition in the backup")?
        .to_path_buf();
    let part_size = std::fs::metadata(&dump)?.len();

    if !yes {
        println!(
            "about to write userdata ({}): {}",
            humansize(part_size),
            if format_userdata {
                "adbd overlay on a clean ext2 (--format-userdata, existing content is lost)"
            } else {
                "adbd overlay on top of the dump, existing content is preserved"
            }
        );
        print!("proceed? [y/N] ");
        ask_yes()?;
    }

    let marker = format!("capsula-jb userspace {}\n", utc_now_iso());
    let out = PathBuf::from("work").join("userdata.img");
    userdata::build_image(
        &dump,
        &out,
        format_userdata,
        part_size,
        &userdata::overlay_files(marker),
        &print_step,
    )
    .context("failed to build the userdata image with the overlay")?;

    // step 5: flash the partition back (same usbplug session)
    let p = progress::CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    let gpt = jb_core::session::read_gpt(s, &progress)?;
    flash::write_partition_padded(s, &gpt, "userdata", &out, &progress)?;

    reboot_and_wait(s, wait)
}

/// The shared tail of every flow: reboot the device and wait for the ADB
/// gadget to come up and stay.
fn reboot_and_wait(s: &mut rockusb::LoaderSession<NusbTransport>, wait: Option<Duration>) -> anyhow::Result<()> {
    println!("rebooting the device...");
    let _ = s.reset(RESET_SUBCODE_NORMAL);
    wait_for_adb_gadget(wait)
}

fn wait_for_adb_gadget(wait: Option<Duration>) -> anyhow::Result<()> {
    println!(
        "waiting for the ADB gadget (2207:0006, {} s stability window)...",
        GADGET_STABLE.as_secs()
    );
    rockusb::monitor::wait_gadget_stable(GADGET_STABLE, wait).context(
        "ADB gadget did not come up (or disappeared after a blink): check the device boot",
    )?;
    println!("done: ADB is up. The device accepts root shell connections.");
    Ok(())
}

/// First generation, stock rockusb loader (330d): the GPT is readable
/// directly (LBA1 is far below any read limit); userdata is written
/// through the stock WRITE_LBA. No backup is possible on this hardware.
fn firstgen_stock_flow(
    s: &mut rockusb::LoaderSession<NusbTransport>,
    serial: &str,
    yes: bool,
    wait: Option<Duration>,
) -> anyhow::Result<()> {
    println!(
        "first-generation column {serial} (stock loader):\n  its BootROM is \
         locked and refuses our usbplug, so a full backup is impossible on this\n  \
         hardware. The stock loader can still read the partition table and flash\n  \
         userdata directly: the adbd overlay will be built fresh (existing\n  \
         userdata content is lost)."
    );

    let p = progress::CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    let gpt = jb_core::session::read_gpt(s, &progress).context(
        "the stock loader did not return a GPT — power-cycle the device",
    )?;
    let part_size = gpt
        .find("userdata")
        .context("no userdata partition in the device GPT")?
        .sectors
        * 512;
    println!("userdata partition: {} (device GPT)", humansize(part_size));

    if !yes {
        println!(
            "about to write userdata ({}): adbd overlay on a clean ext2 — \
             no backup is possible on a first-generation column, existing \
             userdata content is lost",
            humansize(part_size)
        );
        print!("proceed? [y/N] ");
        ask_yes()?;
    }

    let marker = format!("capsula-jb userspace {}\n", utc_now_iso());
    let out = PathBuf::from("work").join("userdata.img");
    userdata::build_image(
        Path::new(""),
        &out,
        true,
        part_size,
        &userdata::overlay_files(marker),
        &print_step,
    )
    .context("failed to build the userdata image with the overlay")?;

    flash::write_partition_padded(s, &gpt, "userdata", &out, &progress)?;
    reboot_and_wait(s, wait)
}

fn ask_yes() -> anyhow::Result<()> {
    use std::io::{IsTerminal, Write};
    // Non-interactive stdin (CI, LLM agent shells, redirected input):
    // never hang on a prompt nobody can answer — fail with an
    // actionable message instead. Nothing has been written at this
    // point, so an exit is safe.
    if !std::io::stdin().is_terminal() {
        bail!(
            "confirmation required before writing userdata, but stdin is not \
             an interactive console; nothing was written. Re-run with --yes \
             once the write has been approved."
        );
    }
    std::io::stdout().flush().ok();
    let mut ans = String::new();
    std::io::stdin().read_line(&mut ans)?;
    let ans = ans.trim().to_lowercase();
    if ans != "y" && ans != "yes" {
        bail!("aborted by user");
    }
    Ok(())
}

/// Live log of 2207:* bus events.
fn monitor() -> anyhow::Result<()> {
    let mut m = rockusb::DeviceMonitor::new();
    println!("Rockchip USB monitor (2207:*), Ctrl-C to stop.");
    m.poll()?;
    if let Some(best) = rockusb::transport::DeviceMode::best(m.modes()) {
        println!("on the bus now: {}", best.label());
    }
    loop {
        for ev in m.poll()? {
            match ev {
                rockusb::monitor::MonitorEvent::Appeared(mode) => {
                    println!(
                        "[{}] appeared 2207:{:04x} ({})",
                        ts(),
                        mode.pid(),
                        mode.label()
                    )
                }
                rockusb::monitor::MonitorEvent::Disappeared(mode) => {
                    println!(
                        "[{}] gone     2207:{:04x} ({})",
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
