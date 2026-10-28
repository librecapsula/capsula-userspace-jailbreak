//! capsula-jb — jailbreak CLI for VK Capsula speakers.
//!
//! Method: userspace overwrite (Rockchip boards). The userdata partition
//! is not signed and can be rewritten by the user freely; no other
//! partition is modified.
//!
//! Default scenario (no subcommand):
//!   0. wait for a supported speaker to be plugged in and powered, then
//!      dispatch on the SoC vendor:
//!      - Rockchip (2207:330d/330e): the full scenario below;
//!      - Amlogic (1b8e:c003, the late minis): identify the board (the
//!        flashing scenario for it is in development).
//!   1. fetch the Capsule-14 OTA, extract the loader into ota/ (cached;
//!      one loader for all supported Rockchip boards)
//!   2. start our usbplug in RAM
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
use jb_core::session::{bring_up, BringUpError, Progress, ProgressFn};
use jb_core::target::{self, Target};
use jb_core::{backup, flash, ota, userdata};
use rockusb::loader::RESET_SUBCODE_NORMAL;
use rockusb::{LoaderContainer, NusbTransport};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The gadget must stay on the bus this long to be considered alive:
/// the stock firmware blinks 0006 for under a second.
const GADGET_STABLE: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(
    name = "capsula-jb",
    version,
    about = "VK Capsula userspace jailbreak: dump -> adbd overlay in userdata -> ADB (Rockchip); board identification and u-boot command passthrough (Amlogic minis)"
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
    /// Live log of the download-mode USB events (2207:* and 1b8e:c003)
    Monitor,
    /// Amlogic mini: identify the board / run u-boot burning commands
    Aml {
        /// u-boot burning commands to execute in sequence (the whole
        /// batch lives within one download window), e.g. "printenv".
        /// "upload mem <addr> normal <size>" streams the memory back and
        /// prints a hexdump. Omit to identify the board only.
        #[arg(allow_hyphen_values = true)]
        cmds: Vec<String>,
    },
    /// Amlogic mini: capture the u-boot environment over USB (read-only)
    AmlEnv,
    /// Amlogic mini: dump a vendor partition by name into backup/ (read-only)
    AmlDump {
        /// Partition name (bootloader, tpl, misc, boot_a, boot_b,
        /// system_a, system_b, data)
        part: String,
    },
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
        Some(Command::Aml { cmds }) => run_amlogic(wait, &cmds),
        Some(Command::AmlEnv) => run_aml_env(wait),
        Some(Command::AmlDump { part }) => run_aml_dump(wait, &part),
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

/// Step 0: prompt to connect the speaker and wait for a supported
/// download mode; the SoC vendor decides the scenario.
fn detect_target(wait: Option<Duration>) -> anyhow::Result<Target> {
    let config = Config::embedded();
    let mut hint = config.hint.text.clone();
    if !config.hint.amlogic_text.is_empty() {
        hint.push('\n');
        hint.push_str(&config.hint.amlogic_text);
    }
    target::wait_target(wait, &hint)
        .context("failed while waiting for a supported speaker on the bus")
}

/// Steps 1-3: loader, device, full dump into backup/, with automatic
/// WinUSB driver supervision on Windows. Returns the live usbplug
/// session (usable for the subsequent write).
///
/// On Windows the board hops between devnodes (330d loader, 330e
/// MaskROM/usbplug) and a fresh devnode may be grabbed by a vendor
/// Rockusb driver before our WinUSB package gets it; when that
/// happens the session rebinds the node and the bring-up — which is a
/// re-entrant state machine over the current bus state — is retried.
fn rockchip_dump_all(
    wait: Option<Duration>,
    drivers: &mut win_drv::Session,
) -> anyhow::Result<rockusb::LoaderSession<NusbTransport>> {
    if win_drv::any_rockchip_node_misbound() {
        println!("a Rockchip device is present without WinUSB — installing the driver");
        start_or_wait_drivers(drivers, Duration::from_secs(180));
    }

    const ATTEMPTS: u32 = 5;
    for attempt in 1..=ATTEMPTS {
        match rockchip_dump_all_once(wait) {
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
fn rockchip_dump_all_once(
    wait: Option<Duration>,
) -> anyhow::Result<rockusb::LoaderSession<NusbTransport>> {
    let config = Config::embedded();
    let loader = ensure_loader(&config)?;

    let p = progress::CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    let mut s = match bring_up(&config, &loader, wait, &progress) {
        Ok(s) => s,
        Err(BringUpError::LoaderRejected) => bail!(
            "usbplug did not start: BootROM rejected the loader signature (unsupported board?)"
        ),
        Err(e) => return Err(e.into()),
    };
    backup::backup(&mut s, &config, Path::new("backup"), &progress)?;
    Ok(s)
}

/// `capsula-jb backup`: dump only.
fn run_backup(wait: Option<Duration>) -> anyhow::Result<()> {
    match detect_target(wait)? {
        Target::Rockchip(_) => {
            let mut drivers = win_drv::Session::new();
            let _session = rockchip_dump_all(wait, &mut drivers)?;
            println!("done: dumps are in backup/ (nothing was written to the device)");
        }
        Target::Amlogic => {
            let ui = progress::CliProgress::new();
            let progress = |p| ui.handle(p);
            let (mut session, soc) = target::bring_up_amlogic(wait, &progress)?;
            require_aml_tpl(&soc)?;
            let report =
                jb_core::aml::backup::backup(&mut session, Path::new("backup"), &progress)?;
            match report.status {
                jb_core::aml::backup::Status::Complete => println!("done: Amlogic backup is in {}", report.path.display()),
                jb_core::aml::backup::Status::Warnings => println!("Amlogic backup has short partitions: {} (see manifest.json and .partial files)", report.path.display()),
                _ => unreachable!("backup returns only finalized reports"),
            }
        }
    }
    Ok(())
}

/// Full jailbreak scenario (steps 0-6).
fn run_jailbreak(wait: Option<Duration>, yes: bool, format_userdata: bool) -> anyhow::Result<()> {
    match detect_target(wait)? {
        Target::Rockchip(_) => rockchip_jailbreak(wait, yes, format_userdata),
        Target::Amlogic => amlogic_scenario(wait),
    }
}

/// The Rockchip userspace-overwrite scenario (steps 1-6).
fn rockchip_jailbreak(
    wait: Option<Duration>,
    yes: bool,
    format_userdata: bool,
) -> anyhow::Result<()> {
    let mut drivers = win_drv::Session::new();
    let mut s = rockchip_dump_all(wait, &mut drivers)?;

    // step 4: overlay on top of the userdata dump
    let store = BackupStore::open(Path::new("backup")).context("no valid backup in backup/")?;
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
    let gpt = jb_core::session::read_gpt(&mut s, &progress)?;
    flash::write_partition_padded(&mut s, &gpt, "userdata", &out, &progress)?;

    // step 6: reboot and wait for ADB
    println!("rebooting the device...");
    let _ = s.reset(RESET_SUBCODE_NORMAL);
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

/// The Amlogic path (late minis): bring-up + identify. The flashing
/// scenario for these boards is in development; the u-boot burning
/// command passthrough (`capsula-jb aml "<cmd>"`) is available.
fn amlogic_scenario(wait: Option<Duration>) -> anyhow::Result<()> {
    println!(
        "Amlogic mini detected. Power it off and on while connected if the \
         download window was missed."
    );
    let p = progress::CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    let (_s, soc) = target::bring_up_amlogic(wait, &progress)?;
    println!("board: Amlogic download mode, {soc}");
    match soc.stage() {
        amlogic::Stage::Tpl => {
            println!("u-boot burning gadget is answering (the vendor factory window).");
        }
        amlogic::Stage::Ipl => match soc.need_password() {
            Some(true) => println!("BootROM download mode: password required (PWD_REQ=1)."),
            Some(false) => println!("BootROM download mode (no password required)."),
            None => println!("BootROM download mode (the reply carries no password flags)."),
        },
        _ => {}
    }
    println!("The flashing scenario for the Amlogic mini is in development.");
    println!("u-boot burning commands are available: capsula-jb aml \"<command>\"");
    Ok(())
}

fn require_aml_tpl(soc: &amlogic::SocId) -> anyhow::Result<()> {
    if soc.stage() != amlogic::Stage::Tpl {
        bail!(
            "the device is in the {} stage — burning commands are only \
             available from the u-boot gadget; power-cycle the speaker to \
             catch its download window",
            soc.stage().label()
        );
    }
    Ok(())
}

/// `capsula-jb aml`: identify the Amlogic board / pass u-boot burning
/// commands through the download mode. The whole batch runs within one
/// caught window; `upload mem <addr> normal <size>` streams the memory
/// back and prints a hexdump.
fn run_amlogic(wait: Option<Duration>, cmds: &[String]) -> anyhow::Result<()> {
    if cmds.is_empty() {
        println!(
            "Connect the Amlogic mini and power it on: the u-boot download \
             window is ~0.5 s at every boot; power-cycle to retry."
        );
    }
    let p = progress::CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    let (mut s, soc) = target::bring_up_amlogic(wait, &progress)?;
    if cmds.is_empty() {
        println!("{soc}");
        return Ok(());
    }
    // the burning-command dispatcher exists only in the u-boot gadget;
    // the BootROM does not answer AM_REQ_BULKCMD
    require_aml_tpl(&soc)?;
    let t0 = std::time::Instant::now();
    for c in cmds {
        // "sleep <ms>": host-side pause, nothing is sent — for testing
        // whether the session dies on a deadline or on a resource leak
        if let Some(ms) = c.strip_prefix("sleep ") {
            let ms: u64 = ms.parse().context("sleep <ms>: bad number")?;
            println!("sleeping {ms}ms (nothing is sent)...");
            std::thread::sleep(Duration::from_millis(ms));
            continue;
        }
        // "id": one identify — the candidate keepalive (the vendor tool
        // identifies before every operation; if each identify restarts
        // the gadget's ~450 ms deadline, periodic identifies make the
        // session immortal)
        if c == "id" {
            let soc = s.identify()?;
            println!("id -> {soc} (+{}ms)", t0.elapsed().as_millis());
            continue;
        }
        let r = if let Some((addr, size)) = parse_upload_cmd(c) {
            println!("uploading {size:#x} bytes from {addr:#x}...");
            s.upload_read(addr, size).map(|data| {
                hexdump(&data, addr);
                format!("done (+{}ms)", t0.elapsed().as_millis())
            })
        } else {
            s.bulk_cmd(c)
                .map(|st| format!("{st} (+{}ms)", t0.elapsed().as_millis()))
        };
        match r {
            Ok(status) => println!("{c} -> {status}"),
            Err(e) => {
                let on_bus = amlogic::present().unwrap_or(false);
                bail!(
                    "command {c:?} failed at +{}ms ({e}); the device is {}",
                    t0.elapsed().as_millis(),
                    if on_bus {
                        "still on the bus (transfer problem)"
                    } else {
                        "gone from the bus (the download window closed mid-command)"
                    }
                );
            }
        }
    }
    Ok(())
}

/// Parse the `upload mem <addr> normal <size>` burning command.
fn parse_upload_cmd(c: &str) -> Option<(u32, usize)> {
    let t: Vec<&str> = c.split_whitespace().collect();
    if t.len() != 5 || t[0] != "upload" || t[1] != "mem" || t[3] != "normal" {
        return None;
    }
    let addr = u32::from_str_radix(t[2].trim_start_matches("0x"), 16).ok()?;
    let size = usize::from_str_radix(t[4].trim_start_matches("0x"), 16).ok()?;
    if size == 0 || size > 0xffff {
        return None;
    }
    Some((addr, size))
}

/// `capsula-jb aml-env`: print the u-boot environment, captured over USB
/// (export to DRAM + read back — answers of bulkcmd go to the UART).
fn run_aml_env(wait: Option<Duration>) -> anyhow::Result<()> {
    println!(
        "Connect the Amlogic mini and power it on: the u-boot download \
         window is ~0.5 s at every boot; power-cycle to retry."
    );
    let p = progress::CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    let (mut s, soc) = target::bring_up_amlogic(wait, &progress)?;
    require_aml_tpl(&soc)?;
    let env = jb_core::aml::capture_env(&mut s)?;
    println!("{env}");
    Ok(())
}

/// `capsula-jb aml-dump <part>`: stream a vendor partition into backup/.
///
/// The reference flasher's flow, verbatim: catch the download device,
/// identify, prime, stream; on a session death catch the device again
/// and continue from the checkpoint. Like the reference flasher, the
/// partition is read TWICE and the SHA256 of both passes must match —
/// the only real guarantee that the streaming did not corrupt or
/// desynchronize anywhere along the way.
fn run_aml_dump(wait: Option<Duration>, part: &str) -> anyhow::Result<()> {
    println!(
        "Connect the Amlogic mini and power it on: the u-boot download \
         window is ~0.5 s at every boot; power-cycle to retry."
    );
    let p = progress::CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    let (first, complete) = dump_pass(wait, part, "", &progress)?;
    if !complete {
        println!(
            "done: backup/{part}.bin, {} (SHORT read: bad blocks — the received \
             length is the truth; verification skipped) (nothing was written to \
             the device)",
            humansize(first.len() as u64)
        );
        return Ok(());
    }

    println!("verify pass: reading the partition again (double read)...");
    let (second, complete2) = dump_pass(wait, part, ".verify", &progress)?;
    if !complete2 {
        bail!(
            "verify pass came up short ({:#x} of {:#x}) — keeping backup/{part}.bin, \
             rerun `aml-dump {part}` to verify",
            second.len(),
            first.len()
        );
    }
    let h1 = Sha256::digest(&first);
    let h2 = Sha256::digest(&second);
    if h1 != h2 {
        bail!(
            "TWO READS DIFFER: {} vs {} — the partition content is unstable; \
             do not trust backup/{part}.bin",
            hex::encode(h1),
            hex::encode(h2)
        );
    }
    let _ = std::fs::remove_file(Path::new("backup").join(format!("{part}.verify.bin")));
    println!(
        "done: backup/{part}.bin, {} — verified by double read, SHA256 {} \
         (nothing was written to the device)",
        humansize(first.len() as u64),
        hex::encode(h1)
    );
    Ok(())
}

/// One full dump pass over the reconnect cycle; `suffix` distinguishes
/// the checkpoint file (the verify pass must not clobber the first pass
/// result). Returns the data and whether the read ran to completion (a
/// short read is a bad-block truncation, not a cycle boundary).
///
/// The flow is the reference flasher's, verbatim: catch the download
/// device, identify, prime, then stream — and if the session dies,
/// catch the device again and continue from the checkpoint. No window
/// re-entry tricks, no port resets: on this u-boot every trick we tried
/// either hangs on a dead pipe or boots the board into Linux, and a
/// fresh download window is the one state we can always re-catch.
fn dump_pass(
    wait: Option<Duration>,
    part: &str,
    suffix: &str,
    progress: ProgressFn,
) -> anyhow::Result<(Vec<u8>, bool)> {
    let mut st = jb_core::aml::DumpState::new(part)?;
    progress(Progress::PartitionStart {
        name: part.into(),
        sectors: st.size as u64 / 512,
    });

    const CHUNK: usize = 256 * 1024;
    // the same-offset failure budget: a persistent failure (not a mere
    // session death) after several reconnect attempts stops the dump
    let mut failures_at_offset = 0u32;
    let mut last_done = st.done();
    const MAX_OFFSET_FAILURES: u32 = 5;

    loop {
        let (mut s, soc) = target::bring_up_amlogic(wait, progress)?;
        require_aml_tpl(&soc)?;
        let t0 = std::time::Instant::now();
        // stream until the session dies or the partition is done; the
        // device announces every burst, the host just consumes
        loop {
            match jb_core::aml::dump_chunk_until(&mut s, &mut st, CHUNK, progress, &|| false) {
                Ok(0) => break,
                Ok(_) => {
                    if st.done() > last_done {
                        last_done = st.done();
                        failures_at_offset = 0;
                    }
                }
                Err(e) => {
                    // session death mid-chunk: reconnect and retry the
                    // same range (DumpState did not advance)
                    log::warn!("session died: {e}");
                    break;
                }
            }
        }
        if st.done() >= st.size || st.short_read {
            break;
        }
        failures_at_offset += 1;
        if failures_at_offset > MAX_OFFSET_FAILURES {
            bail!(
                "dump stuck at +{:#x} after {MAX_OFFSET_FAILURES} reconnect attempts: \
                 power-cycle the speaker and re-run to start a new dump",
                st.done()
            );
        }
        let survived = t0.elapsed();
        // checkpoint: the file write is host-side and can happen after
        // the device is gone
        drop(s);
        let _ = jb_core::aml::write_dump(
            Path::new("backup"),
            &format!("{part}{suffix}"),
            &st.data,
            &|_| {},
        );
        println!(
            "session closed after {} ({}, +{:#x} of {:#x}); catching the download \
             window again — if nothing happens for ~15 s, power-cycle the speaker",
            format_secs(survived),
            humansize(st.done() as u64),
            st.done(),
            st.size
        );
    }

    jb_core::aml::write_dump(
        Path::new("backup"),
        &format!("{part}{suffix}"),
        &st.data,
        progress,
    )?;
    let note = if st.short_read {
        " (short read: bad blocks — the received length is the truth)"
    } else {
        ""
    };
    println!(
        "pass done: backup/{part}{suffix}.bin, {}{note}",
        humansize(st.done() as u64)
    );
    Ok((st.data, !st.short_read))
}

fn format_secs(d: Duration) -> String {
    format!("{:.1}s", d.as_secs_f32())
}

/// 16 bytes per row, with the address column.
fn hexdump(data: &[u8], base: u32) {
    for (row, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!(
            "{:08x}  {:<47}  |{}|",
            base + (row * 16) as u32,
            hex.join(" "),
            ascii
        );
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

/// Live log of the download-mode bus events, both vendors.
fn monitor() -> anyhow::Result<()> {
    println!("USB monitor (2207:* rockchip, 1b8e:c003 amlogic), Ctrl-C to stop.");
    let mut rm = rockusb::DeviceMonitor::new();
    let mut amlogic_on_bus = amlogic::present()?;
    rm.poll()?;
    if let Some(best) = rockusb::transport::DeviceMode::best(rm.modes()) {
        println!(
            "[{}] on the bus now: 2207:{:04x} ({})",
            ts(),
            best.pid(),
            best.label()
        );
    }
    if amlogic_on_bus {
        println!(
            "[{}] on the bus now: 1b8e:c003 (amlogic download mode)",
            ts()
        );
    }
    loop {
        for ev in rm.poll()? {
            match ev {
                rockusb::monitor::MonitorEvent::Appeared(mode) => println!(
                    "[{}] appeared 2207:{:04x} ({})",
                    ts(),
                    mode.pid(),
                    mode.label()
                ),
                rockusb::monitor::MonitorEvent::Disappeared(mode) => println!(
                    "[{}] gone     2207:{:04x} ({})",
                    ts(),
                    mode.pid(),
                    mode.label()
                ),
            }
        }
        let now = amlogic::present()?;
        if now != amlogic_on_bus {
            if now {
                println!("[{}] appeared 1b8e:c003 (amlogic download mode)", ts());
            } else {
                println!("[{}] gone     1b8e:c003 (amlogic download mode)", ts());
            }
            amlogic_on_bus = now;
        }
        std::thread::sleep(jb_core::target::POLL_INTERVAL);
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

#[cfg(test)]
mod read_stage_tests {
    use super::*;

    #[test]
    fn storage_commands_reject_bootrom_spl_and_unknown_stages() {
        for stage in [0, 8, 5] {
            let soc = amlogic::SocId::parse(&[0, 7, 0, stage]).unwrap();
            assert!(require_aml_tpl(&soc).is_err());
        }
        for major in [0, 1] {
            let soc = amlogic::SocId::parse(&[0, 7, major, 16]).unwrap();
            assert!(require_aml_tpl(&soc).is_ok());
        }
    }
}
