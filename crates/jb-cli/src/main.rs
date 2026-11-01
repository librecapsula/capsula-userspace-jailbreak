//! capsula-jb — the VK Capsula userspace jailbreak CLI: backup /
//! userdata-overlay / monitor. The data partition is not signed and is
//! freely rewritable — the overlay with adbd goes into it, everything
//! else stays untouched.
//!
//! main — the entry point: argument parsing, platform selection by the
//! USB device on the bus (jb-cli/src/backend.rs) and the confirmation
//! prompt. The scenario skeleton lives in jb-core (`scenario`), the
//! platform implementations in the jb-rockchip / jb-amlogic crates.

mod backend;
mod logging;
mod progress;
mod util;

use anyhow::bail;
use clap::{Parser, Subcommand};

use jb_core::format::humansize;
use jb_core::progress::Progress;
use jb_core::scenario::{Params, WritePlan};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "capsula-jb",
    version,
    about = "Джейлбрейк VK Capsula: дамп → оверлей adbd в userdata → ADB"
)]
struct Cli {
    /// How many seconds to wait for the speaker on USB (0 = forever)
    #[arg(long, value_name = "SEC", default_value = "0")]
    wait: u64,

    /// Do not ask for confirmation before writing userdata (for scripts)
    #[arg(long)]
    yes: bool,

    /// Build a clean image instead of patching the dump (contents are lost)
    #[arg(long)]
    format_userdata: bool,

    /// Skip backup verification and capture: the image is built from
    /// scratch (contents are lost; edge cases — e.g. a broken directory)
    #[arg(long)]
    no_backup: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Only dump the partitions into backup/ (nothing is written to the speaker)
    Backup,
    /// Restore the data partition from the verified backup (the
    /// jailbreak rollback)
    Restore,
    /// Live log of USB events
    Monitor,
    /// Amlogic Mini: identify the board and pass through u-boot burning
    /// commands (diagnostics; example: capsula-jb aml "printenv bootdelay")
    Aml {
        /// Commands one by one; with no commands — identify only
        #[arg(value_name = "CMD")]
        cmds: Vec<String>,
    },
}

fn main() -> anyhow::Result<()> {
    // The logger comes first: all tool output (including the final
    // error) goes through it, with millisecond timestamps.
    logging::init();
    // An elevated relaunch (Windows UAC manifest) may start in
    // C:\Windows\System32; the tool writes backup/work relative to
    // the CWD, so move next to the executable in that case.
    if let Some(cwd) = win_drv::fix_cwd_if_system32() {
        log::info!("рабочий каталог: {}", cwd.display());
    }
    let cli = Cli::parse();
    let wait = if cli.wait == 0 {
        None
    } else {
        Some(Duration::from_secs(cli.wait))
    };
    // The scenario lives in an inner function: neither `?` nor `bail!`
    // inside it lets an error slip past the interception below
    // (otherwise the runtime prints «Error: …» without a timestamp).
    let result = run(cli, wait);
    if let Err(e) = &result {
        log::error!("{e:?}");
    }
    // Launched from a normal console, Windows elevates the tool into a
    // NEW console window (see the UAC manifest note in .cargo/config.toml);
    // keep that window open so the output is readable. A shared terminal
    // or a redirected/none console gets no pause.
    win_drv::pause_if_own_console();
    match result {
        Ok(()) => Ok(()),
        // The error is already logged with a timestamp; exit silently
        // with code 1 so the runtime does not print it a second time
        // («Error: …»).
        Err(_) => std::process::exit(1),
    }
}

/// Parse the subcommand and run the scenario; all errors go through
/// the return value (intercepted in main and logged with a timestamp).
fn run(cli: Cli, wait: Option<Duration>) -> anyhow::Result<()> {
    let p = progress::CliProgress::new();
    let progress = |ev: Progress| p.handle(ev);
    match cli.command {
        None => {
            let params = Params {
                format_userdata: cli.format_userdata,
                no_backup: cli.no_backup,
                wait,
            };
            let confirm = confirm_write(cli.yes);
            backend::pick_backend(wait)?.jailbreak(&params, &confirm, &progress)
        }
        Some(Command::Backup) => {
            if cli.no_backup {
                bail!("--no-backup несовместим с подкомандой backup");
            }
            backend::pick_backend(wait)?.backup(wait, &progress)
        }
        Some(Command::Restore) => {
            if cli.no_backup {
                bail!("--no-backup несовместим с подкомандой restore");
            }
            let confirm = confirm_write(cli.yes);
            backend::pick_backend(wait)?.restore(wait, &confirm, &progress)
        }
        // The monitor does not wait for a device and does not build a
        // driver session — just the live bus log.
        Some(Command::Monitor) => monitor_bus(),
        // Passthrough is Amlogic Mini diagnostics, outside the main scenario.
        Some(Command::Aml { cmds }) => {
            jb_amlogic::diag::passthrough(wait, &cmds, &progress)
        }
    }
}

/// Write confirmation (skipped with --yes). The skeleton calls it after
/// measuring the partition and BEFORE any writing action — a refusal is
/// safe. One wording for all platforms: the partition name, size and
/// mode description come from the platform's WritePlan.
fn confirm_write(yes: bool) -> impl Fn(&WritePlan) -> anyhow::Result<()> {
    move |plan: &WritePlan| {
        if yes {
            return Ok(());
        }
        let verb = if plan.restore { "восстановление" } else { "запись" };
        log::info!(
            "{verb} {} ({}): {}",
            plan.partition,
            humansize(plan.size),
            plan.mode
        );
        log::info!("продолжить? [y/N]");
        ask_yes()
    }
}

fn ask_yes() -> anyhow::Result<()> {
    use std::io::{IsTerminal, Write};
    // Non-interactive stdin (CI, LLM agent shells, redirected input):
    // never hang on a prompt nobody can answer — fail with an
    // actionable message instead. Nothing has been written at this
    // point, so an exit is safe.
    std::io::stdout().flush().ok();
    if !std::io::stdin().is_terminal() {
        bail!(
            "нужно подтверждение записи, но stdin не интерактивен; ничего \
             не записано. Согласуйте запись и перезапустите с --yes"
        );
    }
    let mut ans = String::new();
    std::io::stdin().read_line(&mut ans)?;
    let ans = ans.trim().to_lowercase();
    if ans != "y" && ans != "yes" {
        bail!("прервано пользователем");
    }
    Ok(())
}

/// Live log of USB events from both vendors: the rockchip monitor
/// (2207:*) plus tracking the appearance/disappearance of 1b8e:c003.
fn monitor_bus() -> anyhow::Result<()> {
    log::info!("Монитор USB (2207:* rockchip, 1b8e:c003 amlogic), Ctrl-C — выход.");
    let mut m = rockusb::DeviceMonitor::new();
    let mut amlogic_on_bus = ::amlogic::present().unwrap_or(false);
    m.poll()?;
    if let Some(best) = rockusb::transport::DeviceMode::best(m.modes()) {
        log::info!("сейчас на шине: 2207:{:04x} ({})", best.pid(), best.label());
    }
    if amlogic_on_bus {
        log::info!("сейчас на шине: 1b8e:c003 (amlogic download)");
    }
    loop {
        // 2207:* events are logged by rockusb::DeviceMonitor itself (usb:
        // appeared/gone); here we only watch the amlogic gadget.
        m.poll()?;
        let now = ::amlogic::present().unwrap_or(amlogic_on_bus);
        if now != amlogic_on_bus {
            if now {
                log::info!("появился 1b8e:c003 (amlogic download)");
            } else {
                log::info!("пропал   1b8e:c003 (amlogic download)");
            }
            amlogic_on_bus = now;
        }
        std::thread::sleep(rockusb::monitor::POLL_INTERVAL);
    }
}
