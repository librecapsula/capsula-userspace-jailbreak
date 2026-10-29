//! capsula-jb — джейлбрейк колонок VK Capsula перезаписью userspace:
//! userdata не подписан и свободно перезаписывается — кладём в него
//! оверлей с adbd, остальное не трогаем.
//!
//! main — входная точка: разбор аргументов, выбор платформенного
//! бэкенда по USB-устройству на шине и запуск сценария. Вся логика
//! платформы — в модулях-бэкендах (контракт — `backend::Backend`,
//! сегодня это `rockchip`).

mod backend;
mod progress;
mod rockchip;

use anyhow::bail;
use clap::{Parser, Subcommand};
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    name = "capsula-jb",
    version,
    about = "Джейлбрейк VK Capsula: дамп → оверлей adbd в userdata → ADB"
)]
struct Cli {
    /// Сколько секунд ждать колонку на USB (0 = бесконечно)
    #[arg(long, value_name = "SEC", default_value = "0")]
    wait: u64,

    /// Не спрашивать подтверждение перед записью userdata (скрипты)
    #[arg(long)]
    yes: bool,

    /// Собрать чистый ext2 вместо патча дампа (содержимое userdata теряется)
    #[arg(long)]
    format_userdata: bool,

    /// Не проверять и не снимать бэкап: userdata собирается с нуля
    /// (содержимое теряется; крайние случаи — например, битый каталог)
    #[arg(long)]
    no_backup: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Только дамп разделов в backup/ (на колонку не пишется)
    Backup,
    /// Живой лог USB-событий
    Monitor,
}

fn main() -> anyhow::Result<()> {
    // An elevated relaunch (Windows UAC manifest) may start in
    // C:\Windows\System32; the tool writes backup/work relative to
    // the CWD, so move next to the executable in that case.
    if let Some(cwd) = win_drv::fix_cwd_if_system32() {
        eprintln!("рабочий каталог: {}", cwd.display());
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let wait = if cli.wait == 0 {
        None
    } else {
        Some(Duration::from_secs(cli.wait))
    };
    let result = match cli.command {
        None => pick_backend(wait)?.jailbreak(cli.yes, cli.format_userdata, cli.no_backup, wait),
        Some(Command::Backup) => {
            if cli.no_backup {
                bail!("--no-backup несовместим с подкомандой backup");
            }
            pick_backend(wait)?.backup(wait)
        }
        // Монитор не ждёт устройства и не строит драйверную сессию —
        // только живой лог шины.
        Some(Command::Monitor) => rockchip::monitor_bus(),
    };
    // Launched from a normal console, Windows elevates the tool into a
    // NEW console window (see the UAC manifest note in .cargo/config.toml);
    // keep that window open so the output is readable. A shared terminal
    // or a redirected/none console gets no pause.
    win_drv::pause_if_own_console();
    result
}

/// Все известные платформы в порядке опроса. Будущая платформа
/// добавляется сюда: опознаётся по своему USB-устройству (`present`),
/// сценарий — через тот же контракт `backend::Backend`.
fn backends() -> Vec<Box<dyn backend::Backend>> {
    vec![Box::new(rockchip::Rockchip::new())]
}

/// Выбор бэкенда по USB-устройству на шине: ждём, пока появится
/// устройство любой известной платформы, и отдаём её бэкенд. Пока шина
/// пуста, печатаем подсказки платформ (как войти в download-режим).
fn pick_backend(wait: Option<Duration>) -> anyhow::Result<Box<dyn backend::Backend>> {
    let start = Instant::now();
    let mut candidates = backends();
    let mut hint_shown = false;
    loop {
        let mut chosen: Option<usize> = None;
        for (i, b) in candidates.iter().enumerate() {
            if b.present()? {
                chosen = Some(i);
                break;
            }
        }
        if let Some(i) = chosen {
            let b = candidates.swap_remove(i);
            log::info!("платформа: {}", b.name());
            return Ok(b);
        }
        if !hint_shown {
            for b in &candidates {
                if let Some(h) = b.wait_hint() {
                    println!("{h}");
                }
            }
            hint_shown = true;
        }
        if let Some(t) = wait {
            if start.elapsed() >= t {
                bail!("ни одна поддерживаемая платформа не появилась на шине (--wait)");
            }
        }
        std::thread::sleep(rockusb::monitor::POLL_INTERVAL);
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
