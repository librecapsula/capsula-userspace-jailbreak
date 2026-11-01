//! `capsula-jb aml "<cmd>"...`: the burning-command passthrough —
//! amlogic diagnostics, outside the scenario. `upload mem <addr>
//! normal <size>` reads memory and prints a hexdump; `sleep <ms>` is a
//! host-side pause; `id` is a single identify keepalive; `dlmem
//! <size>` probes the media flow into DRAM with a compare; `readtest
//! <n> <size>` measures the session throughput; `cycle <n>` re-enters
//! the window without a power cycle.

use crate::platform::{bring_up, open_and_identify, require_tpl};
use anyhow::{bail, Context, Result};
use jb_core::progress::ProgressFn;
use std::time::{Duration, Instant};

/// The passthrough: identify the board and run u-boot burning commands
/// within one caught window.
pub fn passthrough(wait: Option<Duration>, cmds: &[String], progress: ProgressFn) -> Result<()> {
    let (s, soc) = match open_and_identify(progress) {
        Ok(pair) => pair,
        Err(amlogic::Error::DeviceNotFound) => {
            // an empty bus — catch the window as usual
            let mut s = bring_up(wait, progress)?;
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
        // "cycle <n>": n full window re-entries WITHOUT a power cycle —
        // a nested `run try_auto_burn` reinitializes the gadget, then a
        // port reset kills the node forcefully (the stack recipe
        // reenter_download_window; the 18:08 test without a reset gave
        // no re-enumeration within 30 s). Catch the re-enumeration and
        // stream 4 MiB from every new session.
        if let Some(n) = c.strip_prefix("cycle ") {
            let n: u32 = n.parse().context("cycle <n>: не число")?;
            for i in 1..=n {
                log::info!("cycle {i}/{n}: убиваю окно (run try_auto_burn + port reset)...");
                let _ = s.send_bulk_cmd("run try_auto_burn");
                std::thread::sleep(Duration::from_millis(300));
                let _ = s.reset();
                let caught = Instant::now();
                s = bring_up(Some(Duration::from_secs(30)), progress)
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
        // "sleep <ms>": a host-side pause, nothing is sent
        if let Some(ms) = c.strip_prefix("sleep ") {
            let ms: u64 = ms.parse().context("sleep <ms>: не число")?;
            log::info!("пауза {ms}мс (ничего не отправляется)...");
            std::thread::sleep(Duration::from_millis(ms));
            continue;
        }
        // "id": a single identify — a keepalive candidate (the vendor
        // tool identifies before every operation)
        if c == "id" {
            let soc = s.identify()?;
            log::info!("id -> {soc} (+{}мс)", t0.elapsed().as_millis());
            continue;
        }
        // "dlmem <size>": a probe download into DRAM (flash untouched):
        // arm through the TPL channel (AM_REQ_TPL_CMD, as the vendor
        // update) + media packets with a synthetic pattern + a closing
        // `download get_status` (bulkcmd, as the vendor mwrite). Then
        // `upload mem` reads it back and compares: on live hardware
        // this proves the vendor media flow reaches DRAM.
        if let Some(size) = c.strip_prefix("dlmem ") {
            let size = usize::from_str_radix(size.trim_start_matches("0x"), 16)
                .context("dlmem <size>: не hex-число")?;
            anyhow::ensure!(size > 0 && size <= 8 << 20, "dlmem <size>: 1..=0x800000");
            let armed = s.tpl_cmd(&format!(
                "download mem {:#x} normal {size:#x}",
                amlogic::RAM_SCRATCH
            ))?;
            log::info!(
                "dlmem {size:#x}: arm -> {armed} (+{}мс)",
                t0.elapsed().as_millis()
            );
            // a pattern without all-zero runs: zeroed memory must not
            // be confused with unwritten
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
            let diff = back.iter().zip(&data).filter(|(a, b)| a != b).count();
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
        // "readtest <n>": n chunks of "id → nand read 1 MiB → upload
        // mem" within one session — measures how many bytes one window
        // carries with an identify keepalive between chunks (the
        // hypothesis: identification extends the session, the wall is
        // an idle timer, not a budget).
        if let Some(rest) = c.strip_prefix("readtest ") {
            let mut it = rest.split_whitespace();
            let n: u32 = it
                .next()
                .context("readtest <n> [size]: не число")?
                .parse()?;
            let size: usize = it
                .next()
                .map(|s| usize::from_str_radix(s.trim_start_matches("0x"), 16))
                .transpose()
                .context("readtest: размер не hex")?
                .unwrap_or(0x10_0000);
            anyhow::ensure!(
                size > 0 && size <= 0x100_0000,
                "readtest: размер 1..=0x1000000"
            );
            for i in 1..=n {
                let soc = s.identify()?;
                let t_chunk = Instant::now();
                let off = 0x100_0000u32 + (i - 1) * size as u32; // misc/boot_a/system — a readable zone
                                                                 // flasher.sh read_big_from_flash mechanics: one
                                                                 // blocking `nand read` (the status read absorbs the
                                                                 // staging silence) + one `upload mem` stream
                let data = s
                    .nand_read(amlogic::RAM_SCRATCH, off, size)
                    .and_then(|_| s.read_dram(amlogic::RAM_SCRATCH, size, &|_| {}));
                match data {
                    Ok(d) => log::info!(
                        "readtest {i}/{n}: id={soc}, nand+upload {:#x} с {off:#x} за {} мс ({} байт)",
                        size,
                        t_chunk.elapsed().as_millis(),
                        d.len()
                    ),
                    Err(e) => {
                        let on_bus = amlogic::present().unwrap_or(false);
                        log::error!(
                            "readtest {i}/{n}: кусок не прошёл на {} мс ({e}); устройство {}",
                            t_chunk.elapsed().as_millis(),
                            if on_bus { "на шине" } else { "пропало" }
                        );
                        anyhow::bail!("readtest прерван на куске {i}");
                    }
                }
            }
            log::info!("readtest: все {n} кусков прошли в одной сессии");
            continue;
        }
        let r = if let Some((addr, size)) = parse_upload_cmd(c) {
            log::info!("читаю {size:#x} байт с {addr:#x}...");
            s.upload_read(addr, size).map(|data| {
                // a large stream — head + total only; an 8 MiB hexdump
                // serves nobody
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

/// Parse the passthrough command `upload mem <addr> normal <size>`.
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

/// 16 bytes per row with an address column (the passthrough
/// diagnostic hexdump); every row is a logger line.
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
        log::info!(
            "{:08x}  {:<47}  |{}|",
            base + (row * 16) as u32,
            hex.join(" "),
            ascii
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_passthrough_parses_only_wellformed_mem_reads() {
        assert_eq!(
            parse_upload_cmd("upload mem 0x1080000 normal 0x100"),
            Some((0x108_0000, 0x100))
        );
        // without 0x — hex anyway, as the flasher reference does
        assert_eq!(
            parse_upload_cmd("upload mem 1080000 normal 40"),
            Some((0x108_0000, 0x40))
        );
        assert_eq!(parse_upload_cmd("upload store data normal 0x100"), None);
        assert_eq!(parse_upload_cmd("upload mem 0x0 normal 0x800001"), None);
        assert_eq!(parse_upload_cmd("printenv"), None);
    }
}
