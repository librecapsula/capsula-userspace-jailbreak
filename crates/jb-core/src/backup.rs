//! Full GPT partition dump (a port of backup.sh, the LibreRD method).
//! Bring-up (MaskROM -> loader into RAM -> signatures) is done by the
//! session BEFORE this is called.

use crate::backup_store::{append_sha256_line, file_sha256};
use crate::config::Config;
use crate::session::{read_gpt, Progress, ProgressFn};
use rockusb::loader::LoaderSession;
use rockusb::{Error as UsbError, Transport};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

/// Sectors per flash read (bash v1: CHUNK=8192 = 4 MiB).
pub const CHUNK_SECTORS: u32 = 8192;
/// Guard sector for the 0xCC check: first one beyond the stock read limit.
pub const GUARD_LBA: u32 = 0x10000;

#[derive(Debug)]
pub struct BackupReport {
    pub out_dir: std::path::PathBuf,
    pub partitions: usize,
    pub sectors_total: u64,
    pub read_limit_old: u32,
}

/// Patch the usbplug read limit in RAM (backup.sh:72-91): without it,
/// everything above 0x10000 sectors reads back as 0xCC. Returns the
/// previous value.
pub fn patch_read_limit<T: Transport>(
    s: &mut LoaderSession<T>,
    config: &Config,
    progress: ProgressFn,
) -> rockusb::Result<u32> {
    let info = s.flash_detect()?;
    let total = info.sector_total;
    if total <= 34 {
        return Err(UsbError::WrongMode(format!(
            "usbplug отдал бредовый размер флеша: {total} секторов"
        )));
    }
    let addr = config.usbplug.read_limit_addr;
    let mut cur = [0u8; 4];
    s.read_mem(addr, &mut cur)?;
    let old = u32::from_le_bytes(cur);
    if old != total {
        progress(Progress::Step(format!(
            "предел чтения: {old} → {total} секторов (RAM-патч usbplug)"
        )));
        s.write_mem(addr, &total.to_le_bytes())?;
        let mut chk = [0u8; 4];
        s.read_mem(addr, &mut chk)?;
        if chk != total.to_le_bytes() {
            return Err(UsbError::WrongMode(
                "RAM-патч не применился (проверочное чтение не совпало)".into(),
            ));
        }
    } else {
        progress(Progress::Step(format!(
            "предел чтения уже расширен: {total} секторов"
        )));
    }
    Ok(old)
}

/// 0xCC guard: read one sector beyond the old limit; if the mask is
/// still active the backup would be garbage — refuse.
pub fn cc_guard<T: Transport>(
    s: &mut LoaderSession<T>,
    progress: ProgressFn,
) -> rockusb::Result<()> {
    let mut buf = vec![0u8; 512];
    s.read_lba(GUARD_LBA, &mut buf)?;
    if buf.iter().all(|&b| b == 0xcc) {
        return Err(UsbError::WrongMode(format!(
            "LBA {GUARD_LBA:#x} читается как 0xCC — RAM-патч не действует"
        )));
    }
    progress(Progress::Step("маска 0xCC снята".into()));
    Ok(())
}

/// Back up every partition into `out_dir` (v1-compatible layout).
/// The caller has done bring_up(Purpose::Backup): signatures verified.
pub fn backup<T: Transport>(
    s: &mut LoaderSession<T>,
    config: &Config,
    out_dir: &Path,
    progress: ProgressFn,
) -> rockusb::Result<BackupReport> {
    let old_limit = patch_read_limit(s, config, progress)?;
    cc_guard(s, progress)?;

    let (gpt, gpt_raw) = read_gpt(s, progress)?;

    std::fs::create_dir_all(out_dir)?;
    std::fs::write(out_dir.join(".gpt.bin"), &gpt_raw)?;
    std::fs::write(out_dir.join("partition_table.tsv"), gpt.to_tsv())?;
    // Both markers must go before the first partition is written: an
    // interrupted re-dump into an old directory would otherwise leave a
    // stale SUCCESS.txt next to partial sums and pass as a valid backup.
    let _ = std::fs::remove_file(out_dir.join("SUCCESS.txt"));
    let _ = std::fs::remove_file(out_dir.join("SHA256SUMS.txt"));

    let info = s.flash_detect()?;
    progress(Progress::Step(format!(
        "разделов: {}, флеш: {} секторов",
        gpt.entries.len(),
        info.sector_total
    )));

    for e in &gpt.entries {
        let file_name = crate::backup_store::BackupStore::image_name(e.idx, &e.name);
        let path = out_dir.join(&file_name);
        progress(Progress::PartitionStart {
            name: e.name.clone(),
            sectors: e.sectors,
        });
        let mut out = std::fs::File::create(&path)?;
        let mut hasher = Sha256::new();
        // one reusable full-chunk buffer; the last chunk of a partition
        // is a prefix slice
        let mut chunk = vec![0u8; CHUNK_SECTORS as usize * 512];
        let mut done: u64 = 0;
        while done < e.sectors {
            let n = (e.sectors - done).min(CHUNK_SECTORS as u64) as usize;
            let lba = u32::try_from(e.first_lba + done).map_err(|_| {
                UsbError::Loader(format!("{}: LBA за пределами u32-протокола", e.name))
            })?;
            s.read_lba(lba, &mut chunk[..n * 512])?;
            if done == 0 && chunk[..512].iter().all(|&b| b == 0xcc) {
                let _ = std::fs::remove_file(&path);
                return Err(UsbError::WrongMode(format!(
                    "{}: весь 0xCC — маска активна, дамп негоден",
                    e.name
                )));
            }
            hasher.update(&chunk[..n * 512]);
            out.write_all(&chunk[..n * 512])?;
            done += n as u64;
            progress(Progress::PartitionProgress {
                name: e.name.clone(),
                done,
                total: e.sectors,
            });
        }
        out.flush()?;
        drop(out);
        let size = std::fs::metadata(&path)?.len();
        if size != e.sectors * 512 {
            return Err(UsbError::Loader(format!(
                "размер не сошёлся: {file_name} ({size} != {})",
                e.sectors * 512
            )));
        }
        // checksum by an independent pass (sha256sum-compatible)
        let hex = file_sha256(&path).map_err(|e| UsbError::Loader(e.to_string()))?;
        append_sha256_line(out_dir, &file_name, &hex).map_err(rockusb::Error::Io)?;
        progress(Progress::PartitionDone {
            name: e.name.clone(),
        });
    }

    std::fs::write(
        out_dir.join("SUCCESS.txt"),
        format!("SUCCESS: {}\n", out_dir.display()),
    )?;
    progress(Progress::Step(format!(
        "готово: {} (дамп по GPT, не сырой NAND)",
        out_dir.display()
    )));
    Ok(BackupReport {
        out_dir: out_dir.to_path_buf(),
        partitions: gpt.entries.len(),
        sectors_total: info.sector_total as u64,
        read_limit_old: old_limit,
    })
}
