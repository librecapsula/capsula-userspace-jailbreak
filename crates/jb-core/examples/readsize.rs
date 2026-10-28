//! Find the largest workable bulk-IN (READ_LBA) transfer size.
//!
//! nusb enables the WinUSB RAW_IO pipe policy on bulk-IN endpoints, and
//! RAW_IO requests are NOT split by WinUSB: anything above the host
//! stack's maximum transfer size (commonly ~2 MiB) fails instantly with
//! ERROR_INVALID_FUNCTION — which surfaces as `usb: unknown (error 1)`
//! and used to kill the backup at its first 4 MiB chunk on Windows.
//!
//! The example loads the usbplug exactly like the CLI does, patches the
//! read limit, then reads the same LBA with growing chunk sizes. The
//! first failure wedges the data phase (the CBW was already sent, so
//! the device streams into a pipe nobody drains), so the run stops
//! there on purpose — power-cycle the board afterwards to recover.
//!
//! Run from the repository root (uses the ota/ loader cache):
//!   cargo run -p jb-core --example readsize --release

use jb_core::backup::patch_read_limit;
use jb_core::config::Config;
use jb_core::session::{bring_up, BringUpError};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let config = Config::embedded();
    let (loader, ver) =
        jb_core::ota::ensure_loader(Path::new("ota"), &config.ota.platform, &|_| {})?;
    if let Some(v) = ver {
        println!("loader OTA version: {v}");
    }
    let mut s = match bring_up(&config, &loader, None, &|_| {}) {
        Ok(s) => s,
        Err(BringUpError::LoaderRejected) => anyhow::bail!("BootROM rejected the loader"),
        Err(e) => return Err(e.into()),
    };
    let info = s.flash_detect()?;
    println!(
        "usbplug up, flash: {} sectors ({} MiB), block {}",
        info.sector_total,
        info.sector_total / 2 / 1024,
        info.block_size
    );
    patch_read_limit(&mut s, &config, &|_| {})?;

    let lba = 0x2000u32; // inside the first partitions, below the stock limit
    for sectors in [1u32, 64, 512, 1024, 2048, 3072, 4096, 6144, 8192, 16384] {
        let mut buf = vec![0u8; sectors as usize * 512];
        let res = s.read_lba(lba, &mut buf);
        let label = format!("{:>5} sectors ({} KiB)", sectors, sectors * 512 / 1024);
        match res {
            Ok(()) => println!("{label}: OK"),
            Err(e) => {
                println!("{label}: FAIL — {e}");
                println!("first failing size reached; the stream is now wedged, stopping");
                return Ok(());
            }
        }
    }
    println!("all sizes up to 16384 sectors (8 MiB) read fine — RAW_IO limit not hit");
    Ok(())
}
