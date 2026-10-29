//! stock_diag — read-only diagnostics of the stock u-boot rockusb
//! loader (2207:330d), primarily for first-generation columns: what the
//! stock loader itself will tell us and read for us.
//!
//! Strictly read-only: no reset, no writes, nothing is flashed. Run
//! from the repository root:
//!   cargo run -p jb-core --example stock_diag --release

use rockusb::{DeviceMode, LoaderSession, NusbTransport};

fn main() {
    match rockusb::device_serial(&DeviceMode::Loader) {
        Some(serial) => println!("loader serial:   {serial}"),
        None => println!("loader serial:   (not reported)"),
    }

    let t = NusbTransport::open(&DeviceMode::Loader).expect("open the stock loader (330d)");
    let (ep_in, ep_out) = (t.ep_in, t.ep_out);
    let mut s = LoaderSession::new(t, ep_in, ep_out);

    println!("TEST_UNIT_READY: {:?}", s.ready());
    match s.chip_info() {
        Ok(c) => println!(
            "chip_info:       {:?}",
            String::from_utf8_lossy(&c[..]).trim_end_matches('\0')
        ),
        Err(e) => println!("chip_info:       ERR {e}"),
    }
    let flash = s.flash_detect();
    match &flash {
        Ok(f) => println!(
            "flash:           {} sectors ({} MiB), block {}, page {}, ecc {}, \
             mid {:02x}, cs {}, id {:02x?}",
            f.sector_total,
            f.sector_total as u64 * 512 / 1024 / 1024,
            f.block_size,
            f.page_size,
            f.ecc_bits,
            f.manufacturer_id,
            f.chip_select,
            f.id
        ),
        Err(e) => println!("flash:           ERR {e}"),
    }
    println!("capability:      {:?}", s.capability());

    // ---- GPT: LBA1 + 33 entry sectors ----
    let gpt = match jb_core::session::read_gpt(&mut s, &|_| {}) {
        Ok((g, raw)) => {
            println!("GPT:             ok, {} partitions", g.entries.len());
            for e in &g.entries {
                println!(
                    "  #{:<2} {:>10}  LBA {:>7}..{:<7} {:>7} sectors  {:>6} MiB",
                    e.idx,
                    e.name,
                    e.first_lba,
                    e.last_lba,
                    e.sectors,
                    e.sectors * 512 / 1024 / 1024
                );
            }
            if std::fs::create_dir_all("work").is_ok() {
                let _ = std::fs::write("work/stock_gpt.bin", &raw);
                println!("  (raw sectors saved to work/stock_gpt.bin)");
            }
            Some(g)
        }
        Err(e) => {
            println!("GPT:             read/parse error: {e}");
            None
        }
    };

    // ---- read-limit probes: does the stock loader mask high reads? ----
    // (our usbplug masks everything above 0x10000 sectors as 0xCC; the
    // stock u-boot rockusb may not have that protection at all)
    println!("read probes (512 B each):");
    for lba in [
        0x1000u32, 0x8000, 0xFFF0, 0x10000, 0x10001, 0x20000, 0x40000,
    ] {
        let mut buf = vec![0xccu8; 512];
        match s.read_lba(lba, &mut buf) {
            Ok(()) => println!(
                "  LBA {lba:#08x}: ok, all-0xCC={} nonzero={}",
                buf.iter().all(|&b| b == 0xcc),
                buf.iter().any(|&b| b != 0)
            ),
            Err(e) => println!("  LBA {lba:#08x}: ERR {e}"),
        }
    }

    // the very last flash sector: the backup GPT header lives there
    if let Ok(f) = &flash {
        let last = f.sector_total - 1;
        let mut buf = vec![0u8; 512];
        match s.read_lba(last, &mut buf) {
            Ok(()) => println!(
                "  LBA {last:#08x} (last): ok, EFI PART = {}",
                &buf[..8] == b"EFI PART"
            ),
            Err(e) => println!("  LBA {last:#08x} (last): ERR {e}"),
        }
    }

    // ---- userdata: formatted? ----
    if let Some(gpt) = gpt {
        if let Some(e) = gpt.find("userdata") {
            let mut head = vec![0u8; 2048];
            match s.read_lba(e.first_lba as u32, &mut head) {
                Ok(()) => {
                    // ext2/3/4 superblock: offset 1024, magic 0xEF53 at +56
                    let sb = &head[1024..];
                    let magic = u16::from_le_bytes([sb[56], sb[57]]);
                    println!(
                        "userdata head:   ext2 magic {:#06x} ({})",
                        magic,
                        if magic == 0xef53 {
                            "formatted"
                        } else {
                            "NOT ext"
                        }
                    );
                    if magic == 0xef53 {
                        let blocks = u32::from_le_bytes(sb[4..8].try_into().unwrap());
                        let log_bs = sb[24];
                        let bs = 1024u64 << log_bs;
                        println!(
                            "                 block size {bs}, {blocks} blocks ({} MiB fs)",
                            blocks as u64 * bs / 1024 / 1024
                        );
                    }
                }
                Err(err) => println!("userdata head:   ERR {err}"),
            }
        }
    }
    println!("diag done (strictly read-only, nothing was written)");
}
