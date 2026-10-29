//! diag — live device diagnostics in loader mode (debug only):
//! ready/chip_info/flash_detect and a reset, with full error output.

use rockusb::loader::LoaderSession;
use rockusb::{DeviceMode, NusbTransport};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    let mode = rockusb::current_mode().expect("bus");
    println!("bus mode: {mode:?}");

    let t = NusbTransport::open(&DeviceMode::Loader).expect("open 330d");
    let (ep_in, ep_out) = (t.ep_in, t.ep_out);
    let mut s = LoaderSession::new(t, ep_in, ep_out);

    println!("ready:        {:?}", s.ready());
    let chip = s.chip_info();
    println!("chip_info:    {:?}", chip);
    let chip = chip.unwrap_or([0u8; 16]);
    println!(
        "  version:    {}",
        String::from_utf8_lossy(&chip[..]).trim_end_matches('\0')
    );
    println!(
        "flash_detect: {:?}",
        s.flash_detect()
            .map(|f| (f.sector_total, f.page_size, f.ecc_bits))
    );
    println!("capability:   {:?}", s.capability());

    // read the first GPT sectors: is the mask active?
    let mut buf = vec![0u8; 512];
    match s.read_lba(1, &mut buf) {
        Ok(()) => println!("read_lba(1):  ok, EFI PART = {}", &buf[..8] == b"EFI PART"),
        Err(e) => println!("read_lba(1):  {e}"),
    }
    let mut buf2 = vec![0xccu8; 512];
    match s.read_lba(0x10000, &mut buf2) {
        Ok(()) => println!(
            "read_lba(0x10000): ok, all 0xCC = {} (mask {})",
            buf2.iter().all(|&b| b == 0xcc),
            if buf2.iter().all(|&b| b == 0xcc) {
                "ACTIVE"
            } else {
                "off"
            }
        ),
        Err(e) => println!("read_lba(0x10000): {e}"),
    }

    // reset to MaskROM, with the result printed
    println!(
        "reset(maskrom): {:?}",
        s.reset(rockusb::loader::RESET_SUBCODE_MASKROM)
    );
    std::thread::sleep(std::time::Duration::from_secs(2));
    println!("mode after 2s: {:?}", rockusb::current_mode());
}
