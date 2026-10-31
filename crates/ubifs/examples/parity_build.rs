//! Cross-validation driver for the mkfs parity harness: reads a
//! reference image produced by the real mkfs.ubifs (see
//! `tests/mkfs-parity.sh`, which runs mtd-utils in docker), extracts
//! the plan (restoring the original write order from the on-flash node
//! positions), rebuilds and writes our image. The byte-for-byte
//! comparison is done by the script.
//!
//! Usage: parity_build <ref.ubifs> <out.ubifs> <min_io> <leb_size>
//!                    <max_leb_cnt> <journal-bytes|default>

use ubifs::mkfs::{self, Options};
use ubifs::reader::Ubifs;

fn main() {
    let mut args = std::env::args().skip(1);
    let (ref_path, out_path) = (
        args.next().expect("ref path"),
        args.next().expect("out path"),
    );
    let min_io: u32 = args.next().expect("min_io").parse().unwrap();
    let leb_size: u32 = args.next().expect("leb_size").parse().unwrap();
    let max_leb_cnt: u32 = args.next().expect("max_leb_cnt").parse().unwrap();
    let journal: Option<u64> = match args.next().expect("journal").as_str() {
        "default" => None,
        v => Some(parse_size(v).unwrap()),
    };

    let ref_raw = std::fs::read(&ref_path).unwrap();
    let lebs: Vec<Option<Vec<u8>>> = ref_raw
        .chunks(leb_size as usize)
        .map(|c| Some(c.to_vec()))
        .collect();

    let fs = Ubifs::new(lebs).unwrap();
    let plan = fs.extract_plan().unwrap();

    let mut opts = Options::new(min_io, leb_size, max_leb_cnt);
    opts.max_bud_bytes = journal;
    opts.default_compr = ubifs::Compr::None;
    let image = mkfs::mkfs_plan(&plan, &opts).unwrap();
    std::fs::write(&out_path, image.to_vec()).unwrap();
    println!("{out_path} written: {} lebs", image.geometry.leb_cnt);
}

/// Parse a size with an optional KiB/MiB/GiB suffix.
fn parse_size(s: &str) -> Option<u64> {
    let (num, mul) = if let Some(v) = s.strip_suffix("GiB") {
        (v, 1 << 30)
    } else if let Some(v) = s.strip_suffix("MiB") {
        (v, 1 << 20)
    } else if let Some(v) = s.strip_suffix("KiB") {
        (v, 1 << 10)
    } else {
        (s, 1)
    };
    num.parse::<u64>().ok().map(|v| v * mul)
}
