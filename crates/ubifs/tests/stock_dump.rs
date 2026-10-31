//! Cross-validation on a real-world stock volume (a UBI dump of a data
//! partition). The dump path comes from the `UBIFS_STOCK_DUMP`
//! environment variable; without it the test skips.
//!
//! Any real dump works: the assertions check structural invariants and a
//! full extract → repack → reopen round-trip, not device-specific
//! values.

use std::path::PathBuf;

use ubifs::reader::Ubifs;
use ubifs::ubi::{Dump, UbiGeometry};
use ubifs::UBIFS_ROOT_INO;

fn stock_dump() -> Option<Vec<u8>> {
    let path = std::env::var_os("UBIFS_STOCK_DUMP")?;
    std::fs::read(PathBuf::from(path)).ok()
}

#[test]
fn parses_the_stock_data_volume() {
    let Some(raw) = stock_dump() else {
        eprintln!("UBIFS_STOCK_DUMP is not set — test skipped");
        return;
    };
    // Default ubiformat geometry: the VID header in the first min_io
    // unit. For non-default flashes set the expectations accordingly.
    let geom = UbiGeometry::from_peb_size(0x20000, 2048);
    assert_eq!(geom.vid_hdr_offset, 2048);
    assert_eq!(geom.data_offset, 4096);

    let dump = Dump::parse(&raw, geom).expect("UBI dump parses");
    // Note: in dumps captured "by logical capacity" (bad blocks skipped,
    // e.g. raw NAND captures) the layout volume may be absent or off its
    // nominal PEBs, so volumes() can legitimately be empty — volume LEBs
    // are located by scanning VID headers instead.
    let lebs = dump.volume_lebs(0);
    assert!(lebs.len() >= 2, "volume size {}", lebs.len());
    assert!(lebs.iter().filter(|l| l.is_some()).count() > 1);

    let fs = Ubifs::new(lebs).expect("stock volume parses");
    fs.verify().expect("stock volume is consistent");

    // Cross-field invariants of the parsed SB/master.
    let sb = &fs.superblock;
    let mst = &fs.master;
    assert_eq!(fs.geometry.leb_size, sb.leb_size);
    assert_eq!(fs.geometry.leb_cnt, mst.leb_cnt);
    assert!(mst.leb_cnt <= sb.max_leb_cnt);
    assert!(sb.leb_size > sb.min_io_size);
    assert!(sb.leb_size.is_multiple_of(sb.min_io_size));
    assert_eq!(sb.leb_size % 8, 0);

    // The root must be a non-empty directory.
    let entries = fs.dir_entries(UBIFS_ROOT_INO).expect("root listing");
    assert!(!entries.is_empty(), "root has no entries");

    // A full tree extraction.
    let tree = fs.extract().expect("extract");
    match &tree.kind {
        ubifs::tree::Kind::Dir(children) => assert!(!children.is_empty()),
        _ => panic!("root must be a directory"),
    }
}

#[test]
fn stock_volume_rebuilds_and_reopens() {
    let Some(raw) = stock_dump() else {
        eprintln!("UBIFS_STOCK_DUMP is not set — test skipped");
        return;
    };
    let geom = UbiGeometry::from_peb_size(0x20000, 2048);
    let dump = Dump::parse(&raw, geom).unwrap();
    let lebs = dump.volume_lebs(0);
    let fs = Ubifs::new(lebs).unwrap();

    // A repack with the volume's own geometry must produce a valid image.
    let mut opts = ubifs::mkfs::Options::new(
        fs.superblock.min_io_size,
        fs.superblock.leb_size,
        fs.superblock.max_leb_cnt,
    );
    opts.log_lebs = Some(fs.superblock.log_lebs);
    opts.orph_lebs = fs.superblock.orph_lebs;
    opts.fanout = fs.superblock.fanout;
    opts.max_bud_bytes = Some(fs.superblock.max_bud_bytes);
    opts.lsave_cnt = fs.superblock.lsave_cnt;
    opts.default_compr = ubifs::media::UBIFS_COMPR_NONE;
    opts.uuid = fs.superblock.uuid;
    opts.fmt_version = fs.superblock.fmt_version;
    opts.ro_compat_version = fs.superblock.ro_compat_version;

    let tree = fs.extract().unwrap();
    let image = ubifs::mkfs::mkfs(&tree, &opts).expect("repack");
    let fs2 = Ubifs::new(image.lebs[..image.geometry.leb_cnt as usize].to_vec())
        .expect("repacked volume parses");
    fs2.verify().expect("repacked volume is consistent");

    // The root entry names survive the repack.
    let before: Vec<String> = fs
        .dir_entries(UBIFS_ROOT_INO)
        .unwrap()
        .into_iter()
        .map(|d| d.name)
        .collect();
    let after: Vec<String> = fs2
        .dir_entries(UBIFS_ROOT_INO)
        .unwrap()
        .into_iter()
        .map(|d| d.name)
        .collect();
    let mut b = before.clone();
    let mut a = after.clone();
    b.sort();
    a.sort();
    assert_eq!(a, b);
}
