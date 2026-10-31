//! Cross-validation driver for the mkfs parity harness: reads a
//! reference image produced by the real mkfs.ubifs (see
//! `tests/mkfs-parity.sh`, which runs mtd-utils in docker), extracts
//! the tree, restores the readdir order of the children from the order
//! of the dent nodes on flash, rebuilds and writes our image. The
//! byte-for-byte comparison is done by the script.
//!
//! Usage: parity_build <ref.ubifs> <out.ubifs> <min_io> <leb_size>
//!                    <max_leb_cnt> <journal-bytes|default>

use std::collections::HashMap;

use ubifs::media::*;
use ubifs::mkfs::{self, Options};
use ubifs::reader::Ubifs;
use ubifs::tree::{Inode, Kind};

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

    // Per-parent child order: the order of the dent nodes on flash (=
    // the mkfs write order = the readdir order of the source tree).
    let mut child_order: HashMap<u32, Vec<String>> = Default::default();
    for leb in lebs.iter().flatten() {
        let mut pos = 0usize;
        while pos + UBIFS_CH_SZ <= leb.len() {
            let magic = u32::from_le_bytes(leb[pos..pos + 4].try_into().unwrap());
            if magic != UBIFS_NODE_MAGIC {
                break;
            }
            let len = u32::from_le_bytes(leb[pos + 16..pos + 20].try_into().unwrap()) as usize;
            if leb[pos + 20] == UBIFS_DENT_NODE {
                if let Ok(dent) = DentNode::parse(&leb[pos..pos + len]) {
                    child_order
                        .entry(dent.key.inum)
                        .or_default()
                        .push(String::from_utf8_lossy(&dent.name).into_owned());
                }
            }
            pos += len.div_ceil(8) * 8;
        }
    }

    let fs = Ubifs::new(lebs).unwrap();
    let mut tree = fs.extract().unwrap();
    reorder(&fs, &mut tree, UBIFS_ROOT_INO, &child_order);

    let mut opts = Options::new(min_io, leb_size, max_leb_cnt);
    opts.max_bud_bytes = journal;
    let image = mkfs::mkfs(&tree, &opts).unwrap();
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

/// Reorder the children of every directory to follow the on-flash dent
/// node order.
fn reorder(fs: &Ubifs, ino: &mut Inode, dir_inum: u32, order: &HashMap<u32, Vec<String>>) {
    let Kind::Dir(children) = &mut ino.kind else {
        return;
    };
    let want = order.get(&dir_inum).cloned().unwrap_or_default();
    children.sort_by_key(|(name, _)| want.iter().position(|n| n == name).unwrap_or(usize::MAX));
    for (name, child) in children.iter_mut() {
        let path = if dir_inum == UBIFS_ROOT_INO {
            format!("/{name}")
        } else {
            match path_of(fs, dir_inum, name) {
                Some(p) => p,
                None => continue,
            }
        };
        if let Some(inum) = fs.lookup(&path).unwrap() {
            reorder(fs, child, inum, order);
        }
    }
}

/// The path `…/name` inside directory `dir_inum` (a search from the
/// root).
fn path_of(fs: &Ubifs, dir_inum: u32, name: &str) -> Option<String> {
    fn walk(fs: &Ubifs, inum: u32, prefix: &str, target: u32) -> Option<String> {
        for d in fs.dir_entries(inum).ok()? {
            let path = format!("{prefix}/{}", d.name);
            if d.inum == target {
                return Some(path);
            }
            if d.itype == UBIFS_ITYPE_DIR {
                if let Some(p) = walk(fs, d.inum, &path, target) {
                    return Some(p);
                }
            }
        }
        None
    }
    walk(fs, UBIFS_ROOT_INO, "", dir_inum).map(|base| format!("{base}/{name}"))
}
