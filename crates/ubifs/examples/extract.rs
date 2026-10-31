//! Extract a UBIFS image to a directory on the host filesystem.
//!
//! Accepts either a raw `.ubifs` LEB stream or a full UBI partition
//! dump (for dumps `--peb`/`--min-io` describe the flash geometry).
//!
//! Usage: extract [options] <image> <outdir>
//!   --volume <ID>    UBI volume id (dumps only, default 0)
//!   --peb <BYTES>    PEB size for UBI dumps (e.g. 131072)
//!   --min-io <BYTES> min I/O size for UBI dumps (default 2048)
//!
//! Regular files, directories and symlinks are written with their
//! original modes; device nodes, FIFOs and sockets are reported and
//! skipped (creating them needs privileges).

use std::path::Path;

use ubifs::reader::Ubifs;
use ubifs::tree::{Inode, Kind};
use ubifs::ubi::{Dump, UbiGeometry};

fn main() {
    let mut volume: u32 = 0;
    let mut peb: Option<u32> = None;
    let mut min_io: u32 = 2048;
    let mut pos: Vec<String> = vec![];

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--volume" => volume = value(&args, &mut i).parse().unwrap_or_else(|_| usage()),
            "--peb" => peb = Some(value(&args, &mut i).parse().unwrap_or_else(|_| usage())),
            "--min-io" => min_io = value(&args, &mut i).parse().unwrap_or_else(|_| usage()),
            a if a.starts_with("--") => usage(),
            a => pos.push(a.to_string()),
        }
        i += 1;
    }
    if pos.len() != 2 {
        usage();
    }
    let (image, outdir) = (pos[0].clone(), pos[1].clone());

    let lebs = open_image(&image, volume, peb, min_io);
    let fs = Ubifs::new(lebs).unwrap_or_else(|e| die(&format!("cannot open {image}: {e}")));
    let tree = fs
        .extract()
        .unwrap_or_else(|e| die(&format!("cannot extract {image}: {e}")));
    let out = Path::new(&outdir);
    std::fs::create_dir_all(out).unwrap();
    let written = write_tree(out, &tree);
    println!("extracted {} entries to {}", written, out.display());
}

fn value(args: &[String], i: &mut usize) -> String {
    *i += 1;
    args.get(*i).cloned().unwrap_or_else(|| usage())
}

fn usage() -> ! {
    eprintln!("usage: extract [--volume ID] [--peb BYTES] [--min-io BYTES] <image> <outdir>");
    std::process::exit(2);
}

fn die(msg: &str) -> ! {
    eprintln!("extract: {msg}");
    std::process::exit(1);
}

/// Split the image into volume LEBs: a raw `.ubifs` stream is
/// self-describing (the SB carries the LEB size); a UBI dump needs the
/// flash geometry.
fn open_image(path: &str, volume: u32, peb: Option<u32>, min_io: u32) -> Vec<Option<Vec<u8>>> {
    let raw = std::fs::read(path).unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
    let looks_like_ubi = raw.len() >= 4 && &raw[0..4] == b"UBI#";
    if looks_like_ubi {
        let Some(peb) = peb else {
            die("a UBI dump needs --peb <bytes>");
        };
        let geom = UbiGeometry::from_peb_size(peb, min_io);
        let dump = Dump::parse(&raw, geom).unwrap_or_else(|e| die(&format!("{e}")));
        dump.volume_lebs(volume)
    } else {
        // A raw .ubifs stream: the LEB size comes from the superblock.
        let (sb_node, _) = ubifs::media::parse_node(&raw, raw.len(), "superblock")
            .unwrap_or_else(|e| die(&format!("{e}")));
        let sb = ubifs::media::Superblock::parse(sb_node).unwrap();
        raw.chunks(sb.leb_size as usize)
            .map(|c| Some(c.to_vec()))
            .collect()
    }
}

fn write_tree(dir: &Path, ino: &Inode) -> usize {
    let Kind::Dir(children) = &ino.kind else {
        return 0;
    };
    let mut count = 0usize;
    for (name, child) in children {
        let path = dir.join(name);
        count += 1;
        match &child.kind {
            Kind::Dir(_) => {
                std::fs::create_dir_all(&path).unwrap();
                set_mode(&path, child.mode);
                count += write_tree(&path, child);
            }
            Kind::File(data) => {
                std::fs::write(&path, data).unwrap();
                set_mode(&path, child.mode);
            }
            Kind::Symlink(target) => {
                let target = String::from_utf8_lossy(target).into_owned();
                #[cfg(unix)]
                std::os::unix::fs::symlink(&target, &path).unwrap();
                #[cfg(not(unix))]
                eprintln!("symlink {name} -> {target} skipped (not unix)");
            }
            Kind::Dev { rdev } => {
                eprintln!("skipped device node {name} (rdev {rdev})");
            }
            Kind::Fifo => eprintln!("skipped fifo {name}"),
            Kind::Socket => eprintln!("skipped socket {name}"),
        }
    }
    count
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777));
}
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}
