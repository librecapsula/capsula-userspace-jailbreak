//! Inspect a UBI image/dump and the UBIFS volume inside it — a rough
//! offline equivalent of `ubinfo` plus a superblock/master summary.
//!
//! Usage: ubinfo [options] <image>
//!   --volume <ID>    UBI volume id to open as UBIFS (default: first)
//!   --peb <BYTES>    PEB size for UBI dumps (e.g. 131072)
//!   --min-io <BYTES> min I/O size for UBI dumps (default 2048)

use ubifs::reader::Ubifs;
use ubifs::ubi::{Dump, UbiGeometry};

fn main() {
    let mut volume: Option<u32> = None;
    let mut peb: Option<u32> = None;
    let mut min_io: u32 = 2048;
    let mut pos: Vec<String> = vec![];

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--volume" => volume = Some(value(&args, &mut i).parse().unwrap_or_else(|_| usage())),
            "--peb" => peb = Some(value(&args, &mut i).parse().unwrap_or_else(|_| usage())),
            "--min-io" => min_io = value(&args, &mut i).parse().unwrap_or_else(|_| usage()),
            a if a.starts_with("--") => usage(),
            a => pos.push(a.to_string()),
        }
        i += 1;
    }
    let [image] = pos.as_slice() else { usage() };

    let raw = std::fs::read(image).unwrap_or_else(|e| die(&format!("cannot read {image}: {e}")));
    let looks_like_ubi = raw.len() >= 4 && &raw[0..4] == b"UBI#";
    if !looks_like_ubi {
        println!("{image}: raw .ubifs LEB stream");
        let lebs: Vec<Option<Vec<u8>>> = raw_lebs(&raw).into_iter().map(Some).collect();
        print_ubifs(&lebs);
        return;
    }

    let Some(peb) = peb else {
        die("a UBI dump needs --peb <bytes>")
    };
    let geom = UbiGeometry::from_peb_size(peb, min_io);
    println!(
        "{image}: UBI image, PEB {peb}, vid @{}, data @{}",
        geom.vid_hdr_offset, geom.data_offset
    );
    let dump = Dump::parse(&raw, geom).unwrap_or_else(|e| die(&format!("{e}")));
    println!("PEBs: {}", raw.len() / peb as usize);
    for (id, name, vol_type) in dump.volumes() {
        let ty = if vol_type == ubifs::ubi::UBI_VID_STATIC {
            "static"
        } else {
            "dynamic"
        };
        println!(
            "volume {id}: \"{name}\" ({ty}, {} LEBs reserved)",
            dump.vtbl[id as usize].reserved_pebs
        );
    }
    let vol = volume.unwrap_or_else(|| dump.volumes().first().map(|v| v.0).unwrap_or(0));
    println!("opening volume {vol} as UBIFS…");
    print_ubifs(&dump.volume_lebs(vol));
}

fn value(args: &[String], i: &mut usize) -> String {
    *i += 1;
    args.get(*i).cloned().unwrap_or_else(|| usage())
}

fn usage() -> ! {
    eprintln!("usage: ubinfo [--volume ID] [--peb BYTES] [--min-io BYTES] <image>");
    std::process::exit(2);
}

fn die(msg: &str) -> ! {
    eprintln!("ubinfo: {msg}");
    std::process::exit(1);
}

fn raw_lebs(raw: &[u8]) -> Vec<Vec<u8>> {
    let (sb_node, _) = ubifs::media::parse_node(raw, raw.len(), "superblock")
        .unwrap_or_else(|e| die(&format!("{e}")));
    let sb = ubifs::media::Superblock::parse(sb_node).unwrap();
    raw.chunks(sb.leb_size as usize)
        .map(|c| c.to_vec())
        .collect()
}

fn print_ubifs(lebs: &[Option<Vec<u8>>]) {
    let fs = Ubifs::new(lebs.to_vec()).unwrap_or_else(|e| die(&format!("not a UBIFS volume: {e}")));
    let sb = &fs.superblock;
    let mst = &fs.master;
    println!("UBIFS: fmt {}, uuid {}", sb.fmt_version, hex(&sb.uuid));
    println!(
        "  min_io {}, leb_size {}, leb_cnt {}, max_leb_cnt {}",
        sb.min_io_size, sb.leb_size, mst.leb_cnt, sb.max_leb_cnt
    );
    println!(
        "  log {} lpt {} orph {} fanout {} jheads {} compr {}",
        sb.log_lebs,
        sb.lpt_lebs,
        sb.orph_lebs,
        sb.fanout,
        sb.jhead_cnt,
        match sb.default_compr {
            ubifs::media::UBIFS_COMPR_NONE => "none",
            ubifs::media::UBIFS_COMPR_LZO => "lzo",
            ubifs::media::UBIFS_COMPR_ZLIB => "zlib",
            ubifs::media::UBIFS_COMPR_ZSTD => "zstd",
            _ => "?",
        }
    );
    println!(
        "  commit {}, highest_inum {}, idx_lebs {}, index_size {}",
        mst.cmt_no, mst.highest_inum, mst.idx_lebs, mst.index_size
    );
    println!(
        "  space: free {}, dirty {}, used {}, dead {}, dark {}",
        mst.total_free, mst.total_dirty, mst.total_used, mst.total_dead, mst.total_dark
    );
    let leaves = fs.leaves().len();
    println!("  index leaves: {leaves}");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
