//! A command-line ubinize equivalent: build a UBI image from an ini
//! configuration.
//!
//! Usage: ubinize -o <out.img> -p <peb-size> -m <min-io-size> [options]
//!                <config.ini>
//!   -s <bytes>      sub-page size (default: min-io-size)
//!   -O <offset>     VID header offset (default: aligned EC header size)
//!   -e <num>        erase counter value (default 0)
//!   -x <num>        UBI version (default 1)
//!   -Q <num>        image sequence number (default 0; ubinize rolls a
//!                   random one)

use std::collections::HashMap;

use ubifs::ubinize;

fn main() {
    let mut out_path = String::new();
    let mut peb = 0u32;
    let mut min_io = 0u32;
    let mut sub_page: Option<u32> = None;
    let mut vid_offs: Option<u32> = None;
    let mut ec = 0u64;
    let mut ubi_ver = 1u8;
    let mut image_seq = 0u32;
    let mut cfg_path = String::new();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" => out_path = value(&args, &mut i),
            "-p" => peb = num(&args, &mut i),
            "-m" => min_io = num(&args, &mut i),
            "-s" => sub_page = Some(num(&args, &mut i)),
            "-O" => vid_offs = Some(num(&args, &mut i)),
            "-e" => ec = num(&args, &mut i) as u64,
            "-x" => ubi_ver = num(&args, &mut i) as u8,
            "-Q" => image_seq = num(&args, &mut i),
            a if a.starts_with('-') => usage(),
            a => cfg_path = a.to_string(),
        }
        i += 1;
    }
    if out_path.is_empty() || peb == 0 || min_io == 0 || cfg_path.is_empty() {
        usage();
    }

    let text = std::fs::read_to_string(&cfg_path).unwrap();
    let ini = ubinize::parse_config(&text).unwrap_or_else(|e| die(&format!("{e}")));
    let mut images: HashMap<String, Vec<u8>> = HashMap::new();
    let mut vols = Vec::new();
    for v in ini {
        let data = v
            .image
            .as_ref()
            .map(|p| std::fs::read(p).unwrap_or_else(|e| die(&format!("cannot read {p}: {e}"))));
        vols.push(ubinize::Volume::from_ini(v, data).unwrap_or_else(|e| die(&format!("{e}"))));
    }
    let opts = ubinize::Options {
        peb_size: peb,
        min_io_size: min_io,
        sub_page_size: sub_page,
        vid_hdr_offset: vid_offs,
        ec,
        ubi_ver,
        image_seq,
    };
    let img = ubinize::build_image(&opts, &vols).unwrap_or_else(|e| die(&format!("{e}")));
    std::fs::write(&out_path, img).unwrap();
    let _ = &mut images;
}

fn value(args: &[String], i: &mut usize) -> String {
    *i += 1;
    args.get(*i).cloned().unwrap_or_else(|| usage())
}

fn num(args: &[String], i: &mut usize) -> u32 {
    let v = value(args, i);
    if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).unwrap_or_else(|_| usage());
    }
    v.parse().unwrap_or_else(|_| {
        // Size suffixes, as ubinize accepts them (128KiB, 256KiB, ...).
        ubinize::parse_size(&v)
            .unwrap_or_else(|_| usage())
            .try_into()
            .unwrap_or_else(|_| usage())
    })
}

fn usage() -> ! {
    eprintln!(
        "usage: ubinize -o <out.img> -p <peb> -m <min-io> [-s sub] [-O vid-offs] \
         [-e ec] [-x ubi-ver] [-Q image-seq] <config.ini>"
    );
    std::process::exit(2);
}

fn die(msg: &str) -> ! {
    eprintln!("ubinize: {msg}");
    std::process::exit(1);
}
