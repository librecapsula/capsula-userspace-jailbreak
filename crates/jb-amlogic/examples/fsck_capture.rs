//! Rebuild a captured data partition through the fsck path WITHOUT
//! flashing: prints what the salvage recovers and what it loses, then
//! verifies the rebuilt filesystem with the strict reader.
//!
//!   cargo run -p jb-amlogic --example fsck_capture -- <capture.bin> [out.img]

use anyhow::Context;
use jb_amlogic::data_image::build_image;
use jb_core::overlay::overlay_files;
use jb_core::progress::Progress;
use std::path::Path;
use ubifs::reader::Ubifs;
use ubifs::ubi::{Dump, UbiGeometry};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(capture) = args.next() else {
        anyhow::bail!("usage: fsck_capture <capture.bin> [out.img]");
    };
    let out = args.next().unwrap_or_else(|| "/tmp/fsck-data.bin".into());
    let capacity = std::fs::metadata(&capture)?.len();

    let progress = |ev: Progress| {
        if let Progress::Step(msg) = ev {
            println!("{msg}");
        }
    };
    build_image(
        Some(Path::new(&capture)),
        Path::new(&out),
        capacity,
        &overlay_files(format!("capsula-jb fsck {}\n", std::process::id())),
        &progress,
    )
    .context("сборка патченного образа")?;
    println!(
        "образ собран: {out} ({} байт)",
        std::fs::metadata(&out)?.len()
    );

    // strict re-read of the result: the repaired volume must open
    let raw = std::fs::read(&out)?;
    let dump = Dump::parse(&raw, UbiGeometry::from_peb_size(128 * 1024, 2048))?;
    let fs = Ubifs::new(dump.volume_lebs(0))?;
    fs.verify()?;
    println!("строгая проверка собранного образа: ok");
    Ok(())
}
