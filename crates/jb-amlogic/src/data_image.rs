//! The A113X data-partition image builder. On the Mini the data
//! partition is UBI with one UBIFS volume (the overlayfs upper layer
//! source), so the overlay is applied by repacking the filesystem with
//! the `ubifs` crate: open the capture (journal replay included),
//! extract the tree, inject the overlay files, mkfs the tree back with
//! the stock parameters and wrap it into a UBI image again.
//!
//! The rebuilt image is EXACTLY the partition size (the logical
//! capacity `store size` reports at write time): the UBI part carries
//! the filesystem, the tail is free PEBs (an EC header + 0xFF — the
//! state ubiformat leaves). The volume is created with the autoresize
//! flag, so the kernel expands the filesystem over the free PEBs at
//! first attach — the standard `mkfs.ubifs -c` + `ubimkvol -m` flow;
//! the mount path takes the volume size, not the superblock's
//! `leb_cnt` (fs/ubifs/super.c: `c->leb_cnt = c->vi.size`).

use anyhow::{anyhow, ensure, Context, Result};
use jb_core::overlay::{OverlayFile, LAYOUT_DIRS};
use jb_core::progress::{Progress, ProgressFn};
use std::path::Path;
use ubifs::media::Superblock;
use ubifs::mkfs;
use ubifs::reader::Ubifs;
use ubifs::tree::{Inode, Kind};
use ubifs::ubi::{Dump, EcHeader, UbiGeometry, UBI_EC_HDR_SIZE};
use ubifs::ubinize;
use ubifs::Compr;

/// NAND geometry of the Mini: a PEB is 64 pages of 2 KiB (+64 B OOB).
const PEB_SIZE: u32 = 128 * 1024;
const MIN_IO_SIZE: u32 = 2048;
/// The LEB-count ceiling of the stock data volume (its mkfs `-c`): the
/// kernel sizes the LPT from it and grows the filesystem up to it.
const MAX_LEB_CNT: u32 = 2212;
/// The stock volume name (the kernel mounts by id; the name is kept
/// for the tools).
const VOLUME_NAME: &str = "data";

#[derive(Debug, thiserror::Error)]
pub enum DataImageError {
    /// The capture did not parse as UBI/UBIFS — raw or unknown format.
    #[error("захват data не читается как UBI/UBIFS: {0}.\n  если раздел не читается — запустите с --format-userdata")]
    NotUbifs(String),
    #[error("UBI-образ раздела ({0} байт) не влезает в ёмкость {1}")]
    TooBig(u64, u64),
    #[error(transparent)]
    Ubifs(#[from] ubifs::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Build the data partition image: EXACTLY `capacity` bytes, patching
/// the `base` capture when given, from scratch otherwise. The result
/// is verified by re-reading it before the writer picks it up.
pub fn build_image(
    base: Option<&Path>,
    out: &Path,
    capacity: u64,
    files: &[OverlayFile],
    progress: ProgressFn,
) -> Result<()> {
    ensure!(
        capacity > 0 && capacity % PEB_SIZE as u64 == 0,
        "ёмкость раздела не кратна PEB ({capacity} байт)"
    );
    if let Some(dump) = base {
        if let (Ok(a), Ok(b)) = (std::fs::canonicalize(dump), std::fs::canonicalize(out)) {
            ensure!(
                a != b,
                "пути захвата и результата совпадают — захват не модифицируется"
            );
        }
    }
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let (geom, leb_size) = ubinize::Options::new(PEB_SIZE, MIN_IO_SIZE)
        .geometry()
        .context("геометрия UBI платформы")?;
    let dump_geom = UbiGeometry::from_peb_size(PEB_SIZE, MIN_IO_SIZE);

    // The filesystem: patched out of the capture (its own superblock is
    // the source of the parameters), or built fresh from the profile.
    // The tree is a walk::Plan so that hard links in the capture
    // survive the repack.
    let (mut plan, opts, ec, image_seq) = match base {
        Some(dump) => {
            progress(Progress::Step(format!(
                "data: читаю захват {}",
                dump.display()
            )));
            let raw = std::fs::read(dump)
                .with_context(|| format!("чтение захвата {}", dump.display()))?;
            let dump = Dump::parse(&raw, dump_geom)
                .map_err(|e| DataImageError::NotUbifs(e.to_string()))?;
            let lebs = dump.volume_lebs(0);
            // The superblock is parsed directly (the strict open may be
            // skipped by the fsck fallback below).
            let sb = {
                let leb0 = lebs.first().and_then(|l| l.as_ref()).ok_or_else(|| {
                    DataImageError::NotUbifs("leb 0 (superblock) is unmapped".into())
                })?;
                let (node, _) = ubifs::media::parse_node(leb0, leb0.len(), "superblock")
                    .map_err(|e| DataImageError::NotUbifs(e.to_string()))?;
                Superblock::parse(node).map_err(|e| DataImageError::NotUbifs(e.to_string()))?
            };
            ensure!(
                sb.min_io_size == MIN_IO_SIZE && sb.leb_size == leb_size,
                "геометрия захвата (min_io {}, LEB {}) не совпадает с платформой \
                 (min_io {MIN_IO_SIZE}, LEB {leb_size})",
                sb.min_io_size,
                sb.leb_size
            );
            let mut opts = mkfs::Options::new(sb.min_io_size, sb.leb_size, sb.max_leb_cnt);
            opts.log_lebs = Some(sb.log_lebs);
            opts.orph_lebs = sb.orph_lebs;
            opts.fanout = sb.fanout;
            opts.lsave_cnt = sb.lsave_cnt;
            opts.max_bud_bytes = Some(sb.max_bud_bytes);
            opts.default_compr = compr(sb.default_compr)?;
            opts.uuid = sb.uuid;
            opts.fmt_version = sb.fmt_version;
            let (max_ec, image_seq) = scan_ec(&raw, &dump_geom);
            // Strict open first; on a broken index — the fsck rebuild
            // (the official fsck.ubifs -y -b salvage: scan without the
            // index, holes become zeros, unreachable files are deleted).
            let plan = match Ubifs::new(lebs.clone()) {
                Ok(fs) => ubifs::walk::Plan::from_tree(fs.extract()?),
                Err(e) => {
                    progress(Progress::Step(format!(
                        "data: индекс тома не читается ({e}) — восстановление fsck"
                    )));
                    let (plan, report) = ubifs::fsck::rebuild(&lebs)
                        .map_err(|e| DataImageError::NotUbifs(format!("fsck: {e}")))?;
                    progress(Progress::Step(format!(
                        "fsck: узлов {} (мусора {}, невалидных {})",
                        report.nodes_scanned, report.garbage_nodes, report.invalid_nodes
                    )));
                    for p in report.dropped_zero_nlink_files.iter().take(20) {
                        log::warn!("fsck: файл удалён (nlink 0 в захвате): {p}");
                    }
                    if report.dropped_unreachable_inos > 0 {
                        log::warn!(
                            "fsck: удалено недостижимых файлов: {} \
                             (их денты не восстановились — официальное \
                             поведение rebuild без lost+found)",
                            report.dropped_unreachable_inos
                        );
                    }
                    if report.dropped_xattrs > 0 {
                        log::warn!("fsck: отброшено xattr-записей: {}", report.dropped_xattrs);
                    }
                    if report.stale_blocks_dropped > 0 {
                        log::warn!(
                            "fsck: отброшено устаревших блоков (усечение): {}",
                            report.stale_blocks_dropped
                        );
                    }
                    if report.zero_filled_blocks > 0 {
                        log::warn!(
                            "fsck: блоков восстановлено нулями (дыры): {}",
                            report.zero_filled_blocks
                        );
                    }
                    if report.root_created {
                        log::warn!(
                            "fsck: корневого inode не было — создана пустая ФС, \
                             содержимое захвата потеряно"
                        );
                    }
                    plan
                }
            };
            (plan, opts, max_ec + 1, image_seq)
        }
        None => {
            progress(Progress::Step(format!(
                "data: чистый ubifs на {capacity} байт"
            )));
            let mut opts = mkfs::Options::new(MIN_IO_SIZE, leb_size, MAX_LEB_CNT);
            // the layout parameters of the stock data volume
            opts.log_lebs = Some(5);
            opts.orph_lebs = 1;
            opts.default_compr = Compr::Lzo;
            (ubifs::walk::Plan::from_tree(fresh_tree()?), opts, 1, 0)
        }
    };
    for f in files {
        inject(&mut plan.root, f, progress)?;
    }
    let image = mkfs::mkfs_plan(&plan, &opts).context("сборка UBIFS")?;
    let lebs = image.to_vec();

    // One dynamic autoresize volume, the stock name: at attach the
    // kernel grows it over every free PEB of the partition.
    let volume = ubinize::Volume {
        vol_type: ubinize::VolType::Dynamic,
        vol_id: 0,
        vol_name: VOLUME_NAME.to_string(),
        vol_alignment: 1,
        vol_flags: Some(ubinize::VolFlags::Autoresize),
        image: Some(lebs),
        bytes: image.geometry.leb_cnt as u64 * leb_size as u64,
    };
    let ubi = ubinize::build_image(&ubinize::Options::new(PEB_SIZE, MIN_IO_SIZE), &[volume])?;
    ensure!(
        ubi.len() as u64 <= capacity,
        DataImageError::TooBig(ubi.len() as u64, capacity)
    );

    // The tail: free PEBs (an EC header + 0xFF), continuing the capture's
    // counters. The image is exactly the partition size.
    let header = EcHeader {
        ec,
        vid_hdr_offset: geom.vid_hdr_offset,
        data_offset: geom.data_offset,
        image_seq,
    }
    .to_bytes();
    let mut out_bytes = ubi;
    while (out_bytes.len() as u64) < capacity {
        out_bytes.extend_from_slice(&header);
        out_bytes.extend(std::iter::repeat(0xFF).take((PEB_SIZE as usize) - UBI_EC_HDR_SIZE));
    }
    debug_assert_eq!(out_bytes.len() as u64, capacity);
    std::fs::write(out, &out_bytes)?;

    // Self-check: re-read from disk and verify the overlay survived.
    let raw = std::fs::read(out)?;
    let dump = Dump::parse(&raw, dump_geom).map_err(|e| DataImageError::NotUbifs(e.to_string()))?;
    let fs =
        Ubifs::new(dump.volume_lebs(0)).map_err(|e| DataImageError::NotUbifs(e.to_string()))?;
    fs.verify()?;
    for f in files {
        let inum = fs
            .lookup(&f.path)
            .map_err(|e| DataImageError::NotUbifs(e.to_string()))?
            .with_context(|| format!("{} не найден в собранном образе", f.path))?;
        let content = fs.read_file(inum, f.data.len() as u64)?;
        ensure!(content == f.data, "{} не совпал после сборки", f.path);
        let ino = fs
            .ino_node(inum)?
            .with_context(|| format!("{}: нет inode в собранном образе", f.path))?;
        ensure!(
            ino.mode & 0o7777 == f.mode & 0o7777,
            "{}: права не совпали после сборки",
            f.path
        );
    }
    progress(Progress::Step("data: проверка пройдена".into()));
    Ok(())
}

/// The UBIFS compression algorithm by its on-flash code.
fn compr(code: u16) -> Result<Compr> {
    match code {
        0 => Ok(Compr::None),
        1 => Ok(Compr::Lzo),
        2 => Ok(Compr::Zlib),
        other => Err(anyhow!("компрессия {other} в захвате не поддерживается")),
    }
}

/// The largest EC counter and the image sequence number of the capture
/// — the rebuilt PEBs continue the counters instead of resetting them.
fn scan_ec(raw: &[u8], geom: &UbiGeometry) -> (u64, u32) {
    let mut max_ec = 0u64;
    let mut image_seq = 0u32;
    for base in (0..raw.len()).step_by(geom.peb_size as usize) {
        if let Ok(h) = EcHeader::parse(&raw[base..]) {
            max_ec = max_ec.max(h.ec);
            if image_seq == 0 {
                image_seq = h.image_seq;
            }
        }
    }
    (max_ec, image_seq)
}

/// An empty root for a fresh filesystem: the directories the stock boot
/// scripts expect (the overlayfs workdir must EXIST and be empty).
fn fresh_tree() -> Result<Inode> {
    let mut root = Inode::dir(0o755, vec![]);
    for dir in LAYOUT_DIRS {
        let comps: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
        dir_at(&mut root, &comps)?;
    }
    Ok(root)
}

/// Walk (creating, mode 0755, as the ext4 builder does) to the directory
/// at `comps` below `node`.
fn dir_at<'a>(node: &'a mut Inode, comps: &[&str]) -> Result<&'a mut Inode> {
    let mut node = node;
    for name in comps {
        if !matches!(node.kind, Kind::Dir(_)) {
            return Err(anyhow!("путь overlay: {name} — не каталог"));
        }
        let Kind::Dir(children) = &mut node.kind else {
            unreachable!("checked above");
        };
        let idx = match children.iter().position(|(n, _)| n == name) {
            Some(i) => i,
            None => {
                children.push((name.to_string(), Inode::dir(0o755, vec![])));
                children.len() - 1
            }
        };
        node = &mut children[idx].1;
    }
    Ok(node)
}

/// Insert or replace one overlay file in the tree: create the missing
/// parents, rewrite the content, keep the mode (the owner is root —
/// the same as the ext4 builder's set_owner(0, 0)).
fn inject(root: &mut Inode, f: &OverlayFile, progress: ProgressFn) -> Result<()> {
    let comps: Vec<&str> = f.path.split('/').filter(|s| !s.is_empty()).collect();
    let (name, dirs) = comps.split_last().context("пустой путь overlay-файла")?;
    let dir = dir_at(root, dirs)?;
    let file = Inode::file(f.mode & 0o7777, f.data.clone());
    let Kind::Dir(children) = &mut dir.kind else {
        unreachable!("dir_at returns a directory");
    };
    match children.iter_mut().find(|(n, _)| n == name) {
        Some(slot) => slot.1 = file,
        None => children.push((name.to_string(), file)),
    }
    progress(Progress::Step(format!(
        "data: {} ({} байт, права {:o})",
        f.path,
        f.data.len(),
        f.mode
    )));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Test capacity: 20 PEBs — enough for a small mkfs (up to
    /// MAX_LEB_CNT of the synthetic base) plus the layout volume.
    const CAPACITY: u64 = 20 * PEB_SIZE as u64;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("jb-data-image-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn files() -> Vec<OverlayFile> {
        vec![
            OverlayFile {
                path: "/overlay/upper/usr/bin/adbd".into(),
                data: (0..50_000u32).map(|i| (i % 251) as u8).collect(),
                mode: 0o755,
            },
            OverlayFile {
                path: "/overlay/upper/etc/init.d/.usb_config".into(),
                data: b"usb_adb_en\n".to_vec(),
                mode: 0o644,
            },
            OverlayFile {
                path: "/overlay/upper/etc/jailbreak".into(),
                data: b"test-marker\n".to_vec(),
                mode: 0o644,
            },
        ]
    }

    fn quiet(_ev: Progress) {}

    /// A stock-like capture: one data volume with a small tree (the
    /// overlay dirs already in place), built with the platform
    /// geometry, padded to the test capacity.
    fn synthetic_base(dir: &Path) -> PathBuf {
        let (geom, leb_size) = ubinize::Options::new(PEB_SIZE, MIN_IO_SIZE)
            .geometry()
            .unwrap();
        let mut opts = mkfs::Options::new(MIN_IO_SIZE, leb_size, 64);
        opts.default_compr = Compr::Lzo;
        opts.log_lebs = Some(5);
        opts.orph_lebs = 1;
        let root = Inode::dir(
            0o755,
            vec![
                (
                    "voice-agent".into(),
                    Inode::dir(
                        0o755,
                        vec![(
                            "session.json".into(),
                            Inode::file(0o600, b"{\"state\": 1}".to_vec()),
                        )],
                    ),
                ),
                (
                    "overlay".into(),
                    Inode::dir(
                        0o755,
                        vec![
                            ("upper".into(), Inode::dir(0o755, vec![])),
                            ("work".into(), Inode::dir(0o755, vec![])),
                        ],
                    ),
                ),
            ],
        );
        let image = mkfs::mkfs(&root, &opts).unwrap();
        let volume = ubinize::Volume {
            vol_type: ubinize::VolType::Dynamic,
            vol_id: 0,
            vol_name: VOLUME_NAME.into(),
            vol_alignment: 1,
            vol_flags: None,
            image: Some(image.to_vec()),
            bytes: image.geometry.leb_cnt as u64 * leb_size as u64,
        };
        let mut raw =
            ubinize::build_image(&ubinize::Options::new(PEB_SIZE, MIN_IO_SIZE), &[volume]).unwrap();
        let header = EcHeader {
            ec: 1,
            vid_hdr_offset: geom.vid_hdr_offset,
            data_offset: geom.data_offset,
            image_seq: 0,
        }
        .to_bytes();
        while (raw.len() as u64) < CAPACITY {
            raw.extend_from_slice(&header);
            raw.extend(std::iter::repeat(0xFF).take((PEB_SIZE as usize) - UBI_EC_HDR_SIZE));
        }
        let path = dir.join("capture-data.bin");
        std::fs::write(&path, &raw).unwrap();
        path
    }

    /// Open a built image read-only: (fs, ) for content assertions.
    fn open_image(path: &Path) -> Ubifs {
        let raw = std::fs::read(path).unwrap();
        let geom = UbiGeometry::from_peb_size(PEB_SIZE, MIN_IO_SIZE);
        let dump = Dump::parse(&raw, geom).unwrap();
        Ubifs::new(dump.volume_lebs(0)).unwrap()
    }

    fn assert_overlay(fs: &Ubifs) {
        for f in files() {
            let inum = fs.lookup(&f.path).unwrap().expect("overlay file present");
            let content = fs.read_file(inum, f.data.len() as u64).unwrap();
            assert_eq!(content, f.data, "{}", f.path);
            let ino = fs.ino_node(inum).unwrap().unwrap();
            assert_eq!(ino.mode & 0o7777, f.mode, "{}", f.path);
        }
    }

    fn assert_layout_dirs(fs: &Ubifs) {
        for dir in LAYOUT_DIRS {
            let inum = fs.lookup(dir).unwrap().expect("layout dir present");
            let ino = fs.ino_node(inum).unwrap().unwrap();
            assert_eq!(ino.mode & 0o170000, 0o040000, "{dir} is a directory");
        }
    }

    #[test]
    fn patch_keeps_stock_content_and_exact_size() {
        let d = tmpdir("patch");
        let base = synthetic_base(&d);
        let out = d.join("userdata.img");
        build_image(Some(&base), &out, CAPACITY, &files(), &quiet).unwrap();
        assert_eq!(std::fs::metadata(&out).unwrap().len(), CAPACITY);
        let fs = open_image(&out);
        fs.verify().unwrap();
        assert_overlay(&fs);
        // the stock tree survived the repack
        let stock = b"{\"state\": 1}".to_vec();
        let inum = fs.lookup("/voice-agent/session.json").unwrap().unwrap();
        assert_eq!(fs.read_file(inum, stock.len() as u64).unwrap(), stock);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn broken_index_capture_is_salvaged_by_fsck() {
        let d = tmpdir("fsck");
        let base = synthetic_base(&d);
        // blank the root index LEB: the strict open refuses, the
        // fsck-rebuild fallback recovers the tree from the scan
        let mut raw = std::fs::read(&base).unwrap();
        let lebs = Dump::parse(&raw, UbiGeometry::from_peb_size(PEB_SIZE, MIN_IO_SIZE))
            .unwrap()
            .volume_lebs(0);
        let l1 = lebs[1].as_ref().unwrap();
        let (node, _) = ubifs::media::parse_node(l1, l1.len(), "master").unwrap();
        let mst = ubifs::media::Master::parse(node).unwrap();
        let idx = lebs[mst.root_lnum as usize].as_ref().unwrap().clone();
        let at = raw
            .windows(idx.len())
            .position(|w| w == idx.as_slice())
            .expect("the index LEB is in the dump");
        raw[at..at + idx.len()].fill(0xFF);
        let broken = d.join("capture-broken.bin");
        std::fs::write(&broken, &raw).unwrap();

        let out = d.join("userdata.img");
        build_image(Some(&broken), &out, CAPACITY, &files(), &quiet).unwrap();
        assert_eq!(std::fs::metadata(&out).unwrap().len(), CAPACITY);
        let fs = open_image(&out);
        fs.verify().unwrap();
        assert_overlay(&fs);
        // the whole stock tree survived the salvage
        let stock = b"{\"state\": 1}".to_vec();
        let inum = fs.lookup("/voice-agent/session.json").unwrap().unwrap();
        assert_eq!(fs.read_file(inum, stock.len() as u64).unwrap(), stock);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn fresh_build_has_the_layout_dirs_and_exact_size() {
        let d = tmpdir("fresh");
        let out = d.join("userdata.img");
        build_image(None, &out, CAPACITY, &files(), &quiet).unwrap();
        assert_eq!(std::fs::metadata(&out).unwrap().len(), CAPACITY);
        let fs = open_image(&out);
        fs.verify().unwrap();
        assert_overlay(&fs);
        assert_layout_dirs(&fs);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn repacking_a_built_image_is_idempotent() {
        let d = tmpdir("repatch");
        let first = d.join("first.img");
        build_image(None, &first, CAPACITY, &files(), &quiet).unwrap();
        let second = d.join("second.img");
        build_image(Some(&first), &second, CAPACITY, &files(), &quiet).unwrap();
        assert_eq!(std::fs::metadata(&second).unwrap().len(), CAPACITY);
        assert_overlay(&open_image(&second));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn garbage_base_is_rejected_with_a_hint() {
        let d = tmpdir("garbage");
        let base = d.join("capture.bin");
        std::fs::write(&base, vec![0xffu8; 2 * PEB_SIZE as usize]).unwrap();
        let out = d.join("userdata.img");
        let err = build_image(Some(&base), &out, CAPACITY, &files(), &quiet)
            .expect_err("a garbage capture must be rejected");
        assert!(err.to_string().contains("--format-userdata"), "{err}");
        assert!(!out.exists(), "nothing is written on rejection");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn capacity_must_be_a_whole_number_of_pebs() {
        let d = tmpdir("capacity");
        let out = d.join("userdata.img");
        let err = build_image(None, &out, CAPACITY + 512, &files(), &quiet)
            .expect_err("a page-multiple-but-not-PEB capacity must be rejected");
        assert!(err.to_string().contains("PEB"), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
