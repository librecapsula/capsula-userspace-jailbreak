//! Offline tests against the committed official-tools corpus
//! (`tests/data/`, produced by `tests/data/gen.sh` with the real
//! mkfs.ubifs v2.2.0 + xattr and ubinize 2.2.0).
//!
//! * every UBIFS image opens, verifies and extracts to exactly the
//!   fixture tree of `spec.tsv` (kinds, modes, owners, contents,
//!   symlink targets, device numbers, xattrs — with LZO/ZLIB/favor
//!   payloads exercising the real decompression paths);
//! * the `-x none` images rebuild byte-for-byte from
//!   `extract_plan` → `mkfs_plan` (offline byte parity, no docker);
//! * the UBI images parse with the volume table intact and their
//!   static volume CRCs verify.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ubifs::mkfs;
use ubifs::reader::Ubifs;
use ubifs::tree::{Inode, Kind};
use ubifs::ubi::{Dump, UbiGeometry};

// ---------------------------------------------------------------------------
// A tiny test-only SHA-256 (FIPS 180-4).
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bitlen = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

// ---------------------------------------------------------------------------
// Corpus loading.
// ---------------------------------------------------------------------------

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

/// Decompress a corpus image and check it against the manifest hash.
fn load_image(name: &str) -> Vec<u8> {
    let comp = std::fs::read(data_dir().join(format!("{name}.zlib")))
        .unwrap_or_else(|e| panic!("cannot read {name}.zlib (run tests/data/gen.sh): {e}"));
    let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&comp)
        .unwrap_or_else(|e| panic!("{name}: zlib decompress failed: {e:?}"));
    let want = manifest()
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("{name} is not in MANIFEST.tsv"));
    assert_eq!(sha256(&raw), want, "{name}: sha256 mismatch vs manifest");
    raw
}

fn manifest() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(data_dir().join("MANIFEST.tsv")).unwrap();
    let mut out = BTreeMap::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() >= 2 {
            out.insert(f[0].to_string(), f[1].to_string());
        }
    }
    out
}

struct SpecEntry {
    path: String,
    kind: &'static str,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    hash: String,
    target_or_rdev: String,
    xattrs: Vec<(String, String)>,
}

fn spec() -> Vec<SpecEntry> {
    let text = std::fs::read_to_string(data_dir().join("spec.tsv")).unwrap();
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        let kind: &'static str = match f[1] {
            "dir" => "dir",
            "reg" => "reg",
            "lnk" => "lnk",
            "chr" => "chr",
            "blk" => "blk",
            "fifo" => "fifo",
            "sock" => "sock",
            k => panic!("unknown spec kind {k}"),
        };
        let xattrs = if f[8].is_empty() {
            Vec::new()
        } else {
            f[8].split(';')
                .map(|kv| {
                    let (n, v) = kv.split_once('=').expect("xattr pair");
                    (n.to_string(), v.to_string())
                })
                .collect()
        };
        out.push(SpecEntry {
            path: f[0].to_string(),
            kind,
            mode: u32::from_str_radix(f[2], 8).unwrap(),
            uid: f[3].parse().unwrap(),
            gid: f[4].parse().unwrap(),
            size: f[5].parse().unwrap(),
            hash: f[6].to_string(),
            target_or_rdev: f[7].to_string(),
            xattrs,
        });
    }
    out
}

/// Flatten an extracted tree into path → &Inode.
fn flatten<'a>(ino: &'a Inode, path: String, out: &mut BTreeMap<String, &'a Inode>) {
    if let Kind::Dir(children) = &ino.kind {
        for (name, child) in children {
            let child_path = format!("{path}/{name}");
            out.insert(child_path.clone(), child);
            flatten(child, child_path, out);
        }
    }
}

fn kind_name(ino: &Inode) -> &'static str {
    match &ino.kind {
        Kind::Dir(_) => "dir",
        Kind::File(_) => "reg",
        Kind::Symlink(_) => "lnk",
        Kind::Dev { .. } => {
            if ino.mode & 0o170000 == 0o060000 {
                "blk"
            } else {
                "chr"
            }
        }
        Kind::Fifo => "fifo",
        Kind::Socket => "sock",
        Kind::Hardlink { .. } => "hardlink",
    }
}

// ---------------------------------------------------------------------------
// The tests.
// ---------------------------------------------------------------------------

const MKFS_IMAGES: &[&str] = &[
    "g1-none.ubifs",
    "g1-lzo.ubifs",
    "g1-zlib.ubifs",
    "g1-favor.ubifs",
    "g2-none.ubifs",
    "g2-zlib.ubifs",
    "g3-none.ubifs",
];

#[test]
fn official_images_extract_exactly_the_fixture_tree() {
    let spec = spec();
    for name in MKFS_IMAGES {
        let raw = load_image(name);
        let leb_size = u32::from_le_bytes(raw[36..40].try_into().unwrap()) as usize;
        let lebs: Vec<Option<Vec<u8>>> = raw.chunks(leb_size).map(|c| Some(c.to_vec())).collect();
        let fs = Ubifs::new(lebs).unwrap_or_else(|e| panic!("{name}: open failed: {e}"));
        fs.verify()
            .unwrap_or_else(|e| panic!("{name}: verify failed: {e}"));
        assert!(!fs.is_dirty(), "{name}: a fresh image must be clean");

        let tree = fs
            .extract()
            .unwrap_or_else(|e| panic!("{name}: extract failed: {e}"));
        let mut flat = BTreeMap::new();
        flatten(&tree, String::new(), &mut flat);

        // Every spec entry exists with the right kind, mode, owner and
        // content; no extra entries.
        for e in &spec {
            let node = flat
                .get(&e.path)
                .unwrap_or_else(|| panic!("{name}: {} missing", e.path));
            assert_eq!(kind_name(node), e.kind, "{name}: {} kind", e.path);
            assert_eq!(node.mode & 0o7777, e.mode, "{name}: {} mode", e.path);
            assert_eq!(node.uid, e.uid, "{name}: {} uid", e.path);
            assert_eq!(node.gid, e.gid, "{name}: {} gid", e.path);
            match (&node.kind, e.kind) {
                (Kind::File(data), "reg") => {
                    assert_eq!(data.len() as u64, e.size, "{name}: {} size", e.path);
                    assert_eq!(sha256(data), e.hash, "{name}: {} content", e.path);
                }
                (Kind::Symlink(t), "lnk") => {
                    assert_eq!(
                        String::from_utf8_lossy(t),
                        e.target_or_rdev,
                        "{name}: {} target",
                        e.path
                    );
                }
                (Kind::Dev { rdev }, "chr") | (Kind::Dev { rdev }, "blk") => {
                    let (maj, min): (u32, u32) = e
                        .target_or_rdev
                        .split_once(':')
                        .map(|(a, b)| (a.parse().unwrap(), b.parse().unwrap()))
                        .unwrap();
                    assert_eq!(
                        *rdev,
                        ubifs::devtable::makedev(maj, min),
                        "{name}: {} rdev",
                        e.path
                    );
                }
                _ => {}
            }
            // The reader returns xattrs in their original on-flash
            // (llistxattr) order; the spec lists them sorted.
            let mut got_x: Vec<(String, String)> = node
                .xattrs
                .iter()
                .map(|(n, v)| (n.clone(), String::from_utf8_lossy(v).into_owned()))
                .collect();
            got_x.sort();
            assert_eq!(got_x, e.xattrs, "{name}: {} xattrs", e.path);
        }
        assert_eq!(
            flat.len(),
            spec.len(),
            "{name}: extracted entry count mismatch"
        );
    }
}

#[test]
fn none_images_rebuild_byte_for_byte_offline() {
    for name in ["g1-none.ubifs", "g2-none.ubifs", "g3-none.ubifs"] {
        let raw = load_image(name);
        let leb_size = u32::from_le_bytes(raw[36..40].try_into().unwrap()) as usize;
        let lebs: Vec<Option<Vec<u8>>> = raw.chunks(leb_size).map(|c| Some(c.to_vec())).collect();
        let fs = Ubifs::new(lebs).unwrap();

        let plan = fs.extract_plan().unwrap();
        let sb = &fs.superblock;
        let mut opts = mkfs::Options::new(sb.min_io_size, sb.leb_size, sb.max_leb_cnt);
        opts.log_lebs = Some(sb.log_lebs);
        opts.orph_lebs = sb.orph_lebs;
        opts.fanout = sb.fanout;
        opts.max_bud_bytes = Some(sb.max_bud_bytes);
        opts.lsave_cnt = sb.lsave_cnt;
        opts.default_compr = ubifs::Compr::None;
        opts.uuid = sb.uuid;
        opts.fmt_version = sb.fmt_version;
        opts.ro_compat_version = sb.ro_compat_version;

        let image =
            mkfs::mkfs_plan(&plan, &opts).unwrap_or_else(|e| panic!("{name}: rebuild failed: {e}"));
        assert_eq!(
            image.to_vec(),
            raw,
            "{name}: rebuild is not byte-identical to the official image"
        );
    }
}

#[test]
fn compressed_images_use_the_expected_codecs() {
    // Walk the raw leaves and collect the compression types seen in data
    // nodes: the official compressed corpus must exercise our decoders.
    for (name, expect) in [
        ("g1-lzo.ubifs", ubifs::media::UBIFS_COMPR_LZO),
        ("g1-zlib.ubifs", ubifs::media::UBIFS_COMPR_ZLIB),
    ] {
        let raw = load_image(name);
        let leb_size = u32::from_le_bytes(raw[36..40].try_into().unwrap()) as usize;
        let lebs: Vec<Option<Vec<u8>>> = raw.chunks(leb_size).map(|c| Some(c.to_vec())).collect();
        let fs = Ubifs::new(lebs).unwrap();
        let mut seen = false;
        for leaf in fs.leaves() {
            let node = fs.leaf_node(*leaf).unwrap();
            if node[20] == ubifs::media::UBIFS_DATA_NODE {
                let dn = ubifs::media::DataNode::parse(&node).unwrap();
                if dn.compr_type == expect {
                    seen = true;
                }
            }
        }
        assert!(seen, "{name}: no {expect:?}-compressed data blocks found");
    }
}

#[test]
fn ubi_images_parse_with_volume_table() {
    let geom = UbiGeometry::from_peb_size(128 * 1024, 2048);

    let raw = load_image("ub-dyn.img");
    let dump = Dump::parse(&raw, geom).unwrap();
    let info = dump.info();
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].name, "ubifs");
    assert_eq!(info[0].vol_type, ubifs::ubi::UBI_VID_DYNAMIC);
    assert_eq!(info[0].flags, ubifs::ubi::UBI_VTBL_AUTORESIZE_FLG);
    assert_eq!(dump.image_seq(), Some(0x11223344));
    // The inner volume is g3-none: opens and verifies.
    let fs = Ubifs::new(dump.volume_lebs(0)).unwrap();
    fs.verify().unwrap();

    let raw = load_image("ub-mix.img");
    let dump = Dump::parse(&raw, geom).unwrap();
    let info = dump.info();
    assert_eq!(info.len(), 2);
    assert_eq!(info[1].name, "firmware");
    assert_eq!(info[1].vol_type, ubifs::ubi::UBI_VID_STATIC);
    assert_eq!(info[1].flags, ubifs::ubi::UBI_VTBL_SKIP_CRC_CHECK_FLG);
    // The static volume CRCs verify and the payload matches fw.bin.
    dump.verify_static(1).unwrap();
    let fw = std::fs::read(data_dir().join("fw.bin")).unwrap();
    let mut got = Vec::new();
    for leb in dump.volume_lebs(1).into_iter().flatten() {
        got.extend_from_slice(&leb);
    }
    assert_eq!(&got[..fw.len()], &fw[..]);
}
