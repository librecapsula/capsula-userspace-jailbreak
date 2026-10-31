//! A pure-Rust UBIFS crate: reading existing images, building them from
//! scratch (byte parity with mkfs.ubifs for `-x none`) and modifying
//! them (extract the tree → edit → repack).
//!
//! The format follows the Linux kernel's `fs/ubifs/ubifs-media.h` and
//! mtd-utils (`ubifs-utils`); the building mechanics are a port of
//! mkfs.ubifs: the same node order, sqnums, 8-byte alignment, the LPT
//! (including the sparse trees of kernel commits) and the lprops
//! watermarks.
//!
//! # Example: build an image
//! ```
//! use ubifs::{mkfs, tree::{Inode, Kind}};
//!
//! let root = Inode::dir(0o755, vec![
//!     ("etc".into(), Inode::dir(0o755, vec![
//!         ("marker".into(), Inode::file(0o644, b"marker\n".to_vec())),
//!     ])),
//!     ("small.txt".into(), Inode::file(0o644, b"hello".to_vec())),
//! ]);
//! // -m 2048 -e 126976 -c 128: a typical 128 KiB PEB / 2 KiB page NAND
//! let opts = mkfs::Options::new(2048, 126976, 128);
//! let image = mkfs::mkfs(&root, &opts).unwrap();
//! let raw = image.to_vec(); // the LEB stream (.ubifs format)
//! ```
//!
//! # Example: read a UBI partition dump
//! ```
//! use ubifs::{reader, ubi};
//!
//! # fn f(raw: &[u8]) -> ubifs::Result<()> {
//! let geom = ubi::UbiGeometry::from_peb_size(0x20000, 2048);
//! let dump = ubi::Dump::parse(raw, geom)?;
//! let lebs = dump.volume_lebs(0);
//! let fs = reader::Ubifs::new(lebs)?;
//! let tree = fs.extract()?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

pub mod compress;
pub mod crc;
pub mod devtable;
pub mod error;
pub mod geometry;
pub mod key;
pub mod lpt;
pub mod media;
pub mod mkfs;
pub mod reader;
pub mod tnc;
pub mod tree;
pub mod ubi;
pub mod ubinize;
pub mod walk;

pub use compress::Compr;
pub use error::{Error, Result};
pub use geometry::{Geometry, LptGeom};
pub use key::{Key, KeyHash};
pub use lpt::Lprops;
pub use media::{
    Branch, CommonHeader, CsNode, DataNode, DentNode, IdxNode, InoNode, Master, Superblock,
    UBIFS_ROOT_INO,
};
pub use mkfs::Options as MkfsOptions;
pub use reader::Ubifs;
pub use walk::Plan;

/// Extract the tree, apply a mutation and rebuild the image with the
/// same geometry.
///
/// This is a "repack"-style modification: inodes/times/modes are
/// preserved from the source tree, but the sqnums and the layout are
/// those of a fresh mkfs (in effect, this is what mkfs.ubifs would do
/// over the extracted root).
pub fn modify<F>(source: &Ubifs, f: F, opts: &mkfs::Options) -> Result<mkfs::Image>
where
    F: FnOnce(&mut tree::Inode),
{
    let mut root = source.extract()?;
    f(&mut root);
    mkfs::mkfs(&root, opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree::{Inode, Kind};

    fn geom_options() -> mkfs::Options {
        let mut o = mkfs::Options::new(2048, 126976, 2212);
        o.log_lebs = Some(5);
        o.max_bud_bytes = Some(8 << 20);
        o
    }

    fn sample_tree() -> Inode {
        Inode::dir(
            0o755,
            vec![
                (
                    "etc".into(),
                    Inode::dir(
                        0o755,
                        vec![("marker".into(), Inode::file(0o644, b"marker\n".to_vec()))],
                    ),
                ),
                (
                    "usr".into(),
                    Inode::dir(
                        0o755,
                        vec![(
                            "bin".into(),
                            Inode::dir(
                                0o755,
                                vec![(
                                    "tool".into(),
                                    Inode::file(
                                        0o755,
                                        (0..200_000u32).map(|i| (i % 251) as u8).collect(),
                                    ),
                                )],
                            ),
                        )],
                    ),
                ),
                ("small.txt".into(), Inode::file(0o644, b"hello".to_vec())),
                ("empty.bin".into(), Inode::file(0o644, vec![])),
                ("link".into(), Inode::symlink("/etc/marker")),
            ],
        )
    }

    #[test]
    fn mkfs_read_roundtrip() {
        let root = sample_tree();
        let opts = geom_options();
        let image = mkfs::mkfs(&root, &opts).expect("mkfs");
        assert!(image.geometry.leb_cnt < opts.max_leb_cnt);
        let lebs = image.lebs[..image.geometry.leb_cnt as usize].to_vec();
        let fs = Ubifs::new(lebs).expect("open own image");
        fs.verify().expect("verify");

        assert_eq!(fs.lookup("/usr/bin/tool").unwrap(), Some(69));
        let tool_inum = fs.lookup("/usr/bin/tool").unwrap().unwrap();
        let content = fs.read_file(tool_inum, 200_000).unwrap();
        let expect: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(content, expect);

        let entries = fs.dir_entries(UBIFS_ROOT_INO).unwrap();
        let mut names: Vec<&str> = entries.iter().map(|d| d.name.as_str()).collect();
        // On flash the order follows the r5 hash of the keys; compare as
        // a set.
        names.sort_unstable();
        assert_eq!(names, vec!["empty.bin", "etc", "link", "small.txt", "usr"]);

        let tree = fs.extract().unwrap();
        match &tree.kind {
            Kind::Dir(children) => assert_eq!(children.len(), 5),
            _ => panic!("root must be a directory"),
        }
        // Rebuilding from the extracted tree yields a valid image.
        let image2 = mkfs::mkfs(&tree, &opts).expect("rebuild");
        let fs2 = Ubifs::new(image2.lebs[..image2.geometry.leb_cnt as usize].to_vec()).unwrap();
        fs2.verify().unwrap();
    }

    #[test]
    fn modify_replaces_file() {
        let root = sample_tree();
        let opts = geom_options();
        let image = mkfs::mkfs(&root, &opts).unwrap();
        let lebs = image.lebs[..image.geometry.leb_cnt as usize].to_vec();
        let fs = Ubifs::new(lebs).unwrap();

        let image2 = modify(
            &fs,
            |tree| {
                if let Kind::Dir(children) = &mut tree.kind {
                    for (name, ino) in children.iter_mut() {
                        if name == "small.txt" {
                            *ino = Inode::file(0o644, b"replaced!".to_vec());
                        }
                    }
                }
            },
            &opts,
        )
        .unwrap();
        let fs2 = Ubifs::new(image2.lebs[..image2.geometry.leb_cnt as usize].to_vec()).unwrap();
        let inum = fs2.lookup("/small.txt").unwrap().unwrap();
        assert_eq!(fs2.read_file(inum, 9).unwrap(), b"replaced!");
    }

    #[test]
    fn xattr_write_read_roundtrip() {
        let mut file = Inode::file(0o644, vec![7u8; 512]);
        file.xattrs = vec![
            ("user.test".into(), b"value".to_vec()),
            ("user.other".into(), b"v2".to_vec()),
        ];
        let root = Inode::dir(0o755, vec![("f".into(), file)]);

        let mut opts = mkfs::Options::new(2048, 126976, 128);
        opts.default_compr = Compr::None;
        let image = mkfs::mkfs(&root, &opts).unwrap();
        let fs = Ubifs::new(image.lebs[..image.geometry.leb_cnt as usize].to_vec()).unwrap();
        fs.verify().unwrap();

        let tree = fs.extract().unwrap();
        let Kind::Dir(children) = tree.kind else {
            panic!()
        };
        let f = &children.iter().find(|(n, _)| n == "f").unwrap().1;
        assert_eq!(f.xattrs[0].0, "user.test");
        assert_eq!(f.xattrs[0].1, b"value");
        assert_eq!(f.xattrs[1].0, "user.other");
        assert_eq!(f.xattrs[1].1, b"v2");

        // The host inode accounting follows the mkfs.ubifs formulas.
        let inum = fs.lookup("/f").unwrap().unwrap();
        let ino = fs.ino_node(inum).unwrap().unwrap();
        assert_eq!(ino.xattr_cnt, 2);
        // ALIGN(56+9+1,8) + ALIGN(160+5+1,8) + ALIGN(56+10+1,8) +
        // ALIGN(160+2+1,8) = 72+168+72+168 = 480? — compute exactly:
        let want_size = ((crate::media::UBIFS_DENT_NODE_SZ + 9 + 1).div_ceil(8) * 8
            + (crate::media::UBIFS_INO_NODE_SZ + 5 + 1).div_ceil(8) * 8
            + (crate::media::UBIFS_DENT_NODE_SZ + 10 + 1).div_ceil(8) * 8
            + (crate::media::UBIFS_INO_NODE_SZ + 2 + 1).div_ceil(8) * 8)
            as u32;
        assert_eq!(ino.xattr_size, want_size);
        assert_eq!(ino.xattr_names, (9 + 10) as u32);
    }

    #[test]
    fn hardlink_plan_roundtrip() {
        use crate::walk::{LinkGroup, Plan};
        let content: Vec<u8> = (0..100_000u32).map(|i| (i % 199) as u8).collect();
        let root = Inode::dir(
            0o755,
            vec![
                ("a".into(), Inode::file(0o644, content.clone())),
                (
                    "d".into(),
                    Inode::dir(
                        0o755,
                        vec![(
                            "b".into(),
                            Inode::with_kind(
                                0o100644,
                                Kind::Hardlink {
                                    target: vec!["a".into()],
                                },
                            ),
                        )],
                    ),
                ),
            ],
        );
        let plan = Plan {
            root,
            link_groups: vec![LinkGroup {
                tree_path: vec!["a".into()],
                nlink: 2,
                order_key: 0,
            }],
        };
        let mut opts = mkfs::Options::new(2048, 126976, 128);
        opts.default_compr = Compr::None;
        let image = mkfs::mkfs_plan(&plan, &opts).unwrap();
        let fs = Ubifs::new(image.lebs[..image.geometry.leb_cnt as usize].to_vec()).unwrap();
        fs.verify().unwrap();

        let a = fs.lookup("/a").unwrap().unwrap();
        let b = fs.lookup("/d/b").unwrap().unwrap();
        assert_eq!(a, b, "both names must resolve to the same inode");
        assert_eq!(fs.read_file(a, content.len() as u64).unwrap(), content);
        assert_eq!(fs.ino_node(a).unwrap().unwrap().nlink, 2);

        // And the extract_plan side recovers the hard-link structure.
        let plan2 = fs.extract_plan().unwrap();
        assert_eq!(plan2.link_groups.len(), 1);
        assert_eq!(plan2.link_groups[0].nlink, 2);
        let image3 = mkfs::mkfs_plan(&plan2, &opts).unwrap();
        assert_eq!(image3.to_vec(), image.to_vec());
    }

    #[cfg(unix)]
    #[test]
    fn walker_roundtrip() {
        use crate::walk;
        let dir = std::env::temp_dir().join(format!("ubifs-walker-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("file.txt"), b"hello walker").unwrap();
        std::fs::write(dir.join("sub/data.bin"), vec![42u8; 10_000]).unwrap();
        std::os::unix::fs::symlink("file.txt", dir.join("sub/alias")).unwrap();
        std::fs::hard_link(dir.join("file.txt"), dir.join("sub/hard-link")).unwrap();

        let plan = walk::from_directory(&dir, &walk::WalkOptions::default()).expect("walk");
        assert_eq!(plan.link_groups.len(), 1);
        assert_eq!(plan.link_groups[0].nlink, 2);

        let mut opts = mkfs::Options::new(2048, 126976, 128);
        opts.default_compr = Compr::None;
        let image = mkfs::mkfs_plan(&plan, &opts).unwrap();
        let fs = Ubifs::new(image.lebs[..image.geometry.leb_cnt as usize].to_vec()).unwrap();
        fs.verify().unwrap();
        let inum = fs.lookup("/file.txt").unwrap().unwrap();
        assert_eq!(fs.read_file(inum, 12).unwrap(), b"hello walker");
        let link = fs.lookup("/sub/hard-link").unwrap().unwrap();
        assert_eq!(link, inum);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
