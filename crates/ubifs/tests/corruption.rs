//! The corruption matrix, in the spirit of the official mtd-utils
//! `fsck_tests/fsck_bad_image.sh`: every case damages a *good* image
//! (from the committed official corpus) in a precise way and asserts
//! the checker classifies it exactly like the fsck.ubifs problem table
//! would. Detection only — the repair modes themselves are a future
//! stage, so the "safe/danger/rebuild" columns are asserted through
//! [`ubifs::check::ProblemKind::fix_mode`].

use ubifs::check::{check, ProblemKind};
use ubifs::key::Key;
use ubifs::media::*;
use ubifs::reader::Ubifs;
use ubifs::tree::Kind;

fn golden() -> Vec<Option<Vec<u8>>> {
    let comp = std::fs::read("tests/data/g1-none.ubifs.zlib").unwrap();
    let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&comp).unwrap();
    let leb = u32::from_le_bytes(raw[36..40].try_into().unwrap()) as usize;
    raw.chunks(leb).map(|c| Some(c.to_vec())).collect()
}

/// Rewrite a field of the node at (lnum, offs) and recompute the node
/// CRC (corruption with a *valid* CRC — what the official images do).
fn patch(lebs: &mut [Option<Vec<u8>>], lnum: u32, offs: usize, field_off: usize, bytes: &[u8]) {
    let leb = lebs[lnum as usize].as_mut().unwrap();
    let len = u32::from_le_bytes(leb[offs + 16..offs + 20].try_into().unwrap()) as usize;
    leb[offs + field_off..offs + field_off + bytes.len()].copy_from_slice(bytes);
    let crc = ubifs::crc::crc32(&leb[offs + 8..offs + len]);
    leb[offs + 4..offs + 8].copy_from_slice(&crc.to_le_bytes());
}

/// Break the node CRC only.
fn break_crc(lebs: &mut [Option<Vec<u8>>], lnum: u32, offs: usize) {
    let leb = lebs[lnum as usize].as_mut().unwrap();
    leb[offs + 4] ^= 0xFF;
}

/// Find a node by type (and an optional key/inum predicate), scanning
/// every mapped LEB. Returns (lnum, offs).
fn find_node(
    lebs: &[Option<Vec<u8>>],
    want_type: u8,
    pred: impl Fn(&[u8]) -> bool + Copy,
) -> (u32, usize) {
    for (i, leb) in lebs.iter().enumerate() {
        let Some(leb) = leb.as_deref() else { continue };
        if i == 0 && want_type != UBIFS_SB_NODE {
            continue; // SB/SIG area
        }
        let mut pos = 0usize;
        while pos + UBIFS_CH_SZ <= leb.len() {
            if u32::from_le_bytes(leb[pos..pos + 4].try_into().unwrap()) != UBIFS_NODE_MAGIC {
                break;
            }
            let len = u32::from_le_bytes(leb[pos + 16..pos + 20].try_into().unwrap()) as usize;
            if pos + len > leb.len() {
                break;
            }
            if leb[pos + 20] == want_type && pred(&leb[pos..pos + len]) {
                return (i as u32, pos);
            }
            pos += len.div_ceil(8) * 8;
        }
    }
    panic!("node of type {want_type} not found");
}

fn ino_of(fs: &Ubifs, path: &str) -> u32 {
    fs.lookup(path).unwrap().unwrap()
}

/// Rebuild the image from a mutated plan (structural corruptions).
fn rebuild_with(base: &Ubifs, mutate: impl FnOnce(&mut ubifs::walk::Plan)) -> Vec<Option<Vec<u8>>> {
    let mut plan = base.extract_plan().unwrap();
    mutate(&mut plan);
    let sb = &base.superblock;
    let mut opts = ubifs::mkfs::Options::new(sb.min_io_size, sb.leb_size, sb.max_leb_cnt);
    opts.log_lebs = Some(sb.log_lebs);
    opts.max_bud_bytes = Some(sb.max_bud_bytes);
    opts.default_compr = ubifs::Compr::None;
    opts.uuid = sb.uuid;
    let image = ubifs::mkfs::mkfs_plan(&plan, &opts).unwrap();
    image.lebs[..image.geometry.leb_cnt as usize].to_vec()
}

// ---------------------------------------------------------------------------
// The cases.
// ---------------------------------------------------------------------------

#[test]
fn corruption_matrix() {
    type Lebs = Vec<Option<Vec<u8>>>;
    type Maker = Box<dyn Fn(&mut Lebs)>;
    struct Case {
        name: &'static str,
        make: Maker,
        expect: ProblemKind,
        /// What fsck.ubifs would do: 2 = danger_rebuild (-y -b),
        /// 1 = danger_default (-y), 0 = safe (-a), 3 = refuse.
        mode: u8,
    }
    let cases: Vec<Case> = vec![
        // --- superblock: fsck refuses -----------------------------------
        Case {
            name: "sb_fanout",
            expect: ProblemKind::SbCorrupted,
            mode: 3,
            make: Box::new(|l| patch(l, 0, 0, 72, &1u32.to_le_bytes())),
        },
        Case {
            name: "sb_leb_size",
            expect: ProblemKind::SbCorrupted,
            mode: 3,
            make: Box::new(|l| patch(l, 0, 0, 36, &123u32.to_le_bytes())),
        },
        Case {
            name: "sb_min_io_size",
            expect: ProblemKind::SbCorrupted,
            mode: 3,
            make: Box::new(|l| patch(l, 0, 0, 32, &3u32.to_le_bytes())),
        },
        Case {
            name: "sb_fmt_version",
            expect: ProblemKind::SbCorrupted,
            mode: 3,
            make: Box::new(|l| patch(l, 0, 0, 80, &99u32.to_le_bytes())),
        },
        Case {
            name: "sb_log_lebs",
            expect: ProblemKind::SbCorrupted,
            mode: 3,
            make: Box::new(|l| patch(l, 0, 0, 56, &500u32.to_le_bytes())),
        },
        // --- master: danger_rebuild -------------------------------------
        Case {
            name: "master_tnc",
            expect: ProblemKind::TncCorrupted,
            mode: 2,
            make: Box::new(|l| patch(l, 1, 0, 48, &9999u32.to_le_bytes())),
        },
        Case {
            name: "master_lpt",
            expect: ProblemKind::LptCorrupted,
            mode: 2,
            make: Box::new(|l| patch(l, 1, 0, 120, &9999u32.to_le_bytes())),
        },
        Case {
            name: "master_highest_inum",
            expect: ProblemKind::MstCorrupted,
            mode: 2,
            make: Box::new(|l| patch(l, 1, 0, 24, &1u64.to_le_bytes())),
        },
        // --- space statistics: safe -------------------------------------
        Case {
            name: "master_total_free",
            expect: ProblemKind::SpaceStatIncorrect,
            mode: 0,
            make: Box::new(|l| {
                let v = u64::from_le_bytes(lebs_master(l)[80..88].try_into().unwrap()) + 4096;
                patch(l, 1, 0, 80, &v.to_le_bytes());
            }),
        },
        Case {
            name: "master_total_dirty",
            expect: ProblemKind::SpaceStatIncorrect,
            mode: 0,
            make: Box::new(|l| {
                let v = u64::from_le_bytes(lebs_master(l)[88..96].try_into().unwrap()) + 4096;
                patch(l, 1, 0, 88, &v.to_le_bytes());
            }),
        },
        Case {
            name: "master_total_dead",
            expect: ProblemKind::SpaceStatIncorrect,
            mode: 0,
            make: Box::new(|l| {
                let v = u64::from_le_bytes(lebs_master(l)[104..112].try_into().unwrap()) + 4096;
                patch(l, 1, 0, 104, &v.to_le_bytes());
            }),
        },
        Case {
            name: "index_size",
            expect: ProblemKind::IncorrectIdxSize,
            mode: 0,
            make: Box::new(|l| {
                let v = u64::from_le_bytes(lebs_master(l)[72..80].try_into().unwrap()) + 64;
                patch(l, 1, 0, 72, &v.to_le_bytes());
            }),
        },
        // --- journal / orphan -------------------------------------------
        Case {
            name: "journal_log",
            expect: ProblemKind::LogCorrupted,
            mode: 2,
            make: Box::new(|l| break_crc(l, 3, 0)),
        },
        Case {
            name: "journal_bud",
            expect: ProblemKind::BudCorrupted,
            mode: 1,
            make: Box::new(|l| {
                // Plant a REF node (after the CS) pointing at an
                // unmapped LEB: the bud is corrupt.
                let leb = l[3].as_mut().unwrap();
                let mut node = vec![0u8; UBIFS_REF_NODE_SZ];
                node[24..28].copy_from_slice(&9999u32.to_le_bytes());
                finish_node(&mut node, UBIFS_REF_NODE, 1000);
                leb[32..32 + UBIFS_REF_NODE_SZ].copy_from_slice(&node);
            }),
        },
        Case {
            name: "orphan_node",
            expect: ProblemKind::OrphanCorrupted,
            mode: 1,
            make: Box::new(|l| {
                // Flip the master to "orphans present" and plant a broken
                // orphan node in the orphan area (lpt_last + 1).
                let lpt_lebs = u32::from_le_bytes(lebs_first_sb(l)[60..64].try_into().unwrap());
                let log_lebs = u32::from_le_bytes(lebs_first_sb(l)[56..60].try_into().unwrap());
                let orph = 3 + log_lebs + lpt_lebs;
                let flags = u32::from_le_bytes(lebs_master(l)[40..44].try_into().unwrap());
                let nf = (flags | UBIFS_MST_ORPHS) & !UBIFS_MST_NO_ORPHS;
                patch(l, 1, 0, 40, &nf.to_le_bytes());
                let leb = l[orph as usize].as_mut().unwrap();
                let mut node = vec![0u8; UBIFS_ORPH_NODE_SZ];
                finish_node(&mut node, UBIFS_ORPH_NODE, 1);
                node[4] ^= 0xFF; // broken CRC
                leb[..node.len()].copy_from_slice(&node);
            }),
        },
        // --- LPT (effects surface through the space statistics) ---------
        Case {
            name: "lpt_free",
            expect: ProblemKind::SpaceStatIncorrect,
            mode: 0,
            make: Box::new(|l| {
                let lpt_first = lpt_first_leb(l);
                let (lnum, offs) = (lpt_first, 0usize);
                let geom = lpt_geom_of(l);
                let leb = l[lnum as usize].as_ref().unwrap().clone();
                let mut props = ubifs::lpt::unpack_pnode(&geom, &leb[offs..]).unwrap();
                props[0].free = 8192; // was: full data LEB (free 0)
                let mut node = vec![0u8; geom.pnode_sz];
                ubifs::lpt::pack_pnode(&geom, &mut node, 0, &props);
                let leb = l[lnum as usize].as_mut().unwrap();
                leb[offs..offs + geom.pnode_sz].copy_from_slice(&node);
            }),
        },
        Case {
            name: "lpt_dirty",
            expect: ProblemKind::SpaceStatIncorrect,
            mode: 0,
            make: Box::new(|l| {
                let lpt_first = lpt_first_leb(l);
                let (lnum, offs) = (lpt_first, 0usize);
                let geom = lpt_geom_of(l);
                let leb = l[lnum as usize].as_ref().unwrap().clone();
                let mut props = ubifs::lpt::unpack_pnode(&geom, &leb[offs..]).unwrap();
                props[0].dirty = 8192;
                let mut node = vec![0u8; geom.pnode_sz];
                ubifs::lpt::pack_pnode(&geom, &mut node, 0, &props);
                let leb = l[lnum as usize].as_mut().unwrap();
                leb[offs..offs + geom.pnode_sz].copy_from_slice(&node);
            }),
        },
        Case {
            name: "lpt_pos",
            expect: ProblemKind::SpaceStatIncorrect,
            mode: 0,
            make: Box::new(|l| {
                // Drop a branch of the root nnode: a sub-tree vanishes.
                let geom = lpt_geom_of(l);
                let (rlnum, roffs) = {
                    let m = lebs_master(l);
                    (
                        u32::from_le_bytes(m[120..124].try_into().unwrap()),
                        u32::from_le_bytes(m[124..128].try_into().unwrap()),
                    )
                };
                let leb = l[rlnum as usize].as_ref().unwrap().clone();
                let mut branches = ubifs::lpt::unpack_nnode(&geom, &leb[roffs as usize..]).unwrap();
                branches[0] = None; // the sub-tree is gone
                let mut node = vec![0u8; geom.nnode_sz];
                ubifs::lpt::pack_nnode(&geom, &mut node, 1, &branches);
                let leb = l[rlnum as usize].as_mut().unwrap();
                leb[roffs as usize..roffs as usize + geom.nnode_sz].copy_from_slice(&node);
            }),
        },
        // --- index: danger_rebuild --------------------------------------
        // A broken branch length in a level-0 znode damages the leaf
        // reference (data unreachable): TNC_DATA_CORRUPTED for us, even
        // though the official suite names it after the znode.
        Case {
            name: "tnc_lv0_len",
            expect: ProblemKind::TncDataCorrupted,
            mode: 1,
            make: Box::new(|l| {
                let (lnum, offs) = find_node(l, UBIFS_IDX_NODE, |n| {
                    u16::from_le_bytes(n[26..28].try_into().unwrap()) == 0
                });
                patch(l, lnum, offs, 28 + 8, &0u32.to_le_bytes());
            }),
        },
        Case {
            name: "tnc_lv0_key",
            expect: ProblemKind::TncCorrupted,
            mode: 2,
            make: Box::new(|l| {
                let (lnum, offs) = find_node(l, UBIFS_IDX_NODE, |n| {
                    u16::from_le_bytes(n[26..28].try_into().unwrap()) == 0
                });
                // A key above its successor breaks the ordering.
                patch(l, lnum, offs, 28 + 12, &0xFFFFFFFFu32.to_le_bytes());
            }),
        },
        Case {
            name: "corrupted_idx_leb",
            expect: ProblemKind::TncCorrupted,
            mode: 2,
            make: Box::new(|l| {
                let (lnum, offs) = find_node(l, UBIFS_IDX_NODE, |_| true);
                let leb = l[lnum as usize].as_mut().unwrap();
                leb[offs + 8] ^= 0xFF; // sqnum garbage: CRC breaks
            }),
        },
        // --- data ------------------------------------------------------
        Case {
            name: "corrupted_data_leb",
            expect: ProblemKind::TncDataCorrupted,
            mode: 1,
            make: Box::new(|l| {
                let (lnum, offs) = find_node(l, UBIFS_DATA_NODE, |_| true);
                let leb = l[lnum as usize].as_mut().unwrap();
                leb[offs + 4] ^= 0xFF;
            }),
        },
        Case {
            name: "inode_data",
            expect: ProblemKind::InvalidDataNode,
            mode: 1,
            make: Box::new(|l| {
                let (lnum, offs) = find_node(l, UBIFS_DATA_NODE, |_| true);
                patch(l, lnum, offs, 24 + 20, &99u16.to_le_bytes()); // compr_type
            }),
        },
        // --- inodes ----------------------------------------------------
        Case {
            name: "inode_mode",
            expect: ProblemKind::InvalidInoNode,
            mode: 1,
            make: Box::new(|l| {
                let fs = Ubifs::new(l.clone()).unwrap();
                let inum = ino_of(&fs, "/regular/small.txt");
                let (lnum, offs) = find_node(l, UBIFS_INO_NODE, |n| {
                    u32::from_le_bytes(n[24..28].try_into().unwrap()) == inum
                });
                patch(l, lnum, offs, 24 + 80, &0u32.to_le_bytes()); // mode
            }),
        },
        Case {
            name: "inode_nlink",
            expect: ProblemKind::FileIsInconsistent,
            mode: 0,
            make: Box::new(|l| {
                let fs = Ubifs::new(l.clone()).unwrap();
                let inum = ino_of(&fs, "/regular/small.txt");
                let (lnum, offs) = find_node(l, UBIFS_INO_NODE, |n| {
                    u32::from_le_bytes(n[24..28].try_into().unwrap()) == inum
                });
                patch(l, lnum, offs, 24 + 68, &99u32.to_le_bytes()); // nlink
            }),
        },
        Case {
            name: "inode_size",
            expect: ProblemKind::FileIsInconsistent,
            mode: 0,
            make: Box::new(|l| {
                let fs = Ubifs::new(l.clone()).unwrap();
                let inum = ino_of(&fs, "/regular/big.bin");
                let (lnum, offs) = find_node(l, UBIFS_INO_NODE, |n| {
                    u32::from_le_bytes(n[24..28].try_into().unwrap()) == inum
                });
                patch(l, lnum, offs, 24 + 24, &100u64.to_le_bytes()); // size
            }),
        },
        Case {
            name: "inode_xcnt",
            expect: ProblemKind::FileIsInconsistent,
            mode: 0,
            make: Box::new(|l| {
                let fs = Ubifs::new(l.clone()).unwrap();
                let inum = ino_of(&fs, "/attrs/notes.txt");
                let (lnum, offs) = find_node(l, UBIFS_INO_NODE, |n| {
                    u32::from_le_bytes(n[24..28].try_into().unwrap()) == inum
                });
                patch(l, lnum, offs, 24 + 92, &5u32.to_le_bytes()); // xattr_cnt
            }),
        },
        // --- dents -----------------------------------------------------
        Case {
            name: "dentry_key",
            expect: ProblemKind::InvalidDentNode,
            mode: 1,
            make: Box::new(|l| {
                let fs = Ubifs::new(l.clone()).unwrap();
                let inum = ino_of(&fs, "/regular");
                let (lnum, offs) = find_node(l, UBIFS_DENT_NODE, |n| {
                    u32::from_le_bytes(n[24..28].try_into().unwrap()) == 1
                        && n[40..48] == (inum as u64).to_le_bytes()
                });
                patch(l, lnum, offs, 24, &9999u32.to_le_bytes()); // parent inum
            }),
        },
        Case {
            name: "dentry_nlen",
            expect: ProblemKind::InvalidDentNode,
            mode: 1,
            make: Box::new(|l| {
                let fs = Ubifs::new(l.clone()).unwrap();
                let inum = ino_of(&fs, "/regular");
                let (lnum, offs) = find_node(l, UBIFS_DENT_NODE, |n| {
                    u32::from_le_bytes(n[24..28].try_into().unwrap()) == 1
                        && n[40..48] == (inum as u64).to_le_bytes()
                });
                patch(l, lnum, offs, 24 + 26, &200u16.to_le_bytes()); // nlen
            }),
        },
        Case {
            name: "dentry_type",
            expect: ProblemKind::FileHasInconsistType,
            mode: 1,
            make: Box::new(|l| {
                let fs = Ubifs::new(l.clone()).unwrap();
                let inum = ino_of(&fs, "/regular/small.txt");
                let (lnum, offs) = find_node(l, UBIFS_DENT_NODE, |n| {
                    n[40..48] == (inum as u64).to_le_bytes()
                });
                patch(l, lnum, offs, 24 + 25, &[UBIFS_ITYPE_DIR]); // itype
            }),
        },
        // --- xattrs ----------------------------------------------------
        Case {
            name: "xinode_flags",
            expect: ProblemKind::XattrHasNoHost,
            mode: 1,
            make: Box::new(|l| {
                let (lnum, offs) = find_node(l, UBIFS_INO_NODE, |n| {
                    u32::from_le_bytes(n[108..112].try_into().unwrap()) & UBIFS_XATTR_FL != 0
                });
                let flags = 0u32;
                patch(l, lnum, offs, 24 + 84, &flags.to_le_bytes()); // flags
            }),
        },
        Case {
            name: "xentry_nlen",
            expect: ProblemKind::InvalidDentNode,
            mode: 1,
            make: Box::new(|l| {
                let (lnum, offs) = find_node(l, UBIFS_XENT_NODE, |_| true);
                patch(l, lnum, offs, 24 + 26, &200u16.to_le_bytes());
            }),
        },
        Case {
            name: "xent_host",
            expect: ProblemKind::XattrHasWrongHost,
            mode: 1,
            make: Box::new(|l| {
                let fs = Ubifs::new(l.clone()).unwrap();
                let inum = ino_of(&fs, "/attrs/notes.txt");
                let (lnum, offs) = find_node(l, UBIFS_INO_NODE, |n| {
                    u32::from_le_bytes(n[24..28].try_into().unwrap()) == inum
                });
                let flags = UBIFS_XATTR_FL;
                patch(l, lnum, offs, 24 + 84, &flags.to_le_bytes());
            }),
        },
    ];

    for case in &cases {
        let mut lebs = golden();
        (case.make)(&mut lebs);
        let report = check(&lebs);
        assert!(
            report.has(case.expect),
            "{}: expected {:?}, got {:?}",
            case.name,
            case.expect,
            report.problems.iter().map(|p| p.kind).collect::<Vec<_>>()
        );
        assert_eq!(
            report
                .problems
                .iter()
                .map(|p| p.kind.fix_mode())
                .max()
                .unwrap_or(0),
            case.mode,
            "{}: fix mode mismatch",
            case.name
        );
    }
}

/// Structural corruptions need a re-indexed image: built via plan
/// mutation + rebuild.
#[test]
fn structural_corruption_matrix() {
    // dir_many_dentry: a second dent pointing at a directory.
    let base = Ubifs::new(golden()).unwrap();
    let lebs = rebuild_with(&base, |plan| {
        if let Kind::Dir(children) = &mut plan.root.kind {
            children.push((
                "dup".into(),
                ubifs::tree::Inode::with_kind(
                    0o040755,
                    Kind::Hardlink {
                        target: vec!["regular".into()],
                    },
                ),
            ));
        }
    });
    let report = check(&lebs);
    assert!(
        report.has(ProblemKind::FileHasTooManyDent),
        "{:?}",
        report.problems
    );

    // dir_lost: the dent of the "regular" subtree points into the void
    // — the subtree becomes unreachable while its inodes live on.
    let inum = ino_of(&base, "/regular");
    let mut lebs = golden();
    let (lnum, offs) = find_node(&lebs, UBIFS_DENT_NODE, |n| {
        u32::from_le_bytes(n[24..28].try_into().unwrap()) == 1
            && n[40..48] == (inum as u64).to_le_bytes()
    });
    patch(&mut lebs, lnum, offs, 24 + 16, &8888u64.to_le_bytes()); // dent.inum
    let report = check(&lebs);
    assert!(
        report.has(ProblemKind::DentryIsUnreachable),
        "{:?}",
        report.problems
    );
    assert!(
        report.has(ProblemKind::FileIsDisconnected),
        "{:?}",
        report.problems
    );
}

/// The undamaged image must stay clean.
#[test]
fn good_image_is_clean() {
    let report = check(&golden());
    assert!(report.is_ok(), "{:?}", report.problems);
    assert!(report.tree_checked);
}

// ---------------------------------------------------------------------------
// Small helpers over the raw lebs.
// ---------------------------------------------------------------------------

/// The first pnode sits at the start of the LPT area.
fn lpt_first_leb(lebs: &[Option<Vec<u8>>]) -> u32 {
    3 + u32::from_le_bytes(lebs_first_sb(lebs)[56..60].try_into().unwrap())
}

fn lebs_first_sb(lebs: &[Option<Vec<u8>>]) -> Vec<u8> {
    lebs[0].as_ref().unwrap().clone()
}

fn lebs_master(lebs: &[Option<Vec<u8>>]) -> Vec<u8> {
    lebs[1].as_ref().unwrap().clone()
}

fn lpt_geom_of(lebs: &[Option<Vec<u8>>]) -> ubifs::geometry::LptGeom {
    let raw = lebs_first_sb(lebs);
    let (node, _) = parse_node(&raw, raw.len(), "sb").unwrap();
    let sb = Superblock::parse(node).unwrap();
    let master = {
        let m = lebs_master(lebs);
        let (n, _) = parse_node(&m, m.len(), "mst").unwrap();
        Master::parse(n).unwrap()
    };
    let geometry = ubifs::geometry::Geometry {
        min_io_size: sb.min_io_size,
        leb_size: sb.leb_size,
        leb_cnt: master.leb_cnt,
        max_leb_cnt: sb.max_leb_cnt,
        max_bud_bytes: sb.max_bud_bytes,
        log_lebs: sb.log_lebs,
        lpt_lebs: sb.lpt_lebs,
        orph_lebs: sb.orph_lebs,
        jhead_cnt: sb.jhead_cnt,
        fanout: sb.fanout,
        lsave_cnt: sb.lsave_cnt,
        fmt_version: sb.fmt_version,
        default_compr: sb.default_compr,
        flags: sb.flags,
        uuid: sb.uuid,
        ro_compat_version: sb.ro_compat_version,
    };
    geometry.lpt()
}

#[allow(dead_code)]
fn unused(_: &Key) {}
