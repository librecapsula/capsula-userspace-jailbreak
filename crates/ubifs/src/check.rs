//! Consistency checking in the spirit of fsck.ubifs: a soft pipeline
//! that walks the same stages as [`crate::reader::Ubifs::new`] but
//! *collects problems* instead of stopping at the first error, and
//! classifies them along the categories of the mtd-utils `problem.c`
//! table (detection only — repairs are a separate, future stage).

use std::collections::{HashMap, HashSet};

use crate::error::Error;
use crate::geometry::Geometry;
use crate::geometry::LptGeom;
use crate::journal;
use crate::key::Key;
use crate::lpt;
use crate::media::*;
use crate::tnc::{LeafRef, Tnc};

/// A problem category — a Rust mirror of the `problem.c` enum (the
/// repair-mode column of the original table maps to `fix_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProblemKind {
    /// The superblock is unreadable or semantically invalid — always
    /// fatal (`SB_CORRUPTED`).
    SbCorrupted,
    /// The master node is unreadable or inconsistent (`MST_CORRUPTED`).
    MstCorrupted,
    /// The log area is corrupt (`LOG_CORRUPTED`).
    LogCorrupted,
    /// The TNC index is corrupt (`TNC_CORRUPTED`) — unsorted keys,
    /// broken levels, unreadable index nodes.
    TncCorrupted,
    /// The index is empty (`EMPTY_TNC`).
    EmptyTnc,
    /// A bud LEB of the journal is corrupt (`BUD_CORRUPTED`).
    BudCorrupted,
    /// The orphan area is corrupt (`ORPHAN_CORRUPTED`).
    OrphanCorrupted,
    /// The LPT tree is corrupt (`LPT_CORRUPTED`).
    LptCorrupted,
    /// An ltab entry disagrees with reality (`LTAB_INCORRECT`).
    LtabIncorrect,
    /// An nnode carries a wrong position (`NNODE_INCORRECT`).
    NnodeIncorrect,
    /// A pnode carries wrong lprops (`PNODE_INCORRECT` / `LP_INCORRECT`).
    PnodeIncorrect,
    /// Space statistics disagree with the LPT/master (`SPACE_STAT_INCORRECT`).
    SpaceStatIncorrect,
    /// The index size in the master is wrong (`INCORRECT_IDX_SZ`).
    IncorrectIdxSize,
    /// A data LEB referenced by the index is corrupt
    /// (`TNC_DATA_CORRUPTED`).
    TncDataCorrupted,
    /// An inode node is invalid (`INVALID_INO_NODE`).
    InvalidInoNode,
    /// A dent node is invalid (`INVALID_DENT_NODE`).
    InvalidDentNode,
    /// A data node is invalid (`INVALID_DATA_NODE`).
    InvalidDataNode,
    /// Data blocks of an inode that has no inode node (`FILE_HAS_NO_INODE`).
    FileHasNoInode,
    /// A live inode with nlink 0 (`FILE_HAS_0_NLINK_INODE`).
    FileHas0NlinkInode,
    /// The dent type disagrees with the target inode mode
    /// (`FILE_HAS_INCONSIST_TYPE`).
    FileHasInconsistType,
    /// A non-directory is pointed at by several dents
    /// (`FILE_HAS_TOO_MANY_DENT`).
    FileHasTooManyDent,
    /// A non-directory inode carries data blocks (`FILE_SHOULDNT_HAVE_DATA`).
    FileShouldntHaveData,
    /// An inode without any directory entry (`FILE_HAS_NO_DENT`).
    FileHasNoDent,
    /// An xattr inode without a host (`XATTR_HAS_NO_HOST`).
    XattrHasNoHost,
    /// An xattr whose host is itself an xattr (`XATTR_HAS_WRONG_HOST`).
    XattrHasWrongHost,
    /// A file unreachable from the root (`FILE_IS_DISCONNECTED`).
    FileIsDisconnected,
    /// A dent targets the root directory (`FILE_ROOT_HAS_DENT`).
    FileRootHasDent,
    /// A dent targets a missing inode (`DENTRY_IS_UNREACHABLE`).
    DentryIsUnreachable,
    /// Recomputed metadata (nlink/size/xattr accounting) disagrees with
    /// the inode node (`FILE_IS_INCONSISTENT`).
    FileIsInconsistent,
    /// The root directory inode is missing (`ROOT_DIR_NOT_FOUND`).
    RootDirNotFound,
}

impl ProblemKind {
    /// Which fsck.ubifs mode would repair this category: 0 — safe
    /// (`-a`), 1 — danger (`-y`), 2 — rebuild (`-y -b`). Detection-only
    /// parity: this mirrors the `PROBLEM_*` flags of `problem.c`.
    pub fn fix_mode(self) -> u8 {
        match self {
            ProblemKind::SbCorrupted => 3,  // unfixable, fsck refuses
            ProblemKind::LptCorrupted => 2, // PROBLEM_NEED_REBUILD
            ProblemKind::MstCorrupted
            | ProblemKind::LogCorrupted
            | ProblemKind::TncCorrupted
            | ProblemKind::EmptyTnc => 2,
            ProblemKind::BudCorrupted
            | ProblemKind::OrphanCorrupted
            | ProblemKind::TncDataCorrupted
            | ProblemKind::InvalidInoNode
            | ProblemKind::InvalidDentNode
            | ProblemKind::InvalidDataNode
            | ProblemKind::FileHas0NlinkInode
            | ProblemKind::FileHasInconsistType
            | ProblemKind::FileHasTooManyDent
            | ProblemKind::XattrHasNoHost
            | ProblemKind::XattrHasWrongHost
            | ProblemKind::FileIsDisconnected
            | ProblemKind::FileRootHasDent
            | ProblemKind::DentryIsUnreachable
            | ProblemKind::RootDirNotFound => 1,
            ProblemKind::LtabIncorrect
            | ProblemKind::NnodeIncorrect
            | ProblemKind::PnodeIncorrect
            | ProblemKind::SpaceStatIncorrect
            | ProblemKind::IncorrectIdxSize
            | ProblemKind::FileHasNoInode
            | ProblemKind::FileShouldntHaveData
            | ProblemKind::FileHasNoDent
            | ProblemKind::FileIsInconsistent => 0,
        }
    }
}

/// One detected problem.
#[derive(Debug, Clone)]
pub struct Problem {
    /// The category.
    pub kind: ProblemKind,
    /// A human-readable detail (node position, inum, numbers).
    pub detail: String,
}

/// The result of a check run.
#[derive(Debug, Clone, Default)]
pub struct CheckReport {
    /// Every problem found, in discovery order.
    pub problems: Vec<Problem>,
    /// Whether the run got far enough to check the tree semantics.
    pub tree_checked: bool,
}

impl CheckReport {
    /// Whether the volume looks consistent.
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }

    /// Whether at least one problem of the kind is present.
    pub fn has(&self, kind: ProblemKind) -> bool {
        self.problems.iter().any(|p| p.kind == kind)
    }

    /// The highest repair mode over all problems (0 none/safe … 3
    /// unfixable).
    pub fn max_fix_mode(&self) -> u8 {
        self.problems
            .iter()
            .map(|p| p.kind.fix_mode())
            .max()
            .unwrap_or(0)
    }

    fn add(&mut self, kind: ProblemKind, detail: impl Into<String>) {
        self.problems.push(Problem {
            kind,
            detail: detail.into(),
        });
    }
}

/// Check a volume (UBI headers already stripped). This is the soft
/// counterpart of [`crate::reader::Ubifs::new`]: identical stages,
/// problems collected instead of errors raised.
pub fn check(lebs: &[Option<Vec<u8>>]) -> CheckReport {
    let mut r = CheckReport::default();

    // --- The superblock. ---
    let Some(sb_leb) = lebs.get(UBIFS_SB_LNUM as usize).and_then(|l| l.as_deref()) else {
        r.add(ProblemKind::SbCorrupted, "LEB 0 is unmapped");
        return r;
    };
    let sb = match parse_node(sb_leb, sb_leb.len(), "superblock") {
        Ok((node, _)) => match Superblock::parse(node) {
            Ok(sb) => sb,
            Err(e) => {
                r.add(ProblemKind::SbCorrupted, format!("{e}"));
                return r;
            }
        },
        Err(e) => {
            r.add(ProblemKind::SbCorrupted, format!("{e}"));
            return r;
        }
    };
    // The semantic field checks behind the official sb_* images.
    if !sb.leb_size.is_multiple_of(sb.min_io_size)
        || sb.leb_size < UBIFS_MIN_LEB_SZ
        || sb.leb_size > UBIFS_MAX_LEB_SZ
    {
        r.add(
            ProblemKind::SbCorrupted,
            format!("bad leb_size {}", sb.leb_size),
        );
    }
    if !sb.min_io_size.is_power_of_two() {
        r.add(
            ProblemKind::SbCorrupted,
            format!("bad min_io_size {}", sb.min_io_size),
        );
    }
    if sb.fanout < UBIFS_MIN_FANOUT
        || sb.fanout as usize
            > (sb.leb_size as usize - UBIFS_IDX_NODE_SZ)
                / (UBIFS_BRANCH_SZ + crate::key::UBIFS_MAX_KEY_LEN)
    {
        r.add(
            ProblemKind::SbCorrupted,
            format!("bad fanout {}", sb.fanout),
        );
    }
    if sb.fmt_version != 4 && sb.fmt_version != 5 {
        r.add(
            ProblemKind::SbCorrupted,
            format!("bad fmt_version {}", sb.fmt_version),
        );
    }
    if sb.log_lebs < UBIFS_MIN_LOG_LEBS
        || sb.log_lebs >= sb.max_leb_cnt.saturating_sub(UBIFS_MIN_LEB_CNT)
    {
        r.add(
            ProblemKind::SbCorrupted,
            format!("bad log_lebs {}", sb.log_lebs),
        );
    }
    if !r.problems.is_empty() {
        return r; // SB is fatal: the areas cannot be located
    }

    // --- The master node. ---
    let master = (|| -> Option<Master> {
        for lnum in [UBIFS_MST_LNUM, UBIFS_MST_LNUM + 1] {
            let Some(l) = lebs.get(lnum as usize).and_then(|l| l.as_deref()) else {
                continue;
            };
            let Ok((node, _)) = parse_node(l, l.len(), "master") else {
                continue;
            };
            if node[20] != UBIFS_MST_NODE {
                continue;
            }
            if let Ok(m) = Master::parse(node) {
                return Some(m);
            }
        }
        None
    })();
    let Some(master) = master else {
        r.add(ProblemKind::MstCorrupted, "no valid master node");
        return r;
    };
    if master.leb_cnt == 0 || master.leb_cnt > sb.max_leb_cnt {
        r.add(
            ProblemKind::MstCorrupted,
            format!("bad leb_cnt {}", master.leb_cnt),
        );
    }
    // The static areas must fit into the actual volume — the geometry
    // math (main_lebs) would underflow otherwise.
    if UBIFS_LOG_LNUM + sb.log_lebs + sb.lpt_lebs + sb.orph_lebs + 4 > master.leb_cnt {
        r.add(
            ProblemKind::SbCorrupted,
            format!(
                "areas do not fit into leb_cnt {}: log {} lpt {} orph {}",
                master.leb_cnt, sb.log_lebs, sb.lpt_lebs, sb.orph_lebs
            ),
        );
        return r;
    }
    if master.gc_lnum != 0 && master.gc_lnum >= master.leb_cnt {
        r.add(
            ProblemKind::MstCorrupted,
            format!("bad gc_lnum {}", master.gc_lnum),
        );
    }

    let geometry = Geometry {
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

    // --- The LPT and the space statistics. ---
    let lptg: LptGeom = geometry.lpt();
    match lpt::read_lprops(
        &lebs.to_vec(),
        &lptg,
        geometry.lpt_first(),
        geometry.leb_size,
        (master.lpt_lnum, master.lpt_offs),
        geometry.main_lebs() as usize,
    ) {
        Ok(lprops) => {
            let (mut sum_free, mut sum_dirty, mut idx_lebs) = (0u64, 0u64, 0u32);
            for lp in &lprops {
                if lp.free + lp.dirty > geometry.leb_size {
                    r.add(ProblemKind::PnodeIncorrect, "lprops free+dirty > leb_size");
                }
                sum_free += lp.free as u64;
                sum_dirty += lp.dirty as u64;
                if lp.flags & LPROPS_INDEX != 0 {
                    idx_lebs += 1;
                }
            }
            if sum_free != master.total_free {
                r.add(
                    ProblemKind::SpaceStatIncorrect,
                    format!("total_free: lpt {sum_free} != master {}", master.total_free),
                );
            }
            if sum_dirty != master.total_dirty {
                r.add(
                    ProblemKind::SpaceStatIncorrect,
                    format!(
                        "total_dirty: lpt {sum_dirty} != master {}",
                        master.total_dirty
                    ),
                );
            }
            if idx_lebs != master.idx_lebs {
                r.add(
                    ProblemKind::SpaceStatIncorrect,
                    format!("idx_lebs: lpt {idx_lebs} != master {}", master.idx_lebs),
                );
            }
            // The dead/dark split recomputed from the lprops watermarks.
            let (dead_wm, dark_wm) = crate::geometry::watermarks(geometry.min_io_size);
            let (mut dead, mut dark) = (0u64, 0u64);
            for lp in &lprops {
                if lp.flags & LPROPS_INDEX == 0 {
                    let spc = lp.free + lp.dirty;
                    if spc < dead_wm {
                        dead += spc as u64;
                    } else {
                        dark += crate::geometry::calc_dark(dark_wm, spc) as u64;
                    }
                }
            }
            if dead != master.total_dead {
                r.add(
                    ProblemKind::SpaceStatIncorrect,
                    format!(
                        "total_dead: computed {dead} != master {}",
                        master.total_dead
                    ),
                );
            }
            if dark != master.total_dark {
                r.add(
                    ProblemKind::SpaceStatIncorrect,
                    format!(
                        "total_dark: computed {dark} != master {}",
                        master.total_dark
                    ),
                );
            }
        }
        Err(e) => {
            r.add(ProblemKind::LptCorrupted, format!("{e}"));
        }
    }

    // --- The TNC index. ---
    let src: Vec<Option<Vec<u8>>> = lebs.to_vec();
    let tnc = Tnc::new(&src);
    let mut leaves = Vec::new();
    match tnc.walk(
        Branch {
            lnum: master.root_lnum,
            offs: master.root_offs,
            len: master.root_len,
            key: Key::default(),
        },
        |leaf| {
            leaves.push(leaf);
            Ok(())
        },
    ) {
        Ok(n) => {
            if n == 0 {
                r.add(ProblemKind::EmptyTnc, "the index has no leaves");
            }
        }
        Err(e) => {
            r.add(ProblemKind::TncCorrupted, format!("{e}"));
            return r;
        }
    }
    if !check_index_key_order(&src, &geometry, &master, &mut r) {
        return r;
    }
    // The index size cross-check.
    let index_size: u64 = leaves.iter().map(|l| l.len as u64).sum::<u64>() * 2;
    let _ = index_size; // aligned sizes are compared by the walk above

    // --- The journal and the orphan area. ---
    match journal::parse(&src, &master, geometry.log_lebs, geometry.leb_size as usize) {
        Ok(_) => {}
        Err(e) => {
            let kind = if e.to_string().contains("log") {
                ProblemKind::LogCorrupted
            } else {
                ProblemKind::BudCorrupted
            };
            r.add(kind, format!("{e}"));
        }
    }
    if let Err(e) = journal::orphans(&src, &master, geometry.lpt_last() + 1, geometry.orph_lebs) {
        r.add(ProblemKind::OrphanCorrupted, format!("{e}"));
    }

    // --- The tree semantics. ---
    check_tree(&src, &leaves, &master, &mut r);
    r.tree_checked = true;
    r
}

/// Keys inside index nodes must be sorted; branches must point inside
/// the volume. Returns false when the index is unusable.
fn check_index_key_order(
    src: &[Option<Vec<u8>>],
    geometry: &Geometry,
    master: &Master,
    r: &mut CheckReport,
) -> bool {
    let owned_src: Vec<Option<Vec<u8>>> = src.to_vec();
    let tnc = Tnc::new(&owned_src);
    let mut ok = true;
    let mut idx_bytes = 0u64;
    // Walk the index nodes level by level via the root.
    fn walk_idx(
        tnc: &Tnc,
        br: Branch,
        geometry: &Geometry,
        r: &mut CheckReport,
        ok: &mut bool,
        idx_bytes: &mut u64,
    ) {
        let node = match tnc.idx_node(br) {
            Ok(n) => n,
            Err(e) => {
                r.add(ProblemKind::TncCorrupted, format!("{e}"));
                *ok = false;
                return;
            }
        };
        *idx_bytes += (idx_node_sz(node.branches.len()).div_ceil(8) * 8) as u64;
        // Branch keys must be strictly ascending.
        for w in node.branches.windows(2) {
            if w[0].key >= w[1].key {
                r.add(
                    ProblemKind::TncCorrupted,
                    format!("unsorted branch keys at {}:{})", br.lnum, br.offs),
                );
                *ok = false;
            }
        }
        for b in &node.branches {
            if b.lnum >= geometry.leb_cnt || b.offs + b.len > geometry.leb_size {
                r.add(
                    ProblemKind::TncCorrupted,
                    format!("branch points outside the volume: {b:?}"),
                );
                *ok = false;
            }
        }
        if node.level > 0 {
            for b in &node.branches {
                walk_idx(tnc, *b, geometry, r, ok, idx_bytes);
            }
        }
    }
    let root = Branch {
        lnum: master.root_lnum,
        offs: master.root_offs,
        len: master.root_len,
        key: Key::default(),
    };
    walk_idx(&tnc, root, geometry, r, &mut ok, &mut idx_bytes);
    // The master's index_size must match the on-flash index.
    if idx_bytes != master.index_size {
        r.add(
            ProblemKind::IncorrectIdxSize,
            format!(
                "index size: master {} != computed {idx_bytes}",
                master.index_size
            ),
        );
    }
    ok
}

/// The soft leaf collection for the semantic stage: invalid leaves
/// become problems, the rest feeds the tree checks.
fn check_tree(src: &[Option<Vec<u8>>], leaves: &[LeafRef], master: &Master, r: &mut CheckReport) {
    let mut inos: HashMap<u32, InoNode> = HashMap::new();
    let mut dents: HashMap<u32, Vec<DentNode>> = HashMap::new();
    let mut data: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut xents: Vec<DentNode> = Vec::new();
    let mut leaf_order: HashMap<u32, u64> = HashMap::new();

    for leaf in leaves {
        let node = match leaf_bytes(src, *leaf) {
            Ok(n) => n,
            Err(e) => {
                r.add(ProblemKind::TncDataCorrupted, format!("{e}"));
                continue;
            }
        };
        let pos = (leaf.lnum as u64) << 32 | leaf.offs as u64;
        match node[20] {
            UBIFS_INO_NODE => match InoNode::parse(&node) {
                Ok(ino) => {
                    if matches!(
                        ino.mode & 0o170000,
                        0o040000 | 0o100000 | 0o120000 | 0o020000 | 0o060000 | 0o010000 | 0o140000
                    ) {
                        leaf_order.insert(ino.key.inum, pos);
                        inos.insert(ino.key.inum, ino);
                    } else {
                        r.add(
                            ProblemKind::InvalidInoNode,
                            format!("inode {} has unknown mode {:o}", ino.key.inum, ino.mode),
                        );
                    }
                }
                Err(e) => r.add(ProblemKind::InvalidInoNode, format!("{e}")),
            },
            UBIFS_DENT_NODE => match DentNode::parse(&node) {
                Ok(dent) => {
                    dents.entry(dent.key.inum).or_default().push(dent);
                }
                Err(e) => r.add(ProblemKind::InvalidDentNode, format!("{e}")),
            },
            UBIFS_XENT_NODE => match DentNode::parse(&node) {
                Ok(xent) => xents.push(xent),
                Err(e) => r.add(ProblemKind::InvalidDentNode, format!("xent: {e}")),
            },
            UBIFS_DATA_NODE => match DataNode::parse(&node) {
                Ok(dn) => {
                    if dn.compr_type > UBIFS_COMPR_ZSTD || dn.size as usize > UBIFS_BLOCK_SIZE {
                        r.add(
                            ProblemKind::InvalidDataNode,
                            format!(
                                "data node of inode {} has compr {} size {}",
                                dn.key.inum, dn.compr_type, dn.size
                            ),
                        );
                    } else {
                        data.entry(dn.key.inum)
                            .or_default()
                            .insert(dn.key.block_or_hash);
                    }
                }
                Err(e) => r.add(ProblemKind::InvalidDataNode, format!("{e}")),
            },
            t => r.add(
                ProblemKind::TncDataCorrupted,
                format!("unexpected leaf type {t} at {}:{}", leaf.lnum, leaf.offs),
            ),
        }
    }

    // The root.
    if !inos.contains_key(&UBIFS_ROOT_INO) {
        r.add(ProblemKind::RootDirNotFound, "inode 1 (root) is missing");
    }

    // Dents: targets exist, types agree, the root is nobody's child.
    let mut dent_count: HashMap<u32, u32> = HashMap::new();
    for (parent, list) in &dents {
        if !inos.contains_key(parent) && *parent != UBIFS_ROOT_INO {
            r.add(
                ProblemKind::InvalidDentNode,
                format!("dents of missing parent inode {parent}"),
            );
        }
        for dent in list {
            *dent_count.entry(dent.inum as u32).or_insert(0) += 1;
            let target = dent.inum as u32;
            if target == UBIFS_ROOT_INO {
                r.add(
                    ProblemKind::FileRootHasDent,
                    format!(
                        "dent {:?} targets the root",
                        String::from_utf8_lossy(&dent.name)
                    ),
                );
                continue;
            }
            let Some(ino) = inos.get(&target) else {
                r.add(
                    ProblemKind::DentryIsUnreachable,
                    format!(
                        "dent {:?} (parent {parent}) targets missing inode {target}",
                        String::from_utf8_lossy(&dent.name)
                    ),
                );
                continue;
            };
            // dent type vs inode mode.
            let want = match ino.mode & 0o170000 {
                0o040000 => UBIFS_ITYPE_DIR,
                0o100000 => UBIFS_ITYPE_REG,
                0o120000 => UBIFS_ITYPE_LNK,
                0o020000 => UBIFS_ITYPE_CHR,
                0o060000 => UBIFS_ITYPE_BLK,
                0o010000 => UBIFS_ITYPE_FIFO,
                0o140000 => UBIFS_ITYPE_SOCK,
                _ => 0xFF,
            };
            if dent.itype != want {
                r.add(
                    ProblemKind::FileHasInconsistType,
                    format!(
                        "dent {:?} type {} != inode {target} mode {:o}",
                        String::from_utf8_lossy(&dent.name),
                        dent.itype,
                        ino.mode
                    ),
                );
            }
        }
    }

    // Data blocks: of existing inodes, on data-carrying types.
    for (inum, blocks) in &data {
        match inos.get(inum) {
            None => r.add(
                ProblemKind::FileHasNoInode,
                format!(
                    "inode {inum} has {} data blocks but no inode node",
                    blocks.len()
                ),
            ),
            Some(ino) => {
                if ino.mode & 0o170000 != 0o100000 {
                    r.add(
                        ProblemKind::FileShouldntHaveData,
                        format!("inode {inum} of mode {:o} carries data", ino.mode),
                    );
                } else {
                    // The size must cover the highest block.
                    let max_end = blocks
                        .iter()
                        .map(|b| *b as u64 * UBIFS_BLOCK_SIZE as u64 + 4096)
                        .max()
                        .unwrap_or(0);
                    if max_end > ino.size.saturating_add(UBIFS_BLOCK_SIZE as u64) {
                        r.add(
                            ProblemKind::FileIsInconsistent,
                            format!("inode {inum}: data spans {max_end} > size {}", ino.size),
                        );
                    }
                }
            }
        }
    }

    // Xattrs: every xattr inode needs a host; a host must not itself be
    // an xattr.
    for xent in &xents {
        let host = xent.key.inum;
        let attr = xent.inum as u32;
        match inos.get(&attr) {
            None => r.add(
                ProblemKind::XattrHasNoHost,
                format!(
                    "xattr {:?} targets missing inode {attr}",
                    String::from_utf8_lossy(&xent.name)
                ),
            ),
            Some(ino) if ino.flags & UBIFS_XATTR_FL == 0 => r.add(
                ProblemKind::XattrHasNoHost,
                format!(
                    "xattr {:?} target inode {attr} has no XATTR_FL",
                    String::from_utf8_lossy(&xent.name)
                ),
            ),
            _ => {}
        }
        if let Some(host_ino) = inos.get(&host) {
            if host_ino.flags & UBIFS_XATTR_FL != 0 {
                r.add(
                    ProblemKind::XattrHasWrongHost,
                    format!("xattr host {host} is itself an xattr"),
                );
            }
        }
    }

    // Xattr accounting: the host's xattr_cnt must match the xents.
    let mut xent_per_host: HashMap<u32, u32> = HashMap::new();
    for xent in &xents {
        *xent_per_host.entry(xent.key.inum).or_insert(0) += 1;
    }
    for (host, cnt) in &xent_per_host {
        if let Some(ino) = inos.get(host) {
            if ino.xattr_cnt != *cnt {
                r.add(
                    ProblemKind::FileIsInconsistent,
                    format!("inode {host}: xattr_cnt {} != {cnt} xents", ino.xattr_cnt),
                );
            }
        }
    }
    // The master's highest_inum must not lag behind the index.
    if let Some(max_inum) = inos.keys().copied().max() {
        if master.highest_inum < max_inum as u64 {
            r.add(
                ProblemKind::MstCorrupted,
                format!(
                    "master highest_inum {} < index max {max_inum}",
                    master.highest_inum
                ),
            );
        }
    }

    // Reachability from the root and per-inode consistency.
    let mut reachable: HashSet<u32> = HashSet::new();
    reachable.insert(UBIFS_ROOT_INO);
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(UBIFS_ROOT_INO);
    while let Some(dir) = queue.pop_front() {
        if let Some(list) = dents.get(&dir) {
            for dent in list {
                let t = dent.inum as u32;
                if reachable.insert(t) {
                    queue.push_back(t);
                }
            }
        }
    }
    for (&inum, ino) in &inos {
        if inum == UBIFS_ROOT_INO {
            continue;
        }
        if ino.flags & UBIFS_XATTR_FL != 0 {
            continue; // reached via xents, checked above
        }
        if !reachable.contains(&inum) {
            r.add(
                ProblemKind::FileIsDisconnected,
                format!("inode {inum} is unreachable from the root"),
            );
            continue;
        }
        let cnt = dent_count.get(&inum).copied().unwrap_or(0);
        if cnt == 0 {
            r.add(
                ProblemKind::FileHasNoDent,
                format!("inode {inum} has no dents"),
            );
        }
        let is_dir = ino.mode & 0o170000 == 0o040000;
        let want = if is_dir { cnt + 1 } else { cnt };
        if ino.nlink == 0 {
            r.add(
                ProblemKind::FileHas0NlinkInode,
                format!("inode {inum} has nlink 0"),
            );
        } else if is_dir && cnt > 1 {
            // A directory may have exactly one parent.
            r.add(
                ProblemKind::FileHasTooManyDent,
                format!("directory inode {inum} has {cnt} dents"),
            );
        } else if !is_dir && cnt > ino.nlink {
            // More names than links: an extra dent was attached
            // (FILE_HAS_TOO_MANY_DENT).
            r.add(
                ProblemKind::FileHasTooManyDent,
                format!("inode {inum}: {cnt} dents > nlink {}", ino.nlink),
            );
        } else if ino.nlink != want {
            r.add(
                ProblemKind::FileIsInconsistent,
                format!("inode {inum}: nlink {} != {want}", ino.nlink),
            );
        }
    }
}

fn leaf_bytes(src: &[Option<Vec<u8>>], leaf: LeafRef) -> Result<Vec<u8>, Error> {
    let leb = src
        .get(leaf.lnum as usize)
        .and_then(|l| l.as_deref())
        .ok_or_else(|| Error::MissingData(format!("leb {} is unmapped", leaf.lnum)))?;
    let offs = leaf.offs as usize;
    let len = leaf.len as usize;
    if offs + len > leb.len() {
        return Err(Error::BadNode(format!(
            "leaf at {}:{} overruns leb",
            leaf.lnum, leaf.offs
        )));
    }
    let (node, _) = parse_node(&leb[offs..], len, "leaf node")?;
    Ok(node.to_vec())
}

impl crate::reader::Ubifs {
    /// Full consistency check of an opened volume.
    pub fn check(&self) -> CheckReport {
        check(&self.lebs)
    }
}
