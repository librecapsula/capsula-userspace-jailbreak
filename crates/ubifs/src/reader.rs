//! Reading a UBIFS volume: the superblock/master, the LPT, the committed
//! index, the journal replay and high-level filesystem access
//! (lookup/list/read/extract).
//!
//! The volume is opened at its *post-replay* state: the committed index
//! overlaid with the journal (buds referenced by the log) and the
//! orphan deletions, exactly like the kernel mounts an unclean volume —
//! and, being idempotent for the current commit's log, also exactly
//! like a clean mount.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::compress::decompress;
use crate::error::{Error, Result};
use crate::geometry::Geometry;
use crate::journal::{self, JournalNode};
use crate::key::Key;
use crate::lpt::{read_lprops, Lprops};
use crate::media::*;
use crate::tnc::{LeafRef, Tnc};
use crate::tree::{Inode, Kind};

/// A UBIFS volume on top of a set of LEBs (UBI headers already stripped).
pub struct Ubifs {
    /// The volume LEBs (UBI headers stripped).
    pub lebs: Vec<Option<Vec<u8>>>,
    /// The volume superblock.
    pub superblock: Superblock,
    /// The current master node.
    pub master: Master,
    /// The volume geometry.
    pub geometry: Geometry,
    lprops: Vec<Lprops>,
    /// The committed-index leaves in-order (keys ascending; dents with
    /// equal keys ordered by name).
    leaves: Vec<LeafRef>,
    /// The post-replay view of all leaves (the query cache).
    collected: Collected,
    /// The parsed journal (log + buds), when present.
    pub journal: Option<journal::Journal>,
    /// The inodes deleted via the orphan area.
    pub orphan_inums: Vec<u32>,
}

/// A directory entry as seen by the reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dirent {
    /// The entry name.
    pub name: String,
    /// The target inode number.
    pub inum: u32,
    /// The target type (`UBIFS_ITYPE_*`).
    pub itype: u8,
}

/// The working maps of the post-replay view.
#[derive(Default)]
struct Collected {
    inos: BTreeMap<u32, InoNode>,
    /// inum → the on-flash position of its ino node (the write order).
    ino_pos: HashMap<u32, u64>,
    /// Parent inum → (position, dent), position = the on-flash write
    /// order; `finish` sorts and strips it.
    dents: BTreeMap<u32, Vec<(u64, DentNode)>>,
    data: BTreeMap<u32, BTreeMap<u32, Vec<u8>>>,
    /// Host inum → xattrs in original write order.
    xattrs: BTreeMap<u32, Vec<(String, Vec<u8>)>>,
    /// Raw xent stream (position, host, name, attr inum) — the input of
    /// the xattrs map, so journal xents can extend it.
    raw_xents: Vec<(u64, u32, String, u32)>,
}

impl Ubifs {
    /// Open a volume: parse the SB/MST, read the LPT, cross-check the
    /// totals (as in `lpt_init_rd` + the mount checks), walk the index
    /// and replay the journal on top.
    pub fn new(lebs: Vec<Option<Vec<u8>>>) -> Result<Ubifs> {
        let leb = |lnum: u32| -> Result<&Vec<u8>> {
            lebs.get(lnum as usize)
                .and_then(|l| l.as_ref())
                .ok_or_else(|| Error::MissingData(format!("leb {lnum} is unmapped")))
        };
        let sb_leb = leb(UBIFS_SB_LNUM)?;
        let (sb_node, _) = parse_node(sb_leb, sb_leb.len(), "superblock")?;
        expect_type(sb_node[20], UBIFS_SB_NODE, "leb 0")?;
        let superblock = Superblock::parse(sb_node)?;

        // fsck.ubifs refuses authenticated volumes; encrypted (format 5)
        // volumes are not supported by this reader either.
        if superblock.flags & UBIFS_FLG_AUTHENTICATION != 0 {
            return Err(Error::Unsupported(
                "authenticated volumes are not supported".into(),
            ));
        }
        if superblock.flags & (UBIFS_FLG_ENCRYPTION | UBIFS_FLG_DOUBLE_HASH) != 0 {
            return Err(Error::Unsupported(
                "encrypted (format 5) volumes are not supported".into(),
            ));
        }

        // The current master: LEB 1, on failure LEB 2 (UBIFS_MST_LEBS = 2).
        let master = (|| -> Result<Master> {
            for lnum in [UBIFS_MST_LNUM, UBIFS_MST_LNUM + 1] {
                let Ok(l) = leb(lnum) else { continue };
                let Ok((node, _)) = parse_node(l, l.len(), "master") else {
                    continue;
                };
                if node[20] != UBIFS_MST_NODE {
                    continue;
                }
                if let Ok(m) = Master::parse(node) {
                    return Ok(m);
                }
            }
            Err(Error::MissingData("no valid master node".into()))
        })()?;

        // Geometry: the parameters come from the SB, leb_cnt from the
        // master (the actual volume state, as at mount time).
        let geometry = Geometry {
            min_io_size: superblock.min_io_size,
            leb_size: superblock.leb_size,
            leb_cnt: master.leb_cnt,
            max_leb_cnt: superblock.max_leb_cnt,
            max_bud_bytes: superblock.max_bud_bytes,
            log_lebs: superblock.log_lebs,
            lpt_lebs: superblock.lpt_lebs,
            orph_lebs: superblock.orph_lebs,
            jhead_cnt: superblock.jhead_cnt,
            fanout: superblock.fanout,
            lsave_cnt: superblock.lsave_cnt,
            fmt_version: superblock.fmt_version,
            default_compr: superblock.default_compr,
            flags: superblock.flags,
            uuid: superblock.uuid,
            ro_compat_version: superblock.ro_compat_version,
        };

        // The LPT: main-area lprops + a cross-check against the master
        // totals.
        let lptg = geometry.lpt();
        let lprops = read_lprops(
            &lebs,
            &lptg,
            geometry.lpt_first(),
            geometry.leb_size,
            (master.lpt_lnum, master.lpt_offs),
            geometry.main_lebs() as usize,
        )?;
        let mut idx_lebs = 0u32;
        let mut sum_free = 0u64;
        let mut sum_dirty = 0u64;
        for lp in &lprops {
            if lp.free + lp.dirty > geometry.leb_size {
                return Err(Error::BadGeometry(format!(
                    "lprops: free({}) + dirty({}) > leb_size",
                    lp.free, lp.dirty
                )));
            }
            sum_free += lp.free as u64;
            sum_dirty += lp.dirty as u64;
            if lp.flags & LPROPS_INDEX != 0 {
                idx_lebs += 1;
            }
        }
        if sum_free != master.total_free {
            return Err(Error::BadGeometry(format!(
                "LPT total_free {sum_free} != master {}",
                master.total_free
            )));
        }
        if sum_dirty != master.total_dirty {
            return Err(Error::BadGeometry(format!(
                "LPT total_dirty {sum_dirty} != master {}",
                master.total_dirty
            )));
        }
        if idx_lebs != master.idx_lebs {
            return Err(Error::BadGeometry(format!(
                "LPT idx_lebs {idx_lebs} != master {}",
                master.idx_lebs
            )));
        }

        // Walk the committed index.
        let tnc = Tnc::new(&lebs);
        let mut leaves = Vec::new();
        tnc.walk(
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
        )?;

        // The journal and the orphan area.
        let jrn = match journal::parse(
            &lebs,
            &master,
            geometry.log_lebs,
            geometry.leb_size as usize,
        ) {
            Ok(j) => Some(j),
            Err(e) => {
                if std::env::var_os("UBIFS_DEBUG_JOURNAL").is_some() {
                    eprintln!("journal parse failed: {e}");
                }
                None
            }
        };
        let orph_first = geometry.lpt_last() + 1;
        let orphan_inums =
            journal::orphans(&lebs, &master, orph_first, geometry.orph_lebs).unwrap_or_default();

        // The post-replay view.
        let mut collected = Collected::default();
        for leaf in &leaves {
            collect_leaf(&lebs, *leaf, &mut collected)?;
        }
        if let Some(jrn) = &jrn {
            apply_overlay(&mut collected, jrn, &orphan_inums)?;
        }
        collected.finish();

        Ok(Ubifs {
            lebs,
            superblock,
            master,
            geometry,
            lprops,
            leaves,
            collected,
            journal: jrn,
            orphan_inums,
        })
    }

    /// Read the raw bytes of a committed-index leaf (the whole node,
    /// verified).
    pub fn leaf_node(&self, leaf: LeafRef) -> Result<Vec<u8>> {
        let leb = self
            .lebs
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

    /// The main-area lprops (after the totals cross-check).
    pub fn lprops(&self) -> &[Lprops] {
        &self.lprops
    }

    /// The committed-index leaves in-order.
    pub fn leaves(&self) -> &[LeafRef] {
        &self.leaves
    }

    /// Whether the volume was stopped uncleanly (a journal with live
    /// buds over the committed state).
    pub fn is_dirty(&self) -> bool {
        self.master.flags & UBIFS_MST_DIRTY != 0
            || self.journal.as_ref().is_some_and(|j| !j.entries.is_empty())
    }

    /// Find an ino node by inode number.
    pub fn ino_node(&self, inum: u32) -> Result<Option<InoNode>> {
        Ok(self.collected.inos.get(&inum).cloned())
    }

    /// All dents of directory `dir_inum`, sorted by name.
    pub fn dir_entries(&self, dir_inum: u32) -> Result<Vec<Dirent>> {
        let mut out: Vec<Dirent> = self
            .collected
            .dents
            .get(&dir_inum)
            .map(|list| {
                list.iter()
                    .map(|(_, dent)| Dirent {
                        name: String::from_utf8_lossy(&dent.name).into_owned(),
                        inum: dent.inum as u32,
                        itype: dent.itype,
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Resolve a path from the root (`/a/b/c`).
    pub fn lookup(&self, path: &str) -> Result<Option<u32>> {
        let mut inum = UBIFS_ROOT_INO;
        for comp in path.split('/').filter(|s| !s.is_empty()) {
            let entries = self.dir_entries(inum)?;
            match entries.iter().find(|d| d.name == comp) {
                Some(d) => inum = d.inum,
                None => return Ok(None),
            }
        }
        Ok(Some(inum))
    }

    /// Read the contents of a file (blocks of 4 KiB, with decompression).
    pub fn read_file(&self, inum: u32, size: u64) -> Result<Vec<u8>> {
        let mut out = vec![0u8; size as usize];
        if let Some(blocks) = self.collected.data.get(&inum) {
            for (block, chunk) in blocks {
                let off = *block as usize * UBIFS_BLOCK_SIZE;
                if off + chunk.len() > out.len() {
                    return Err(Error::BadNode(format!(
                        "data block {block} overruns file size {size}"
                    )));
                }
                out[off..off + chunk.len()].copy_from_slice(chunk);
            }
        }
        Ok(out)
    }

    /// Extract the whole tree as a plain [`Inode`] tree: hard-linked
    /// files appear at every link (with the shared content and
    /// metadata).
    pub fn extract(&self) -> Result<Inode> {
        let mut visited = Default::default();
        self.assemble(UBIFS_ROOT_INO, &[], &mut visited, false)
    }

    /// Extract the volume into a [`crate::walk::Plan`]: hard links
    /// become [`Kind::Hardlink`] markers plus link groups with the
    /// original write order, so that
    /// [`mkfs_plan`](crate::mkfs::mkfs_plan) can rebuild a byte-identical
    /// image. Extended attributes land in [`Inode::xattrs`] in their
    /// original on-flash order.
    pub fn extract_plan(&self) -> Result<crate::walk::Plan> {
        // Pass 1: count the dents per target inum to spot hard links.
        let mut dent_count: HashMap<u32, u32> = Default::default();
        for list in self.collected.dents.values() {
            for (_, d) in list {
                *dent_count.entry(d.inum as u32).or_insert(0) += 1;
            }
        }
        let mut visited: HashMap<u32, Vec<String>> = Default::default();
        let root = self.assemble(UBIFS_ROOT_INO, &[], &mut visited, true)?;
        let mut link_groups = Vec::new();
        for (inum, path) in &visited {
            if dent_count.get(inum).copied().unwrap_or(0) > 1 {
                let Some(ino) = self.collected.inos.get(inum) else {
                    continue;
                };
                let order_key = self.collected.ino_pos.get(inum).copied().unwrap_or(0);
                link_groups.push(crate::walk::LinkGroup {
                    tree_path: path.clone(),
                    nlink: ino.nlink.max(1),
                    order_key,
                });
            }
        }
        Ok(crate::walk::Plan { root, link_groups })
    }

    /// Assemble the tree of `inum` at `path`. In `plan_mode`, already
    /// visited non-directories become [`Kind::Hardlink`] markers and
    /// `visited` records the first-occurrence path of every non-dir.
    fn assemble(
        &self,
        inum: u32,
        path: &[String],
        visited: &mut HashMap<u32, Vec<String>>,
        plan_mode: bool,
    ) -> Result<Inode> {
        let c = &self.collected;
        let ino = c.inos.get(&inum).ok_or_else(|| {
            Error::NotFound(format!("inode {inum} referenced by index is missing"))
        })?;
        // Xattr inodes are not part of the file tree.
        if ino.flags & UBIFS_XATTR_FL != 0 && inum != UBIFS_ROOT_INO {
            return Err(Error::NotFound(format!("inode {inum} is an xattr inode")));
        }
        let base = Inode {
            mode: ino.mode,
            uid: ino.uid,
            gid: ino.gid,
            atime_sec: ino.atime_sec,
            ctime_sec: ino.ctime_sec,
            mtime_sec: ino.mtime_sec,
            atime_nsec: ino.atime_nsec,
            ctime_nsec: ino.ctime_nsec,
            mtime_nsec: ino.mtime_nsec,
            nlink: ino.nlink,
            flags: ino.flags,
            xattrs: c.xattrs.get(&inum).cloned().unwrap_or_default(),
            kind: Kind::Dir(vec![]),
        };
        let is_dir = ino.mode & 0o170000 == 0o040000;
        if !is_dir && inum != UBIFS_ROOT_INO {
            visited.entry(inum).or_insert_with(|| path.to_vec());
        }
        let kind = match ino.mode & 0o170000 {
            0o040000 => {
                let mut children = Vec::new();
                if let Some(list) = c.dents.get(&inum) {
                    for (_, dent) in list {
                        let child_inum = dent.inum as u32;
                        let name = String::from_utf8_lossy(&dent.name).into_owned();
                        if plan_mode && visited.contains_key(&child_inum) {
                            // A later hard-link occurrence (or a
                            // self-referencing loop): only a marker.
                            let target = visited[&child_inum].clone();
                            let mode = c.inos.get(&child_inum).map(|i| i.mode).unwrap_or(0);
                            children
                                .push((name, Inode::with_kind(mode, Kind::Hardlink { target })));
                            continue;
                        }
                        let mut child_path = path.to_vec();
                        child_path.push(name.clone());
                        let child = self.assemble(child_inum, &child_path, visited, plan_mode)?;
                        children.push((name, child));
                    }
                }
                Kind::Dir(children)
            }
            0o100000 => {
                let mut content = vec![0u8; ino.size as usize];
                if let Some(blocks) = c.data.get(&inum) {
                    for (block, chunk) in blocks {
                        let off = *block as usize * UBIFS_BLOCK_SIZE;
                        if off + chunk.len() > content.len() {
                            return Err(Error::BadNode(format!(
                                "data block {block} overruns file size {}",
                                ino.size
                            )));
                        }
                        content[off..off + chunk.len()].copy_from_slice(chunk);
                    }
                }
                Kind::File(content)
            }
            0o120000 => Kind::Symlink(ino.data.clone()),
            0o020000 | 0o060000 => {
                let mut rdev = 0u64;
                if ino.data.len() >= 8 {
                    rdev = u64::from_le_bytes(ino.data[..8].try_into().unwrap());
                }
                Kind::Dev { rdev }
            }
            0o010000 => Kind::Fifo,
            0o140000 => Kind::Socket,
            m => return Err(Error::BadNode(format!("inode {inum}: unknown mode {m:o}"))),
        };
        Ok(Inode { kind, ..base })
    }

    /// A light consistency check (in the spirit of fsck.ubifs): the
    /// totals were cross-checked at open time; here — tree connectivity:
    /// dents point at existing inodes and data does not exceed file
    /// sizes.
    pub fn verify(&self) -> Result<()> {
        let c = &self.collected;
        for list in c.dents.values() {
            for (_, dent) in list {
                if !c.inos.contains_key(&(dent.inum as u32)) {
                    return Err(Error::NotFound(format!(
                        "dent {:?} targets missing inode {}",
                        String::from_utf8_lossy(&dent.name),
                        dent.inum
                    )));
                }
            }
        }
        for (inum, blocks) in &c.data {
            let Some(ino) = c.inos.get(inum) else {
                return Err(Error::NotFound(format!("data of missing inode {inum}")));
            };
            let mut bytes = 0u64;
            for (block, chunk) in blocks {
                let off = *block as u64 * UBIFS_BLOCK_SIZE as u64 + chunk.len() as u64;
                bytes = bytes.max(off);
            }
            if bytes > ino.size {
                return Err(Error::BadNode(format!(
                    "inode {inum}: data blocks hold {bytes} bytes, size {}",
                    ino.size
                )));
            }
        }
        Ok(())
    }
}

/// Gather one committed-index leaf into the working maps. Dents and
/// xents keep their on-flash position — the original mkfs write order.
fn collect_leaf(lebs: &[Option<Vec<u8>>], leaf: LeafRef, c: &mut Collected) -> Result<()> {
    let leb = lebs
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
    let pos = (leaf.lnum as u64) << 32 | leaf.offs as u64;
    match node[20] {
        UBIFS_INO_NODE => {
            let ino = InoNode::parse(node)?;
            c.ino_pos.insert(ino.key.inum, pos);
            c.inos.insert(ino.key.inum, ino);
        }
        UBIFS_DENT_NODE => {
            let dent = DentNode::parse(node)?;
            c.dents.entry(dent.key.inum).or_default().push((pos, dent));
        }
        UBIFS_DATA_NODE => {
            let dn = DataNode::parse(node)?;
            let content = decompress(dn.compr_type, &dn.data, dn.size as usize)?;
            c.data
                .entry(dn.key.inum)
                .or_default()
                .insert(dn.key.block_or_hash, content);
        }
        UBIFS_XENT_NODE => {
            let xent = DentNode::parse(node)?;
            c.raw_xents.push((
                pos,
                xent.key.inum,
                String::from_utf8_lossy(&xent.name).into_owned(),
                xent.inum as u32,
            ));
        }
        t => return Err(Error::BadNode(format!("unexpected leaf type {t}"))),
    }
    Ok(())
}

impl Collected {
    /// Sort the per-parent dent lists into the original write order and
    /// build the xattrs map from the raw xent stream (position order =
    /// the original write order, journal entries appended after the
    /// committed ones).
    fn finish(&mut self) {
        for list in self.dents.values_mut() {
            list.sort_by_key(|(pos, _)| *pos);
        }
        self.finish_xattrs();
    }

    fn finish_xattrs(&mut self) {
        self.raw_xents.sort_by_key(|(pos, _, _, _)| *pos);
        let raw = std::mem::take(&mut self.raw_xents);
        for (_, host, name, attr_inum) in raw {
            let value = self
                .inos
                .get(&attr_inum)
                .map(|ino| ino.data.clone())
                .unwrap_or_default();
            let list = self.xattrs.entry(host).or_default();
            // A same-named journal xattr replaces the committed value.
            list.retain(|(n, _)| *n != name);
            list.push((name, value));
        }
    }
}

/// Apply the journal overlay: orphans first, then the per-key
/// max-sqnum-winning entries, then truncations.
fn apply_overlay(c: &mut Collected, j: &journal::Journal, orphan_inums: &[u32]) -> Result<()> {
    // Orphans and nlink-0 journal inodes: every key of the inode dies.
    let mut dead: HashSet<u32> = orphan_inums.iter().copied().collect();

    // The winning entry per key (max sqnum).
    let mut best: BTreeMap<u64, &journal::JournalEntry> = BTreeMap::new();
    for e in &j.entries {
        let k = e.key.as_u64();
        match best.get(&k) {
            Some(prev) if prev.sqnum >= e.sqnum => {}
            _ => {
                best.insert(k, e);
            }
        }
    }
    // Deletion markers whose key no longer has a live writer also mark
    // the TARGET inum dead (kernel: last_reference handling) — only when
    // the deletion is the winner.
    for e in best.values() {
        if let JournalNode::Ino(ino) = &e.node {
            if ino.nlink == 0 {
                dead.insert(ino.key.inum);
            }
        }
    }

    // Winning truncations per inum (max sqnum).
    let mut truns: HashMap<u32, (u64, u64)> = HashMap::new(); // inum -> (sqnum, new_size)
    for e in best.values() {
        if let JournalNode::Trun { inum, new_size, .. } = &e.node {
            let t = truns.entry(*inum).or_insert((0, 0));
            if e.sqnum > t.0 {
                *t = (e.sqnum, *new_size);
            }
        }
    }

    // Apply the winning entries.
    for e in best.values() {
        if let JournalNode::Trun { .. } = &e.node {
            continue; // applied below
        }
        match &e.node {
            JournalNode::Ino(ino) => {
                if dead.contains(&ino.key.inum) {
                    continue;
                }
                c.inos.insert(ino.key.inum, ino.clone());
            }
            JournalNode::Data(dn) => {
                if dead.contains(&dn.key.inum) {
                    continue;
                }
                // A truncation newer than this block kills it.
                if let Some((trun_sqnum, new_size)) = truns.get(&dn.key.inum) {
                    if *trun_sqnum > e.sqnum {
                        let block = dn.key.block_or_hash as u64;
                        if block * UBIFS_BLOCK_SIZE as u64 >= *new_size {
                            continue;
                        }
                    }
                }
                let content = decompress(dn.compr_type, &dn.data, dn.size as usize)?;
                c.data
                    .entry(dn.key.inum)
                    .or_default()
                    .insert(dn.key.block_or_hash, content);
            }
            JournalNode::Dent(dent) => {
                if dead.contains(&dent.key.inum) {
                    continue;
                }
                let list = c.dents.entry(dent.key.inum).or_default();
                list.retain(|(_, d)| d.key.as_u64() != e.key.as_u64());
                if !e.deletion {
                    // Journal dents sort after every committed position
                    // (in sqnum order among themselves).
                    list.push((u64::MAX - e.sqnum, dent.clone()));
                }
            }
            JournalNode::Xent(xent) => {
                if dead.contains(&xent.key.inum) {
                    continue;
                }
                let name = String::from_utf8_lossy(&xent.name).into_owned();
                if e.deletion {
                    c.raw_xents.retain(|(_, _, n, _)| *n != name);
                    c.xattrs
                        .entry(xent.key.inum)
                        .or_default()
                        .retain(|(n, _)| *n != name);
                } else {
                    // Journal entries sort after every committed position
                    // (in sqnum order among themselves).
                    c.raw_xents
                        .push((u64::MAX - e.sqnum, xent.key.inum, name, xent.inum as u32));
                }
            }
            JournalNode::Trun { .. } => unreachable!(),
        }
    }

    // Truncations: drop the stale tail and fix the inode size unless a
    // newer inode node already carries it.
    for (inum, (trun_sqnum, new_size)) in truns {
        if dead.contains(&inum) {
            continue;
        }
        if let Some(blocks) = c.data.get_mut(&inum) {
            let keep_blocks = new_size.div_ceil(UBIFS_BLOCK_SIZE as u64) as u32;
            blocks.retain(|block, _| *block < keep_blocks);
        }
        if let Some(ino) = c.inos.get_mut(&inum) {
            let ino_is_newer = best
                .get(&Key::ino(inum).as_u64())
                .map(|e| e.sqnum > trun_sqnum)
                .unwrap_or(false);
            if !ino_is_newer && ino.size > new_size {
                ino.size = new_size;
            }
        }
    }

    // Finally drop everything belonging to dead inodes.
    for inum in &dead {
        c.inos.remove(inum);
        c.dents.remove(inum);
        c.data.remove(inum);
        c.xattrs.remove(inum);
        c.ino_pos.remove(inum);
    }
    // And the dents pointing at them.
    let lists: Vec<u32> = c.dents.keys().copied().collect();
    for parent in lists {
        if let Some(list) = c.dents.get_mut(&parent) {
            list.retain(|(_, d)| !dead.contains(&(d.inum as u32)));
        }
    }
    Ok(())
}
