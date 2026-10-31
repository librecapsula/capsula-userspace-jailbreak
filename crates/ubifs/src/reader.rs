//! Reading a UBIFS volume: the superblock/master, the LPT, the committed
//! index and high-level filesystem access (lookup/list/read/extract).

use std::collections::BTreeMap;

use crate::compress::decompress;
use crate::error::{Error, Result};
use crate::geometry::Geometry;
use crate::key::{Key, UBIFS_DENT_KEY};
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

/// The working maps of an extraction pass.
#[derive(Default)]
struct Collected {
    inos: BTreeMap<u32, InoNode>,
    /// inum → the on-flash position of its ino node (the write order).
    ino_pos: std::collections::HashMap<u32, u64>,
    /// Parent inum → dents in original write order.
    dents: BTreeMap<u32, Vec<DentNode>>,
    data: BTreeMap<u32, BTreeMap<u32, Vec<u8>>>,
    /// Host inum → xattrs in original write order.
    xattrs: BTreeMap<u32, Vec<(String, Vec<u8>)>>,
}

impl Ubifs {
    /// Open a volume: parse the SB/MST, read the LPT, cross-check the
    /// totals (as in `lpt_init_rd` + the mount checks) and walk the
    /// index.
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

        Ok(Ubifs {
            lebs,
            superblock,
            master,
            geometry,
            lprops,
            leaves,
        })
    }

    /// The main-area lprops (after the totals cross-check).
    pub fn lprops(&self) -> &[Lprops] {
        &self.lprops
    }

    /// The index leaves in-order.
    pub fn leaves(&self) -> &[LeafRef] {
        &self.leaves
    }

    fn leaf_bytes(&self, leaf: LeafRef) -> Result<Vec<u8>> {
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

    /// The range of leaves with the given key (start..end) — a binary
    /// search.
    fn key_range(&self, key: &Key) -> (usize, usize) {
        let start = self.leaves.partition_point(|l| l.key < *key);
        let end = start + self.leaves[start..].partition_point(|l| l.key == *key);
        (start, end)
    }

    /// Find an ino node by inode number.
    pub fn ino_node(&self, inum: u32) -> Result<Option<InoNode>> {
        let (s, e) = self.key_range(&Key::ino(inum));
        if s == e {
            return Ok(None);
        }
        let node = self.leaf_bytes(self.leaves[s])?;
        Ok(Some(InoNode::parse(&node)?))
    }

    /// All dents of directory `dir_inum`, sorted by name (inside equal
    /// keys the order is by name — as in the index).
    pub fn dir_entries(&self, dir_inum: u32) -> Result<Vec<Dirent>> {
        let mut out = Vec::new();
        // The first dent key of the directory: (dir, DENT, hash). Hashes
        // are >= 3, but the search starts from the lower key bound.
        let mut probe = Key {
            inum: dir_inum,
            key_type: UBIFS_DENT_KEY,
            block_or_hash: 0,
        };
        // A binary search over all directory keys: the dents of a
        // directory form a contiguous range between (dir, DENT, 0) and
        // (dir, DENT+1, 0).
        let start = self.leaves.partition_point(|l| l.key < probe);
        probe.key_type = UBIFS_DENT_KEY + 1;
        let end = self.leaves.partition_point(|l| l.key < probe);
        for leaf in &self.leaves[start..end] {
            let node = self.leaf_bytes(*leaf)?;
            let dent = DentNode::parse(&node)?;
            out.push(Dirent {
                name: String::from_utf8_lossy(&dent.name).into_owned(),
                inum: dent.inum as u32,
                itype: dent.itype,
            });
        }
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
        let mut block = 0u32;
        loop {
            let key = Key::data(inum, block);
            let (s, e) = self.key_range(&key);
            if s == e {
                break;
            }
            let node = self.leaf_bytes(self.leaves[s])?;
            let dn = DataNode::parse(&node)?;
            let data = decompress(dn.compr_type, &dn.data, dn.size as usize)?;
            let off = block as usize * UBIFS_BLOCK_SIZE;
            if off + data.len() > out.len() {
                return Err(Error::BadNode(format!(
                    "data block {block} overruns file size {size}"
                )));
            }
            out[off..off + data.len()].copy_from_slice(&data);
            block += 1;
        }
        Ok(out)
    }

    /// Extract the whole tree as a plain [`Inode`] tree: hard-linked
    /// files appear at every link (with the shared content and
    /// metadata).
    pub fn extract(&self) -> Result<Inode> {
        let c = self.collect()?;
        let mut visited = Default::default();
        self.assemble(&c, UBIFS_ROOT_INO, &[], &mut visited, false)
    }

    /// Extract the volume into a [`crate::walk::Plan`]: hard links
    /// become [`Kind::Hardlink`] markers plus link groups with the
    /// original write order, so that
    /// [`mkfs_plan`](crate::mkfs::mkfs_plan) can rebuild a byte-identical
    /// image. Extended attributes land in [`Inode::xattrs`] in their
    /// original on-flash order.
    pub fn extract_plan(&self) -> Result<crate::walk::Plan> {
        let c = self.collect()?;
        // Pass 1: count the dents per target inum to spot hard links.
        let mut dent_count: std::collections::HashMap<u32, u32> = Default::default();
        for list in c.dents.values() {
            for d in list {
                *dent_count.entry(d.inum as u32).or_insert(0) += 1;
            }
        }
        let mut visited: std::collections::HashMap<u32, Vec<String>> = Default::default();
        let root = self.assemble(&c, UBIFS_ROOT_INO, &[], &mut visited, true)?;
        let mut link_groups = Vec::new();
        for (inum, path) in &visited {
            if dent_count.get(inum).copied().unwrap_or(0) > 1 {
                let Some(ino) = c.inos.get(inum) else {
                    continue;
                };
                let order_key = c.ino_pos.get(inum).copied().unwrap_or(0);
                link_groups.push(crate::walk::LinkGroup {
                    tree_path: path.clone(),
                    nlink: ino.nlink.max(1),
                    order_key,
                });
            }
        }
        Ok(crate::walk::Plan { root, link_groups })
    }

    /// Gather every leaf into the working maps (one pass over the leaf
    /// cache). Dents and xents are ordered by their on-flash position —
    /// the original mkfs write order (readdir order); xattr inodes stay
    /// out of the file tree.
    fn collect(&self) -> Result<Collected> {
        let mut c = Collected::default();
        // (position, node) per kind — position = the write order of the
        // node on flash.
        let mut dents: BTreeMap<u32, Vec<(u64, DentNode)>> = BTreeMap::new();
        let mut xents: Vec<(u64, u32, String, u32)> = Vec::new();
        for leaf in &self.leaves {
            let node = self.leaf_bytes(*leaf)?;
            let pos = (leaf.lnum as u64) << 32 | leaf.offs as u64;
            match node[20] {
                UBIFS_INO_NODE => {
                    let ino = InoNode::parse(&node)?;
                    c.ino_pos.insert(ino.key.inum, pos);
                    c.inos.insert(ino.key.inum, ino);
                }
                UBIFS_DENT_NODE => {
                    let dent = DentNode::parse(&node)?;
                    dents.entry(dent.key.inum).or_default().push((pos, dent));
                }
                UBIFS_DATA_NODE => {
                    let dn = DataNode::parse(&node)?;
                    let content = decompress(dn.compr_type, &dn.data, dn.size as usize)?;
                    c.data
                        .entry(dn.key.inum)
                        .or_default()
                        .insert(dn.key.block_or_hash, content);
                }
                UBIFS_XENT_NODE => {
                    let xent = DentNode::parse(&node)?;
                    xents.push((
                        pos,
                        xent.key.inum,
                        String::from_utf8_lossy(&xent.name).into_owned(),
                        xent.inum as u32,
                    ));
                }
                t => return Err(Error::BadNode(format!("unexpected leaf type {t}"))),
            }
        }
        for (parent, list) in dents {
            let mut list = list;
            list.sort_by_key(|(pos, _)| *pos);
            c.dents
                .insert(parent, list.into_iter().map(|(_, d)| d).collect());
        }
        xents.sort_by_key(|(pos, _, _, _)| *pos);
        for (_, host, name, attr_inum) in xents {
            let value = c
                .inos
                .get(&attr_inum)
                .map(|ino| ino.data.clone())
                .unwrap_or_default();
            c.xattrs.entry(host).or_default().push((name, value));
        }
        Ok(c)
    }

    /// Assemble the tree of `inum` at `path`. In `plan_mode`, already
    /// visited non-directories become [`Kind::Hardlink`] markers and
    /// `visited` records the first-occurrence path of every non-dir.
    fn assemble(
        &self,
        c: &Collected,
        inum: u32,
        path: &[String],
        visited: &mut std::collections::HashMap<u32, Vec<String>>,
        plan_mode: bool,
    ) -> Result<Inode> {
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
                    for dent in list {
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
                        let child =
                            self.assemble(c, child_inum, &child_path, visited, plan_mode)?;
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
        let mut inos: BTreeMap<u32, (u64, u32)> = BTreeMap::new();
        let mut data_max: BTreeMap<u32, (u32, u64)> = BTreeMap::new();
        for leaf in &self.leaves {
            let node = self.leaf_bytes(*leaf)?;
            match node[20] {
                UBIFS_INO_NODE => {
                    let ino = InoNode::parse(&node)?;
                    inos.insert(ino.key.inum, (ino.size, ino.mode));
                }
                UBIFS_DATA_NODE => {
                    let dn = DataNode::parse(&node)?;
                    let e = data_max.entry(dn.key.inum).or_insert((0, 0));
                    e.0 = e.0.max(dn.key.block_or_hash);
                    e.1 += dn.size as u64;
                }
                UBIFS_DENT_NODE | UBIFS_XENT_NODE => {}
                t => return Err(Error::BadNode(format!("unexpected leaf type {t}"))),
            }
        }
        for leaf in &self.leaves {
            let node = self.leaf_bytes(*leaf)?;
            if node[20] != UBIFS_DENT_NODE {
                continue;
            }
            let dent = DentNode::parse(&node)?;
            let Some(&(_size, _mode)) = inos.get(&(dent.inum as u32)) else {
                return Err(Error::NotFound(format!(
                    "dent {:?} targets missing inode {}",
                    String::from_utf8_lossy(&dent.name),
                    dent.inum
                )));
            };
        }
        for (inum, (max_block, bytes)) in data_max {
            let Some(&(size, _)) = inos.get(&inum) else {
                return Err(Error::NotFound(format!("data of missing inode {inum}")));
            };
            if bytes > size {
                return Err(Error::BadNode(format!(
                    "inode {inum}: data blocks hold {bytes} bytes, size {size}"
                )));
            }
            let _ = max_block;
        }
        Ok(())
    }
}
