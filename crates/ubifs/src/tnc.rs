//! The TNC index (a B-tree of keys): building at mkfs time (a port of
//! `write_index` from mkfs.ubifs.c) and reading/searching the committed
//! index.

use crate::error::{Error, Result};
use crate::key::Key;
use crate::media::*;

/// An entry for index building: a key plus the leaf node position.
#[derive(Debug, Clone)]
pub struct IdxEntry {
    /// The node key.
    pub key: Key,
    /// The name (DENT/XENT only — the secondary sort key on hash
    /// collisions, like `namecmp` in mkfs).
    pub name: Vec<u8>,
    /// The leaf node LEB.
    pub lnum: u32,
    /// The leaf node offset.
    pub offs: u32,
    /// The leaf node length.
    pub len: u32,
}

/// The node sink used while building the index — the mkfs write head
/// (`add_idx_node`): fills in the common header with the next sqnum,
/// reserves space with 8-byte alignment and pads the tail with 0xFF.
pub trait NodeSink {
    /// Write a node: `node` carries the body with a zeroed `[0..24]`
    /// header (the node length is `node.len()`); the implementation fills
    /// in `ch`, writes the node and returns (lnum, offs, len).
    fn put(&mut self, node_type: u8, node: Vec<u8>) -> Result<(u32, u32, u32)>;
    /// The index head position (`ihead_lnum`,
    /// `ALIGN(head_offs, min_io)`) — taken BEFORE the final flush.
    fn ihead(&self) -> (u32, u32);
}

/// The result of index building.
pub struct IndexResult {
    /// The root branch (zroot: the root idx node position).
    pub root: Branch,
    /// The index head position (before the final flush).
    pub ihead: (u32, u32),
    /// The on-flash index size (the sum of aligned lengths,
    /// `bi.old_idx_sz`).
    pub index_size: u64,
}

/// Entry comparison as `cmp_idx`: key first, then name.
fn cmp_entries(a: &IdxEntry, b: &IdxEntry) -> std::cmp::Ordering {
    a.key.cmp(&b.key).then_with(|| a.name.cmp(&b.name))
}

/// Build the index and write the idx nodes into `sink`.
pub fn write_index(
    sink: &mut dyn NodeSink,
    fanout: u32,
    leb_size: u32,
    mut entries: Vec<IdxEntry>,
) -> Result<IndexResult> {
    if fanout < 2 {
        return Err(Error::BadGeometry(format!("bad fanout {fanout}")));
    }
    let fanout = fanout as usize;
    let leb_size = leb_size as usize;
    entries.sort_by(cmp_entries);
    let leaf_cnt = entries.len();

    let mut index_size: u64 = 0;
    let mut zroot = Branch {
        lnum: 0,
        offs: 0,
        len: 0,
        key: Key::default(),
    };

    // The (lnum, offs, len) positions of the nodes of the current level.
    let mut level_positions: Vec<(u32, u32, u32)> = Vec::new();

    // Level 0: branches to leaf nodes; the node key is the key of its
    // first leaf.
    let cnt = leaf_cnt.div_ceil(fanout);
    let mut pos = 0usize;
    for i in 0..cnt {
        let child_cnt = last_cnt(i, cnt, leaf_cnt, fanout);
        let len = idx_node_sz(child_cnt);
        let mut node = vec![0u8; len];
        node[24..26].copy_from_slice(&(child_cnt as u16).to_le_bytes());
        // level == 0
        for (j, e) in entries[pos..pos + child_cnt].iter().enumerate() {
            let off = UBIFS_IDX_NODE_SZ + j * UBIFS_BRANCH_SZ;
            node[off..off + 4].copy_from_slice(&e.lnum.to_le_bytes());
            node[off + 4..off + 8].copy_from_slice(&e.offs.to_le_bytes());
            node[off + 8..off + 12].copy_from_slice(&e.len.to_le_bytes());
            e.key.write_le8(&mut node[off + 12..off + 20]);
        }
        let (lnum, offs, len) = sink.put(UBIFS_IDX_NODE, node)?;
        index_size += align8(len as usize) as u64;
        zroot = Branch {
            lnum,
            offs,
            len,
            key: entries[pos].key,
        };
        level_positions.push((lnum, offs, len));
        pos += child_cnt;
    }

    // The levels above. The key of branch (i, j) is the key of leaf
    // (i*fanout + j) * pstep (the first leaf under the branch); the
    // positions of the level below are computed arithmetically with an
    // 8-byte step and a carry to the next LEB.
    let mut level: u16 = 0;
    while level_positions.len() > 1 {
        level += 1;
        let bcnt = level_positions.len();
        let blast_len = level_positions.last().unwrap().2;
        let cnt = bcnt.div_ceil(fanout);
        let pstep = fanout.pow(level as u32);
        let mut next: Vec<(u32, u32, u32)> = Vec::with_capacity(cnt);
        let mut blnum = level_positions[0].0;
        let mut boffs = level_positions[0].1 as usize;
        for i in 0..cnt {
            let child_cnt = last_cnt(i, cnt, bcnt, fanout);
            let len = idx_node_sz(child_cnt);
            let mut node = vec![0u8; len];
            node[24..26].copy_from_slice(&(child_cnt as u16).to_le_bytes());
            node[26..28].copy_from_slice(&level.to_le_bytes());
            for j in 0..child_cnt {
                let bn = i * fanout + j;
                let (_, _, row_len) = level_positions[bn];
                let blen = if bn == bcnt - 1 { blast_len } else { row_len } as usize;
                if boffs + blen > leb_size {
                    blnum += 1;
                    boffs = 0;
                }
                let off = UBIFS_IDX_NODE_SZ + j * UBIFS_BRANCH_SZ;
                node[off..off + 4].copy_from_slice(&blnum.to_le_bytes());
                node[off + 4..off + 8].copy_from_slice(&(boffs as u32).to_le_bytes());
                node[off + 8..off + 12].copy_from_slice(&(blen as u32).to_le_bytes());
                let leaf_idx = bn * pstep;
                entries[leaf_idx]
                    .key
                    .write_le8(&mut node[off + 12..off + 20]);
                boffs += align8(blen);
            }
            let (lnum, offs, len) = sink.put(UBIFS_IDX_NODE, node)?;
            index_size += align8(len as usize) as u64;
            zroot = Branch {
                lnum,
                offs,
                len,
                key: Key::default(),
            };
            next.push((lnum, offs, len));
        }
        level_positions = next;
    }

    // The root key is never used during lookup; mkfs leaves the key of
    // the tree's first leaf there.
    zroot.key = entries[0].key;

    let ihead = sink.ihead();
    Ok(IndexResult {
        root: zroot,
        ihead,
        index_size,
    })
}

fn last_cnt(i: usize, cnt: usize, total: usize, fanout: usize) -> usize {
    if i == cnt - 1 {
        let rem = total % fanout;
        if rem == 0 {
            fanout
        } else {
            rem
        }
    } else {
        fanout
    }
}

fn align8(x: usize) -> usize {
    x.div_ceil(8) * 8
}

// ---------------------------------------------------------------------------
// Reading the index.
// ---------------------------------------------------------------------------

/// A leaf node found in the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafRef {
    /// The leaf node LEB.
    pub lnum: u32,
    /// The leaf node offset.
    pub offs: u32,
    /// The leaf node length.
    pub len: u32,
    /// The leaf node key.
    pub key: Key,
}

/// A walker over the committed index backed by a LEB source.
pub struct Tnc<'a> {
    src: &'a dyn crate::lpt::LebSource,
}

impl<'a> Tnc<'a> {
    /// Create a walker over a LEB source.
    pub fn new(src: &'a dyn crate::lpt::LebSource) -> Tnc<'a> {
        Tnc { src }
    }

    fn node_at(&self, lnum: u32, offs: u32, len: u32) -> Result<Vec<u8>> {
        let leb = self
            .src
            .leb(lnum)
            .ok_or_else(|| Error::MissingData(format!("index leb {lnum} is unmapped")))?;
        let offs = offs as usize;
        let len = len as usize;
        if offs + len > leb.len() {
            return Err(Error::BadNode(format!(
                "node at {lnum}:{offs} overruns leb"
            )));
        }
        let (node, _) = parse_node(&leb[offs..], len, "index node")?;
        Ok(node.to_vec())
    }

    /// Read the idx node a branch points to.
    pub fn idx_node(&self, br: Branch) -> Result<IdxNode> {
        let node = self.node_at(br.lnum, br.offs, br.len)?;
        if node[20] != UBIFS_IDX_NODE {
            return Err(Error::BadNode(format!(
                "expected idx node at {}:{}, got type {}",
                br.lnum, br.offs, node[20]
            )));
        }
        IdxNode::parse(&node)
    }

    /// Read a leaf node by reference.
    pub fn leaf_node(&self, leaf: LeafRef) -> Result<Vec<u8>> {
        self.node_at(leaf.lnum, leaf.offs, leaf.len)
    }

    /// Walk the whole tree in-order (in ascending key order).
    pub fn walk(
        &self,
        root: Branch,
        mut visit: impl FnMut(LeafRef) -> Result<()>,
    ) -> Result<usize> {
        enum Item {
            Idx(IdxNode, usize),
            Leaf(LeafRef),
        }
        let mut count = 0usize;
        let mut stack: Vec<Item> = vec![Item::Idx(self.idx_node(root)?, 0)];
        while let Some(item) = stack.pop() {
            match item {
                Item::Leaf(leaf) => {
                    count += 1;
                    visit(leaf)?;
                }
                Item::Idx(node, next) => {
                    if next < node.branches.len() {
                        stack.push(Item::Idx(node.clone(), next + 1));
                        let br = node.branches[next];
                        if node.level == 0 {
                            stack.push(Item::Leaf(LeafRef {
                                lnum: br.lnum,
                                offs: br.offs,
                                len: br.len,
                                key: br.key,
                            }));
                        } else {
                            let child = self.idx_node(br)?;
                            if child.level != node.level - 1 {
                                return Err(Error::BadNode(format!(
                                    "index level mismatch: {} != {}",
                                    child.level,
                                    node.level - 1
                                )));
                            }
                            stack.push(Item::Idx(child, 0));
                        }
                    }
                }
            }
        }
        Ok(count)
    }

    /// Find a leaf by key (an exact match). On a dent hash collision this
    /// returns the first leaf with the given key — keep enumerating via
    /// [`Tnc::next_leaf`].
    pub fn lookup(&self, root: Branch, key: &Key) -> Result<Option<LeafRef>> {
        let mut cur = root;
        loop {
            let node = self.idx_node(cur)?;
            // Branches are sorted by key: take the last branch with a key
            // <= the wanted one.
            let mut best: Option<Branch> = None;
            for br in &node.branches {
                match br.key.cmp(key) {
                    std::cmp::Ordering::Less | std::cmp::Ordering::Equal => best = Some(*br),
                    std::cmp::Ordering::Greater => break,
                }
            }
            let Some(br) = best else { return Ok(None) };
            if node.level == 0 {
                return if br.key == *key {
                    Ok(Some(LeafRef {
                        lnum: br.lnum,
                        offs: br.offs,
                        len: br.len,
                        key: br.key,
                    }))
                } else {
                    Ok(None)
                };
            }
            cur = br;
        }
    }

    /// The first leaf with a key >= `after` (in-order) — for enumerating
    /// dent collisions and iterating over ranges.
    pub fn next_leaf(&self, root: Branch, after: &Key) -> Result<Option<LeafRef>> {
        let mut stack: Vec<(IdxNode, usize)> = vec![(self.idx_node(root)?, 0)];
        while let Some((node, ref mut next)) = stack.last_mut() {
            if *next >= node.branches.len() {
                stack.pop();
                continue;
            }
            let i = *next;
            *next += 1;
            let br = node.branches[i];
            if node.level == 0 {
                if br.key >= *after {
                    return Ok(Some(LeafRef {
                        lnum: br.lnum,
                        offs: br.offs,
                        len: br.len,
                        key: br.key,
                    }));
                }
            } else if br.key >= *after || i + 1 == node.branches.len() {
                let child = self.idx_node(br)?;
                stack.push((child, 0));
            }
        }
        Ok(None)
    }
}
