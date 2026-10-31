//! The journal: the log (CS + bud references), bud scanning and the
//! orphan area — the pieces needed to replay the post-commit state of
//! an uncleanly stopped volume (a port of the reader side of
//! `fs/ubifs/log.c`, `replay.c` and `orphan.c`).
//!
//! Replaying the journal of the *current* commit is idempotent (the
//! committed index already references those very nodes), so the overlay
//! built here can be applied unconditionally, exactly like the kernel
//! replays on every mount.

use crate::error::{Error, Result};
use crate::key::Key;
use crate::lpt::LebSource;
use crate::media::*;

/// A bud reference from the log (`struct ubifs_ref_node`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudRef {
    /// The bud LEB.
    pub lnum: u32,
    /// Where the bud data starts in the LEB.
    pub offs: u32,
    /// The journal head the bud belongs to.
    pub jhead: u32,
}

/// One node recovered from a bud.
#[derive(Debug, Clone)]
pub enum JournalNode {
    /// An inode node.
    Ino(InoNode),
    /// A directory entry (`deletion` is tracked on the entry).
    Dent(DentNode),
    /// An xattr entry.
    Xent(DentNode),
    /// A data block.
    Data(DataNode),
    /// A truncation record.
    Trun {
        /// The truncated inode.
        inum: u32,
        /// The size before truncation.
        old_size: u64,
        /// The size after truncation.
        new_size: u64,
    },
}

/// One journal entry: the key, the sqnum (the replay order), the node,
/// and whether it is a deletion marker (a dent/xent with `inum == 0`,
/// as `ubifs_jnl_write_deletion` writes them).
#[derive(Debug, Clone)]
pub struct JournalEntry {
    /// The node key (TRUN: a synthetic ino-scoped key).
    pub key: Key,
    /// The sequence number.
    pub sqnum: u64,
    /// The node contents.
    pub node: JournalNode,
    /// Whether this entry deletes its key.
    pub deletion: bool,
}

/// The parsed journal.
#[derive(Debug, Clone, Default)]
pub struct Journal {
    /// The sqnum of the commit start node.
    pub cs_sqnum: u64,
    /// The bud references, in log order.
    pub refs: Vec<BudRef>,
    /// The bud nodes, in bud scan order (their sqnums give the order
    /// per key).
    pub entries: Vec<JournalEntry>,
}

/// Parse the journal of a volume: walk the log from
/// `master.log_lnum` (the log head — the LEB holding the CS node of the
/// current commit), collect bud references and scan the buds. The log
/// ends where older, already-committed leftovers begin (nodes with
/// sqnum below the CS sqnum) or at an empty LEB.
pub fn parse(
    lebs: &dyn LebSource,
    master: &Master,
    log_lebs: u32,
    leb_size: usize,
) -> Result<Journal> {
    let log_first = UBIFS_LOG_LNUM;
    let log_last = log_first + log_lebs - 1;
    if !(log_first..=log_last).contains(&master.log_lnum) {
        return Err(Error::BadGeometry(format!(
            "master log_lnum {} is outside the log area",
            master.log_lnum
        )));
    }

    let mut j = Journal::default();
    let head_lnum = master.log_lnum;
    let mut lnum = head_lnum;
    while let Some(leb) = lebs.leb(lnum) {
        let mut offs = 0usize;
        let mut first = true;
        while offs + UBIFS_CH_SZ <= leb.len() && offs < leb_size {
            let Ok((node, ch)) = parse_node(&leb[offs..], leb.len() - offs, "log node") else {
                break; // an empty/corrupted log tail ends the log
            };
            if first {
                if ch.node_type != UBIFS_CS_NODE {
                    return Err(Error::BadNode(format!(
                        "the first log node at LEB {lnum} is not a CS node"
                    )));
                }
                let cs = CsNode::parse(node)?;
                if cs.cmt_no != master.cmt_no {
                    return Err(Error::BadNode(format!(
                        "log CS commit {} != master {}",
                        cs.cmt_no, master.cmt_no
                    )));
                }
                j.cs_sqnum = ch.sqnum;
                first = false;
                offs += node.len().div_ceil(8) * 8;
                continue;
            }
            // Older leftovers: the log wrapped into data of the previous
            // rotation.
            if ch.sqnum < j.cs_sqnum {
                break;
            }
            match ch.node_type {
                UBIFS_REF_NODE => {
                    let lnum_ref = u32::from_le_bytes(node[24..28].try_into().unwrap());
                    let offs_ref = u32::from_le_bytes(node[28..32].try_into().unwrap());
                    let jhead = u32::from_le_bytes(node[32..36].try_into().unwrap());
                    j.refs.push(BudRef {
                        lnum: lnum_ref,
                        offs: offs_ref,
                        jhead,
                    });
                }
                UBIFS_PAD_NODE => {}
                t => {
                    return Err(Error::BadNode(format!(
                        "unexpected node type {t} in the log"
                    )));
                }
            }
            offs += node.len().div_ceil(8) * 8;
        }
        if first {
            if lnum == head_lnum {
                // The log head must always start with a CS node.
                return Err(Error::BadNode(format!(
                    "log head LEB {lnum} has no commit start node"
                )));
            }
            // Beyond the head an empty LEB is the normal log end.
            break;
        }
        lnum = if lnum == log_last {
            log_first
        } else {
            lnum + 1
        };
        if lnum == master.log_lnum {
            break; // a full circle
        }
    }

    // The buds must live inside the volume (validate_ref).
    for r in &j.refs {
        if lebs.leb(r.lnum).is_none() {
            return Err(Error::BadNode(format!("bud leb {} is unmapped", r.lnum)));
        }
    }
    // Scan the buds (in log order).
    for r in j.refs.clone() {
        scan_bud(lebs, r, &mut j.entries)?;
    }
    Ok(j)
}

/// Scan one bud LEB from the reference offset, collecting the journal
/// nodes. A corrupted tail (an unclean shutdown mid-write) simply ends
/// the scan.
fn scan_bud(lebs: &dyn LebSource, r: BudRef, out: &mut Vec<JournalEntry>) -> Result<()> {
    let Some(leb) = lebs.leb(r.lnum) else {
        return Ok(());
    };
    let mut offs = r.offs as usize;
    while offs + UBIFS_CH_SZ <= leb.len() {
        let Ok((node, ch)) = parse_node(&leb[offs..], leb.len() - offs, "bud node") else {
            break;
        };
        match ch.node_type {
            UBIFS_PAD_NODE => {}
            UBIFS_INO_NODE => {
                let ino = InoNode::parse(node)?;
                out.push(JournalEntry {
                    key: ino.key,
                    sqnum: ch.sqnum,
                    node: JournalNode::Ino(ino),
                    deletion: false,
                });
            }
            UBIFS_DENT_NODE | UBIFS_XENT_NODE => {
                let dent = DentNode::parse(node)?;
                let deletion = dent.inum == 0;
                out.push(JournalEntry {
                    key: dent.key,
                    sqnum: ch.sqnum,
                    node: if ch.node_type == UBIFS_DENT_NODE {
                        JournalNode::Dent(dent)
                    } else {
                        JournalNode::Xent(dent)
                    },
                    deletion,
                });
            }
            UBIFS_DATA_NODE => {
                let dn = DataNode::parse(node)?;
                out.push(JournalEntry {
                    key: dn.key,
                    sqnum: ch.sqnum,
                    node: JournalNode::Data(dn),
                    deletion: false,
                });
            }
            UBIFS_TRUN_NODE => {
                // struct ubifs_trun_node: inum @24, old_size @40,
                // new_size @48.
                let inum = u32::from_le_bytes(node[24..28].try_into().unwrap());
                let old_size = u64::from_le_bytes(node[40..48].try_into().unwrap());
                let new_size = u64::from_le_bytes(node[48..56].try_into().unwrap());
                out.push(JournalEntry {
                    key: Key::ino(inum),
                    sqnum: ch.sqnum,
                    node: JournalNode::Trun {
                        inum,
                        old_size,
                        new_size,
                    },
                    deletion: false,
                });
            }
            _ => break, // not a journal node: the bud data ended
        }
        offs += node.len().div_ceil(8) * 8;
    }
    Ok(())
}

/// Read the orphan area (`ubifs_mount_orphans`, read side): the inodes
/// deleted while still referenced — every key of such an inode is
/// dropped at replay. Only orphan nodes of the current commit count.
pub fn orphans(
    lebs: &dyn LebSource,
    master: &Master,
    orph_first: u32,
    orph_lebs: u32,
) -> Result<Vec<u32>> {
    if master.flags & UBIFS_MST_NO_ORPHS != 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for i in 0..orph_lebs {
        let lnum = orph_first + i;
        let Some(leb) = lebs.leb(lnum) else { continue };
        let mut offs = 0usize;
        while offs + UBIFS_ORPH_NODE_SZ <= leb.len() {
            if leb[offs..offs + 4] == [0xFF; 4] {
                break; // the area tail
            }
            let (node, ch) = parse_node(&leb[offs..], leb.len() - offs, "orphan node")?;
            if ch.node_type != UBIFS_ORPH_NODE {
                break;
            }
            let cmt_no = u64::from_le_bytes(node[24..32].try_into().unwrap());
            if cmt_no == master.cmt_no {
                let cnt = (node.len() - UBIFS_ORPH_NODE_SZ) / 8;
                for k in 0..cnt {
                    let inum = u64::from_le_bytes(
                        node[UBIFS_ORPH_NODE_SZ + k * 8..][..8].try_into().unwrap(),
                    );
                    if inum > u32::MAX as u64 {
                        return Err(Error::BadNode(format!("orphan inum {inum} is too large")));
                    }
                    out.push(inum as u32);
                }
            }
            offs += node.len().div_ceil(8) * 8;
        }
    }
    Ok(out)
}
