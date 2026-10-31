//! The on-flash format (a port of `fs/ubifs/ubifs-media.h`): constants,
//! node types, node sizes and field read/write at exact offsets.
//!
//! Every node starts with the common header `ubifs_ch` (24 bytes):
//! magic(4), crc(4), sqnum(8), len(4), node_type(1), group_type(1),
//! padding(2). The CRC covers node bytes `[8..len]`.

use crate::crc::crc32;
use crate::error::{other, Error, Result};

/// UBIFS node magic (`UBIFS_NODE_MAGIC`).
pub const UBIFS_NODE_MAGIC: u32 = 0x0610_1831;

/// Size of the common header (`UBIFS_CH_SZ`).
pub const UBIFS_CH_SZ: usize = 24;

/// Superblock LEB number (`UBIFS_SB_LNUM`).
pub const UBIFS_SB_LNUM: u32 = 0;
/// First master LEB (`UBIFS_MST_LNUM`).
pub const UBIFS_MST_LNUM: u32 = 1;
/// First log LEB (`UBIFS_LOG_LNUM`).
pub const UBIFS_LOG_LNUM: u32 = 3;
/// Root inode number (`UBIFS_ROOT_INO`).
pub const UBIFS_ROOT_INO: u32 = 1;
/// First allocated inode number (`UBIFS_FIRST_INO`).
pub const UBIFS_FIRST_INO: u32 = 64;
/// Data block size (`UBIFS_BLOCK_SIZE`).
pub const UBIFS_BLOCK_SIZE: usize = 4096;
/// Maximum inode inline data size (`UBIFS_MAX_INO_DATA`).
pub const UBIFS_MAX_INO_DATA: usize = UBIFS_BLOCK_SIZE;
/// Maximum name length (`UBIFS_MAX_NLEN`).
pub const UBIFS_MAX_NLEN: usize = 255;
/// Minimum LEB size (`UBIFS_MIN_LEB_SZ`).
pub const UBIFS_MIN_LEB_SZ: u32 = 15 * 1024;
/// Maximum LEB size (`UBIFS_MAX_LEB_SZ`).
pub const UBIFS_MAX_LEB_SZ: u32 = 2 * 1024 * 1024;
/// Minimum LEB count (`UBIFS_MIN_LEB_CNT`): SB(1)+MST(2)+log(2)+LPT(2)+orph(1)+4.
pub const UBIFS_MIN_LEB_CNT: u32 = 12;
/// Minimum TNC fanout (`UBIFS_MIN_FANOUT`).
pub const UBIFS_MIN_FANOUT: u32 = 3;
/// Number of superblock LEBs (`UBIFS_SB_LEBS`).
pub const UBIFS_SB_LEBS: u32 = 1;
/// Number of master LEBs (`UBIFS_MST_LEBS`).
pub const UBIFS_MST_LEBS: u32 = 2;
/// Minimum log LEBs (`UBIFS_MIN_LOG_LEBS`).
pub const UBIFS_MIN_LOG_LEBS: u32 = 2;
/// Minimum LPT LEBs (`UBIFS_MIN_LPT_LEBS`).
pub const UBIFS_MIN_LPT_LEBS: u32 = 2;
/// Minimum orphan LEBs (`UBIFS_MIN_ORPH_LEBS`).
pub const UBIFS_MIN_ORPH_LEBS: u32 = 1;

/// Node types (`enum ubifs_node_type`); values follow the enum order.
/// An inode node.
pub const UBIFS_INO_NODE: u8 = 0;
/// A file data node.
pub const UBIFS_DATA_NODE: u8 = 1;
/// A directory entry.
pub const UBIFS_DENT_NODE: u8 = 2;
/// An extended attribute entry.
pub const UBIFS_XENT_NODE: u8 = 3;
/// A truncation entry (journal only).
pub const UBIFS_TRUN_NODE: u8 = 4;
/// A padding node.
pub const UBIFS_PAD_NODE: u8 = 5;
/// The superblock.
pub const UBIFS_SB_NODE: u8 = 6;
/// The master node.
pub const UBIFS_MST_NODE: u8 = 7;
/// A log reference to a bud.
pub const UBIFS_REF_NODE: u8 = 8;
/// A TNC index node.
pub const UBIFS_IDX_NODE: u8 = 9;
/// Commit start.
pub const UBIFS_CS_NODE: u8 = 10;
/// An orphan record.
pub const UBIFS_ORPH_NODE: u8 = 11;
/// An HMAC node (authenticated images).
pub const UBIFS_AUTH_NODE: u8 = 12;
/// A superblock signature (pkcs7).
pub const UBIFS_SIG_NODE: u8 = 13;

/// Inode flags (`UBIFS_COMPR_FL` and friends).
/// Compress by default.
pub const UBIFS_COMPR_FL: u32 = 0x1;
/// Synchronous writes.
pub const UBIFS_SYNC_FL: u32 = 0x2;
/// Immutable.
pub const UBIFS_IMMUTABLE_FL: u32 = 0x4;
/// Append-only.
pub const UBIFS_APPEND_FL: u32 = 0x8;
/// Synchronous directory changes.
pub const UBIFS_DIRSYNC_FL: u32 = 0x10;
/// An extended-attribute inode.
pub const UBIFS_XATTR_FL: u32 = 0x20;
/// An encrypted inode.
pub const UBIFS_CRYPT_FL: u32 = 0x40;

/// Node grouping (`UBIFS_NO_NODE_GROUP`).
pub const UBIFS_NO_NODE_GROUP: u8 = 0;

/// Node sizes (the `sizeof` of the corresponding C structures).
/// Flexible arrays (`data[]`, `branches[]`) are not included.
/// `sizeof(struct ubifs_ino_node)`.
pub const UBIFS_INO_NODE_SZ: usize = 160;
/// `sizeof(struct ubifs_data_node)`.
pub const UBIFS_DATA_NODE_SZ: usize = 48;
/// `sizeof(struct ubifs_dent_node)`.
pub const UBIFS_DENT_NODE_SZ: usize = 56;
/// `sizeof(struct ubifs_trun_node)`.
pub const UBIFS_TRUN_NODE_SZ: usize = 48;
/// `sizeof(struct ubifs_pad_node)`.
pub const UBIFS_PAD_NODE_SZ: usize = 28;
/// `sizeof(struct ubifs_sb_node)`.
pub const UBIFS_SB_NODE_SZ: usize = 4096;
/// `sizeof(struct ubifs_mst_node)`.
pub const UBIFS_MST_NODE_SZ: usize = 512;
/// `sizeof(struct ubifs_ref_node)`.
pub const UBIFS_REF_NODE_SZ: usize = 64;
/// `sizeof(struct ubifs_idx_node)`.
pub const UBIFS_IDX_NODE_SZ: usize = 28;
/// `sizeof(struct ubifs_cs_node)`.
pub const UBIFS_CS_NODE_SZ: usize = 32;
/// `sizeof(struct ubifs_orph_node)`.
pub const UBIFS_ORPH_NODE_SZ: usize = 24;
/// `sizeof(struct ubifs_sig_node)`.
pub const UBIFS_SIG_NODE_SZ: usize = 64;
/// Size of one index branch: lnum+offs+len+key (simple format, 8 bytes).
pub const UBIFS_BRANCH_SZ: usize = 12 + crate::key::UBIFS_SK_LEN;
/// Maximum node size (`UBIFS_MAX_NODE_SZ` = largest inode with inline data).
pub const UBIFS_MAX_NODE_SZ: usize = UBIFS_INO_NODE_SZ + UBIFS_MAX_INO_DATA;
/// Blocks shorter than this are stored uncompressed
/// (`UBIFS_MIN_COMPR_LEN`).
pub const UBIFS_MIN_COMPR_LEN: usize = 128;
/// Largest data node (`UBIFS_MAX_DATA_NODE_SZ`).
pub const UBIFS_MAX_DATA_NODE_SZ: usize = UBIFS_DATA_NODE_SZ + UBIFS_BLOCK_SIZE;
/// Minimum write size (for the lprops watermarks, `MIN_WRITE_SZ`).
pub const MIN_WRITE_SZ: usize = UBIFS_DATA_NODE_SZ + 8;

/// The padding byte (`UBIFS_PADDING_BYTE`).
pub const UBIFS_PADDING_BYTE: u8 = 0xCE;

/// Superblock flags (`UBIFS_FLG_*`).
/// LPT in the big model.
pub const UBIFS_FLG_BIGLPT: u32 = 0x1;
/// Free space must be fixed up on the first mount.
pub const UBIFS_FLG_SPACE_FIXUP: u32 = 0x2;
/// Double dent hash (cookies).
pub const UBIFS_FLG_DOUBLE_HASH: u32 = 0x4;
/// An encrypted volume.
pub const UBIFS_FLG_ENCRYPTION: u32 = 0x8;
/// An authenticated volume (HMAC).
pub const UBIFS_FLG_AUTHENTICATION: u32 = 0x10;

/// Master flags (`UBIFS_MST_*`).
/// The volume was not unmounted cleanly.
pub const UBIFS_MST_DIRTY: u32 = 0x1;
/// The orphan area is empty.
pub const UBIFS_MST_NO_ORPHS: u32 = 0x2;
/// The orphan area contains records.
pub const UBIFS_MST_ORPHS: u32 = 0x4;

/// On-flash inode types (`UBIFS_ITYPE_*`).
/// A regular file.
pub const UBIFS_ITYPE_REG: u8 = 0;
/// A directory.
pub const UBIFS_ITYPE_DIR: u8 = 1;
/// A symbolic link.
pub const UBIFS_ITYPE_LNK: u8 = 2;
/// A block device.
pub const UBIFS_ITYPE_BLK: u8 = 3;
/// A character device.
pub const UBIFS_ITYPE_CHR: u8 = 4;
/// A FIFO.
pub const UBIFS_ITYPE_FIFO: u8 = 5;
/// A socket.
pub const UBIFS_ITYPE_SOCK: u8 = 6;

/// Compression algorithms (`UBIFS_COMPR_*`).
/// No compression.
pub const UBIFS_COMPR_NONE: u16 = 0;
/// LZO1X.
pub const UBIFS_COMPR_LZO: u16 = 1;
/// ZLIB (deflate).
pub const UBIFS_COMPR_ZLIB: u16 = 2;
/// Zstandard.
pub const UBIFS_COMPR_ZSTD: u16 = 3;

/// lprops flags (`LPROPS_*`, bit values as in `ubifs.h`).
/// No category.
pub const LPROPS_UNCAT: u32 = 0;
/// A dirty LEB.
pub const LPROPS_DIRTY: u32 = 1 << 0;
/// Has free space.
pub const LPROPS_FREE: u32 = 1 << 1;
/// The LEB is occupied by the TNC index.
pub const LPROPS_INDEX: u32 = 1 << 2;
/// The LEB is taken by internal areas (log, LPT, etc.).
pub const LPROPS_TAKEN: u32 = 1 << 3;
/// Number of lprops heaps.
pub const LPROPS_HEAP_CNT: u32 = 3;

/// Default time granularity (`DEFAULT_TIME_GRAN`).
pub const DEFAULT_TIME_GRAN: u32 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Bounds-checked little-endian field reads.
// ---------------------------------------------------------------------------

pub(crate) fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
pub(crate) fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
pub(crate) fn le64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

// ---------------------------------------------------------------------------
// Common node header.
// ---------------------------------------------------------------------------

/// A parsed common header `ubifs_ch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonHeader {
    /// The `UBIFS_NODE_MAGIC` magic.
    pub magic: u32,
    /// CRC32 of the node body (bytes `[8..len]`).
    pub crc: u32,
    /// The node sequence number.
    pub sqnum: u64,
    /// The full on-flash node length.
    pub len: u32,
    /// The node type.
    pub node_type: u8,
    /// Node grouping in the journal.
    pub group_type: u8,
}

impl CommonHeader {
    /// Parse the header from the first 24 bytes of a node.
    pub fn parse(b: &[u8]) -> Result<CommonHeader> {
        if b.len() < UBIFS_CH_SZ {
            return Err(Error::BadNode(format!(
                "node is too short: {} bytes",
                b.len()
            )));
        }
        Ok(CommonHeader {
            magic: le32(b, 0),
            crc: le32(b, 4),
            sqnum: le64(b, 8),
            len: le32(b, 16),
            node_type: b[20],
            group_type: b[21],
        })
    }
}

/// Parse a node: verify the magic, CRC and bounds. Returns the whole node
/// slice (`[0..len]`) and its header.
pub fn parse_node<'a>(
    buf: &'a [u8],
    max_len: usize,
    what: &str,
) -> Result<(&'a [u8], CommonHeader)> {
    let ch = CommonHeader::parse(buf)?;
    if ch.magic != UBIFS_NODE_MAGIC {
        return Err(Error::BadNode(format!("{what}: bad magic {:#x}", ch.magic)));
    }
    let len = ch.len as usize;
    if len < UBIFS_CH_SZ || len > max_len {
        return Err(Error::BadNode(format!(
            "{what}: bad node length {len} (max {max_len})"
        )));
    }
    if len > buf.len() {
        return Err(Error::BadNode(format!(
            "{what}: node length {len} overruns buffer"
        )));
    }
    let node = &buf[..len];
    if le32(node, 4) != crc32(&node[8..]) {
        return Err(Error::BadCrc(format!(
            "{what}: node crc mismatch at sqnum {}",
            ch.sqnum
        )));
    }
    Ok((node, ch))
}

/// Write the common header + CRC into a finished node body.
///
/// `buf` is the full node: `[0..24]` gets filled in, the body `buf[24..len]`
/// must already be in place. (`ubifs_init_node` + `ubifs_crc_node`.)
pub fn finish_node(buf: &mut [u8], node_type: u8, sqnum: u64) {
    buf[0..4].copy_from_slice(&UBIFS_NODE_MAGIC.to_le_bytes());
    buf[8..16].copy_from_slice(&sqnum.to_le_bytes());
    let len = buf.len() as u32;
    buf[16..20].copy_from_slice(&len.to_le_bytes());
    buf[20] = node_type;
    buf[21] = UBIFS_NO_NODE_GROUP;
    buf[22] = 0;
    buf[23] = 0;
    let crc = crc32(&buf[8..]);
    buf[4..8].copy_from_slice(&crc.to_le_bytes());
}

// ---------------------------------------------------------------------------
// SB (struct ubifs_sb_node).
// ---------------------------------------------------------------------------

/// The superblock: volume geometry and parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Superblock {
    /// Key hash type (0 — r5).
    pub key_hash: u8,
    /// Key format (0 — the simple 8-byte format).
    pub key_fmt: u8,
    /// `UBIFS_FLG_*` flags.
    pub flags: u32,
    /// Minimum I/O unit size.
    pub min_io_size: u32,
    /// LEB size.
    pub leb_size: u32,
    /// Number of volume LEBs.
    pub leb_cnt: u32,
    /// Maximum number of LEBs (the growth ceiling).
    pub max_leb_cnt: u32,
    /// Maximum journal size (buds).
    pub max_bud_bytes: u64,
    /// Log size in LEBs.
    pub log_lebs: u32,
    /// Number of LPT-area LEBs.
    pub lpt_lebs: u32,
    /// Number of orphan-area LEBs.
    pub orph_lebs: u32,
    /// Number of journal heads.
    pub jhead_cnt: u32,
    /// TNC tree fanout.
    pub fanout: u32,
    /// Number of lsave entries (big LPT).
    pub lsave_cnt: u32,
    /// On-flash format version (4/5).
    pub fmt_version: u32,
    /// Default compression algorithm.
    pub default_compr: u16,
    /// Reserved pool size.
    pub rp_size: u64,
    /// Time granularity, nanoseconds.
    pub time_gran: u32,
    /// The UUID generated at mkfs time.
    pub uuid: [u8; 16],
    /// Read-only compatibility version.
    pub ro_compat_version: u32,
    /// The SB node sqnum.
    pub sqnum: u64,
}

impl Superblock {
    /// Field offsets inside the node (after ch): `padding[2] @24`,
    /// `key_hash @26`, `key_fmt @27`, then the structure fields.
    pub fn parse(node: &[u8]) -> Result<Superblock> {
        if node.len() < UBIFS_SB_NODE_SZ {
            return Err(Error::BadNode(format!(
                "superblock is too short: {} < {}",
                node.len(),
                UBIFS_SB_NODE_SZ
            )));
        }
        Ok(Superblock {
            key_hash: node[26],
            key_fmt: node[27],
            flags: le32(node, 28),
            min_io_size: le32(node, 32),
            leb_size: le32(node, 36),
            leb_cnt: le32(node, 40),
            max_leb_cnt: le32(node, 44),
            max_bud_bytes: le64(node, 48),
            log_lebs: le32(node, 56),
            lpt_lebs: le32(node, 60),
            orph_lebs: le32(node, 64),
            jhead_cnt: le32(node, 68),
            fanout: le32(node, 72),
            lsave_cnt: le32(node, 76),
            fmt_version: le32(node, 80),
            default_compr: le16(node, 84),
            rp_size: le64(node, 96),
            time_gran: le32(node, 104),
            uuid: node[108..124].try_into().unwrap(),
            ro_compat_version: le32(node, 124),
            sqnum: CommonHeader::parse(node)?.sqnum,
        })
    }

    /// Serialize the SB node (4096 bytes, the CRC covers the whole node).
    pub fn to_node(&self, sqnum: u64) -> Vec<u8> {
        let mut n = vec![0u8; UBIFS_SB_NODE_SZ];
        n[26] = self.key_hash;
        n[27] = self.key_fmt;
        n[28..32].copy_from_slice(&self.flags.to_le_bytes());
        n[32..36].copy_from_slice(&self.min_io_size.to_le_bytes());
        n[36..40].copy_from_slice(&self.leb_size.to_le_bytes());
        n[40..44].copy_from_slice(&self.leb_cnt.to_le_bytes());
        n[44..48].copy_from_slice(&self.max_leb_cnt.to_le_bytes());
        n[48..56].copy_from_slice(&self.max_bud_bytes.to_le_bytes());
        n[56..60].copy_from_slice(&self.log_lebs.to_le_bytes());
        n[60..64].copy_from_slice(&self.lpt_lebs.to_le_bytes());
        n[64..68].copy_from_slice(&self.orph_lebs.to_le_bytes());
        n[68..72].copy_from_slice(&self.jhead_cnt.to_le_bytes());
        n[72..76].copy_from_slice(&self.fanout.to_le_bytes());
        n[76..80].copy_from_slice(&self.lsave_cnt.to_le_bytes());
        n[80..84].copy_from_slice(&self.fmt_version.to_le_bytes());
        n[84..86].copy_from_slice(&self.default_compr.to_le_bytes());
        n[96..104].copy_from_slice(&self.rp_size.to_le_bytes());
        n[104..108].copy_from_slice(&self.time_gran.to_le_bytes());
        n[108..124].copy_from_slice(&self.uuid);
        n[124..128].copy_from_slice(&self.ro_compat_version.to_le_bytes());
        finish_node(&mut n, UBIFS_SB_NODE, sqnum);
        n
    }
}

// ---------------------------------------------------------------------------
// MST (struct ubifs_mst_node).
// ---------------------------------------------------------------------------

/// The master node: references to the committed state of the volume.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Master {
    /// The highest inode number in the committed index.
    pub highest_inum: u64,
    /// Commit number.
    pub cmt_no: u64,
    /// `UBIFS_MST_*` flags.
    pub flags: u32,
    /// Log start.
    pub log_lnum: u32,
    /// LEB of the root index node.
    pub root_lnum: u32,
    /// Offset of the root index node.
    pub root_offs: u32,
    /// Length of the root index node.
    pub root_len: u32,
    /// The LEB reserved for GC.
    pub gc_lnum: u32,
    /// LEB of the index head.
    pub ihead_lnum: u32,
    /// Offset of the index head.
    pub ihead_offs: u32,
    /// On-flash index size.
    pub index_size: u64,
    /// Total free space.
    pub total_free: u64,
    /// Total dirty space.
    pub total_dirty: u64,
    /// Total used space (data).
    pub total_used: u64,
    /// Dead space (data).
    pub total_dead: u64,
    /// Dark space (data).
    pub total_dark: u64,
    /// LEB of the LPT root.
    pub lpt_lnum: u32,
    /// Offset of the LPT root.
    pub lpt_offs: u32,
    /// LEB of the LPT write head.
    pub nhead_lnum: u32,
    /// Offset of the LPT write head.
    pub nhead_offs: u32,
    /// The ltab LEB.
    pub ltab_lnum: u32,
    /// The ltab offset.
    pub ltab_offs: u32,
    /// The lsave LEB (big LPT).
    pub lsave_lnum: u32,
    /// The lsave offset.
    pub lsave_offs: u32,
    /// The last LEB scanned by LPT.
    pub lscan_lnum: u32,
    /// Number of empty LEBs.
    pub empty_lebs: u32,
    /// Number of index LEBs.
    pub idx_lebs: u32,
    /// The actual number of volume LEBs.
    pub leb_cnt: u32,
}

impl Master {
    /// Field offsets: `highest_inum @24`, `cmt_no @32`, `flags @40`, ...
    pub fn parse(node: &[u8]) -> Result<Master> {
        if node.len() < UBIFS_MST_NODE_SZ {
            return Err(Error::BadNode(format!(
                "master is too short: {} < {}",
                node.len(),
                UBIFS_MST_NODE_SZ
            )));
        }
        Ok(Master {
            highest_inum: le64(node, 24),
            cmt_no: le64(node, 32),
            flags: le32(node, 40),
            log_lnum: le32(node, 44),
            root_lnum: le32(node, 48),
            root_offs: le32(node, 52),
            root_len: le32(node, 56),
            gc_lnum: le32(node, 60),
            ihead_lnum: le32(node, 64),
            ihead_offs: le32(node, 68),
            index_size: le64(node, 72),
            total_free: le64(node, 80),
            total_dirty: le64(node, 88),
            total_used: le64(node, 96),
            total_dead: le64(node, 104),
            total_dark: le64(node, 112),
            lpt_lnum: le32(node, 120),
            lpt_offs: le32(node, 124),
            nhead_lnum: le32(node, 128),
            nhead_offs: le32(node, 132),
            ltab_lnum: le32(node, 136),
            ltab_offs: le32(node, 140),
            lsave_lnum: le32(node, 144),
            lsave_offs: le32(node, 148),
            lscan_lnum: le32(node, 152),
            empty_lebs: le32(node, 156),
            idx_lebs: le32(node, 160),
            leb_cnt: le32(node, 164),
        })
    }

    /// Serialize the MST node (512 bytes).
    pub fn to_node(&self, sqnum: u64) -> Vec<u8> {
        let mut n = vec![0u8; UBIFS_MST_NODE_SZ];
        n[24..32].copy_from_slice(&self.highest_inum.to_le_bytes());
        n[32..40].copy_from_slice(&self.cmt_no.to_le_bytes());
        n[40..44].copy_from_slice(&self.flags.to_le_bytes());
        n[44..48].copy_from_slice(&self.log_lnum.to_le_bytes());
        n[48..52].copy_from_slice(&self.root_lnum.to_le_bytes());
        n[52..56].copy_from_slice(&self.root_offs.to_le_bytes());
        n[56..60].copy_from_slice(&self.root_len.to_le_bytes());
        n[60..64].copy_from_slice(&self.gc_lnum.to_le_bytes());
        n[64..68].copy_from_slice(&self.ihead_lnum.to_le_bytes());
        n[68..72].copy_from_slice(&self.ihead_offs.to_le_bytes());
        n[72..80].copy_from_slice(&self.index_size.to_le_bytes());
        n[80..88].copy_from_slice(&self.total_free.to_le_bytes());
        n[88..96].copy_from_slice(&self.total_dirty.to_le_bytes());
        n[96..104].copy_from_slice(&self.total_used.to_le_bytes());
        n[104..112].copy_from_slice(&self.total_dead.to_le_bytes());
        n[112..120].copy_from_slice(&self.total_dark.to_le_bytes());
        n[120..124].copy_from_slice(&self.lpt_lnum.to_le_bytes());
        n[124..128].copy_from_slice(&self.lpt_offs.to_le_bytes());
        n[128..132].copy_from_slice(&self.nhead_lnum.to_le_bytes());
        n[132..136].copy_from_slice(&self.nhead_offs.to_le_bytes());
        n[136..140].copy_from_slice(&self.ltab_lnum.to_le_bytes());
        n[140..144].copy_from_slice(&self.ltab_offs.to_le_bytes());
        n[144..148].copy_from_slice(&self.lsave_lnum.to_le_bytes());
        n[148..152].copy_from_slice(&self.lsave_offs.to_le_bytes());
        n[152..156].copy_from_slice(&self.lscan_lnum.to_le_bytes());
        n[156..160].copy_from_slice(&self.empty_lebs.to_le_bytes());
        n[160..164].copy_from_slice(&self.idx_lebs.to_le_bytes());
        n[164..168].copy_from_slice(&self.leb_cnt.to_le_bytes());
        finish_node(&mut n, UBIFS_MST_NODE, sqnum);
        n
    }
}

// ---------------------------------------------------------------------------
// INO (struct ubifs_ino_node).
// ---------------------------------------------------------------------------

/// An inode node: metadata + inline data (symlinks, devices, xattrs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InoNode {
    /// The node key.
    pub key: crate::key::Key,
    /// sqnum at inode creation time.
    pub creat_sqnum: u64,
    /// Content size in bytes.
    pub size: u64,
    /// Access time, seconds.
    pub atime_sec: i64,
    /// Creation/metadata change time, seconds.
    pub ctime_sec: i64,
    /// Modification time, seconds.
    pub mtime_sec: i64,
    /// atime nanoseconds.
    pub atime_nsec: u32,
    /// ctime nanoseconds.
    pub ctime_nsec: u32,
    /// mtime nanoseconds.
    pub mtime_nsec: u32,
    /// Hard link count.
    pub nlink: u32,
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Mode with S_IFMT.
    pub mode: u32,
    /// `UBIFS_*_FL` flags.
    pub flags: u32,
    /// Number of xattrs.
    pub xattr_cnt: u32,
    /// Total size of xattr values.
    pub xattr_size: u32,
    /// Total length of xattr names.
    pub xattr_names: u32,
    /// Default compression for this inode.
    pub compr_type: u16,
    /// Inline data (symlink target, device number).
    pub data: Vec<u8>,
}

impl InoNode {
    /// Parse from a node (with the common header). `data` is taken per
    /// `data_len`.
    pub fn parse(node: &[u8]) -> Result<InoNode> {
        if node.len() < UBIFS_INO_NODE_SZ {
            return Err(Error::BadNode(format!(
                "ino node too short: {}",
                node.len()
            )));
        }
        let data_len = le32(node, 112) as usize;
        if node.len() < UBIFS_INO_NODE_SZ + data_len {
            return Err(Error::BadNode("ino node data_len overruns node".into()));
        }
        Ok(InoNode {
            key: crate::key::Key::from_le8(&node[24..40]),
            creat_sqnum: le64(node, 40),
            size: le64(node, 48),
            atime_sec: le64(node, 56) as i64,
            ctime_sec: le64(node, 64) as i64,
            mtime_sec: le64(node, 72) as i64,
            atime_nsec: le32(node, 80),
            ctime_nsec: le32(node, 84),
            mtime_nsec: le32(node, 88),
            nlink: le32(node, 92),
            uid: le32(node, 96),
            gid: le32(node, 100),
            mode: le32(node, 104),
            flags: le32(node, 108),
            xattr_cnt: le32(node, 116),
            xattr_size: le32(node, 120),
            xattr_names: le32(node, 128),
            compr_type: le16(node, 132),
            data: node[UBIFS_INO_NODE_SZ..UBIFS_INO_NODE_SZ + data_len].to_vec(),
        })
    }

    /// Serialize the INO node.
    pub fn to_node(&self, sqnum: u64) -> Vec<u8> {
        let mut n = vec![0u8; UBIFS_INO_NODE_SZ + self.data.len()];
        self.key.write_le16(&mut n[24..40]);
        n[40..48].copy_from_slice(&self.creat_sqnum.to_le_bytes());
        n[48..56].copy_from_slice(&self.size.to_le_bytes());
        n[56..64].copy_from_slice(&(self.atime_sec as u64).to_le_bytes());
        n[64..72].copy_from_slice(&(self.ctime_sec as u64).to_le_bytes());
        n[72..80].copy_from_slice(&(self.mtime_sec as u64).to_le_bytes());
        n[80..84].copy_from_slice(&self.atime_nsec.to_le_bytes());
        n[84..88].copy_from_slice(&self.ctime_nsec.to_le_bytes());
        n[88..92].copy_from_slice(&self.mtime_nsec.to_le_bytes());
        n[92..96].copy_from_slice(&self.nlink.to_le_bytes());
        n[96..100].copy_from_slice(&self.uid.to_le_bytes());
        n[100..104].copy_from_slice(&self.gid.to_le_bytes());
        n[104..108].copy_from_slice(&self.mode.to_le_bytes());
        n[108..112].copy_from_slice(&self.flags.to_le_bytes());
        n[112..116].copy_from_slice(&(self.data.len() as u32).to_le_bytes());
        n[116..120].copy_from_slice(&self.xattr_cnt.to_le_bytes());
        n[120..124].copy_from_slice(&self.xattr_size.to_le_bytes());
        n[124..128].copy_from_slice(&0u32.to_le_bytes()); // padding1
        n[128..132].copy_from_slice(&self.xattr_names.to_le_bytes());
        n[132..134].copy_from_slice(&self.compr_type.to_le_bytes());
        n[134..UBIFS_INO_NODE_SZ].fill(0); // padding2
        n[UBIFS_INO_NODE_SZ..].copy_from_slice(&self.data);
        finish_node(&mut n, UBIFS_INO_NODE, sqnum);
        n
    }
}

// ---------------------------------------------------------------------------
// DENT (struct ubifs_dent_node).
// ---------------------------------------------------------------------------

/// A directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DentNode {
    /// The parent directory key (parent inum + name hash).
    pub key: crate::key::Key,
    /// Target inode number.
    pub inum: u64,
    /// Target type (`UBIFS_ITYPE_*`).
    pub itype: u8,
    /// Cookie (0 in the simple format without double-hash).
    pub cookie: u32,
    /// Name (without the trailing NUL).
    pub name: Vec<u8>,
}

impl DentNode {
    /// Parse from a node; the name length comes from `nlen`.
    pub fn parse(node: &[u8]) -> Result<DentNode> {
        if node.len() < UBIFS_DENT_NODE_SZ {
            return Err(Error::BadNode(format!(
                "dent node too short: {}",
                node.len()
            )));
        }
        let nlen = le16(node, 50) as usize;
        if node.len() < UBIFS_DENT_NODE_SZ + nlen + 1 {
            return Err(Error::BadNode("dent node name overruns node".into()));
        }
        Ok(DentNode {
            key: crate::key::Key::from_le8(&node[24..40]),
            inum: le64(node, 40),
            itype: node[49],
            cookie: le32(node, 52),
            name: node[UBIFS_DENT_NODE_SZ..UBIFS_DENT_NODE_SZ + nlen].to_vec(),
        })
    }

    /// Serialize the DENT node (a trailing NUL follows the name).
    pub fn to_node(&self, sqnum: u64) -> Vec<u8> {
        let mut n = vec![0u8; UBIFS_DENT_NODE_SZ + self.name.len() + 1];
        self.key.write_le16(&mut n[24..40]);
        n[40..48].copy_from_slice(&self.inum.to_le_bytes());
        n[48] = 0; // padding1
        n[49] = self.itype;
        n[50..52].copy_from_slice(&(self.name.len() as u16).to_le_bytes());
        n[52..56].copy_from_slice(&self.cookie.to_le_bytes());
        n[UBIFS_DENT_NODE_SZ..UBIFS_DENT_NODE_SZ + self.name.len()].copy_from_slice(&self.name);
        n[UBIFS_DENT_NODE_SZ + self.name.len()] = 0;
        finish_node(&mut n, UBIFS_DENT_NODE, sqnum);
        n
    }
}

// ---------------------------------------------------------------------------
// DATA (struct ubifs_data_node).
// ---------------------------------------------------------------------------

/// A file data node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataNode {
    /// The node key.
    pub key: crate::key::Key,
    /// Uncompressed block size.
    pub size: u32,
    /// Block compression algorithm.
    pub compr_type: u16,
    /// Compressed size (only meaningful for encrypted volumes).
    pub compr_size: u16,
    /// The compressed (or raw) block content.
    pub data: Vec<u8>,
}

impl DataNode {
    /// Parse from a node; the data is every byte after the 48-byte header.
    pub fn parse(node: &[u8]) -> Result<DataNode> {
        if node.len() < UBIFS_DATA_NODE_SZ {
            return Err(Error::BadNode(format!(
                "data node too short: {}",
                node.len()
            )));
        }
        Ok(DataNode {
            key: crate::key::Key::from_le8(&node[24..40]),
            size: le32(node, 40),
            compr_type: le16(node, 44),
            compr_size: le16(node, 46),
            data: node[UBIFS_DATA_NODE_SZ..].to_vec(),
        })
    }

    /// Serialize the DATA node (the 48-byte header is present in every
    /// format version — the `compr_size` field is part of `sizeof`).
    pub fn to_node(&self, sqnum: u64) -> Vec<u8> {
        let mut n = vec![0u8; UBIFS_DATA_NODE_SZ + self.data.len()];
        self.key.write_le16(&mut n[24..40]);
        n[40..44].copy_from_slice(&self.size.to_le_bytes());
        n[44..46].copy_from_slice(&self.compr_type.to_le_bytes());
        n[46..48].copy_from_slice(&self.compr_size.to_le_bytes());
        n[UBIFS_DATA_NODE_SZ..].copy_from_slice(&self.data);
        finish_node(&mut n, UBIFS_DATA_NODE, sqnum);
        n
    }
}

// ---------------------------------------------------------------------------
// IDX (struct ubifs_idx_node) and branches.
// ---------------------------------------------------------------------------

/// An index branch: a reference to a child node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Branch {
    /// The child node LEB.
    pub lnum: u32,
    /// The child node offset.
    pub offs: u32,
    /// The child node length.
    pub len: u32,
    /// The key of the first leaf under the branch.
    pub key: crate::key::Key,
}

/// A TNC index node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdxNode {
    /// Number of branches.
    pub child_cnt: u16,
    /// Tree level (0 — right above the leaves).
    pub level: u16,
    /// Branches to child nodes.
    pub branches: Vec<Branch>,
}

impl IdxNode {
    /// Parse from a node. A branch key is 8 bytes (simple format).
    pub fn parse(node: &[u8]) -> Result<IdxNode> {
        if node.len() < UBIFS_IDX_NODE_SZ {
            return Err(Error::BadNode(format!(
                "idx node too short: {}",
                node.len()
            )));
        }
        let child_cnt = le16(node, 24);
        let level = le16(node, 26);
        let need = UBIFS_IDX_NODE_SZ + child_cnt as usize * UBIFS_BRANCH_SZ;
        if node.len() < need {
            return Err(Error::BadNode(format!(
                "idx node truncated: {} < {need}",
                node.len()
            )));
        }
        let mut branches = Vec::with_capacity(child_cnt as usize);
        for i in 0..child_cnt as usize {
            let off = UBIFS_IDX_NODE_SZ + i * UBIFS_BRANCH_SZ;
            branches.push(Branch {
                lnum: le32(node, off),
                offs: le32(node, off + 4),
                len: le32(node, off + 8),
                key: crate::key::Key::from_le8(&node[off + 12..off + 20]),
            });
        }
        Ok(IdxNode {
            child_cnt,
            level,
            branches,
        })
    }

    /// Serialize the IDX node.
    pub fn to_node(&self, sqnum: u64) -> Vec<u8> {
        let mut n = vec![0u8; UBIFS_IDX_NODE_SZ + self.branches.len() * UBIFS_BRANCH_SZ];
        n[24..26].copy_from_slice(&(self.branches.len() as u16).to_le_bytes());
        n[26..28].copy_from_slice(&self.level.to_le_bytes());
        for (i, b) in self.branches.iter().enumerate() {
            let off = UBIFS_IDX_NODE_SZ + i * UBIFS_BRANCH_SZ;
            n[off..off + 4].copy_from_slice(&b.lnum.to_le_bytes());
            n[off + 4..off + 8].copy_from_slice(&b.offs.to_le_bytes());
            n[off + 8..off + 12].copy_from_slice(&b.len.to_le_bytes());
            b.key.write_le8(&mut n[off + 12..off + 20]);
        }
        finish_node(&mut n, UBIFS_IDX_NODE, sqnum);
        n
    }
}

/// Size of an IDX node with `child_cnt` branches (`ubifs_idx_node_sz`).
pub fn idx_node_sz(child_cnt: usize) -> usize {
    UBIFS_IDX_NODE_SZ + child_cnt * UBIFS_BRANCH_SZ
}

// ---------------------------------------------------------------------------
// CS / PAD (small nodes).
// ---------------------------------------------------------------------------

/// A commit start node (`struct ubifs_cs_node`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsNode {
    /// Commit number.
    pub cmt_no: u64,
}

impl CsNode {
    /// Parse the node from raw bytes.
    pub fn parse(node: &[u8]) -> Result<CsNode> {
        if node.len() < UBIFS_CS_NODE_SZ {
            return Err(Error::BadNode(format!("cs node too short: {}", node.len())));
        }
        Ok(CsNode {
            cmt_no: le64(node, 24),
        })
    }

    /// Serialize the node (header + CRC).
    pub fn to_node(&self, sqnum: u64) -> Vec<u8> {
        let mut n = vec![0u8; UBIFS_CS_NODE_SZ];
        n[24..32].copy_from_slice(&self.cmt_no.to_le_bytes());
        finish_node(&mut n, UBIFS_CS_NODE, sqnum);
        n
    }
}

/// The pad node (`struct ubifs_pad_node`) and gap filling (`ubifs_pad`):
/// with `pad >= UBIFS_PAD_NODE_SZ` a pad node is written and the rest is
/// zeroed; otherwise the bytes are `UBIFS_PADDING_BYTE`.
pub fn ubifs_pad(out: &mut [u8]) {
    let pad = out.len();
    if pad >= UBIFS_PAD_NODE_SZ {
        let mut n = vec![0u8; UBIFS_PAD_NODE_SZ];
        n[24..28].copy_from_slice(&((pad - UBIFS_PAD_NODE_SZ) as u32).to_le_bytes());
        finish_node(&mut n, UBIFS_PAD_NODE, 0);
        out[..UBIFS_PAD_NODE_SZ].copy_from_slice(&n);
        out[UBIFS_PAD_NODE_SZ..].fill(0);
    } else if pad > 0 {
        out.fill(UBIFS_PADDING_BYTE);
    }
}

/// Verify that a node type is the expected one.
pub fn expect_type(node_type: u8, want: u8, what: &str) -> Result<()> {
    if node_type != want {
        return other(format!(
            "{what}: expected node type {want}, got {node_type}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Key;

    #[test]
    fn node_sizes_match_media_h() {
        // sizeof(struct ...) for every node.
        assert_eq!(UBIFS_CH_SZ, 24);
        assert_eq!(UBIFS_INO_NODE_SZ, 160);
        assert_eq!(UBIFS_DATA_NODE_SZ, 48);
        assert_eq!(UBIFS_DENT_NODE_SZ, 56);
        assert_eq!(UBIFS_TRUN_NODE_SZ, 48);
        assert_eq!(UBIFS_PAD_NODE_SZ, 28);
        assert_eq!(UBIFS_SB_NODE_SZ, 4096);
        assert_eq!(UBIFS_MST_NODE_SZ, 512);
        assert_eq!(UBIFS_REF_NODE_SZ, 64);
        assert_eq!(UBIFS_IDX_NODE_SZ, 28);
        assert_eq!(UBIFS_CS_NODE_SZ, 32);
        assert_eq!(UBIFS_BRANCH_SZ, 20);
        assert_eq!(UBIFS_MAX_NODE_SZ, 160 + 4096);
    }

    #[test]
    fn ino_roundtrip() {
        let ino = InoNode {
            key: Key::ino(7),
            creat_sqnum: 9,
            size: 123,
            atime_sec: 1,
            ctime_sec: 2,
            mtime_sec: 3,
            atime_nsec: 4,
            ctime_nsec: 5,
            mtime_nsec: 6,
            nlink: 1,
            uid: 1000,
            gid: 100,
            mode: 0o100_644,
            flags: 0,
            xattr_cnt: 0,
            xattr_size: 0,
            xattr_names: 0,
            compr_type: UBIFS_COMPR_NONE,
            data: vec![1, 2, 3],
        };
        let n = ino.to_node(42);
        assert_eq!(n.len(), UBIFS_INO_NODE_SZ + 3);
        assert_eq!(CommonHeader::parse(&n).unwrap().node_type, UBIFS_INO_NODE);
        let back = InoNode::parse(&n).unwrap();
        assert_eq!(back, ino);
    }

    #[test]
    fn dent_layout() {
        let dent = DentNode {
            key: Key::dent(1, b"adbd").unwrap(),
            inum: 65,
            itype: UBIFS_ITYPE_REG,
            cookie: 0,
            name: b"adbd".to_vec(),
        };
        let n = dent.to_node(1);
        assert_eq!(n.len(), UBIFS_DENT_NODE_SZ + 4 + 1);
        // Fields at ubifs_dent_node offsets: inum @40, padding1 @48,
        // type @49, nlen @50, cookie @52, name @56 (+ a trailing NUL).
        assert_eq!(crate::media::le64(&n, 40), 65);
        assert_eq!(n[48], 0);
        assert_eq!(n[49], UBIFS_ITYPE_REG);
        assert_eq!(crate::media::le16(&n, 50), 4);
        assert_eq!(crate::media::le32(&n, 52), 0);
        assert_eq!(&n[56..60], b"adbd");
        assert_eq!(n[60], 0);
        assert_eq!(DentNode::parse(&n).unwrap(), dent);
    }

    #[test]
    fn pad_semantics() {
        // >= 28: a pad node + zeros; < 28: 0xCE bytes.
        let mut b = vec![0xFF; 100];
        ubifs_pad(&mut b);
        assert_eq!(CommonHeader::parse(&b).unwrap().node_type, UBIFS_PAD_NODE);
        assert_eq!(crate::media::le32(&b, 24), 100 - UBIFS_PAD_NODE_SZ as u32);
        assert!(b[UBIFS_PAD_NODE_SZ..].iter().all(|&x| x == 0));

        let mut b = vec![0xFF; 10];
        ubifs_pad(&mut b);
        assert!(b.iter().all(|&x| x == UBIFS_PADDING_BYTE));
    }
}
