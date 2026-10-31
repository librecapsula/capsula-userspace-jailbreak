//! The lprops tree (LPT): bit-packed nodes (`lpt.c`/`lpt_commit.c`),
//! LPT creation at mkfs time (`ubifs_create_lpt`) and reading from flash.
//!
//! Key format properties:
//! * the bitstream of every node starts **after** the 2-byte CRC16
//!   (`pack_bits(c, buf + UBIFS_LPT_CRC_BYTES, ...)`);
//! * fields are packed LSB-first inside consecutive bytes;
//! * a "missing branch" in an nnode packs as `lpt_last + 1 - lpt_first` —
//!   in kernel semantics an absent node means the whole sub-branch
//!   describes empty LEBs (free = leb_size, dirty = 0);
//! * at commit time the kernel writes only "dirty" nodes — the on-flash
//!   tree is sparse, and a reader must expand missing pnodes into the
//!   default lprops.

use crate::crc::crc16;
use crate::error::{Error, Result};
use crate::geometry::{
    LptGeom, UBIFS_LPT_CRC_BYTES, UBIFS_LPT_FANOUT, UBIFS_LPT_FANOUT_SHIFT, UBIFS_LPT_LSAVE,
    UBIFS_LPT_LTAB, UBIFS_LPT_NNODE, UBIFS_LPT_PNODE,
};

/// Properties of one main-area LEB (`struct ubifs_lprops`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lprops {
    /// Free space in bytes.
    pub free: u32,
    /// Dirty space in bytes (a multiple of 8).
    pub dirty: u32,
    /// `LPROPS_*` flags; only `LPROPS_INDEX` — the LEB holds index nodes —
    /// is stored on flash.
    pub flags: u32,
}

/// Properties of an LPT-area LEB (`struct ubifs_lpt_lprops`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LptLprops {
    /// Free space in bytes.
    pub free: u32,
    /// Dirty space inside an LPT-area LEB.
    pub dirty: u32,
}

// ---------------------------------------------------------------------------
// The bitstream (pack_bits/unpack_bits from lpt.c).
// ---------------------------------------------------------------------------

/// A bit-field packer: LSB-first inside bytes, fields consecutively from
/// bit 0.
///
/// Mirrors `pack_bits` from `fs/ubifs/lpt.c`; the buffer is passed
/// starting at the position after the node CRC bytes.
pub struct Packer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Packer<'a> {
    /// Create a packer over a buffer (position — bit 0).
    pub fn new(buf: &'a mut [u8]) -> Packer<'a> {
        Packer { buf, pos: 0 }
    }

    /// `pack_bits`: `nrbits` bits of `val`, least significant bits first.
    pub fn pack(&mut self, val: u32, nrbits: u32) {
        debug_assert!(nrbits > 0 && nrbits <= 32);
        for i in 0..nrbits {
            let bit = (val >> i) & 1;
            let (p, b) = (self.pos / 8, self.pos % 8);
            self.buf[p] |= (bit << b) as u8;
            self.pos += 1;
        }
    }
}

/// A bit-field unpacker (`ubifs_unpack_bits`).
pub struct Unpacker<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Unpacker<'a> {
    /// Create an unpacker over a buffer (position — bit 0).
    pub fn new(buf: &'a [u8]) -> Unpacker<'a> {
        Unpacker { buf, pos: 0 }
    }

    /// Read `nrbits` bits (LSB-first).
    pub fn unpack(&mut self, nrbits: u32) -> Result<u32> {
        let mut val = 0u32;
        for i in 0..nrbits {
            let p = self.pos / 8;
            if p >= self.buf.len() {
                return Err(Error::BadNode("LPT node bitstream overruns buffer".into()));
            }
            let b = self.pos % 8;
            val |= (((self.buf[p] >> b) & 1) as u32) << i;
            self.pos += 1;
        }
        Ok(val)
    }
}

/// `ubifs_calc_nnode_num`: an nnode number is the path from the root — a
/// leading 1, then 2 bits per level (the base-4 branch index at each
/// level).
pub fn calc_nnode_num(row: u32, col: u32) -> u32 {
    let mut num = 1u32;
    let mut col = col;
    let mut row = row;
    while row > 0 {
        row -= 1;
        let bits = col & (UBIFS_LPT_FANOUT - 1);
        col >>= UBIFS_LPT_FANOUT_SHIFT;
        num <<= UBIFS_LPT_FANOUT_SHIFT;
        num |= bits;
    }
    num
}

// ---------------------------------------------------------------------------
// Node packing (ubifs_pack_pnode/nnode/ltab/lsave).
// ---------------------------------------------------------------------------

/// Pack a pnode into `buf` (of size `geom.pnode_sz`).
pub fn pack_pnode(geom: &LptGeom, buf: &mut [u8], num: u32, lprops: &[Lprops; 4]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    let mut p = Packer::new(&mut buf[UBIFS_LPT_CRC_BYTES..]);
    p.pack(UBIFS_LPT_PNODE, 4);
    if geom.big_lpt {
        p.pack(num, geom.pcnt_bits);
    }
    for lp in lprops {
        p.pack(lp.free >> 3, geom.space_bits);
        p.pack(lp.dirty >> 3, geom.space_bits);
        p.pack(u32::from(lp.flags & crate::media::LPROPS_INDEX != 0), 1);
    }
    write_crc(buf, geom.pnode_sz);
}

/// An nnode branch: `(lnum relative to lpt_first, offs)`; `None` means
/// "no branch" (packed as `lpt_lebs`, i.e. `lpt_last + 1 - lpt_first`).
pub type NBranch = Option<(u32, u32)>;

/// Pack an nnode into `buf` (of size `geom.nnode_sz`).
pub fn pack_nnode(geom: &LptGeom, buf: &mut [u8], num: u32, branches: &[NBranch; 4]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    let mut p = Packer::new(&mut buf[UBIFS_LPT_CRC_BYTES..]);
    p.pack(UBIFS_LPT_NNODE, 4);
    if geom.big_lpt {
        p.pack(num, geom.pcnt_bits);
    }
    for br in branches {
        let (rel_lnum, offs) = match br {
            Some((lnum, offs)) => (*lnum, *offs),
            // "No branch": lnum = lpt_last + 1, relative = lpt_lebs.
            None => (geom.lpt_lebs_count, 0),
        };
        p.pack(rel_lnum, geom.lpt_lnum_bits);
        p.pack(offs, geom.lpt_offs_bits);
    }
    write_crc(buf, geom.nnode_sz);
}

/// Pack an ltab into `buf` (of size `geom.ltab_sz`).
pub fn pack_ltab(geom: &LptGeom, buf: &mut [u8], ltab: &[LptLprops]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    let mut p = Packer::new(&mut buf[UBIFS_LPT_CRC_BYTES..]);
    p.pack(UBIFS_LPT_LTAB, 4);
    for lp in ltab {
        p.pack(lp.free, geom.lpt_spc_bits);
        p.pack(lp.dirty, geom.lpt_spc_bits);
    }
    write_crc(buf, geom.ltab_sz);
}

/// Pack an lsave into `buf` (of size `geom.lsave_sz`).
pub fn pack_lsave(geom: &LptGeom, buf: &mut [u8], lsave: &[u32]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    let mut p = Packer::new(&mut buf[UBIFS_LPT_CRC_BYTES..]);
    p.pack(UBIFS_LPT_LSAVE, 4);
    for &v in lsave {
        p.pack(v, geom.lnum_bits);
    }
    write_crc(buf, geom.lsave_sz);
}

fn write_crc(buf: &mut [u8], sz: usize) {
    let crc = crc16(0xFFFF, &buf[UBIFS_LPT_CRC_BYTES..sz]);
    buf[0] = crc as u8;
    buf[1] = (crc >> 8) as u8;
}

// ---------------------------------------------------------------------------
// Node unpacking.
// ---------------------------------------------------------------------------

/// Read the LPT node type from a buffer (the first 4 bits after the CRC).
pub fn node_type(buf: &[u8]) -> Result<u32> {
    if buf.len() < UBIFS_LPT_CRC_BYTES + 1 {
        return Err(Error::BadNode("LPT node too short".into()));
    }
    let mut u = Unpacker::new(&buf[UBIFS_LPT_CRC_BYTES..]);
    u.unpack(4)
}

/// Unpack a pnode (4 lprops). `buf` is the whole node, starting at the
/// CRC.
pub fn unpack_pnode(geom: &LptGeom, buf: &[u8]) -> Result<[Lprops; 4]> {
    check_crc(buf, geom.pnode_sz)?;
    let mut u = Unpacker::new(&buf[UBIFS_LPT_CRC_BYTES..]);
    let t = u.unpack(4)?;
    if t != UBIFS_LPT_PNODE {
        return Err(Error::BadNode(format!("LPT: expected pnode, got type {t}")));
    }
    if geom.big_lpt {
        let _ = u.unpack(geom.pcnt_bits)?;
    }
    let mut out = [Lprops {
        free: 0,
        dirty: 0,
        flags: 0,
    }; 4];
    for lp in &mut out {
        lp.free = u.unpack(geom.space_bits)? << 3;
        lp.dirty = u.unpack(geom.space_bits)? << 3;
        lp.flags = if u.unpack(1)? != 0 {
            crate::media::LPROPS_INDEX
        } else {
            0
        };
    }
    Ok(out)
}

/// Unpack an nnode (4 branches, lnum relative to `lpt_first`).
pub fn unpack_nnode(geom: &LptGeom, buf: &[u8]) -> Result<[NBranch; 4]> {
    check_crc(buf, geom.nnode_sz)?;
    let mut u = Unpacker::new(&buf[UBIFS_LPT_CRC_BYTES..]);
    let t = u.unpack(4)?;
    if t != UBIFS_LPT_NNODE {
        return Err(Error::BadNode(format!("LPT: expected nnode, got type {t}")));
    }
    if geom.big_lpt {
        let _ = u.unpack(geom.pcnt_bits)?;
    }
    let mut out: [NBranch; 4] = [None; 4];
    for br in &mut out {
        let lnum = u.unpack(geom.lpt_lnum_bits)?;
        let offs = u.unpack(geom.lpt_offs_bits)?;
        if lnum < geom.lpt_lebs_count {
            *br = Some((lnum, offs));
        }
    }
    Ok(out)
}

/// Unpack an ltab.
pub fn unpack_ltab(geom: &LptGeom, buf: &[u8]) -> Result<Vec<LptLprops>> {
    check_crc(buf, geom.ltab_sz)?;
    let mut u = Unpacker::new(&buf[UBIFS_LPT_CRC_BYTES..]);
    let t = u.unpack(4)?;
    if t != UBIFS_LPT_LTAB {
        return Err(Error::BadNode(format!("LPT: expected ltab, got type {t}")));
    }
    let mut out = Vec::with_capacity(geom.lpt_lebs_count as usize);
    for _ in 0..geom.lpt_lebs_count {
        out.push(LptLprops {
            free: u.unpack(geom.lpt_spc_bits)?,
            dirty: u.unpack(geom.lpt_spc_bits)?,
        });
    }
    Ok(out)
}

/// Unpack an lsave.
pub fn unpack_lsave(geom: &LptGeom, buf: &[u8]) -> Result<Vec<u32>> {
    check_crc(buf, geom.lsave_sz)?;
    let mut u = Unpacker::new(&buf[UBIFS_LPT_CRC_BYTES..]);
    let t = u.unpack(4)?;
    if t != UBIFS_LPT_LSAVE {
        return Err(Error::BadNode(format!("LPT: expected lsave, got type {t}")));
    }
    let mut out = Vec::with_capacity(geom.lsave_count as usize);
    for _ in 0..geom.lsave_count {
        out.push(u.unpack(geom.lnum_bits)?);
    }
    Ok(out)
}

fn check_crc(buf: &[u8], sz: usize) -> Result<()> {
    if buf.len() < sz {
        return Err(Error::BadNode(format!(
            "LPT node truncated: {} < {sz}",
            buf.len()
        )));
    }
    let stored = u16::from_le_bytes([buf[0], buf[1]]);
    if stored != crc16(0xFFFF, &buf[UBIFS_LPT_CRC_BYTES..sz]) {
        return Err(Error::BadCrc("LPT node crc16 mismatch".into()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LPT creation (a port of ubifs_create_lpt from mtd-utils).
// ---------------------------------------------------------------------------

/// The result of LPT creation.
pub struct CreatedLpt {
    /// The LPT-area LEBs (index 0 = `lpt_first`); each is `leb_size`
    /// bytes.
    pub lebs: Vec<Vec<u8>>,
    /// The nnode root position (absolute lnum, offs).
    pub root: (u32, u32),
    /// The write-head position (absolute lnum, offs aligned to min_io).
    pub nhead: (u32, u32),
    /// The ltab position (absolute lnum, offs).
    pub ltab: (u32, u32),
    /// The lsave position (big LPT only).
    pub lsave: Option<(u32, u32)>,
    /// The last occupied LEB of the area (absolute).
    pub last_lnum: u32,
}

/// Build an LPT from the main-area lprops (mkfs semantics: a full tree,
/// `pnode_cnt = ceil(main_lebs / LPT_FANOUT)`).
///
/// `lprops` is the main-area table (a short table is padded with empty
/// LEBs), `lpt_first`/`main_first` are absolute LEB numbers.
pub fn create_lpt(
    geom: &LptGeom,
    lprops: &[Lprops],
    lpt_first: u32,
    main_first: u32,
    leb_size: usize,
    min_io_size: usize,
) -> Result<CreatedLpt> {
    let pnodes = geom.pnode_cnt;
    if lprops.len() > pnodes * UBIFS_LPT_FANOUT as usize {
        return Err(Error::BadGeometry("lprops do not fit LPT geometry".into()));
    }
    let empty_prop = Lprops {
        free: leb_size as u32,
        dirty: 0,
        flags: 0,
    };

    let mut lebs: Vec<Vec<u8>> = vec![vec![0xFF; leb_size]; geom.lpt_lebs_count as usize];
    let mut ltab = vec![
        LptLprops {
            free: leb_size as u32,
            dirty: 0
        };
        geom.lpt_lebs_count as usize
    ];
    let mut buf: Vec<u8> = Vec::with_capacity(leb_size);
    let mut lnum = 0u32; // relative to lpt_first

    // set_ltab from ubifs_create_lpt: free = leb_size - alen, dirty = alen - len.
    fn set_ltab(ltab: &mut [LptLprops], lnum: usize, len: usize, leb_size: usize, min_io: usize) {
        let alen = len.div_ceil(min_io) * min_io;
        ltab[lnum] = LptLprops {
            free: (leb_size - alen) as u32,
            dirty: (alen - len) as u32,
        };
    }
    // Close the current LEB (ubifs_leb_change with 0xFF padding up to the
    // end of the LEB).
    fn flush(
        lebs: &mut [Vec<u8>],
        ltab: &mut [LptLprops],
        lnum: &mut u32,
        buf: &mut Vec<u8>,
        leb_size: usize,
        min_io_size: usize,
    ) {
        if buf.is_empty() {
            return;
        }
        let n = *lnum;
        set_ltab(ltab, n as usize, buf.len(), leb_size, min_io_size);
        let leb = &mut lebs[n as usize];
        leb[..buf.len()].copy_from_slice(buf);
        // The tail stays 0xFF (as in mkfs when writing an image file).
        buf.clear();
        *lnum = n + 1;
    }

    let mut cnt = pnodes;
    let mut blnum = 0u32; // the relative LEB of the level below
    let mut boffs = 0usize;
    let mut bcnt = cnt as u32;
    let mut bsz = geom.pnode_sz as u32;

    // The pnodes.
    for i in 0..cnt {
        if buf.len() + geom.pnode_sz > leb_size {
            flush(
                &mut lebs,
                &mut ltab,
                &mut lnum,
                &mut buf,
                leb_size,
                min_io_size,
            );
        }
        let mut node = vec![0u8; geom.pnode_sz];
        let mut props = [empty_prop; 4];
        for (j, lp) in props.iter_mut().enumerate() {
            if let Some(&src) = lprops.get(i * UBIFS_LPT_FANOUT as usize + j) {
                *lp = src;
            }
        }
        pack_pnode(geom, &mut node, i as u32, &props);
        buf.extend_from_slice(&node);
    }

    // The nnodes, level by level bottom-up; row 0 is the root.
    let mut row = geom.lpt_hght - 1;
    let mut root = (0u32, 0u32);
    loop {
        cnt = cnt.div_ceil(UBIFS_LPT_FANOUT as usize).max(1);
        for i in 0..cnt {
            if buf.len() + geom.nnode_sz > leb_size {
                flush(
                    &mut lebs,
                    &mut ltab,
                    &mut lnum,
                    &mut buf,
                    leb_size,
                    min_io_size,
                );
            }
            if row == 0 {
                root = (lnum + lpt_first, buf.len() as u32);
            }
            let mut node = vec![0u8; geom.nnode_sz];
            let mut branches: [NBranch; 4] = [None; 4];
            for br in branches.iter_mut() {
                if bcnt > 0 {
                    if boffs + bsz as usize > leb_size {
                        blnum += 1;
                        boffs = 0;
                    }
                    *br = Some((blnum, boffs as u32));
                    boffs += bsz as usize;
                    bcnt -= 1;
                }
            }
            pack_nnode(geom, &mut node, calc_nnode_num(row, i as u32), &branches);
            buf.extend_from_slice(&node);
        }
        if row == 0 {
            break;
        }
        bcnt = cnt as u32;
        bsz = geom.nnode_sz as u32;
        row -= 1;
    }

    // lsave (big LPT): lsave[i] = main_first + i (the first main_lebs
    // entries), then main_first.
    let mut lsave_pos = None;
    if geom.big_lpt {
        if buf.len() + geom.lsave_sz > leb_size {
            flush(
                &mut lebs,
                &mut ltab,
                &mut lnum,
                &mut buf,
                leb_size,
                min_io_size,
            );
        }
        lsave_pos = Some((lnum + lpt_first, buf.len() as u32));
        let mut lsave = vec![main_first; geom.lsave_count as usize];
        for (i, v) in lsave.iter_mut().enumerate() {
            if i < lprops.len() {
                *v = main_first + i as u32;
            }
        }
        let mut node = vec![0u8; geom.lsave_sz];
        pack_lsave(geom, &mut node, &lsave);
        buf.extend_from_slice(&node);
    }

    // The ltab goes last; its own position and size are accounted for in
    // its own lprops.
    if buf.len() + geom.ltab_sz > leb_size {
        flush(
            &mut lebs,
            &mut ltab,
            &mut lnum,
            &mut buf,
            leb_size,
            min_io_size,
        );
    }
    let ltab_pos = (lnum + lpt_first, buf.len() as u32);
    // "Update ltab before packing it" (mkfs): the length and alignment
    // include the ltab itself; nhead is in the SAME LEB without an
    // increment.
    let len_after = buf.len() + geom.ltab_sz;
    let alen = len_after.div_ceil(min_io_size) * min_io_size;
    set_ltab(&mut ltab, lnum as usize, len_after, leb_size, min_io_size);
    {
        let mut node = vec![0u8; geom.ltab_sz];
        pack_ltab(geom, &mut node, &ltab);
        buf.extend_from_slice(&node);
    }
    {
        let leb = &mut lebs[lnum as usize];
        leb[..buf.len()].copy_from_slice(&buf);
        buf.clear();
    }
    let nhead = (lnum + lpt_first, alen as u32);
    Ok(CreatedLpt {
        lebs,
        root,
        nhead,
        ltab: ltab_pos,
        lsave: lsave_pos,
        last_lnum: lnum,
    })
}

// ---------------------------------------------------------------------------
// Reading the LPT from flash.
// ---------------------------------------------------------------------------

/// A source of LEBs for LPT reading.
pub trait LebSource {
    /// The LEB contents (`leb_size` bytes), or `None` if the LEB is not
    /// mapped.
    fn leb(&self, lnum: u32) -> Option<&[u8]>;
}

impl LebSource for Vec<Option<Vec<u8>>> {
    fn leb(&self, lnum: u32) -> Option<&[u8]> {
        self.get(lnum as usize).and_then(|l| l.as_deref())
    }
}

impl<T: LebSource + ?Sized> LebSource for &T {
    fn leb(&self, lnum: u32) -> Option<&[u8]> {
        (**self).leb(lnum)
    }
}

/// Read the main-area lprops from the LPT (kernel semantics: absent
/// branches = empty LEBs). Returns `main_lebs` entries.
pub fn read_lprops(
    src: &dyn LebSource,
    geom: &LptGeom,
    lpt_first: u32,
    leb_size: u32,
    root: (u32, u32),
    main_lebs: usize,
) -> Result<Vec<Lprops>> {
    let empty = Lprops {
        free: leb_size,
        dirty: 0,
        flags: 0,
    };
    let cap = main_lebs.max(geom.pnode_cnt * UBIFS_LPT_FANOUT as usize);
    let mut out = vec![empty; cap];

    // An iterative walk: every frame is an nnode with the index of the
    // next branch; the path from the root (base-4) determines the pnode
    // positions in the table.
    struct Frame {
        lnum: u32,
        offs: u32,
        child: u32,
        path: u32,
        level: u32,
    }

    let mut stack = vec![Frame {
        lnum: root.0,
        offs: root.1,
        child: 0,
        path: 0,
        level: 0,
    }];
    while let Some(frame) = stack.pop() {
        if frame.child >= UBIFS_LPT_FANOUT {
            continue;
        }
        stack.push(Frame {
            child: frame.child + 1,
            ..frame
        });

        let child_path = frame.path * UBIFS_LPT_FANOUT + frame.child;
        let levels_below = geom.lpt_hght - 1 - frame.level;

        let leb = src
            .leb(frame.lnum)
            .ok_or_else(|| Error::MissingData(format!("LPT leb {} is unmapped", frame.lnum)))?;
        if frame.offs as usize + geom.nnode_sz > leb.len() {
            return Err(Error::BadNode(format!(
                "LPT nnode at {}:{} overruns leb",
                frame.lnum, frame.offs
            )));
        }
        let node = &leb[frame.offs as usize..frame.offs as usize + geom.nnode_sz];
        let branches = unpack_nnode(geom, node)?;
        match branches[frame.child as usize] {
            None => {
                // The whole sub-branch is empty LEBs; `out` already holds
                // the defaults.
            }
            Some((rel_lnum, boffs)) => {
                let abs_lnum = lpt_first + rel_lnum;
                if levels_below > 0 {
                    stack.push(Frame {
                        lnum: abs_lnum,
                        offs: boffs,
                        child: 0,
                        path: child_path,
                        level: frame.level + 1,
                    });
                } else {
                    let pleb = src.leb(abs_lnum).ok_or_else(|| {
                        Error::MissingData(format!("LPT leb {abs_lnum} is unmapped"))
                    })?;
                    if boffs as usize + geom.pnode_sz > pleb.len() {
                        return Err(Error::BadNode(format!(
                            "LPT pnode at {abs_lnum}:{boffs} overruns leb"
                        )));
                    }
                    let props = unpack_pnode(geom, &pleb[boffs as usize..])?;
                    // child_path is the pnode number; its lprops occupy
                    // positions [pnode * LPT_FANOUT .. +FANOUT].
                    let base = (child_path << UBIFS_LPT_FANOUT_SHIFT) as usize;
                    for (j, lp) in props.into_iter().enumerate() {
                        let idx = base + j;
                        if idx < out.len() {
                            out[idx] = lp;
                        }
                    }
                }
            }
        }
    }

    out.truncate(main_lebs);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::Geometry;

    /// The same representative NAND volume as in the geometry tests.
    fn geom() -> (Geometry, LptGeom) {
        let g = Geometry {
            min_io_size: 2048,
            leb_size: 126976,
            leb_cnt: 579,
            max_leb_cnt: 2212,
            max_bud_bytes: 8 << 20,
            log_lebs: 5,
            lpt_lebs: 2,
            orph_lebs: 1,
            jhead_cnt: 1,
            fanout: 8,
            lsave_cnt: 256,
            fmt_version: 4,
            default_compr: 1,
            flags: 0,
            uuid: [0; 16],
            ro_compat_version: 0,
        };
        let l = g.lpt();
        (g, l)
    }

    #[test]
    fn nnode_num_formula() {
        // Kernel: num=1; while row--: num = num*4 + (col&3), col>>=2.
        assert_eq!(calc_nnode_num(0, 0), 1);
        assert_eq!(calc_nnode_num(0, 3), 1);
        assert_eq!(calc_nnode_num(1, 0), 4);
        assert_eq!(calc_nnode_num(1, 3), 7);
        assert_eq!(calc_nnode_num(2, 5), 21);
    }

    #[test]
    fn pack_unpack_pnode_roundtrip() {
        let (_g, l) = geom();
        let props = [
            Lprops {
                free: 0,
                dirty: 126904,
                flags: 0,
            },
            Lprops {
                free: 2048,
                dirty: 1000,
                flags: crate::media::LPROPS_INDEX,
            },
            Lprops {
                free: 126976,
                dirty: 0,
                flags: 0,
            },
            Lprops {
                free: 4096,
                dirty: 8,
                flags: 0,
            },
        ];
        let mut buf = vec![0u8; l.pnode_sz];
        pack_pnode(&l, &mut buf, 5, &props);
        assert_eq!(unpack_pnode(&l, &buf).unwrap(), props);
    }

    #[test]
    fn pack_unpack_nnode_roundtrip() {
        let (_g, l) = geom();
        let branches = [Some((0, 125021)), Some((1, 65536)), None, Some((1, 0))];
        let mut buf = vec![0u8; l.nnode_sz];
        pack_nnode(&l, &mut buf, calc_nnode_num(4, 0), &branches);
        assert_eq!(unpack_nnode(&l, &buf).unwrap(), branches);
    }

    #[test]
    fn create_then_read() {
        let (g, l) = geom();
        let main_lebs = g.main_lebs() as usize;
        let mut lprops = vec![
            Lprops {
                free: 126976,
                dirty: 0,
                flags: 0
            };
            main_lebs
        ];
        lprops[0] = Lprops {
            free: 0,
            dirty: 126904,
            flags: 0,
        };
        lprops[1] = Lprops {
            free: 512,
            dirty: 296,
            flags: 0,
        };
        lprops[10] = Lprops {
            free: 0,
            dirty: 100000,
            flags: crate::media::LPROPS_INDEX,
        };
        lprops[560] = Lprops {
            free: 2048,
            dirty: 64,
            flags: 0,
        };
        let created = create_lpt(
            &l,
            &lprops,
            g.lpt_first(),
            g.main_first(),
            g.leb_size as usize,
            g.min_io_size as usize,
        )
        .unwrap();
        // mkfs writes the full tree: every pnode is present.
        let src = CreatedLebs(&created.lebs);
        let read =
            read_lprops(&src, &l, g.lpt_first(), g.leb_size, created.root, main_lebs).unwrap();
        assert_eq!(read, lprops);
    }

    struct CreatedLebs<'a>(&'a [Vec<u8>]);
    impl LebSource for CreatedLebs<'_> {
        fn leb(&self, lnum: u32) -> Option<&[u8]> {
            self.0.get((lnum - 8) as usize).map(|v| v.as_slice())
        }
    }
}
