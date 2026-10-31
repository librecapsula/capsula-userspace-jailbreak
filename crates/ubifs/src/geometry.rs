//! Volume geometry: the derived LPT sizes (`do_calc_lpt_geom` from
//! `fs/ubifs/lpt.c`), the default geometry (`ubifs_calc_dflt_lpt_geom`),
//! log minimums and the lprops watermarks.

use crate::error::{Error, Result};
use crate::media::*;

/// The LPT fanout — a format constant, independent of the TNC fanout
/// (`UBIFS_LPT_FANOUT`).
pub const UBIFS_LPT_FANOUT: u32 = 4;
/// Shift of the LPT fanout (`UBIFS_LPT_FANOUT_SHIFT`).
pub const UBIFS_LPT_FANOUT_SHIFT: u32 = 2;

/// LPT node types (`enum ubifs_lpt_type`).
/// A pnode — an lprops leaf.
pub const UBIFS_LPT_PNODE: u32 = 0;
/// An nnode — an internal LPT node.
pub const UBIFS_LPT_NNODE: u32 = 1;
/// An ltab — lprops of the LPT area itself.
pub const UBIFS_LPT_LTAB: u32 = 2;
/// An lsave — the lnum table (big LPT).
pub const UBIFS_LPT_LSAVE: u32 = 3;
/// The "not a node" value (all ones).
pub const UBIFS_LPT_NOT_A_NODE: u32 = 15;

/// Size of the LPT CRC field in bytes (`UBIFS_LPT_CRC_BYTES`).
pub const UBIFS_LPT_CRC_BYTES: usize = 2;
/// Size of the LPT CRC field in bits (`UBIFS_LPT_CRC_BITS`).
pub const UBIFS_LPT_CRC_BITS: u32 = 16;
/// Size of the LPT type field in bits (`UBIFS_LPT_TYPE_BITS`).
pub const UBIFS_LPT_TYPE_BITS: u32 = 4;

/// Volume geometry (SB fields + derived values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Geometry {
    /// Minimum I/O unit size.
    pub min_io_size: u32,
    /// LEB size.
    pub leb_size: u32,
    /// The actual number of LEBs (after finalize — as in the master node).
    pub leb_cnt: u32,
    /// The LEB count ceiling.
    pub max_leb_cnt: u32,
    /// Maximum journal size.
    pub max_bud_bytes: u64,
    /// Log size in LEBs.
    pub log_lebs: u32,
    /// Number of LPT LEBs.
    pub lpt_lebs: u32,
    /// Number of orphan-area LEBs.
    pub orph_lebs: u32,
    /// Number of journal heads.
    pub jhead_cnt: u32,
    /// TNC fanout.
    pub fanout: u32,
    /// Number of lsave entries.
    pub lsave_cnt: u32,
    /// Format version.
    pub fmt_version: u32,
    /// Default compression.
    pub default_compr: u16,
    /// SB flags.
    pub flags: u32,
    /// Volume UUID.
    pub uuid: [u8; 16],
    /// Read-only compatibility version.
    pub ro_compat_version: u32,
}

/// The derived LPT geometry (`struct lpt_geometry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LptGeom {
    /// LPT tree height (the number of nnode levels).
    pub lpt_hght: u32,
    /// Number of pnodes (ceil(main_lebs / 4)).
    pub pnode_cnt: usize,
    /// Number of nnodes per the geometry.
    pub nnode_cnt: usize,
    /// The LPT model.
    pub big_lpt: bool,
    /// Bits per free/dirty value (fls(leb_size) − 3).
    pub space_bits: u32,
    /// Bits per relative branch lnum.
    pub lpt_lnum_bits: u32,
    /// Bits per branch offset.
    pub lpt_offs_bits: u32,
    /// Bits per ltab free-space value.
    pub lpt_spc_bits: u32,
    /// Bits per pnode number (big LPT).
    pub pcnt_bits: u32,
    /// Bits per lnum in lsave.
    pub lnum_bits: u32,
    /// pnode size in bytes.
    pub pnode_sz: usize,
    /// nnode size in bytes.
    pub nnode_sz: usize,
    /// ltab size in bytes.
    pub ltab_sz: usize,
    /// lsave size in bytes.
    pub lsave_sz: usize,
    /// Estimated LPT size in bytes.
    pub lpt_sz: u64,
    /// Number of LPT-area LEBs (a copy of `Geometry::lpt_lebs`).
    pub lpt_lebs_count: u32,
    /// Number of lsave entries (a copy of `Geometry::lsave_cnt`).
    pub lsave_count: u32,
}

impl LptGeom {
    /// The body of `do_calc_lpt_geom`: every size derives from the volume
    /// geometry and from `n = main_lebs + max_leb_cnt - leb_cnt` (the
    /// kernel variant) or `n = max_leb_cnt - main_first` (the mkfs
    /// variant) — see [`Geometry::lpt`] and [`Geometry::lpt_for_build`].
    pub fn calc(g: &Geometry, n: u32) -> LptGeom {
        let max_pnode_cnt = n.div_ceil(UBIFS_LPT_FANOUT);

        let mut lpt_hght = 1u32;
        let mut m = UBIFS_LPT_FANOUT;
        while m < max_pnode_cnt {
            lpt_hght += 1;
            m <<= UBIFS_LPT_FANOUT_SHIFT;
        }

        let main_lebs = g.main_lebs();
        let pnode_cnt = main_lebs.div_ceil(UBIFS_LPT_FANOUT);
        let mut m = pnode_cnt.div_ceil(UBIFS_LPT_FANOUT);
        let mut nnode_cnt = m;
        for _ in 1..lpt_hght {
            m = m.div_ceil(UBIFS_LPT_FANOUT);
            nnode_cnt += m;
        }

        let big_lpt = g.big_lpt();
        let space_bits = fls(g.leb_size) - 3;
        let lpt_lnum_bits = fls(g.lpt_lebs);
        let lpt_offs_bits = fls(g.leb_size - 1);
        let lpt_spc_bits = fls(g.leb_size);
        let pcnt_bits = fls(g.max_leb_cnt.div_ceil(UBIFS_LPT_FANOUT) - 1);
        let lnum_bits = fls(g.max_leb_cnt - 1);

        let bits = |per: u32| -> u64 {
            (UBIFS_LPT_CRC_BITS + UBIFS_LPT_TYPE_BITS + if big_lpt { pcnt_bits } else { 0 } + per)
                as u64
        };
        let pnode_sz = bits((space_bits * 2 + 1) * UBIFS_LPT_FANOUT).div_ceil(8) as usize;
        let nnode_sz =
            bits((lpt_lnum_bits + lpt_offs_bits) * UBIFS_LPT_FANOUT).div_ceil(8) as usize;
        let ltab_sz = bits(g.lpt_lebs * lpt_spc_bits * 2).div_ceil(8) as usize;
        let lsave_sz = bits(lnum_bits * g.lsave_cnt).div_ceil(8) as usize;

        let lpt_sz = pnode_cnt as u64 * pnode_sz as u64
            + nnode_cnt as u64 * nnode_sz as u64
            + ltab_sz as u64
            + u64::from(big_lpt) * lsave_sz as u64;

        LptGeom {
            lpt_hght,
            pnode_cnt: pnode_cnt as usize,
            nnode_cnt: nnode_cnt as usize,
            big_lpt,
            space_bits,
            lpt_lnum_bits,
            lpt_offs_bits,
            lpt_spc_bits,
            pcnt_bits,
            lnum_bits,
            pnode_sz,
            nnode_sz,
            ltab_sz,
            lsave_sz,
            lpt_sz,
            lpt_lebs_count: g.lpt_lebs,
            lsave_count: g.lsave_cnt,
        }
    }
}

impl Geometry {
    /// The first LEB of the main area (`main_first`).
    pub fn main_first(&self) -> u32 {
        UBIFS_LOG_LNUM + self.log_lebs + self.lpt_lebs + self.orph_lebs
    }

    /// Number of main-area LEBs (`main_lebs`).
    pub fn main_lebs(&self) -> u32 {
        self.leb_cnt - self.main_first()
    }

    /// The first LPT LEB (`lpt_first`).
    pub fn lpt_first(&self) -> u32 {
        UBIFS_LOG_LNUM + self.log_lebs
    }

    /// The last LPT LEB (`lpt_last`).
    pub fn lpt_last(&self) -> u32 {
        self.lpt_first() + self.lpt_lebs - 1
    }

    /// `big_lpt` per the SB flags.
    pub fn big_lpt(&self) -> bool {
        self.flags & UBIFS_FLG_BIGLPT != 0
    }

    /// `do_calc_lpt_geom` from `fs/ubifs/lpt.c` — the kernel mount
    /// semantics: the tree height derives from
    /// `main_lebs + max_leb_cnt - leb_cnt` (the volume may grow up to
    /// `max_leb_cnt`, and the tree must fit the corresponding number of
    /// pnodes).
    pub fn lpt(&self) -> LptGeom {
        let n = self.main_lebs() + self.max_leb_cnt - self.leb_cnt;
        LptGeom::calc(self, n)
    }

    /// The mkfs.ubifs variant: the tree height derives from
    /// `max_leb_cnt - main_first` (at mkfs time `leb_cnt` is not known
    /// yet — see the `MKFS_PROGRAM_TYPE` branch in the mtd-utils
    /// `libubifs/lpt.c`). It matches the height computed by the kernel
    /// at mount: the final `leb_cnt <= max_leb_cnt`.
    pub fn lpt_for_build(&self) -> LptGeom {
        let n = self.max_leb_cnt - self.main_first();
        LptGeom::calc(self, n)
    }

    /// `ubifs_calc_dflt_lpt_geom`: pick `lpt_lebs`/`big_lpt` for the given
    /// number of main LEBs (input/output, as in the mkfs init). Returns
    /// an updated copy of the geometry.
    pub fn calc_dflt_lpt_geom(&self, main_lebs: &mut u32) -> Result<Geometry> {
        let mut g = self.clone();
        g.lpt_lebs = UBIFS_MIN_LPT_LEBS;
        g.flags &= !UBIFS_FLG_BIGLPT;
        let set_main = |g: &mut Geometry, ml: u32| {
            g.leb_cnt = UBIFS_LOG_LNUM + g.log_lebs + g.lpt_lebs + g.orph_lebs + ml;
        };
        let ml = *main_lebs - g.lpt_lebs;
        set_main(&mut g, ml);
        if *main_lebs <= g.lpt_lebs {
            return Err(Error::BadGeometry("too few LEBs for LPT area".into()));
        }

        // A small LPT must fit into a single LEB, otherwise it becomes big.
        if g.lpt().lpt_sz > g.leb_size as u64 {
            g.flags |= UBIFS_FLG_BIGLPT;
        }

        for _ in 0..64 {
            let sz = g.lpt().lpt_sz * 4; // a ×4 margin, as in the kernel
            let lebs_needed = sz.div_ceil(g.leb_size as u64) as u32;
            if lebs_needed > g.lpt_lebs {
                g.lpt_lebs = lebs_needed;
                if *main_lebs <= g.lpt_lebs {
                    return Err(Error::BadGeometry("too few LEBs for LPT area".into()));
                }
                let ml = *main_lebs - g.lpt_lebs;
                set_main(&mut g, ml);
                continue;
            }
            if g.lpt().ltab_sz > g.leb_size as usize {
                return Err(Error::BadGeometry("LPT ltab too big".into()));
            }
            *main_lebs = g.main_lebs();
            return Ok(g);
        }
        Err(Error::BadGeometry("cannot fit LPT geometry".into()))
    }
}

/// `fls(x)`: the 1-based index of the highest set bit, as in the kernel.
pub(crate) fn fls(x: u32) -> u32 {
    32 - x.leading_zeros()
}

/// The lprops watermarks (`lpt_init_rd`/mkfs init):
/// `dead_wm = ALIGN(MIN_WRITE_SZ, min_io)`,
/// `dark_wm = ALIGN(UBIFS_MAX_NODE_SZ, min_io)`.
pub fn watermarks(min_io_size: u32) -> (u32, u32) {
    let align = |x: u32| x.div_ceil(min_io_size) * min_io_size;
    (align(MIN_WRITE_SZ as u32), align(UBIFS_MAX_NODE_SZ as u32))
}

/// `calc_dark` (mkfs.ubifs / lprops.c): the dark space of a LEB.
pub fn calc_dark(dark_wm: u32, spc: u32) -> u32 {
    if spc < dark_wm {
        return spc;
    }
    if spc - dark_wm < MIN_WRITE_SZ as u32 {
        return spc - MIN_WRITE_SZ as u32;
    }
    dark_wm
}

/// `calc_min_log_lebs` (mkfs.ubifs): the minimum number of log LEBs.
pub fn calc_min_log_lebs(
    leb_size: u32,
    min_io_size: u32,
    max_bud_bytes: u64,
    jhead_cnt: u32,
) -> u32 {
    let buds = max_bud_bytes.div_ceil(leb_size as u64);
    let align = |x: u64| x.div_ceil(min_io_size as u64) * min_io_size as u64;
    let mut log_size = align(UBIFS_REF_NODE_SZ as u64) * buds;
    log_size += align((UBIFS_CS_NODE_SZ + UBIFS_REF_NODE_SZ * (jhead_cnt as usize + 2)) as u64);
    (log_size.div_ceil(leb_size as u64) + 1) as u32
}

/// The default `max_bud_bytes` (mkfs.ubifs get_options): ~12.5% of the
/// main area, capped at 8 MiB, floored at 4 LEBs.
pub fn default_max_bud_bytes(
    leb_size: u32,
    max_leb_cnt: u32,
    log_lebs: u32,
    orph_lebs: u32,
) -> u64 {
    let mut lebs = max_leb_cnt - UBIFS_SB_LEBS - UBIFS_MST_LEBS - orph_lebs;
    lebs -= log_lebs.max(UBIFS_MIN_LOG_LEBS);
    lebs -= UBIFS_MIN_LPT_LEBS;
    let mut v = (lebs / 8) as u64 * leb_size as u64;
    if v > 8 * 1024 * 1024 {
        v = 8 * 1024 * 1024;
    }
    if v < 4 * leb_size as u64 {
        v = 4 * leb_size as u64;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative 128 KiB-PEB / 2 KiB-page NAND volume; the derived
    /// values below are cross-checked against `fs/ubifs/lpt.c`.
    pub(crate) fn nand_geometry() -> Geometry {
        Geometry {
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
        }
    }

    #[test]
    fn nand_lpt_geometry() {
        let g = nand_geometry();
        let l = g.lpt();
        // Cross-checked with a hand computation over fs/ubifs/lpt.c.
        assert_eq!(g.main_first(), 11);
        assert_eq!(g.main_lebs(), 568);
        assert_eq!(l.lpt_hght, 5);
        assert_eq!(l.pnode_cnt, 142);
        assert_eq!(l.nnode_cnt, 50);
        assert!(!l.big_lpt);
        assert_eq!(l.space_bits, 14);
        assert_eq!(l.lpt_lnum_bits, 2);
        assert_eq!(l.lpt_offs_bits, 17);
        assert_eq!(l.lpt_spc_bits, 17);
        assert_eq!(l.pcnt_bits, 10);
        assert_eq!(l.lnum_bits, 12);
        assert_eq!(l.pnode_sz, 17);
        assert_eq!(l.nnode_sz, 12);
        assert_eq!(l.ltab_sz, 11);
        assert_eq!(l.lsave_sz, 387);
    }

    #[test]
    fn watermarks_nand() {
        let (dead, dark) = watermarks(2048);
        // MIN_WRITE_SZ = 48+8 = 56 -> 2048; MAX_NODE_SZ = 4256 -> 6144.
        assert_eq!(dead, 2048);
        assert_eq!(dark, 6144);
        assert_eq!(calc_dark(dark, 6200), 6144);
        assert_eq!(calc_dark(dark, 6160), 6160 - MIN_WRITE_SZ as u32);
        assert_eq!(calc_dark(dark, 5000), 5000);
    }
}
