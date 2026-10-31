//! Building a UBIFS image from scratch — a port of mkfs.ubifs
//! (`ubifs-utils/mkfs.ubifs`).
//!
//! The order and semantics mirror the original: data writes (children →
//! dent → the directory's own ino), gc_lnum, the index (`write_index`),
//! the leb_cnt finalize, the LPT (`ubifs_create_lpt`), the master node
//! ×2, the superblock (+ the SIG node), the log (a CS node) and the
//! orphan area. Nodes inside a LEB are aligned to 8 bytes; a LEB tail is
//! padded with a pad node/0xCE up to min_io and with 0xFF to the end.

use crate::error::{Error, Result};
use crate::geometry::{self, Geometry};
use crate::key::Key;
use crate::lpt::{create_lpt, Lprops};
use crate::media::*;
use crate::tnc::{write_index, IdxEntry, IndexResult, NodeSink};
use crate::tree::{Inode, Kind};

/// The default compression picked by [`Options::new`].
///
/// Write-side compression is not implemented yet (it lands with the
/// `compress` work), so the default stays `NONE`; once compressed
/// writes exist the default will mirror mkfs.ubifs ("LZO if built with
/// LZO, else ZLIB, else none").
pub const DEFAULT_COMPR: u16 = UBIFS_COMPR_NONE;

/// mkfs options — a mirror of the mkfs.ubifs command line.
#[derive(Debug, Clone)]
pub struct Options {
    /// Minimum I/O unit size (`-m`).
    pub min_io_size: u32,
    /// LEB size (`-e`).
    pub leb_size: u32,
    /// The LEB count ceiling (`-c`). The final leb_cnt is smaller — it
    /// reflects the actual image.
    pub max_leb_cnt: u32,
    /// Log size (`-l`); None — the journal minimum + 2.
    pub log_lebs: Option<u32>,
    /// Number of orphan-area LEBs.
    pub orph_lebs: u32,
    /// TNC fanout (`-f`, mkfs.ubifs default 8).
    pub fanout: u32,
    /// Journal size (`-j`); None — the mkfs default.
    pub max_bud_bytes: Option<u64>,
    /// Number of lsave entries.
    pub lsave_cnt: u32,
    /// Default compression (`-x`; compressed writes are byte-compatible
    /// in structure, see the crate docs).
    pub default_compr: u16,
    /// Volume UUID (mkfs.ubifs generates a random one; the crate default
    /// is all zeroes — set your own for reproducible builds).
    pub uuid: [u8; 16],
    /// Format version.
    pub fmt_version: u32,
    /// Read-only compatibility version.
    pub ro_compat_version: u32,
    /// `UBIFS_FLG_SPACE_FIXUP` (`-F`).
    pub space_fixup: bool,
    /// Time granularity, nanoseconds.
    pub time_gran: u32,
}

impl Options {
    /// Create options with the mandatory flash geometry (`-m/-e/-c` are
    /// required by mkfs.ubifs for file targets too) and the mkfs.ubifs
    /// defaults for everything else.
    pub fn new(min_io_size: u32, leb_size: u32, max_leb_cnt: u32) -> Options {
        Options {
            min_io_size,
            leb_size,
            max_leb_cnt,
            log_lebs: None,
            orph_lebs: UBIFS_MIN_ORPH_LEBS,
            fanout: 8,
            max_bud_bytes: None,
            lsave_cnt: 256,
            default_compr: DEFAULT_COMPR,
            uuid: [0; 16],
            fmt_version: 4,
            ro_compat_version: 0,
            space_fixup: false,
            time_gran: DEFAULT_TIME_GRAN,
        }
    }

    /// Validation, as in `validate_options`.
    pub fn validate(&self) -> Result<()> {
        if !self.min_io_size.is_power_of_two() {
            return Err(Error::BadGeometry(
                "min. I/O unit size must be power of 2".into(),
            ));
        }
        if self.leb_size < self.min_io_size {
            return Err(Error::BadGeometry(
                "min. I/O unit cannot be larger than LEB size".into(),
            ));
        }
        if self.leb_size < UBIFS_MIN_LEB_SZ {
            return Err(Error::BadGeometry(format!(
                "too small LEB size {}, minimum is {UBIFS_MIN_LEB_SZ}",
                self.leb_size
            )));
        }
        if !self.leb_size.is_multiple_of(self.min_io_size) {
            return Err(Error::BadGeometry(
                "LEB must be multiple of min. I/O units".into(),
            ));
        }
        if !self.leb_size.is_multiple_of(8) {
            return Err(Error::BadGeometry("LEB size must be multiple of 8".into()));
        }
        if self.leb_size > UBIFS_MAX_LEB_SZ {
            return Err(Error::BadGeometry("too large LEB size".into()));
        }
        if self.max_leb_cnt < UBIFS_MIN_LEB_CNT {
            return Err(Error::BadGeometry("too low max. count of LEBs".into()));
        }
        if self.fanout < UBIFS_MIN_FANOUT {
            return Err(Error::BadGeometry("too low fanout".into()));
        }
        let max_fanout = (self.leb_size as usize - UBIFS_IDX_NODE_SZ)
            / (UBIFS_BRANCH_SZ + crate::key::UBIFS_MAX_KEY_LEN);
        if self.fanout as usize > max_fanout {
            return Err(Error::BadGeometry("too high fanout".into()));
        }
        Ok(())
    }
}

/// A finished image: the LEB contents (None — an empty 0xFF LEB upon
/// serialization) plus the final geometry and master node.
pub struct Image {
    /// The image LEBs; None — an empty LEB (0xFF).
    pub lebs: Vec<Option<Vec<u8>>>,
    /// The final geometry (the actual leb_cnt).
    pub geometry: Geometry,
    /// The image master node.
    pub master: Master,
}

impl Image {
    /// Serialize into a LEB stream (the .ubifs format: LEB i lives at
    /// offset i * leb_size; empty LEBs are 0xFF).
    pub fn to_vec(&self) -> Vec<u8> {
        let leb_size = self.geometry.leb_size as usize;
        let mut out = Vec::with_capacity(self.geometry.leb_cnt as usize * leb_size);
        for i in 0..self.geometry.leb_cnt as usize {
            match &self.lebs[i] {
                Some(v) => out.extend_from_slice(v),
                None => out.resize(out.len() + leb_size, 0xFF),
            }
        }
        out
    }
}

/// Space statistics (`struct ubifs_info::lst`).
#[derive(Debug, Default, Clone, Copy)]
struct Lst {
    total_free: u64,
    total_dirty: u64,
    total_used: u64,
    total_dead: u64,
    total_dark: u64,
    empty_lebs: u32,
    idx_lebs: u32,
}

/// Build an image from a tree (a full port of mkfs()).
pub fn mkfs(root: &Inode, opts: &Options) -> Result<Image> {
    opts.validate()?;
    root.validate()?;

    // --- init(): the geometry ---
    let max_bud = match opts.max_bud_bytes {
        Some(v) => v,
        None => geometry::default_max_bud_bytes(
            opts.leb_size,
            opts.max_leb_cnt,
            opts.log_lebs.unwrap_or(UBIFS_MIN_LOG_LEBS),
            opts.orph_lebs,
        ),
    };
    let log_lebs = match opts.log_lebs {
        Some(v) => v,
        None => geometry::calc_min_log_lebs(opts.leb_size, opts.min_io_size, max_bud, 1) + 2,
    };
    let mut main_lebs =
        opts.max_leb_cnt - UBIFS_SB_LEBS - UBIFS_MST_LEBS - log_lebs - opts.orph_lebs;
    let base = Geometry {
        min_io_size: opts.min_io_size,
        leb_size: opts.leb_size,
        leb_cnt: 0,
        max_leb_cnt: opts.max_leb_cnt,
        max_bud_bytes: max_bud,
        log_lebs,
        lpt_lebs: 0,
        orph_lebs: opts.orph_lebs,
        jhead_cnt: 1,
        fanout: opts.fanout,
        lsave_cnt: opts.lsave_cnt,
        fmt_version: opts.fmt_version,
        default_compr: opts.default_compr,
        flags: 0,
        uuid: opts.uuid,
        ro_compat_version: opts.ro_compat_version,
    };
    let mut geom = base.calc_dflt_lpt_geom(&mut main_lebs)?;
    let mut flags = 0u32;
    if geom.big_lpt() {
        flags |= UBIFS_FLG_BIGLPT;
    }
    if opts.space_fixup {
        flags |= UBIFS_FLG_SPACE_FIXUP;
    }
    geom.flags = flags;
    let main_first = geom.main_first() as usize;
    let (dead_wm, dark_wm) = geometry::watermarks(opts.min_io_size);

    let leb_size = opts.leb_size as usize;
    let mut st = State {
        lebs: vec![None; opts.max_leb_cnt as usize],
        head_lnum: main_first,
        head_offs: 0,
        head_flags: 0,
        max_sqnum: 0,
        highest_inum: UBIFS_FIRST_INO as u64,
        creat_sqnum: 0,
        lst: Lst::default(),
        lpt: vec![
            Lprops {
                free: 0,
                dirty: 0,
                flags: 0
            };
            main_lebs as usize
        ],
        dead_wm,
        dark_wm,
        leb_size,
        min_io_size: opts.min_io_size as usize,
        main_first,
        idx_entries: Vec::new(),
        default_compr: opts.default_compr,
    };

    // --- write_data(): children → dent → the directory's own ino ---
    st.add_directory(root, UBIFS_ROOT_INO)?;
    st.flush_nodes()?;

    // --- set_gc_lnum() ---
    let gc_lnum = st.head_lnum as u32;
    st.head_lnum += 1;
    st.write_empty_leb(gc_lnum)?;
    st.set_lprops(gc_lnum, 0, 0);
    st.lst.empty_lebs += 1;

    // --- write_index() ---
    st.head_flags = LPROPS_INDEX;
    let idx: IndexResult = {
        let entries = std::mem::take(&mut st.idx_entries);
        let mut sink = Sink(&mut st);
        write_index(&mut sink, opts.fanout, opts.leb_size, entries)?
    };
    // ihead is taken before the flush; the owner performs the flush.
    let ihead = idx.ihead;
    st.flush_nodes()?;

    // --- finalize_leb_cnt() ---
    let leb_cnt = st.head_lnum as u32;
    if leb_cnt > opts.max_leb_cnt {
        return Err(Error::Overflow(format!(
            "max_leb_cnt too low ({} needed)",
            leb_cnt
        )));
    }
    geom.leb_cnt = leb_cnt;
    let main_lebs_final = geom.main_lebs() as usize;
    st.lpt.truncate(main_lebs_final);

    // --- write_lpt() ---
    let lptg_build = geom.lpt_for_build();
    let created = create_lpt(
        &lptg_build,
        &st.lpt,
        geom.lpt_first(),
        geom.main_first(),
        leb_size,
        st.min_io_size,
    )?;
    let lpt_first = geom.lpt_first() as usize;
    for (i, leb) in created.lebs.iter().enumerate() {
        st.lebs[lpt_first + i] = Some(leb.clone());
    }
    // LEBs from nhead up to lpt_last are empty (write_lpt).
    for lnum in (created.nhead.0 as usize + 1)..=(geom.lpt_last() as usize) {
        st.write_empty_leb(lnum as u32)?;
    }
    let lscan_lnum = geom.main_first();

    // --- write_master() ---
    let mut master = Master {
        highest_inum: st.highest_inum,
        cmt_no: 0,
        flags: UBIFS_MST_NO_ORPHS,
        log_lnum: UBIFS_LOG_LNUM,
        root_lnum: idx.root.lnum,
        root_offs: idx.root.offs,
        root_len: idx.root.len,
        gc_lnum,
        ihead_lnum: ihead.0,
        ihead_offs: ihead.1,
        index_size: idx.index_size,
        total_free: st.lst.total_free,
        total_dirty: st.lst.total_dirty,
        total_used: st.lst.total_used,
        total_dead: st.lst.total_dead,
        total_dark: st.lst.total_dark,
        lpt_lnum: created.root.0,
        lpt_offs: created.root.1,
        nhead_lnum: created.nhead.0,
        nhead_offs: created.nhead.1,
        ltab_lnum: created.ltab.0,
        ltab_offs: created.ltab.1,
        lsave_lnum: 0,
        lsave_offs: 0,
        lscan_lnum,
        empty_lebs: st.lst.empty_lebs,
        idx_lebs: st.lst.idx_lebs,
        leb_cnt,
    };
    if let Some((lnum, offs)) = created.lsave {
        master.lsave_lnum = lnum;
        master.lsave_offs = offs;
    }
    let mst = master.to_node(st.next_sqnum());
    st.write_node(&mst, UBIFS_MST_LNUM)?;
    let mst = master.to_node(st.next_sqnum());
    st.write_node(&mst, UBIFS_MST_LNUM + 1)?;

    // --- write_super() ---
    let sb = Superblock {
        key_hash: 0,
        key_fmt: 0,
        flags: geom.flags,
        min_io_size: opts.min_io_size,
        leb_size: opts.leb_size,
        leb_cnt,
        max_leb_cnt: opts.max_leb_cnt,
        max_bud_bytes: max_bud,
        log_lebs,
        lpt_lebs: geom.lpt_lebs,
        orph_lebs: opts.orph_lebs,
        jhead_cnt: 1,
        fanout: opts.fanout,
        lsave_cnt: opts.lsave_cnt,
        fmt_version: opts.fmt_version,
        default_compr: opts.default_compr,
        rp_size: 0,
        time_gran: opts.time_gran,
        uuid: opts.uuid,
        ro_compat_version: opts.ro_compat_version,
        sqnum: 0,
    };
    st.write_super(&sb)?;

    // --- write_log() ---
    let cs = CsNode { cmt_no: 0 }.to_node(st.next_sqnum());
    st.write_node(&cs, UBIFS_LOG_LNUM)?;
    for lnum in UBIFS_LOG_LNUM + 1..UBIFS_LOG_LNUM + log_lebs {
        st.write_empty_leb(lnum)?;
    }

    // --- write_orphan_area() ---
    for lnum in geom.lpt_last() + 1..geom.main_first() {
        st.write_empty_leb(lnum)?;
    }

    Ok(Image {
        lebs: st.lebs,
        geometry: geom,
        master,
    })
}

// ---------------------------------------------------------------------------
// Build state.
// ---------------------------------------------------------------------------

struct State {
    lebs: Vec<Option<Vec<u8>>>,
    head_lnum: usize,
    head_offs: usize,
    head_flags: u32,
    max_sqnum: u64,
    highest_inum: u64,
    creat_sqnum: u64,
    lst: Lst,
    lpt: Vec<Lprops>,
    dead_wm: u32,
    dark_wm: u32,
    leb_size: usize,
    min_io_size: usize,
    main_first: usize,
    idx_entries: Vec<IdxEntry>,
    default_compr: u16,
}

impl State {
    fn next_sqnum(&mut self) -> u64 {
        self.max_sqnum += 1;
        self.max_sqnum
    }

    /// `write_empty_leb`.
    fn write_empty_leb(&mut self, lnum: u32) -> Result<()> {
        self.lebs[lnum as usize] = Some(vec![0xFF; self.leb_size]);
        Ok(())
    }

    /// `flush_nodes`: close the write head.
    fn flush_nodes(&mut self) -> Result<()> {
        if self.head_offs == 0 {
            return Ok(());
        }
        let len = self.head_offs.div_ceil(self.min_io_size) * self.min_io_size;
        {
            let leb = self.lebs[self.head_lnum].get_or_insert_with(|| vec![0xFF; self.leb_size]);
            ubifs_pad(&mut leb[self.head_offs..len]);
        }
        let (lnum, offs, flags) = (self.head_lnum as u32, self.head_offs, self.head_flags);
        self.set_lprops(lnum, offs, flags);
        self.head_lnum += 1;
        self.head_offs = 0;
        Ok(())
    }

    /// `set_lprops` (mkfs): LEB properties from the actual fill level.
    fn set_lprops(&mut self, lnum: u32, offs: usize, flags: u32) {
        let i = lnum as usize - self.main_first;
        let a = self.min_io_size.max(8);
        let free = (self.leb_size - offs.div_ceil(a) * a) as u32;
        let dirty = (self.leb_size - free as usize - offs.div_ceil(8) * 8) as u32;
        if i < self.lpt.len() {
            self.lpt[i] = Lprops { free, dirty, flags };
        }
        self.lst.total_free += free as u64;
        self.lst.total_dirty += dirty as u64;
        if flags & LPROPS_INDEX != 0 {
            self.lst.idx_lebs += 1;
        } else {
            let spc = free + dirty;
            if spc < self.dead_wm {
                self.lst.total_dead += spc as u64;
            } else {
                self.lst.total_dark += geometry::calc_dark(self.dark_wm, spc) as u64;
            }
            self.lst.total_used += (self.leb_size as u32 - spc) as u64;
        }
    }

    /// `write_node`: a node into its own LEB (master, sb, cs): 0xFF up to
    /// an 8-byte alignment, a pad node/0xCE up to min_io, 0xFF to the end.
    fn write_node(&mut self, node: &[u8], lnum: u32) -> Result<()> {
        let alen = node.len().div_ceil(8) * 8;
        let wlen = node.len().div_ceil(self.min_io_size) * self.min_io_size;
        let leb = self.lebs[lnum as usize].get_or_insert_with(|| vec![0xFF; self.leb_size]);
        leb[..node.len()].copy_from_slice(node);
        leb[node.len()..alen].fill(0xFF);
        ubifs_pad(&mut leb[alen..wlen]);
        Ok(())
    }

    /// `write_super`: the SB node followed by a zeroed SIG node
    /// (prepare with padding).
    fn write_super(&mut self, sb: &Superblock) -> Result<()> {
        let sbn = sb.to_node(self.next_sqnum());
        // mkfs writes a zeroed SIG node (len=0) after the SB: the ch is
        // filled in but node_type stays zero — the kernel reads it by
        // offset, not by type (as in mtd-utils 2.2.0 and at HEAD).
        let mut sig = vec![0u8; UBIFS_SIG_NODE_SZ];
        finish_node(&mut sig, 0, self.next_sqnum());
        // ubifs_prepare_node(sig, 64, pad=1): pad up to min_io inside the
        // buffer.
        let alen = sig.len().div_ceil(8) * 8;
        let wlen = sig.len().div_ceil(self.min_io_size) * self.min_io_size;
        sig.resize(wlen, 0xFF);
        ubifs_pad(&mut sig[alen..wlen]);

        let leb =
            self.lebs[UBIFS_SB_LNUM as usize].get_or_insert_with(|| vec![0xFF; self.leb_size]);
        leb[..UBIFS_SB_NODE_SZ].copy_from_slice(&sbn);
        leb[UBIFS_SB_NODE_SZ..UBIFS_SB_NODE_SZ + wlen].copy_from_slice(&sig);
        Ok(())
    }

    /// `reserve_space` + writing a node at the head
    /// (add_node/add_idx_node).
    fn put_node(&mut self, node_type: u8, mut node: Vec<u8>) -> Result<(u32, u32, u32)> {
        let len = node.len();
        if len > self.leb_size - self.head_offs {
            self.flush_nodes()?;
        }
        let lnum = self.head_lnum as u32;
        let offs = self.head_offs as u32;
        self.head_offs += len.div_ceil(8) * 8;
        finish_node(&mut node, node_type, self.next_sqnum());
        let leb = self.lebs[self.head_lnum].get_or_insert_with(|| vec![0xFF; self.leb_size]);
        leb[offs as usize..offs as usize + len].copy_from_slice(&node);
        leb[offs as usize + len..offs as usize + len.div_ceil(8) * 8].fill(0xFF);
        Ok((lnum, offs, len as u32))
    }

    /// `add_node`: a leaf node plus an index entry.
    fn add_leaf_node(
        &mut self,
        key: Key,
        name: Vec<u8>,
        node_type: u8,
        node: Vec<u8>,
    ) -> Result<()> {
        let (lnum, offs, len) = self.put_node(node_type, node)?;
        self.idx_entries.push(IdxEntry {
            key,
            name,
            lnum,
            offs,
            len,
        });
        Ok(())
    }

    /// `add_directory`/`add_non_dir`: the children, the dents, then the
    /// directory's own ino.
    fn add_directory(&mut self, dir: &Inode, dir_inum: u32) -> Result<()> {
        let children = match &dir.kind {
            Kind::Dir(children) => children,
            _ => return Err(Error::Other("root must be a directory".into())),
        };
        let dir_creat_sqnum = self.next_sqnum();
        let mut size = UBIFS_INO_NODE_SZ as u64;
        let mut nlink = 2u32;

        for (name, child) in children {
            let inum = (self.highest_inum + 1) as u32;
            self.highest_inum += 1;
            let itype = match &child.kind {
                Kind::Dir(_) => {
                    self.add_directory(child, inum)?;
                    nlink += 1;
                    UBIFS_ITYPE_DIR
                }
                _ => {
                    self.add_non_dir(child, inum)?;
                    child.itype()
                }
            };
            self.add_dent_node(dir_inum, name, inum, itype)?;
            size += ((UBIFS_DENT_NODE_SZ + name.len() + 1).div_ceil(8) * 8) as u64;
        }

        // The directory's ino goes after the children; its creat_sqnum
        // was reserved before them.
        self.creat_sqnum = dir_creat_sqnum;
        let ino = InoNode {
            key: Key::ino(dir_inum),
            creat_sqnum: dir_creat_sqnum,
            size,
            atime_sec: dir.atime_sec,
            ctime_sec: dir.ctime_sec,
            mtime_sec: dir.mtime_sec,
            atime_nsec: dir.atime_nsec,
            ctime_nsec: dir.ctime_nsec,
            mtime_nsec: dir.mtime_nsec,
            nlink,
            uid: dir.uid,
            gid: dir.gid,
            mode: dir.mode,
            flags: self.inode_flags(),
            xattr_cnt: 0,
            xattr_size: 0,
            xattr_names: 0,
            compr_type: self.default_compr,
            data: vec![],
        };
        self.add_leaf_node(Key::ino(dir_inum), vec![], UBIFS_INO_NODE, ino.to_node(0))?;
        Ok(())
    }

    /// `add_non_dir`: a file (data nodes), a symlink, a device or another
    /// metadata-only object.
    fn add_non_dir(&mut self, ino: &Inode, inum: u32) -> Result<()> {
        self.creat_sqnum = self.next_sqnum();
        match &ino.kind {
            Kind::File(data) => {
                // add_file: blocks of 4 KiB, all-zero blocks are skipped.
                let mut block_no = 0u32;
                for chunk in data.chunks(UBIFS_BLOCK_SIZE) {
                    if chunk.iter().all(|&b| b == 0) {
                        block_no += 1;
                        continue;
                    }
                    let dn = DataNode {
                        key: Key::data(inum, block_no),
                        size: chunk.len() as u32,
                        compr_type: self.default_compr,
                        compr_size: 0,
                        data: chunk.to_vec(),
                    };
                    let key = dn.key;
                    self.add_leaf_node(key, vec![], UBIFS_DATA_NODE, dn.to_node(0))?;
                    block_no += 1;
                }
                let node = InoNode {
                    key: Key::ino(inum),
                    creat_sqnum: self.creat_sqnum,
                    size: data.len() as u64,
                    atime_sec: ino.atime_sec,
                    ctime_sec: ino.ctime_sec,
                    mtime_sec: ino.mtime_sec,
                    atime_nsec: ino.atime_nsec,
                    ctime_nsec: ino.ctime_nsec,
                    mtime_nsec: ino.mtime_nsec,
                    nlink: 1,
                    uid: ino.uid,
                    gid: ino.gid,
                    mode: ino.mode,
                    flags: self.inode_flags(),
                    xattr_cnt: 0,
                    xattr_size: 0,
                    xattr_names: 0,
                    compr_type: self.default_compr,
                    data: vec![],
                };
                let key = node.key;
                self.add_leaf_node(key, vec![], UBIFS_INO_NODE, node.to_node(0))?;
            }
            kind => {
                // Metadata-only kinds carry their content inline in the
                // inode node.
                let data = match kind {
                    Kind::Symlink(target) => target.clone(),
                    // The huge-encoded device number (__le64).
                    Kind::Dev { rdev } => rdev.to_le_bytes().to_vec(),
                    Kind::Fifo | Kind::Socket => vec![],
                    Kind::Dir(_) | Kind::File(_) => unreachable!(),
                };
                let node = InoNode {
                    key: Key::ino(inum),
                    creat_sqnum: self.creat_sqnum,
                    size: data.len() as u64,
                    atime_sec: ino.atime_sec,
                    ctime_sec: ino.ctime_sec,
                    mtime_sec: ino.mtime_sec,
                    atime_nsec: ino.atime_nsec,
                    ctime_nsec: ino.ctime_nsec,
                    mtime_nsec: ino.mtime_nsec,
                    nlink: 1,
                    uid: ino.uid,
                    gid: ino.gid,
                    mode: ino.mode,
                    flags: self.inode_flags(),
                    xattr_cnt: 0,
                    xattr_size: 0,
                    xattr_names: 0,
                    compr_type: self.default_compr,
                    data,
                };
                let key = node.key;
                self.add_leaf_node(key, vec![], UBIFS_INO_NODE, node.to_node(0))?;
            }
        }
        Ok(())
    }

    /// use_flags as in add_inode: COMPR_FL when compression is on by
    /// default.
    fn inode_flags(&self) -> u32 {
        if self.default_compr != UBIFS_COMPR_NONE {
            UBIFS_COMPR_FL
        } else {
            0
        }
    }

    /// `add_dent_node`.
    fn add_dent_node(&mut self, dir_inum: u32, name: &str, inum: u32, itype: u8) -> Result<()> {
        let key = Key::dent(dir_inum, name.as_bytes())?;
        let dent = DentNode {
            key,
            inum: inum as u64,
            itype,
            cookie: 0,
            name: name.as_bytes().to_vec(),
        };
        self.add_leaf_node(
            key,
            name.as_bytes().to_vec(),
            UBIFS_DENT_NODE,
            dent.to_node(0),
        )?;
        Ok(())
    }
}

/// An adapter of [`State`] to [`NodeSink`] for index building.
struct Sink<'a>(&'a mut State);

impl NodeSink for Sink<'_> {
    fn put(&mut self, node_type: u8, node: Vec<u8>) -> Result<(u32, u32, u32)> {
        self.0.put_node(node_type, node)
    }

    fn ihead(&self) -> (u32, u32) {
        let s: &State = self.0;
        (
            s.head_lnum as u32,
            (s.head_offs.div_ceil(s.min_io_size) * s.min_io_size) as u32,
        )
    }
}
