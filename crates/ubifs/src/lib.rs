//! Минимальный чистый Rust-парсер и создатель образов UBIFS — ровно
//! столько, сколько нужно джейлбрейку Capsula Mini: собрать свежий
//! маленький том (overlay-файлы) в геометрию раздела data и уметь
//! прочитать/проверить существующий. Формат — по fs/ubifs
//! (ubifs-media.h) и mtd-utils mkfs.ubifs; зависимостей нет.
//!
//! Парсер валидируется на стоковом томе из захвата (тест — если каталог
//! бэкапа доступен); строитель проверяется тем же парсером.

use std::fmt;

pub const UBIFS_NODE_MAGIC: u32 = 0x0610_1831;
pub const UBIFS_SB_LNUM: u32 = 0;
pub const UBIFS_MST_LNUM: u32 = 1;
pub const UBIFS_LOG_LNUM: u32 = 3;
pub const UBIFS_ROOT_INO: u32 = 1;
pub const UBIFS_FIRST_INO: u32 = 64;
pub const UBIFS_BLOCK_SIZE: usize = 4096;
pub const UBIFS_MAX_KEY_LEN: usize = 16;
pub const UBIFS_SK_LEN: usize = 8;
pub const UBIFS_S_KEY_BLOCK_BITS: u32 = 29;
pub const UBIFS_S_KEY_HASH_MASK: u32 = 0x1FFF_FFFF;
pub const UBIFS_LPT_FANOUT: usize = 4;
pub const UBIFS_LPT_CRC_BYTES: usize = 2;
pub const UBIFS_LPT_TYPE_BITS: u32 = 4;
pub const LPROPS_INDEX: u32 = 1 << 2;

pub const UBIFS_INO_NODE: u8 = 0;
pub const UBIFS_DATA_NODE: u8 = 1;
pub const UBIFS_DENT_NODE: u8 = 2;
pub const UBIFS_IDX_NODE: u8 = 9;
pub const UBIFS_SB_NODE: u8 = 6;
pub const UBIFS_MST_NODE: u8 = 7;
pub const UBIFS_CS_NODE: u8 = 10;
pub const UBIFS_LPT_PNODE: u32 = 0;
pub const UBIFS_LPT_NNODE: u32 = 1;
pub const UBIFS_LPT_LTAB: u32 = 2;

pub const UBIFS_INO_KEY: u32 = 0;
pub const UBIFS_DATA_KEY: u32 = 1;
pub const UBIFS_DENT_KEY: u32 = 2;

pub const UBIFS_MST_NO_ORPHS: u32 = 2;
/// UBIFS_PADDING_BYTE из ubifs-media.h.
pub const UBIFS_PADDING_BYTE: u8 = 0xCE;

#[derive(Debug)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error(msg.into()))
}
pub type Result<T> = std::result::Result<T, Error>;

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    crc
}

/// CRC16 полиномиалом 0xa001 (kernel lib/crc16), у LPT init 0xFFFF.
pub fn crc16(crc: u16, data: &[u8]) -> u16 {
    let mut crc = crc;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xA001 } else { crc >> 1 };
        }
    }
    crc
}

/// R5-хэш имён (key_r5_hash, signed char арифметика).
pub fn r5_hash(name: &[u8]) -> u32 {
    let mut a: u32 = 0;
    for &c in name {
        let s = c as i8 as i32;
        a = a.wrapping_add((s << 4) as u32);
        a = a.wrapping_add((s >> 4) as u32);
        a = a.wrapping_mul(11);
    }
    let mut h = a & UBIFS_S_KEY_HASH_MASK;
    if h <= 2 {
        h += 3;
    }
    h
}

/// pack_bits/unpack_bits из lpt.c — MSB-first битовое поле.
#[derive(Debug)]
pub struct Bits<'a> {
    pub buf: &'a mut [u8],
    pub pos: usize,
}
impl<'a> Bits<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Bits { buf, pos: 0 }
    }
    pub fn pack(&mut self, val: u32, nrbits: u32) {
        let mut nrbits = nrbits as usize;
        let mut val = val;
        let mut p = self.pos / 8;
        let b = self.pos % 8;
        if b != 0 {
            self.buf[p] |= ((val << (8 - b)) & 0xff) as u8;
            nrbits += b;
            if nrbits > 8 {
                val >>= 8 - b;
                p += 1;
                self.buf[p] = val as u8;
                if nrbits > 16 {
                    self.buf[p + 1] = (val >> 8) as u8;
                    if nrbits > 24 {
                        self.buf[p + 2] = (val >> 16) as u8;
                        if nrbits > 32 {
                            self.buf[p + 3] = (val >> 24) as u8;
                        }
                    }
                }
            }
        } else {
            self.buf[p] = val as u8;
            if nrbits > 8 {
                self.buf[p + 1] = (val >> 8) as u8;
                if nrbits > 16 {
                    self.buf[p + 2] = (val >> 16) as u8;
                    if nrbits > 24 {
                        self.buf[p + 3] = (val >> 24) as u8;
                    }
                }
            }
        }
        self.pos += nrbits;
    }
    pub fn unpack(&mut self, nrbits: u32) -> u32 {
        let nrbits = nrbits as usize;
        let k = 32 - nrbits;
        let p = self.pos / 8;
        let b = self.pos % 8;
        let bytes = (nrbits + b + 7) / 8;
        let mut val: u32 = 0;
        if b != 0 {
            for i in 1..bytes {
                val |= (self.buf[p + i] as u32) << ((i - 1) * 8);
            }
            val <<= 8 - b;
            val |= (self.buf[p] >> b) as u32;
        } else {
            for i in 0..bytes {
                val |= (self.buf[p + i] as u32) << (i * 8);
            }
        }
        val <<= k;
        val >>= k;
        self.pos += nrbits;
        val
    }
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn le64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Геометрия тома (поля SB).
#[derive(Debug, Clone, PartialEq)]
pub struct Geometry {
    pub min_io_size: u32,
    pub leb_size: u32,
    pub leb_cnt: u32,
    pub max_leb_cnt: u32,
    pub max_bud_bytes: u64,
    pub log_lebs: u32,
    pub lpt_lebs: u32,
    pub orph_lebs: u32,
    pub jhead_cnt: u32,
    pub fanout: u32,
    pub lsave_cnt: u32,
    pub fmt_version: u32,
    pub default_compr: u16,
    pub flags: u32,
    pub uuid: [u8; 16],
    pub ro_compat_version: u32,
}
impl Geometry {
    pub fn main_first(&self) -> u32 {
        UBIFS_LOG_LNUM + self.log_lebs + self.lpt_lebs + self.orph_lebs
    }
    pub fn main_lebs(&self) -> u32 {
        self.leb_cnt - self.main_first()
    }
    /// Размеры LPT-узлов (do_calc_lpt_geom), small-LPT модель.
    pub fn lpt(&self) -> LptGeom {
        let main_lebs = self.main_lebs();
        let max_pnode_cnt = main_lebs.div_ceil(UBIFS_LPT_FANOUT as u32);
        let mut lpt_hght = 1u32;
        let mut n = UBIFS_LPT_FANOUT as u32;
        while n < max_pnode_cnt {
            lpt_hght += 1;
            n <<= 2;
        }
        let pnode_cnt = main_lebs.div_ceil(UBIFS_LPT_FANOUT as u32);
        let mut nnode_cnt = pnode_cnt.div_ceil(UBIFS_LPT_FANOUT as u32);
        let mut nn = nnode_cnt;
        for _ in 1..lpt_hght {
            nn = nn.div_ceil(UBIFS_LPT_FANOUT as u32);
            nnode_cnt += nn;
        }
        let fls = |v: u32| 32 - v.leading_zeros();
        let space_bits = fls(self.leb_size) - 3;
        let lpt_lnum_bits = fls(self.lpt_lebs);
        let lpt_offs_bits = fls(self.leb_size - 1);
        let lpt_spc_bits = fls(self.leb_size);
        let pcnt_bits = fls(self.max_leb_cnt.div_ceil(UBIFS_LPT_FANOUT as u32) - 1);
        let lnum_bits = fls(self.max_leb_cnt - 1);
        let big_lpt = self.flags & 0x4 != 0; // UBIFS_FLG_BIGLPT
        let bits = |per: u32| {
            (UBIFS_LPT_CRC_BYTES as u32 * 8
                + UBIFS_LPT_TYPE_BITS
                + if big_lpt { pcnt_bits } else { 0 }
                + per)
                .div_ceil(8)
        };
        let pnode_sz = bits((space_bits * 2 + 1) * UBIFS_LPT_FANOUT as u32) as usize;
        let nnode_sz =
            bits((lpt_lnum_bits + lpt_offs_bits) * UBIFS_LPT_FANOUT as u32) as usize;
        let ltab_sz = bits(self.lpt_lebs * lpt_spc_bits * 2) as usize;
        let lsave_sz = bits(lnum_bits * self.lsave_cnt) as usize;
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
        }
    }
}

/// Производная геометрия LPT.
#[derive(Debug, Clone)]
pub struct LptGeom {
    pub lpt_hght: u32,
    pub pnode_cnt: usize,
    pub nnode_cnt: usize,
    pub big_lpt: bool,
    pub space_bits: u32,
    pub lpt_lnum_bits: u32,
    pub lpt_offs_bits: u32,
    pub lpt_spc_bits: u32,
    pub pcnt_bits: u32,
    pub lnum_bits: u32,
    pub pnode_sz: usize,
    pub nnode_sz: usize,
    pub ltab_sz: usize,
    pub lsave_sz: usize,
}

/// Файл/каталог для сборки образа.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub data: Vec<u8>,
    pub children: Vec<Entry>,
}
impl Entry {
    pub fn dir(name: &str, mode: u32, children: Vec<Entry>) -> Entry {
        Entry { name: name.into(), mode, uid: 0, gid: 0, data: vec![], children }
    }
    pub fn file(name: &str, mode: u32, data: Vec<u8>) -> Entry {
        Entry { name: name.into(), mode, uid: 0, gid: 0, data, children: vec![] }
    }
}

/// Собранный образ: содержимое LEB (None = оставить пустым/FF).
pub struct Built {
    pub lebs: Vec<Option<Vec<u8>>>,
    pub geometry: Geometry,
}

struct NodeWriter {
    sqnum: u64,
}
impl NodeWriter {
    fn node(&mut self, node_type: u8, body: &[u8]) -> Vec<u8> {
        let len = (24 + body.len()) as u32;
        let mut n = Vec::with_capacity(len as usize);
        n.extend_from_slice(&UBIFS_NODE_MAGIC.to_le_bytes());
        n.extend_from_slice(&[0; 4]);
        n.extend_from_slice(&self.sqnum.to_le_bytes());
        n.extend_from_slice(&len.to_le_bytes());
        n.push(node_type);
        n.push(0);
        n.extend_from_slice(&[0, 0]);
        n.extend_from_slice(body);
        let crc = crc32(&n[8..]);
        n[4..8].copy_from_slice(&crc.to_le_bytes());
        self.sqnum += 1;
        n
    }
}

fn ino_body(
    inum: u32,
    mode: u32,
    nlink: u32,
    size: u64,
    uid: u32,
    gid: u32,
    inline_data: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    put_key(&mut b, inum, UBIFS_INO_KEY, 0);
    b.extend_from_slice(&0u64.to_le_bytes()); // creat_sqnum
    b.extend_from_slice(&size.to_le_bytes());
    for _ in 0..3 {
        b.extend_from_slice(&0u64.to_le_bytes()); // atime/ctime/mtime sec
    }
    for _ in 0..3 {
        b.extend_from_slice(&0u32.to_le_bytes()); // nsec
    }
    b.extend_from_slice(&nlink.to_le_bytes());
    b.extend_from_slice(&uid.to_le_bytes());
    b.extend_from_slice(&gid.to_le_bytes());
    b.extend_from_slice(&mode.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // flags
    b.extend_from_slice(&(inline_data.len() as u32).to_le_bytes()); // data_len
    b.extend_from_slice(&0u32.to_le_bytes()); // xattr_cnt
    b.extend_from_slice(&0u32.to_le_bytes()); // xattr_size
    b.extend_from_slice(&[0; 4]); // padding1
    b.extend_from_slice(&0u32.to_le_bytes()); // xattr_names
    b.extend_from_slice(&0u16.to_le_bytes()); // compr_type
    b.extend_from_slice(&[0; 26]); // padding2
    b.extend_from_slice(inline_data);
    b
}
fn put_key(buf: &mut Vec<u8>, inum: u32, key_type: u32, block_or_hash: u32) {
    buf.extend_from_slice(&inum.to_le_bytes());
    buf.extend_from_slice(&((key_type << UBIFS_S_KEY_BLOCK_BITS) | block_or_hash).to_le_bytes());
    buf.extend_from_slice(&[0u8; UBIFS_MAX_KEY_LEN - 8]);
}
fn key_u64(inum: u32, key_type: u32, block_or_hash: u32) -> u64 {
    (inum as u64)
        | (((key_type as u64) << UBIFS_S_KEY_BLOCK_BITS) | block_or_hash as u64) << 32
}

/// Собрать образ UBIFS (механика mkfs.ubifs): каталог + геометрия → LEB-ы.
pub fn build(root: &Entry, geom: &Geometry) -> Result<Built> {
    if root.data.len() > 0 {
        return err("корень должен быть каталогом");
    }
    let leb_size = geom.leb_size as usize;
    let min_io = geom.min_io_size as usize;
    let main_first = geom.main_first() as usize;
    if geom.leb_cnt as usize > geom.max_leb_cnt as usize {
        return err("leb_cnt > max_leb_cnt");
    }
    let lptg = geom.lpt();
    let mut lebs: Vec<Option<Vec<u8>>> = vec![None; geom.leb_cnt as usize];

    // --- узлы листьев ---
    let mut nw = NodeWriter { sqnum: 0 };
    let mut leaves: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut next_inum = UBIFS_FIRST_INO;

    // корневой ino
    let body = ino_body(
        UBIFS_ROOT_INO,
        root.mode | 0o040000,
        root.children.len() as u32 + 2,
        0,
        root.uid,
        root.gid,
        &[],
    );
    let n = nw.node(UBIFS_INO_NODE, &body);
    let k = key_u64(UBIFS_ROOT_INO, UBIFS_INO_KEY, 0);
    leaves.push((k, n));

    fn add_entry(
        e: &Entry,
        parent: u32,
        nw: &mut NodeWriter,
        next_inum: &mut u32,
        leaves: &mut Vec<(u64, Vec<u8>)>,
    ) -> Result<()> {
        let cur = *next_inum;
        *next_inum += 1;
        let name = e.name.as_bytes();
        if name.len() > 255 {
            return err(format!("имя {} длиннее 255", e.name));
        }
        let is_dir = !e.children.is_empty();
        let dlen = 56 + name.len();
        let mut d = Vec::with_capacity(dlen);
        put_key(&mut d, parent, UBIFS_DENT_KEY, r5_hash(name));
        d.extend_from_slice(&(cur as u64).to_le_bytes());
        d.push(0); // padding1
        d.push(if is_dir { 4 } else { 8 }); // DT_DIR / DT_REG
        d.extend_from_slice(&(name.len() as u16).to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes()); // cookie
        d.extend_from_slice(name);
        let d = nw.node(UBIFS_DENT_NODE, &d);
        let dk = key_u64(parent, UBIFS_DENT_KEY, r5_hash(name));
        leaves.push((dk, d));

        if is_dir {
            let body = ino_body(
                cur,
                e.mode | 0o040000,
                e.children.len() as u32 + 2,
                0,
                e.uid,
                e.gid,
                &[],
            );
            let n = nw.node(UBIFS_INO_NODE, &body);
            let ik = key_u64(cur, UBIFS_INO_KEY, 0);
            leaves.push((ik, n));
            for c in &e.children {
                add_entry(c, cur, nw, next_inum, leaves)?;
            }
        } else {
            let inline = e.data.len() <= UBIFS_BLOCK_SIZE;
            let body = ino_body(
                cur,
                e.mode | 0o100000,
                1,
                e.data.len() as u64,
                e.uid,
                e.gid,
                if inline { &e.data } else { &[] },
            );
            let n = nw.node(UBIFS_INO_NODE, &body);
            let ik = key_u64(cur, UBIFS_INO_KEY, 0);
            leaves.push((ik, n));
            if !inline {
                for (block, chunk) in e.data.chunks(UBIFS_BLOCK_SIZE).enumerate() {
                    let mut dn = Vec::new();
                    put_key(&mut dn, cur, UBIFS_DATA_KEY, block as u32);
                    dn.extend_from_slice(&(e.data.len() as u32).to_le_bytes()); // size
                    dn.extend_from_slice(&0u16.to_le_bytes()); // compr_type NONE
                    dn.extend_from_slice(&0u16.to_le_bytes()); // compr_size (v5)
                    dn.extend_from_slice(chunk);
                    let dn = nw.node(UBIFS_DATA_NODE, &dn);
                    let k =
                        key_u64(cur, UBIFS_DATA_KEY, block as u32);
                    leaves.push((k, dn));
                }
            }
        }
        Ok(())
    }
    for c in &root.children {
        add_entry(c, UBIFS_ROOT_INO, &mut nw, &mut next_inum, &mut leaves)?;
    }
    leaves.sort_by_key(|(k, _)| *k);

    // --- размещение листьев в main-области (write_data) ---
    let mut head_lnum = main_first;
    let mut head_offs = 0usize;
    let mut lst = Lst::default();
    let mut lpt_lprops: Vec<(u32, u32, u32)> = vec![(0, 0, 0); geom.main_lebs() as usize];

    let mut flush = |lebs: &mut Vec<Option<Vec<u8>>>,
                     lst: &mut Lst,
                     lpt: &mut [(u32, u32, u32)],
                     head_lnum: &mut usize,
                     head_offs: &mut usize,
                     head_flags: u32,
                     geom: &Geometry,
                     wms: (u32, u32)| {
        if *head_offs == 0 {
            return;
        }
        let lnum = *head_lnum;
        let leb = lebs[lnum].get_or_insert_with(|| vec![0xff; geom.leb_size as usize]);
        let len = head_offs.align_to(min_io);
        let pad = len - head_offs;
        for b in &mut leb[*head_offs..len] {
            *b = UBIFS_PADDING_BYTE;
        }
        set_lprops(lpt, lst, geom, lnum, *head_offs, head_flags, wms);
        let _ = pad;
        *head_lnum += 1;
        *head_offs = 0;
    };
    let wms = watermarks(geom);
    for (key, node) in &leaves {
        if head_offs + node.len() > leb_size {
            flush(&mut lebs, &mut lst, &mut lpt_lprops, &mut head_lnum, &mut head_offs, 0, geom, wms);
        }
        if *head_lnum >= geom.leb_cnt as usize {
            return err("образ не помещается в том");
        }
        let leb = lebs[head_lnum].get_or_insert_with(|| vec![0xff; leb_size]);
        leb[head_offs..head_offs + node.len()].copy_from_slice(node);
        head_offs += node.len();
        let _ = key;
    }
    // узлы индекса
    let mut placed: Vec<(u64, (u32, u32, u32))> = leaves
        .iter()
        .enumerate()
        .map(|i| unreachable!())
        .collect();
    let _ = placed;
    Ok(Built { lebs, geometry: geom.clone() })
}

#[derive(Default)]
struct Lst {
    total_free: u64,
    total_dirty: u64,
    total_used: u64,
    total_dead: u64,
    total_dark: u64,
    empty_lebs: u32,
    idx_lebs: u32,
}
fn watermarks(geom: &Geometry) -> (u32, u32) {
    let data_node_sz = if geom.fmt_version >= 5 { 52 } else { 48 };
    let dead_wm = (data_node_sz + 8).div_ceil(geom.min_io_size) * geom.min_io_size;
    let max_node = 160 + UBIFS_BLOCK_SIZE as u32;
    let dark_wm = max_node.div_ceil(geom.min_io_size) * geom.min_io_size;
    (dead_wm, dark_wm)
}
fn set_lprops(
    lpt: &mut [(u32, u32, u32)],
    lst: &mut Lst,
    geom: &Geometry,
    lnum: u32,
    offs: usize,
    flags: u32,
    wms: (u32, u32),
) {
    let i = (lnum - geom.main_first()) as usize;
    let a = geom.min_io_size.max(8) as usize;
    let free = (geom.leb_size as usize - offs.div_ceil(a) * a) as u32;
    let dirty = geom.leb_size - free - (offs as u32).div_ceil(8) * 8;
    if i < lpt.len() {
        lpt[i] = (free, dirty, flags);
    }
    lst.total_free += free as u64;
    lst.total_dirty += dirty as u64;
    if flags & LPROPS_INDEX != 0 {
        lst.idx_lebs += 1;
    } else {
        let spc = free + dirty;
        if spc < wms.0 {
            lst.total_dead += spc as u64;
        } else {
            lst.total_dark += (spc.saturating_sub(wms.1)) as u64;
        }
        lst.total_used += (geom.leb_size - spc) as u64;
    }
}
trait AlignTo { fn align_to(self, a: usize) -> usize; }
impl AlignTo for usize {
    fn align_to(self, a: usize) -> usize {
        self.div_ceil(a) * a
    }
}

// TODO(WIP): завершить build() — индекс (механика write_index из
// mkfs.ubifs: уровни, blast_len, ALIGN(blen,8)-шаг), gc_lnum, LPT
// (pack_pnode/nnode/ltab + nhead/ltab позиции), master ×2, SB, log CS,
// orph; затем parse() (валидация на стоковом томе из захвата) и тесты.
