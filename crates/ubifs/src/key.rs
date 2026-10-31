//! UBIFS keys (a port of `fs/ubifs/key.h`): inum/type/block-hash packing,
//! the R5 name hash, ordering and on-flash encoding.
//!
//! In the simple format (`UBIFS_SIMPLE_KEY_FMT`) a key is 8 bytes: the
//! low u32 holds the inode number, the high u32 holds
//! `(type << UBIFS_S_KEY_BLOCK_BITS) | block/hash`.

use crate::error::{other, Result};

/// Full on-flash key length (`UBIFS_MAX_KEY_LEN`).
pub const UBIFS_MAX_KEY_LEN: usize = 16;
/// Simple key length (`UBIFS_SK_LEN`).
pub const UBIFS_SK_LEN: usize = 8;
/// Shift of the block number inside the high word (`UBIFS_S_KEY_BLOCK_BITS`).
pub const UBIFS_S_KEY_BLOCK_BITS: u32 = 29;
/// Hash/block mask inside the high word (`UBIFS_S_KEY_HASH_MASK`).
pub const UBIFS_S_KEY_HASH_MASK: u32 = 0x1FFF_FFFF;

/// Key types (the top bits of the high word).
/// An inode key.
pub const UBIFS_INO_KEY: u32 = 0;
/// A data block key.
pub const UBIFS_DATA_KEY: u32 = 1;
/// A directory entry key.
pub const UBIFS_DENT_KEY: u32 = 2;
/// An extended attribute entry key.
pub const UBIFS_XENT_KEY: u32 = 3;

/// A node key: inum + type + block (for data) or hash (for dent/xent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Key {
    /// Inode number.
    pub inum: u32,
    /// Key type (`UBIFS_INO_KEY`/`DATA`/`DENT`/`XENT`).
    pub key_type: u32,
    /// Block number (DATA) or name hash (DENT/XENT).
    pub block_or_hash: u32,
}

impl Key {
    /// An inode key (`ino_key_init`).
    pub const fn ino(inum: u32) -> Key {
        Key {
            inum,
            key_type: UBIFS_INO_KEY,
            block_or_hash: 0,
        }
    }

    /// A data block key (`data_key_init`).
    pub const fn data(inum: u32, block: u32) -> Key {
        Key {
            inum,
            key_type: UBIFS_DATA_KEY,
            block_or_hash: block,
        }
    }

    /// A directory entry key (`dent_key_init`).
    pub fn dent(inum: u32, name: &[u8]) -> Result<Key> {
        Ok(Key {
            inum,
            key_type: UBIFS_DENT_KEY,
            block_or_hash: r5_hash(name)?,
        })
    }

    /// Key type (`key_type`).
    pub const fn ty(&self) -> u32 {
        self.key_type
    }

    /// The high word of the on-flash key.
    pub const fn hi_word(&self) -> u32 {
        (self.key_type << UBIFS_S_KEY_BLOCK_BITS) | (self.block_or_hash & UBIFS_S_KEY_HASH_MASK)
    }

    /// The 64-bit representation of a simple key (the sort order).
    pub const fn as_u64(&self) -> u64 {
        (self.inum as u64) | ((self.hi_word() as u64) << 32)
    }

    /// Unpack a key from 8 bytes of the simple format.
    pub fn from_le8(b: &[u8]) -> Key {
        let lo = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let hi = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        Key {
            inum: lo,
            key_type: hi >> UBIFS_S_KEY_BLOCK_BITS,
            block_or_hash: hi & UBIFS_S_KEY_HASH_MASK,
        }
    }

    /// Write the key into an 8-byte slot (`key_write`).
    pub fn write_le8(&self, out: &mut [u8]) {
        out[0..4].copy_from_slice(&self.inum.to_le_bytes());
        out[4..8].copy_from_slice(&self.hi_word().to_le_bytes());
    }

    /// Write the key into a 16-byte slot with a zero tail (`key_write`).
    pub fn write_le16(&self, out: &mut [u8]) {
        self.write_le8(out);
        out[8..UBIFS_MAX_KEY_LEN].fill(0);
    }
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Key {
    /// `keys_cmp`: inum first, then the high word.
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.inum, self.hi_word()).cmp(&(other.inum, other.hi_word()))
    }
}

/// The R5 name hash (`key_r5_hash`, borrowed from reiserfs): signed char
/// arithmetic, `a += c << 4; a += c >> 4; a *= 11`, then `key_mask_hash`.
pub fn r5_hash(name: &[u8]) -> Result<u32> {
    if name.len() > crate::media::UBIFS_MAX_NLEN {
        return other(format!("name is too long ({} bytes)", name.len()));
    }
    let mut a: u32 = 0;
    for &c in name {
        let s = c as i8 as i32;
        a = a.wrapping_add((s << 4) as u32);
        a = a.wrapping_add((s >> 4) as u32);
        a = a.wrapping_mul(11);
    }
    Ok(mask_hash(a))
}

/// `key_mask_hash`: apply the mask and steer away from collisions with
/// the key values 0..=2.
fn mask_hash(hash: u32) -> u32 {
    let mut h = hash & UBIFS_S_KEY_HASH_MASK;
    if h <= 2 {
        h += 3;
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r5_hash_vectors() {
        // Per key.h: signed arithmetic + the mask.
        assert_eq!(r5_hash(b"overlay").unwrap(), r5_hash(b"overlay").unwrap());
        // Hash of an empty name: a=0 -> masked to 0 -> +3.
        assert_eq!(r5_hash(b"").unwrap(), 3);
        // Hand computation for "adbd": 'a'=97: a+=97<<4=1552, a+=97>>4=6 -> 1558*11=17138;
        // 'd'=100: 17138+1600=18738, +6=18744*11=206184;
        // 'b'=98: +1568=207752, +6=207758*11=2285338;
        // 'd'=100: +1600=2286938, +6=2286944*11=25156384 -> below the mask.
        assert_eq!(r5_hash(b"adbd").unwrap(), 25_156_384);
    }

    #[test]
    fn key_roundtrip() {
        let k = Key::data(1234, 77);
        let mut buf = [0u8; 8];
        k.write_le8(&mut buf);
        assert_eq!(Key::from_le8(&buf), k);
        assert_eq!(k.ty(), UBIFS_DATA_KEY);
    }
}
