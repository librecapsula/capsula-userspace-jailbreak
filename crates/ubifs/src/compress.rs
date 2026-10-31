//! UBIFS data compression (`fs/ubifs/compress.c` and the mkfs.ubifs
//! `common/compr.c`).
//!
//! Reading supports NONE, ZLIB (the `miniz_oxide` crate), LZO1X (the
//! `lzo` crate) and — behind the `zstd` feature — ZSTD. Writing supports
//! NONE/ZLIB/LZO1X/ZSTD and the `favor_lzo` policy of mkfs.ubifs.
//!
//! Note on byte parity: mkfs.ubifs compresses with zlib (raw deflate,
//! 2 KiB window, memLevel 8, default level) and `lzo1x_999`. The pure
//! Rust codecs here (miniz_oxide and lzo1x-1) produce different — but
//! fully valid and kernel-readable — streams, so compressed images are
//! **not** byte-identical to mkfs.ubifs output; `-x none` images are.

use crate::error::{Error, Result};
use crate::media::*;

/// The compression algorithm of a volume or block (the `-x` option of
/// mkfs.ubifs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compr {
    /// No compression (`UBIFS_COMPR_NONE`).
    #[default]
    None,
    /// LZO1X (`UBIFS_COMPR_LZO`); needs the `lzo` feature to write
    /// (reading uses the pure-Rust decoder).
    Lzo,
    /// ZLIB raw deflate (`UBIFS_COMPR_ZLIB`); needs the `zlib` feature.
    Zlib,
    /// Zstandard (`UBIFS_COMPR_ZSTD`); needs the `zstd` feature (C
    /// library).
    Zstd,
    /// The mkfs.ubifs "favor LZO" policy: compress with both LZO and
    /// ZLIB and pick per block (needs both features).
    FavorLzo,
}

impl Compr {
    /// The on-flash `UBIFS_COMPR_*` value.
    pub fn to_u16(self) -> u16 {
        match self {
            Compr::None => UBIFS_COMPR_NONE,
            Compr::Lzo | Compr::FavorLzo => UBIFS_COMPR_LZO,
            Compr::Zlib => UBIFS_COMPR_ZLIB,
            Compr::Zstd => UBIFS_COMPR_ZSTD,
        }
    }

    /// Whether writing this algorithm is possible with the compiled
    /// feature set.
    pub fn writable(self) -> bool {
        match self {
            Compr::None => true,
            Compr::Lzo => cfg!(feature = "lzo"),
            Compr::Zlib => cfg!(feature = "zlib"),
            Compr::Zstd => cfg!(feature = "zstd"),
            Compr::FavorLzo => cfg!(all(feature = "lzo", feature = "zlib")),
        }
    }
}

/// Decompress a data block. `out_len` is the expected uncompressed size
/// (`DataNode::size`); it is only used to pre-allocate and to validate.
pub fn decompress(compr_type: u16, data: &[u8], out_len: usize) -> Result<Vec<u8>> {
    match compr_type {
        UBIFS_COMPR_NONE => Ok(data.to_vec()),
        UBIFS_COMPR_ZLIB => {
            #[cfg(feature = "zlib")]
            {
                // UBIFS stores a *raw* deflate stream (the kernel crypto
                // API and mkfs.ubifs both use windowBits = -11).
                let out = miniz_oxide::inflate::decompress_to_vec(data)
                    .map_err(|e| Error::Other(format!("zlib decompress failed: {e:?}")))?;
                if out.len() != out_len {
                    return Err(Error::Other(format!(
                        "zlib decompressed {} bytes, expected {out_len}",
                        out.len()
                    )));
                }
                Ok(out)
            }
            #[cfg(not(feature = "zlib"))]
            Err(Error::Other(
                "zlib support is disabled (feature 'zlib')".into(),
            ))
        }
        UBIFS_COMPR_LZO => {
            #[cfg(feature = "lzo")]
            {
                let mut out = vec![0u8; out_len];
                let n = lzo::decompress_into(data, &mut out)
                    .map_err(|e| Error::Other(format!("lzo decompress failed: {e:?}")))?;
                if n != out_len {
                    return Err(Error::Other(format!(
                        "lzo decompressed {n} bytes, expected {out_len}"
                    )));
                }
                out.truncate(n);
                Ok(out)
            }
            #[cfg(not(feature = "lzo"))]
            Err(Error::Other(
                "lzo support is disabled (feature 'lzo')".into(),
            ))
        }
        UBIFS_COMPR_ZSTD => {
            #[cfg(feature = "zstd")]
            {
                let out = zstd::decode_all(data)
                    .map_err(|e| Error::Other(format!("zstd decompress failed: {e}")))?;
                if out.len() != out_len {
                    return Err(Error::Other(format!(
                        "zstd decompressed {} bytes, expected {out_len}",
                        out.len()
                    )));
                }
                Ok(out)
            }
            #[cfg(not(feature = "zstd"))]
            Err(Error::Other(
                "zstd support is disabled (feature 'zstd')".into(),
            ))
        }
        t => Err(Error::Other(format!("unknown compression type {t}"))),
    }
}

/// Compress one block for writing, with mkfs.ubifs `compress_data()`
/// semantics: blocks shorter than `UBIFS_MIN_COMPR_LEN` and blocks that
/// do not shrink are stored uncompressed; `favor_lzo` picks between LZO
/// and ZLIB per block.
///
/// Returns the on-flash compression type and the payload.
pub fn compress(compr: Compr, favor_percent: u32, data: &[u8]) -> Result<(u16, Vec<u8>)> {
    if data.len() < UBIFS_MIN_COMPR_LEN {
        return Ok((UBIFS_COMPR_NONE, data.to_vec()));
    }
    let picked = match compr {
        Compr::FavorLzo => favor_lzo_compress(favor_percent, data)?,
        Compr::Lzo => (UBIFS_COMPR_LZO, one(UBIFS_COMPR_LZO, data)?),
        Compr::Zlib => (UBIFS_COMPR_ZLIB, one(UBIFS_COMPR_ZLIB, data)?),
        Compr::Zstd => (UBIFS_COMPR_ZSTD, one(UBIFS_COMPR_ZSTD, data)?),
        Compr::None => (UBIFS_COMPR_NONE, data.to_vec()),
    };
    let (ty, out) = picked;
    if out.len() >= data.len() {
        return Ok((UBIFS_COMPR_NONE, data.to_vec()));
    }
    Ok((ty, out))
}

/// `favor_lzo_compress`: try both codecs, prefer LZO unless ZLIB is
/// `favor_percent` smaller.
fn favor_lzo_compress(favor_percent: u32, data: &[u8]) -> Result<(u16, Vec<u8>)> {
    #[cfg(feature = "lzo")]
    let lzo_res: Option<Vec<u8>> = one(UBIFS_COMPR_LZO, data).ok();
    #[cfg(not(feature = "lzo"))]
    let lzo_res: Option<Vec<u8>> = None;
    #[cfg(feature = "zlib")]
    let zlib_res: Option<Vec<u8>> = one(UBIFS_COMPR_ZLIB, data).ok();
    #[cfg(not(feature = "zlib"))]
    let zlib_res: Option<Vec<u8>> = None;
    match (lzo_res, zlib_res) {
        (None, None) => Ok((UBIFS_COMPR_NONE, data.to_vec())),
        (Some(lzo), None) => Ok((UBIFS_COMPR_LZO, lzo)),
        (None, Some(zlib)) => Ok((UBIFS_COMPR_ZLIB, zlib)),
        (Some(lzo), Some(zlib)) => {
            if lzo.len() <= zlib.len() {
                return Ok((UBIFS_COMPR_LZO, lzo));
            }
            // percent = zlib_len / lzo_len * 100; LZO wins unless ZLIB is
            // favor_percent smaller (percent <= 100 - favor_percent).
            let percent = (zlib.len() as f64 / lzo.len() as f64) * 100.0;
            if percent > 100.0 - favor_percent as f64 {
                Ok((UBIFS_COMPR_LZO, lzo))
            } else {
                Ok((UBIFS_COMPR_ZLIB, zlib))
            }
        }
    }
}

/// Compress with a single algorithm; `None` when the codec is disabled
/// or fails.
fn one(compr_type: u16, data: &[u8]) -> Result<Vec<u8>> {
    match compr_type {
        UBIFS_COMPR_LZO => {
            #[cfg(feature = "lzo")]
            {
                Ok(lzo1x::compress(data))
            }
            #[cfg(not(feature = "lzo"))]
            {
                let _ = data;
                Err(Error::Unsupported(
                    "lzo support is disabled (feature 'lzo')".into(),
                ))
            }
        }
        UBIFS_COMPR_ZLIB => {
            #[cfg(feature = "zlib")]
            {
                // Raw deflate at the default level (mkfs.ubifs: level 6,
                // windowBits -11, memLevel 8 — miniz has fixed window and
                // match finder, so the bytes differ from zlib).
                Ok(miniz_oxide::deflate::compress_to_vec(data, 6))
            }
            #[cfg(not(feature = "zlib"))]
            {
                let _ = data;
                Err(Error::Unsupported(
                    "zlib support is disabled (feature 'zlib')".into(),
                ))
            }
        }
        UBIFS_COMPR_ZSTD => {
            #[cfg(feature = "zstd")]
            {
                // mkfs.ubifs uses level 0 = the zstd default (3).
                zstd::bulk::compress(data, 0)
                    .map_err(|e| Error::Other(format!("zstd compress failed: {e}")))
            }
            #[cfg(not(feature = "zstd"))]
            {
                let _ = data;
                Err(Error::Unsupported(
                    "zstd support is disabled (feature 'zstd')".into(),
                ))
            }
        }
        t => Err(Error::Other(format!("unknown compression type {t}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_is_passthrough() {
        assert_eq!(decompress(UBIFS_COMPR_NONE, b"hello", 5).unwrap(), b"hello");
        assert_eq!(
            compress(Compr::None, 20, b"hello").unwrap(),
            (UBIFS_COMPR_NONE, b"hello".to_vec())
        );
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn zlib_roundtrip() {
        // A raw deflate stream of "hello world hello world hello"
        // (python: zlib.compressobj(9, zlib.DEFLATED, -15)).
        let compressed: &[u8] = &[
            0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0xc8, 0x40,
            0x67, 0x03, 0x00,
        ];
        let out = decompress(UBIFS_COMPR_ZLIB, compressed, 29).unwrap();
        assert_eq!(out, b"hello world hello world hello");

        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let (ty, c) = compress(Compr::Zlib, 20, &big).unwrap();
        assert_eq!(ty, UBIFS_COMPR_ZLIB);
        assert!(c.len() < big.len());
        assert_eq!(decompress(ty, &c, big.len()).unwrap(), big);
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn short_block_stays_raw() {
        // compress_data(): below UBIFS_MIN_COMPR_LEN nothing happens.
        let (ty, out) = compress(Compr::Zlib, 20, &[0xAA; 100]).unwrap();
        assert_eq!(ty, UBIFS_COMPR_NONE);
        assert_eq!(out, vec![0xAA; 100]);
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn incompressible_falls_back_to_none() {
        // Random-looking data does not shrink with a 128-byte minimum.
        let mut x: u32 = 0x12345678;
        let data: Vec<u8> = (0..256)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        let (ty, out) = compress(Compr::Zlib, 20, &data).unwrap();
        assert_eq!(ty, UBIFS_COMPR_NONE);
        assert_eq!(out, data);
    }

    #[cfg(feature = "lzo")]
    #[test]
    fn lzo_roundtrip() {
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let (ty, c) = compress(Compr::Lzo, 20, &big).unwrap();
        assert_eq!(ty, UBIFS_COMPR_LZO);
        assert_eq!(decompress(ty, &c, big.len()).unwrap(), big);
    }

    #[cfg(all(feature = "lzo", feature = "zlib"))]
    #[test]
    fn favor_policy_threshold() {
        let data: Vec<u8> = vec![b'a'; 4096];
        // lzo1x-1 gives ~27 bytes, zlib level 6 ~20 bytes: zlib is ~25%
        // smaller.
        // With favor_percent = 99 ZLIB would have to be 99% smaller —
        // impossible, LZO is picked.
        let (ty, out) = compress(Compr::FavorLzo, 99, &data).unwrap();
        assert_eq!(ty, UBIFS_COMPR_LZO);
        assert!(out.len() < data.len());
        // With favor_percent = 1 a 1% advantage suffices — ZLIB wins.
        let (ty, _) = compress(Compr::FavorLzo, 1, &data).unwrap();
        assert_eq!(ty, UBIFS_COMPR_ZLIB);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn zstd_roundtrip() {
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let (ty, c) = compress(Compr::Zstd, 20, &big).unwrap();
        assert_eq!(ty, UBIFS_COMPR_ZSTD);
        assert_eq!(decompress(ty, &c, big.len()).unwrap(), big);
    }
}
