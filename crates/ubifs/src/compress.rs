//! UBIFS data decompression (`fs/ubifs/compress.c`).
//!
//! Image building writes `UBIFS_COMPR_NONE` blocks; reading existing
//! images supports NONE, ZLIB (the `miniz_oxide` crate) and LZO1X (the
//! `lzo` crate). ZSTD data nodes are rare in the wild and are currently
//! rejected.

use crate::error::{Error, Result};
use crate::media::*;

/// Decompress a data block. `out_len` is the expected uncompressed size
/// (`DataNode::size`); it is only used to pre-allocate and to validate.
pub fn decompress(compr_type: u16, data: &[u8], out_len: usize) -> Result<Vec<u8>> {
    match compr_type {
        UBIFS_COMPR_NONE => Ok(data.to_vec()),
        UBIFS_COMPR_ZLIB => {
            #[cfg(feature = "zlib")]
            {
                // UBIFS stores a raw zlib stream.
                let out = miniz_oxide::inflate::decompress_to_vec_zlib(data)
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
        UBIFS_COMPR_ZSTD => Err(Error::Other("UBIFS_COMPR_ZSTD is not supported".into())),
        t => Err(Error::Other(format!("unknown compression type {t}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_is_passthrough() {
        assert_eq!(decompress(UBIFS_COMPR_NONE, b"hello", 5).unwrap(), b"hello");
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn zlib_roundtrip() {
        // A standard zlib stream of "hello world" (python zlib.compress).
        let compressed: &[u8] = &[
            0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x01,
            0x00, 0x1a, 0x0b, 0x04, 0x5d,
        ];
        let out = decompress(UBIFS_COMPR_ZLIB, compressed, 11).unwrap();
        assert_eq!(out, b"hello world");
    }

    #[cfg(feature = "lzo")]
    #[test]
    fn lzo_roundtrip() {
        // Compression comes from rust-lzo1x (dev-dependency, the `lzo1x`
        // library), decompression from the `lzo` crate.
        let compressed = lzo1x::compress(b"hello world hello world hello");
        let out = decompress(UBIFS_COMPR_LZO, &compressed, 29).unwrap();
        assert_eq!(out, b"hello world hello world hello");
    }
}
