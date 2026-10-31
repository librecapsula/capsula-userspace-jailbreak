//! UBIFS checksums: CRC32 (the kernel form, `lib/crc32.c` — `crc32_le`
//! without the final XOR) and CRC16 (polynomial 0xA001, `lib/crc16.c`).

/// The UBIFS CRC32 initial value (`UBIFS_CRC32_INIT` = 0xFFFFFFFF).
///
/// This is `crc32_le` with init 0xFFFFFFFF and no final XOR: the on-flash
/// value equals the standard zlib crc32 of the same data inverted
/// (`ubifs_crc ^ 0xFFFFFFFF == zlib.crc32(data)`).
pub const UBIFS_CRC32_INIT: u32 = 0xFFFF_FFFF;

/// CRC32 in the kernel form used by UBIFS nodes.
pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(UBIFS_CRC32_INIT, data)
}

/// CRC32 in the kernel form, continuing from a previous value.
pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut crc = crc;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// The LPT CRC16 (`crc16(-1, ...)` in the kernel): polynomial 0xA001,
/// the initial value is supplied by the caller (UBIFS always uses 0xFFFF).
pub fn crc16(crc: u16, data: &[u8]) -> u16 {
    let mut crc = crc;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_kernel_form() {
        // zlib.crc32("123456789") = 0xCBF43926; the kernel form is the inverse.
        assert_eq!(crc32(b"123456789"), 0x340B_C6D9);
        // Empty buffer: init without xor-out.
        assert_eq!(crc32(b""), 0xFFFF_FFFF);
    }

    #[test]
    fn crc16_matches_kernel() {
        // crc16(-1, "123456789") per lib/crc16.c.
        assert_eq!(crc16(0xFFFF, b"123456789"), 0x4B37);
    }
}
