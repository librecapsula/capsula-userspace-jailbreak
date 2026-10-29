//! Checksums of the Amlogic update protocol, bit-for-bit compatible
//! with the device side (`add_sum` in the u-boot v2_burning gadget) and
//! with pyamlboot `_amlsChecksum`.

/// The `add_sum` checksum: the sum of little-endian u32 words with a
/// natural wrap-around; a 1..3-byte tail adds its masked LE word. Used
/// for the media (download) transfers and by the tooling around them.
pub fn add_sum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        sum = sum.wrapping_add(u32::from_le_bytes(c.try_into().unwrap()));
    }
    match chunks.remainder() {
        [a] => sum.wrapping_add(*a as u32),
        [a, b] => sum.wrapping_add(u16::from_le_bytes([*a, *b]) as u32),
        [a, b, c] => sum.wrapping_add((*a as u32) | ((*b as u32) << 8) | ((*c as u32) << 16)),
        _ => sum,
    }
}

#[cfg(test)]
mod tests {
    use super::add_sum;

    #[test]
    fn add_sum_matches_uboot_add_sum() {
        // empty — identity
        assert_eq!(add_sum(&[]), 0);
        // single words
        assert_eq!(add_sum(&1u32.to_le_bytes()), 1);
        assert_eq!(add_sum(&0xffffffffu32.to_le_bytes()), 0xffffffff);
        // wrap-around like the C `unsigned` accumulator
        assert_eq!(add_sum(&0xffffffffu32.to_le_bytes().repeat(2)), 0xfffffffe);
        // tail masking (rest == 1 / 2 / 3), per the device side
        assert_eq!(add_sum(&[0x11]), 0x11);
        assert_eq!(add_sum(&[0x22, 0x11]), 0x1122);
        assert_eq!(add_sum(&[0x33, 0x22, 0x11]), 0x112233);
        // a whole + tail mix
        assert_eq!(add_sum(&[1, 0, 0, 0, 0xff, 0xff, 0xff]), 1 + 0x00ffffff);
    }
}
