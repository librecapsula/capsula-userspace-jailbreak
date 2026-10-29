//! First-generation ("gift") column detection.
//!
//! These units ship a locked BootROM (`secure:yes` with first-generation
//! keys): it silently refuses our usbplug, so the RAM-loader backup flow
//! is impossible on them. What they DO expose in download mode is the
//! stock u-boot rockusb loader (2207:330d) — enough to flash userdata
//! directly.
//!
//! Recognition: the USB serial of the stock u-boot personas. Regular
//! columns carry the chip UID, which starts with four digits
//! ("01139EB3613ABD80"); gift units have a random-looking hex string
//! ("e5fe5a07c23ce39a").

/// Is this USB serial a first-generation column?
pub fn is_first_generation(serial: &str) -> bool {
    !serial.chars().take(4).all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_serials_pass() {
        // real regular-column serials start with the numeric UID prefix
        assert!(!is_first_generation("01139EB3613ABD80"));
        assert!(!is_first_generation("0001123456789ABC"));
        assert!(!is_first_generation("9999XXXXXXXXXXXX"));
    }

    #[test]
    fn gift_serials_flagged() {
        assert!(is_first_generation("e5fe5a07c23ce39a"));
        assert!(is_first_generation("A1139EB3613ABD80"));
        assert!(is_first_generation("1 139EB3613ABD80"));
    }

    #[test]
    fn short_serials_follow_the_prefix_rule() {
        // a truncated serial still has a non-numeric prefix -> gift
        assert!(is_first_generation("ab1"));
        // a MISSING serial (string read failed) must not block the
        // normal flow: all() over nothing is true, so "" is regular;
        // the normal flow fails safely on a gift column (LoaderRejected)
        assert!(!is_first_generation(""));
    }
}
