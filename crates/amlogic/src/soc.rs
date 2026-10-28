//! The identify reply (AM_REQ_IDENTIFY_HOST) and the SoC boot stage.

/// The boot stage the USB download device is in (the stage_major/stage_minor
/// bytes of the identify reply; names per pyamlboot `SocId`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// BootROM (the BL1/Initial Program Loader) download mode.
    Ipl,
    /// SPL (DDR-init/BL2 stage) — seen on some boot chains.
    Spl,
    /// TPL — the u-boot USB-burning gadget ("optimus").
    Tpl,
    /// Unrecognized stage reported by the device.
    Unknown(u8, u8),
}

impl Stage {
    pub fn label(&self) -> &'static str {
        match self {
            Stage::Ipl => "BootROM (IPL)",
            Stage::Spl => "SPL",
            Stage::Tpl => "u-boot burning gadget (TPL)",
            Stage::Unknown(..) => "unknown stage",
        }
    }
}

/// The parsed AM_REQ_IDENTIFY_HOST reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocId {
    pub major: u8,
    pub minor: u8,
    pub stage_major: u8,
    pub stage_minor: u8,
    /// Bytes 4.. of the reply (a locked BootROM adds the password flags
    /// there: need_password, password_ok).
    pub extra: Vec<u8>,
}

/// stage_minor of the BootROM.
pub const STAGE_MINOR_IPL: u8 = 0;
/// stage_minor of the SPL stage.
pub const STAGE_MINOR_SPL: u8 = 8;
/// stage_minor of the TPL (u-boot) stage.
pub const STAGE_MINOR_TPL: u8 = 16;

impl SocId {
    /// Parse an identify reply; at least 4 bytes are required.
    pub fn parse(data: &[u8]) -> Option<SocId> {
        if data.len() < 4 {
            return None;
        }
        Some(SocId {
            major: data[0],
            minor: data[1],
            stage_major: data[2],
            stage_minor: data[3],
            extra: data[4..].to_vec(),
        })
    }

    pub fn stage(&self) -> Stage {
        match (self.stage_major, self.stage_minor) {
            (0, STAGE_MINOR_IPL) => Stage::Ipl,
            (0, STAGE_MINOR_SPL) => Stage::Spl,
            (0, STAGE_MINOR_TPL) => Stage::Tpl,
            (1, STAGE_MINOR_TPL) => Stage::Tpl,
            (m, s) => Stage::Unknown(m, s),
        }
    }

    /// Whether the reply's optional bytes are valid: the spec gates
    /// PWD_REQ/PWD_OK/MAP on a nonzero V3 (our `stage_minor`).
    pub fn has_optional_fields(&self) -> bool {
        self.stage_minor != 0
    }

    /// `PWD_REQ` (byte 4): the device demands a password before accepting
    /// commands. `None` when the reply is too short or V3 is zero.
    pub fn need_password(&self) -> Option<bool> {
        if !self.has_optional_fields() {
            return None;
        }
        self.extra.first().map(|&byte| byte != 0)
    }

    /// `PWD_OK` (byte 5): the password was accepted. `None` when the
    /// reply is too short or V3 is zero.
    pub fn password_ok(&self) -> Option<bool> {
        if !self.has_optional_fields() {
            return None;
        }
        self.extra.get(1).map(|&byte| byte != 0)
    }

    /// `MAP6`/`MAP7` (bytes 6 and 7); byte 7 also signals their presence.
    pub fn page_map(&self) -> Option<[u8; 2]> {
        if !self.has_optional_fields() || self.extra.len() < 4 || self.extra[3] == 0 {
            return None;
        }
        Some([self.extra[2], self.extra[3]])
    }

    /// Version string like `0-9-0-0` (major-minor-stage_major-stage_minor).
    pub fn version(&self) -> String {
        format!(
            "{}-{}-{}-{}",
            self.major, self.minor, self.stage_major, self.stage_minor
        )
    }
}

impl std::fmt::Display for SocId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.version(), self.stage().label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stages() {
        let rom = SocId::parse(&[0x00, 0x20, 0x00, 0x00]).unwrap();
        assert_eq!(rom.stage(), Stage::Ipl);
        assert_eq!(rom.version(), "0-32-0-0");

        let uboot = SocId::parse(&[0x00, 0x20, 0x01, STAGE_MINOR_TPL]).unwrap();
        assert_eq!(uboot.stage(), Stage::Tpl);

        let other = SocId::parse(&[0, 0, 0x02, 0x05]).unwrap();
        assert_eq!(other.stage(), Stage::Unknown(0x02, 0x05));
    }

    #[test]
    fn password_flags_and_short_replies() {
        // 4-byte reply: no password info
        let id = SocId::parse(&[0, 0, 0, 0]).unwrap();
        assert_eq!(id.need_password(), None);
        // V3 == 0 masks bytes 4..7 even when they are nonzero
        let id = SocId::parse(&[0, 7, 0, 0, 1, 0]).unwrap();
        assert_eq!(id.need_password(), None);
        // locked BootROM (V3 != 0): need_password=1, password_ok=0
        let id = SocId::parse(&[0, 7, 0, 16, 1, 0]).unwrap();
        assert_eq!(id.need_password(), Some(true));
        assert_eq!(id.password_ok(), Some(false));
        // MAP6/MAP7 are present when byte 7 is nonzero
        let id = SocId::parse(&[0, 7, 0, 16, 0, 1, 2, 3]).unwrap();
        assert_eq!(id.page_map(), Some([2, 3]));
        let id = SocId::parse(&[0, 7, 0, 16, 0, 1, 2, 0]).unwrap();
        assert_eq!(id.page_map(), None);
        assert!(SocId::parse(&[0, 0, 0]).is_none());
    }
}
