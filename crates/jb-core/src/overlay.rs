//! The overlay file set placed into the data partition: adbd, the USB
//! gadget flag and the jailbreak marker. The set is
//! platform-independent (rockchip patches it into ext4 userdata, the
//! amlogic Mini into the UBIFS data volume); the per-platform builders
//! own the filesystem mechanics.

/// Prefix inside the data partition: the overlayfs upper layer. Files
/// placed here show up at the root of the running system.
pub const UPPER_DIR: &str = "/overlay/upper";

/// Dirs the stock boot scripts expect to exist in the data partition:
/// overlayfs needs an EMPTY workdir next to the upper layer
/// (S23overlayfs.sh mounts workdir=/data/overlay/work). Created on
/// fresh images; on captures they already exist (mkdir is a no-op).
pub const LAYOUT_DIRS: &[&str] = &["/overlay", UPPER_DIR, "/overlay/work"];

/// adbd build (aarch64/glibc; built in docker/adbd, linked against
/// glibc 2.31 / OpenSSL 1.1 — runs on the stock rootfs). Listens on
/// USB and TCP:5555 at once (ADBD_TCP_PORT overrides the port).
pub const OVERLAY_ADBD: &[u8] = include_bytes!("../../../resources/overlay/usr/bin/adbd");
/// USB gadget flag for firmwares that parse it; harmless elsewhere.
pub const OVERLAY_USB_CONFIG: &[u8] =
    include_bytes!("../../../resources/overlay/etc/init.d/.usb_config");

/// One overlay file (the path is inside the data partition).
pub struct OverlayFile {
    pub path: String,
    pub data: Vec<u8>,
    pub mode: u32,
}

/// The overlay file set: adbd + the gadget flag + the jailbreak marker.
/// After boot they appear as /usr/bin/adbd, /etc/init.d/.usb_config and
/// /etc/jailbreak.
pub fn overlay_files(marker: String) -> Vec<OverlayFile> {
    vec![
        OverlayFile {
            path: format!("{UPPER_DIR}/usr/bin/adbd"),
            data: OVERLAY_ADBD.to_vec(),
            mode: 0o755,
        },
        OverlayFile {
            path: format!("{UPPER_DIR}/etc/init.d/.usb_config"),
            data: OVERLAY_USB_CONFIG.to_vec(),
            mode: 0o644,
        },
        OverlayFile {
            path: format!("{UPPER_DIR}/etc/jailbreak"),
            data: marker.into_bytes(),
            mode: 0o644,
        },
    ]
}
