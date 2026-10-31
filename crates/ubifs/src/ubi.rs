//! The UBI layer: PEB headers (EC/VID), the volume table (the layout
//! volume), parsing partition dumps and building images with volumes.
//!
//! The format follows `drivers/mtd/ubi/ubi-media.h`: all fields are
//! big-endian.

use crate::crc::crc32;
use crate::error::{Error, Result};

/// EC header magic (`UBI_EC_HDR_MAGIC` "UBI#").
pub const UBI_EC_HDR_MAGIC: u32 = 0x5542_4923;
/// VID header magic (`UBI_VID_HDR_MAGIC` "UBI!").
pub const UBI_VID_HDR_MAGIC: u32 = 0x5542_4921;
/// Volume table record magic (`UBI_VTBL_MAGIC`).
pub const UBI_VTBL_MAGIC: u32 = 0x4E4F_5655;

/// The UBI on-flash format version.
pub const UBI_VERSION: u8 = 1;
/// EC header size.
pub const UBI_EC_HDR_SIZE: usize = 64;
/// VID header size.
pub const UBI_VID_HDR_SIZE: usize = 64;
/// Volume table record size.
pub const UBI_VTBL_RECORD_SIZE: usize = 172;
/// The internal layout-volume id (`UBI_LAYOUT_VOLUME_ID` =
/// `UBI_INTERNAL_VOL_START` = 0x7FFFFFFF − 0x1000).
pub const UBI_LAYOUT_VOLUME_ID: u32 = 0x7FFF_EFFF;
/// A dynamic volume (`UBI_VID_DYNAMIC`).
pub const UBI_VID_DYNAMIC: u8 = 1;
/// A static volume (`UBI_VID_STATIC`).
pub const UBI_VID_STATIC: u8 = 2;
/// The volume "autoresize" flag (`UBI_VTBL_AUTORESIZE_FLG`).
pub const UBI_VTBL_AUTORESIZE_FLG: u8 = 0x01;
/// The volume "skip static CRC check" flag
/// (`UBI_VTBL_SKIP_CRC_CHECK_FLG`).
pub const UBI_VTBL_SKIP_CRC_CHECK_FLG: u8 = 0x02;
/// The maximum number of volumes per device (`UBI_MAX_VOLUMES`).
pub const UBI_MAX_VOLUMES: u32 = 128;
/// The maximum volume name length (`UBI_VOL_NAME_MAX`).
pub const UBI_VOL_NAME_MAX: usize = 127;
/// Compatibility: delete this internal volume (`UBI_COMPAT_DELETE`).
pub const UBI_COMPAT_DELETE: u8 = 1;
/// Compatibility: attach read-only (`UBI_COMPAT_RO`).
pub const UBI_COMPAT_RO: u8 = 2;
/// Compatibility: preserve (`UBI_COMPAT_PRESERVE`).
pub const UBI_COMPAT_PRESERVE: u8 = 4;
/// Compatibility: reject the image (`UBI_COMPAT_REJECT`) — the layout
/// volume's marker.
pub const UBI_COMPAT_REJECT: u8 = 5;

/// A PEB EC header (`struct ubi_ec_hdr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcHeader {
    /// The erase counter.
    pub ec: u64,
    /// The VID header offset inside the PEB.
    pub vid_hdr_offset: u32,
    /// The data offset inside the PEB.
    pub data_offset: u32,
    /// The image sequence number.
    pub image_seq: u32,
}

impl EcHeader {
    /// Parse from raw (big-endian) bytes with a CRC check.
    pub fn parse(b: &[u8]) -> Result<EcHeader> {
        if b.len() < UBI_EC_HDR_SIZE {
            return Err(Error::BadNode("EC header truncated".into()));
        }
        if be32(b, 0) != UBI_EC_HDR_MAGIC {
            return Err(Error::BadNode(format!("bad EC magic {:#x}", be32(b, 0))));
        }
        let stored = be32(b, 60);
        if stored != crc32(&b[..60]) {
            return Err(Error::BadCrc("EC header crc mismatch".into()));
        }
        Ok(EcHeader {
            ec: be64(b, 8),
            vid_hdr_offset: be32(b, 16),
            data_offset: be32(b, 20),
            image_seq: be32(b, 24),
        })
    }

    /// Serialize to raw bytes with a CRC.
    pub fn to_bytes(&self) -> [u8; UBI_EC_HDR_SIZE] {
        let mut b = [0u8; UBI_EC_HDR_SIZE];
        b[0..4].copy_from_slice(&UBI_EC_HDR_MAGIC.to_be_bytes());
        b[4] = UBI_VERSION;
        b[8..16].copy_from_slice(&self.ec.to_be_bytes());
        b[16..20].copy_from_slice(&self.vid_hdr_offset.to_be_bytes());
        b[20..24].copy_from_slice(&self.data_offset.to_be_bytes());
        b[24..28].copy_from_slice(&self.image_seq.to_be_bytes());
        let crc = crc32(&b[..60]);
        b[60..64].copy_from_slice(&crc.to_be_bytes());
        b
    }
}

/// A PEB VID header (`struct ubi_vid_hdr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VidHeader {
    /// Volume type (dynamic/static).
    pub vol_type: u8,
    /// The LEB copy flag (garbage collection).
    pub copy_flag: u8,
    /// The compatibility field (internal volumes only; the layout
    /// volume carries `UBI_COMPAT_REJECT`).
    pub compat: u8,
    /// Volume identifier.
    pub vol_id: u32,
    /// The LEB number inside the volume.
    pub lnum: u32,
    /// Static volumes: the data size.
    pub data_size: u32,
    /// Static volumes: the number of used LEBs.
    pub used_ebs: u32,
    /// Data padding.
    pub data_pad: u32,
    /// Static volumes: the data CRC.
    pub data_crc: u32,
}

impl VidHeader {
    /// Parse from raw (big-endian) bytes with a CRC check.
    pub fn parse(b: &[u8]) -> Result<VidHeader> {
        if b.len() < UBI_VID_HDR_SIZE {
            return Err(Error::BadNode("VID header truncated".into()));
        }
        if be32(b, 0) != UBI_VID_HDR_MAGIC {
            return Err(Error::BadNode(format!("bad VID magic {:#x}", be32(b, 0))));
        }
        let stored = be32(b, 60);
        if stored != crc32(&b[..60]) {
            return Err(Error::BadCrc("VID header crc mismatch".into()));
        }
        Ok(VidHeader {
            vol_type: b[5],
            copy_flag: b[6],
            compat: b[7],
            vol_id: be32(b, 8),
            lnum: be32(b, 12),
            data_size: be32(b, 20),
            used_ebs: be32(b, 24),
            data_pad: be32(b, 28),
            data_crc: be32(b, 32),
        })
    }

    /// Serialize to raw bytes with a CRC.
    pub fn to_bytes(&self) -> [u8; UBI_VID_HDR_SIZE] {
        let mut b = [0u8; UBI_VID_HDR_SIZE];
        b[0..4].copy_from_slice(&UBI_VID_HDR_MAGIC.to_be_bytes());
        b[4] = UBI_VERSION;
        b[5] = self.vol_type;
        b[6] = self.copy_flag;
        b[7] = self.compat;
        b[8..12].copy_from_slice(&self.vol_id.to_be_bytes());
        b[12..16].copy_from_slice(&self.lnum.to_be_bytes());
        b[20..24].copy_from_slice(&self.data_size.to_be_bytes());
        b[24..28].copy_from_slice(&self.used_ebs.to_be_bytes());
        b[28..32].copy_from_slice(&self.data_pad.to_be_bytes());
        b[32..36].copy_from_slice(&self.data_crc.to_be_bytes());
        let crc = crc32(&b[..60]);
        b[60..64].copy_from_slice(&crc.to_be_bytes());
        b
    }
}

/// A volume table record (`struct ubi_vtbl_record`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtblRecord {
    /// How many PEBs are reserved for the volume.
    pub reserved_pebs: u32,
    /// Volume alignment.
    pub alignment: u32,
    /// Data padding.
    pub data_pad: u32,
    /// Volume type.
    pub vol_type: u8,
    /// The update marker.
    pub upd_marker: u8,
    /// Name length.
    pub name_len: u16,
    /// The volume name (NUL-terminated).
    pub name: [u8; 128],
    /// Flags (`UBI_VTBL_AUTORESIZE_FLG`).
    pub flags: u8,
}

impl VtblRecord {
    /// An empty record (the volume slot is free). Serializing it via
    /// [`VtblRecord::to_bytes`] yields the CRC-carrying empty record of
    /// `ubigen_create_vtbl` (the CRC is always recomputed from the
    /// fields).
    pub fn empty() -> VtblRecord {
        VtblRecord {
            reserved_pebs: 0,
            alignment: 0,
            data_pad: 0,
            vol_type: 0,
            upd_marker: 0,
            name_len: 0,
            name: [0; 128],
            flags: 0,
        }
    }

    /// Parse from raw (big-endian) bytes with a CRC check.
    pub fn parse(b: &[u8]) -> Result<VtblRecord> {
        if b.len() < UBI_VTBL_RECORD_SIZE {
            return Err(Error::BadNode("vtbl record truncated".into()));
        }
        let crc_stored = be32(b, UBI_VTBL_RECORD_SIZE - 4);
        let rec = VtblRecord {
            reserved_pebs: be32(b, 0),
            alignment: be32(b, 4),
            data_pad: be32(b, 8),
            vol_type: b[12],
            upd_marker: b[13],
            name_len: be16(b, 14),
            name: b[16..144].try_into().unwrap(),
            flags: b[144],
        };
        // An empty record (all FF / zeros) skips the CRC check.
        if rec.reserved_pebs == 0 {
            return Ok(rec);
        }
        // The record CRC is in the kernel form (crc32_le without the
        // final XOR) over all 168 bytes before the crc field.
        if crc_stored != crc32(&b[..UBI_VTBL_RECORD_SIZE - 4]) {
            return Err(Error::BadCrc("vtbl record crc mismatch".into()));
        }
        Ok(rec)
    }

    /// Serialize to raw bytes with a CRC.
    pub fn to_bytes(&self) -> [u8; UBI_VTBL_RECORD_SIZE] {
        let mut b = [0u8; UBI_VTBL_RECORD_SIZE];
        b[0..4].copy_from_slice(&self.reserved_pebs.to_be_bytes());
        b[4..8].copy_from_slice(&self.alignment.to_be_bytes());
        b[8..12].copy_from_slice(&self.data_pad.to_be_bytes());
        b[12] = self.vol_type;
        b[13] = self.upd_marker;
        b[14..16].copy_from_slice(&self.name_len.to_be_bytes());
        b[16..144].copy_from_slice(&self.name);
        b[144] = self.flags;
        let crc = crc32(&b[..UBI_VTBL_RECORD_SIZE - 4]);
        b[UBI_VTBL_RECORD_SIZE - 4..].copy_from_slice(&crc.to_be_bytes());
        b
    }

    /// The volume name as a string.
    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name[..self.name_len as usize]).into_owned()
    }
}

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}
fn be64(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

/// The geometry of a UBI dump or image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UbiGeometry {
    /// PEB size.
    pub peb_size: u32,
    /// The VID header offset.
    pub vid_hdr_offset: u32,
    /// The data offset.
    pub data_offset: u32,
}

impl UbiGeometry {
    /// The default geometry (as ubiformat): the VID header in the first
    /// min_io unit, the data after it (the 64-byte VID header is aligned
    /// up to min_io). For a 128 KiB PEB flash with 2 KiB min_io this
    /// gives vid @2048 and data @4096.
    pub fn from_peb_size(peb_size: u32, min_io_size: u32) -> UbiGeometry {
        let vid = min_io_size.min(peb_size);
        let data = (vid + UBI_VID_HDR_SIZE as u32).div_ceil(min_io_size) * min_io_size;
        UbiGeometry {
            peb_size,
            vid_hdr_offset: vid,
            data_offset: data,
        }
    }
}

/// A parsed UBI partition dump.
pub struct Dump<'a> {
    /// The raw partition dump.
    pub raw: &'a [u8],
    /// The dump geometry.
    pub geom: UbiGeometry,
    /// The volume table (layout volume records).
    pub vtbl: Vec<VtblRecord>,
}

impl<'a> Dump<'a> {
    /// Parse a dump: scan the PEBs, read the volume table (the layout
    /// volume).
    pub fn parse(raw: &'a [u8], geom: UbiGeometry) -> Result<Dump<'a>> {
        let peb = geom.peb_size as usize;
        if raw.len() < peb * 2 {
            return Err(Error::MissingData("dump is smaller than two PEBs".into()));
        }
        // Only the first max_volumes records of the LEB are the table
        // (the LEB tail is 0xFF padding).
        let leb_size = peb - geom.data_offset as usize;
        let max_volumes = ((leb_size / UBI_VTBL_RECORD_SIZE) as u32).min(UBI_MAX_VOLUMES) as usize;
        let mut vtbl = Vec::new();
        // The layout volume: two PEBs with the layout volume id, lnum
        // 0/1; the vtbl records live in the data at data_offset.
        for base in [0usize, peb] {
            let vid = &raw[base + geom.vid_hdr_offset as usize..];
            let Ok(vh) = VidHeader::parse(vid) else {
                continue;
            };
            if vh.vol_id != UBI_LAYOUT_VOLUME_ID {
                continue;
            }
            let data = &raw[base + geom.data_offset as usize..base + peb];
            let recs = (data.len() / UBI_VTBL_RECORD_SIZE).min(max_volumes);
            for r in 0..recs {
                let rec = VtblRecord::parse(&data[r * UBI_VTBL_RECORD_SIZE..])?;
                if vtbl.len() <= r {
                    vtbl.resize(r + 1, VtblRecord::empty());
                }
                if rec.reserved_pebs != 0 {
                    vtbl[r] = rec;
                }
            }
        }
        Ok(Dump { raw, geom, vtbl })
    }

    /// The volume list (id, name, type) from the volume table.
    pub fn volumes(&self) -> Vec<(u32, String, u8)> {
        self.vtbl
            .iter()
            .enumerate()
            .filter(|(_, r)| r.reserved_pebs != 0)
            .map(|(i, r)| (i as u32, r.name_str(), r.vol_type))
            .collect()
    }

    /// The LEBs of a volume (per the VID headers; unmapped — None).
    pub fn volume_lebs(&self, vol_id: u32) -> Vec<Option<Vec<u8>>> {
        let mut lebs: Vec<Option<Vec<u8>>> = Vec::new();
        let peb = self.geom.peb_size as usize;
        let mut base = 0usize;
        while base + peb <= self.raw.len() {
            let vid = &self.raw[base + self.geom.vid_hdr_offset as usize..];
            if let Ok(vh) = VidHeader::parse(vid) {
                if vh.vol_id == vol_id {
                    if lebs.len() <= vh.lnum as usize {
                        lebs.resize(vh.lnum as usize + 1, None);
                    }
                    lebs[vh.lnum as usize] =
                        Some(self.raw[base + self.geom.data_offset as usize..base + peb].to_vec());
                }
            }
            base += peb;
        }
        lebs
    }
}

/// A summary of one volume of a dump (the `ubinfo -a` view).
#[derive(Debug, Clone)]
pub struct VolInfo {
    /// The volume id.
    pub vol_id: u32,
    /// The volume name.
    pub name: String,
    /// The volume type (`UBI_VID_DYNAMIC`/`UBI_VID_STATIC`).
    pub vol_type: u8,
    /// How many PEBs are reserved for the volume.
    pub reserved_pebs: u32,
    /// The volume alignment.
    pub alignment: u32,
    /// The data padding of the alignment.
    pub data_pad: u32,
    /// `UBI_VTBL_*` flags.
    pub flags: u8,
}

impl<'a> Dump<'a> {
    /// The volume summary from the volume table (an `ubinfo` view).
    pub fn info(&self) -> Vec<VolInfo> {
        self.vtbl
            .iter()
            .enumerate()
            .filter(|(_, r)| r.reserved_pebs != 0)
            .map(|(i, r)| VolInfo {
                vol_id: i as u32,
                name: r.name_str(),
                vol_type: r.vol_type,
                reserved_pebs: r.reserved_pebs,
                alignment: r.alignment,
                data_pad: r.data_pad,
                flags: r.flags,
            })
            .collect()
    }

    /// The VID headers of a volume's LEBs (unmapped — None), in LEB
    /// order. Static volumes carry `data_size`/`used_ebs`/`data_crc`
    /// here.
    pub fn volume_vids(&self, vol_id: u32) -> Vec<Option<VidHeader>> {
        let mut out: Vec<Option<VidHeader>> = Vec::new();
        let peb = self.geom.peb_size as usize;
        let mut base = 0usize;
        while base + peb <= self.raw.len() {
            let vid = &self.raw[base + self.geom.vid_hdr_offset as usize..];
            if let Ok(vh) = VidHeader::parse(vid) {
                if vh.vol_id == vol_id {
                    if out.len() <= vh.lnum as usize {
                        out.resize(vh.lnum as usize + 1, None);
                    }
                    out[vh.lnum as usize] = Some(vh);
                }
            }
            base += peb;
        }
        out
    }

    /// Verify a static volume: recompute the per-LEB `data_crc` of the
    /// payload and compare with the VID headers.
    pub fn verify_static(&self, vol_id: u32) -> Result<()> {
        let vids = self.volume_vids(vol_id);
        let lebs = self.volume_lebs(vol_id);
        for (lnum, (vid, leb)) in vids.iter().zip(lebs.iter()).enumerate() {
            let Some(vid) = vid else { continue };
            let Some(leb) = leb else {
                return Err(Error::MissingData(format!(
                    "static volume {vol_id}: leb {lnum} is unmapped"
                )));
            };
            let data = &leb[..vid.data_size as usize];
            if crate::crc::crc32(data) != vid.data_crc {
                return Err(Error::BadCrc(format!(
                    "static volume {vol_id}: leb {lnum} data crc mismatch"
                )));
            }
        }
        Ok(())
    }

    /// The image sequence number from the first valid EC header.
    pub fn image_seq(&self) -> Option<u32> {
        let peb = self.geom.peb_size as usize;
        let mut base = 0usize;
        while base + peb <= self.raw.len() {
            if let Ok(ec) = EcHeader::parse(&self.raw[base..]) {
                return Some(ec.image_seq);
            }
            base += peb;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_vid_roundtrip() {
        let ec = EcHeader {
            ec: 42,
            vid_hdr_offset: 2048,
            data_offset: 4096,
            image_seq: 7,
        };
        let b = ec.to_bytes();
        assert_eq!(EcHeader::parse(&b).unwrap(), ec);

        let vh = VidHeader {
            vol_type: UBI_VID_DYNAMIC,
            copy_flag: 0,
            compat: 0,
            vol_id: 0,
            lnum: 5,
            data_size: 0,
            used_ebs: 0,
            data_pad: 0,
            data_crc: 0,
        };
        let b = vh.to_bytes();
        assert_eq!(VidHeader::parse(&b).unwrap(), vh);
    }

    #[test]
    fn ubinize_build_then_parse() {
        use crate::ubinize;
        let opts = ubinize::Options::new(0x20000, 2048);
        let (geom, leb) = opts.geometry().unwrap();
        assert_eq!(geom.vid_hdr_offset, 2048);
        assert_eq!(geom.data_offset, 4096);
        assert_eq!(leb, 0x20000 - 4096);

        let vols = vec![
            ubinize::Volume {
                vol_type: ubinize::VolType::Dynamic,
                vol_id: 0,
                vol_name: "data".into(),
                vol_alignment: 1,
                vol_flags: None,
                image: Some(vec![0xAB; leb as usize * 3]),
                bytes: leb as u64 * 3,
            },
            ubinize::Volume {
                vol_type: ubinize::VolType::Static,
                vol_id: 1,
                vol_name: "firmware".into(),
                vol_alignment: 1,
                vol_flags: Some(ubinize::VolFlags::SkipCheck),
                image: Some(vec![0xCD; 1000]),
                bytes: 1000,
            },
        ];
        let img = ubinize::build_image(&opts, &vols).unwrap();
        let dump = Dump::parse(&img, geom).unwrap();
        let info = dump.info();
        assert_eq!(info.len(), 2);
        assert_eq!(info[0].name, "data");
        assert_eq!(info[1].name, "firmware");
        assert_eq!(info[1].vol_type, UBI_VID_STATIC);

        let lebs = dump.volume_lebs(0);
        assert_eq!(lebs.len(), 3);
        assert!(lebs.iter().all(|l| l.as_ref().unwrap()[0] == 0xAB));
        dump.verify_static(1).unwrap();
        assert_eq!(dump.image_seq(), Some(0));

        // The layout volume sits at PEBs 0-1 with compat = REJECT.
        let vids = dump.volume_vids(UBI_LAYOUT_VOLUME_ID);
        assert_eq!(vids.len(), 2);
        assert_eq!(vids[0].unwrap().compat, UBI_COMPAT_REJECT);
    }
}
