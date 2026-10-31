//! The `ubinize` equivalent: build a full UBI image (a `.img` flashable
//! to a partition) from an ini-style volume configuration — dynamic and
//! static volumes, alignments, the volume table and the layout volume,
//! byte-compatible with the mtd-utils tool.

use crate::crc::crc32;
use crate::error::{Error, Result};
use crate::ubi::{
    UbiGeometry, VidHeader, VtblRecord, UBI_EC_HDR_SIZE, UBI_LAYOUT_VOLUME_ID, UBI_MAX_VOLUMES,
    UBI_VID_DYNAMIC, UBI_VID_HDR_SIZE, UBI_VID_STATIC, UBI_VOL_NAME_MAX, UBI_VTBL_RECORD_SIZE,
    UBI_VTBL_SKIP_CRC_CHECK_FLG,
};

/// The volume type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VolType {
    /// A dynamic volume (`UBI_VID_DYNAMIC`, the default).
    #[default]
    Dynamic,
    /// A static volume (`UBI_VID_STATIC`): requires an image, every LEB
    /// carries a data CRC.
    Static,
}

/// The `vol_flags` ini key — exactly one at a time, as in ubinize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolFlags {
    /// `UBI_VTBL_AUTORESIZE_FLG`: resize this volume to fill the
    /// remaining space at attach time (at most one volume per image).
    Autoresize,
    /// `UBI_VTBL_SKIP_CRC_CHECK_FLG`: skip the data CRC check on a
    /// static volume at attach time (static volumes only).
    SkipCheck,
}

/// The flash geometry and tool options (`-p/-m/-s/-O/-e/-x/-Q` of
/// ubinize; the image sequence number is explicit — ubinize rolls a
/// random one, a library should stay deterministic).
#[derive(Debug, Clone)]
pub struct Options {
    /// PEB size in bytes (`-p`).
    pub peb_size: u32,
    /// Minimum I/O unit size (`-m`).
    pub min_io_size: u32,
    /// Sub-page size (`-s`); defaults to min_io in ubinize.
    pub sub_page_size: Option<u32>,
    /// VID header offset (`-O`); None — the EC header size aligned up
    /// to the sub-page size.
    pub vid_hdr_offset: Option<u32>,
    /// The erase counter value written into every EC header (`-e`,
    /// default 0).
    pub ec: u64,
    /// The UBI format version (`-x`, default 1).
    pub ubi_ver: u8,
    /// The image sequence number (`-Q`).
    pub image_seq: u32,
}

impl Options {
    /// Options with only the mandatory geometry.
    pub fn new(peb_size: u32, min_io_size: u32) -> Options {
        Options {
            peb_size,
            min_io_size,
            sub_page_size: None,
            vid_hdr_offset: None,
            ec: 0,
            ubi_ver: 1,
            image_seq: 0,
        }
    }

    /// The derived geometry: (vid_hdr_offset, data_offset, leb_size),
    /// per `ubigen_init`.
    pub fn geometry(&self) -> Result<(UbiGeometry, u32)> {
        if !self.min_io_size.is_power_of_two() {
            return Err(Error::BadGeometry(
                "min. I/O size must be a power of 2".into(),
            ));
        }
        let sub = self.sub_page_size.unwrap_or(self.min_io_size);
        if self.peb_size == 0 || !self.peb_size.is_multiple_of(self.min_io_size) {
            return Err(Error::BadGeometry(
                "PEB size must be a multiple of min. I/O".into(),
            ));
        }
        if sub == 0 || !self.min_io_size.is_multiple_of(sub) {
            return Err(Error::BadGeometry(
                "sub-page size must divide min. I/O size".into(),
            ));
        }
        let align = |x: u32, a: u32| x.div_ceil(a) * a;
        let vid = match self.vid_hdr_offset {
            Some(v) => v,
            None => align(UBI_EC_HDR_SIZE as u32, sub),
        };
        let data = align(vid + UBI_VID_HDR_SIZE as u32, self.min_io_size);
        if data >= self.peb_size {
            return Err(Error::BadGeometry(
                "data offset does not fit the PEB".into(),
            ));
        }
        Ok((
            UbiGeometry {
                peb_size: self.peb_size,
                vid_hdr_offset: vid,
                data_offset: data,
            },
            self.peb_size - data,
        ))
    }

    /// The maximum number of volumes (as `ubigen_init`).
    pub fn max_volumes(&self, leb_size: u32) -> u32 {
        (leb_size / UBI_VTBL_RECORD_SIZE as u32).min(UBI_MAX_VOLUMES)
    }
}

/// One volume as parsed from the ini file (the image still a path).
#[derive(Debug, Clone)]
pub struct IniVolume {
    /// The section name.
    pub section: String,
    /// `vol_type` (default dynamic).
    pub vol_type: VolType,
    /// `image`: the path to the volume payload (mandatory for static
    /// volumes, optional otherwise).
    pub image: Option<String>,
    /// `vol_id` (mandatory).
    pub vol_id: u32,
    /// `vol_size` in bytes (default: the image size).
    pub vol_size: Option<u64>,
    /// `vol_name` (mandatory).
    pub vol_name: String,
    /// `vol_alignment` (default 1).
    pub vol_alignment: u32,
    /// `vol_flags`: autoresize or skip-check.
    pub vol_flags: Option<VolFlags>,
}

/// A resolved volume ready for building.
#[derive(Debug, Clone)]
pub struct Volume {
    /// The volume type.
    pub vol_type: VolType,
    /// The volume id.
    pub vol_id: u32,
    /// The volume name.
    pub vol_name: String,
    /// The volume alignment.
    pub vol_alignment: u32,
    /// The volume flags.
    pub vol_flags: Option<VolFlags>,
    /// The payload bytes (None for an empty dynamic volume).
    pub image: Option<Vec<u8>>,
    /// The volume size in bytes (`vol_size`, or the image size).
    pub bytes: u64,
}

impl Volume {
    /// Resolve an ini volume with its payload read in (`image_data` —
    /// the contents of the `image=` file, if any).
    pub fn from_ini(v: IniVolume, image_data: Option<Vec<u8>>) -> Result<Volume> {
        let image = image_data;
        if v.vol_type == VolType::Static && image.is_none() {
            return Err(Error::Other(format!(
                "static volume \"{}\" needs an image",
                v.section
            )));
        }
        if let Some(data) = &image {
            if v.vol_size.is_some_and(|s| data.len() as u64 > s) {
                return Err(Error::Other(format!(
                    "volume \"{}\": image ({} bytes) is larger than vol_size",
                    v.section,
                    data.len()
                )));
            }
        }
        if v.vol_size.is_none() && image.is_none() {
            return Err(Error::Other(format!(
                "volume \"{}\" needs vol_size or an image",
                v.section
            )));
        }
        let bytes = v
            .vol_size
            .unwrap_or_else(|| image.as_ref().map(|d| d.len() as u64).unwrap_or(0));
        Ok(Volume {
            vol_type: v.vol_type,
            vol_id: v.vol_id,
            vol_name: v.vol_name,
            vol_alignment: v.vol_alignment,
            vol_flags: v.vol_flags,
            image,
            bytes,
        })
    }
}

/// Parse an ini configuration (the ubinize input format: `[section]`
/// headers, `key=value` or `key: value` pairs, `#`/`;` comments).
/// Non-`mode=ubi` sections are skipped, as in ubinize.
pub fn parse_config(text: &str) -> Result<Vec<IniVolume>> {
    let mut out: Vec<IniVolume> = Vec::new();
    let mut section = String::new();
    let mut kv: Vec<(String, String)> = Vec::new();

    let mut flush = |section: &str, kv: &Vec<(String, String)>| -> Result<()> {
        if section.is_empty() {
            return Ok(());
        }
        let get = |k: &str| kv.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let mode = get("mode")
            .ok_or_else(|| Error::Other(format!("section \"{section}\": no \"mode\" key")))?;
        if mode != "ubi" {
            return Ok(()); // skip non-ubi sections
        }
        let vol_type = match get("vol_type").as_deref() {
            None | Some("dynamic") => VolType::Dynamic,
            Some("static") => VolType::Static,
            Some(t) => {
                return Err(Error::Other(format!(
                    "section \"{section}\": invalid vol_type \"{t}\""
                )))
            }
        };
        let Some(vol_id) = get("vol_id") else {
            return Err(Error::Other(format!(
                "section \"{section}\": no \"vol_id\" key"
            )));
        };
        let vol_id: u32 = vol_id
            .parse()
            .map_err(|_| Error::Other(format!("section \"{section}\": bad vol_id \"{vol_id}\"")))?;
        let Some(vol_name) = get("vol_name") else {
            return Err(Error::Other(format!(
                "section \"{section}\": no \"vol_name\" key"
            )));
        };
        if vol_name.len() > UBI_VOL_NAME_MAX {
            return Err(Error::Other(format!(
                "section \"{section}\": volume name is too long"
            )));
        }
        let vol_size = match get("vol_size") {
            Some(s) => Some(parse_size(&s)?),
            None => None,
        };
        let vol_alignment = match get("vol_alignment") {
            Some(a) => a
                .parse()
                .map_err(|_| Error::Other(format!("section \"{section}\": bad vol_alignment")))?,
            None => 1,
        };
        let vol_flags = match get("vol_flags").as_deref() {
            None => None,
            Some("autoresize") => Some(VolFlags::Autoresize),
            Some("skip-check") => Some(VolFlags::SkipCheck),
            Some(f) => {
                return Err(Error::Other(format!(
                    "section \"{section}\": unknown vol_flags \"{f}\""
                )))
            }
        };
        out.push(IniVolume {
            section: section.to_string(),
            vol_type,
            image: get("image"),
            vol_id,
            vol_size,
            vol_name,
            vol_alignment,
            vol_flags,
        });
        Ok(())
    };

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            flush(&section, &kv)?;
            section = name.trim().to_string();
            kv.clear();
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .or_else(|| line.split_once(':'))
            .ok_or_else(|| Error::Other(format!("bad ini line: {raw:?}")))?;
        kv.push((k.trim().to_string(), v.trim().to_string()));
    }
    flush(&section, &kv)?;
    Ok(out)
}

/// Parse a size with an optional KiB/MiB/GiB suffix (`util_get_bytes`).
pub fn parse_size(s: &str) -> Result<u64> {
    let (num, mul) = if let Some(v) = s.strip_suffix("GiB") {
        (v, 1u64 << 30)
    } else if let Some(v) = s.strip_suffix("MiB") {
        (v, 1u64 << 20)
    } else if let Some(v) = s.strip_suffix("KiB") {
        (v, 1u64 << 10)
    } else {
        (s, 1)
    };
    num.trim()
        .parse::<u64>()
        .map(|v| v * mul)
        .map_err(|_| Error::Other(format!("bad size \"{s}\"")))
}

/// Build the UBI image (the full ubinize flow: volumes sequentially
/// after the two layout PEBs, the volume table written last into PEBs
/// 0-1).
pub fn build_image(opts: &Options, vols: &[Volume]) -> Result<Vec<u8>> {
    let (geom, leb_size) = opts.geometry()?;
    let peb = opts.peb_size as usize;
    let data_offs = geom.data_offset as usize;
    let vid_offs = geom.vid_hdr_offset as usize;
    let usable_leb = |alignment: u32| -> Result<usize> {
        if alignment == 0 || alignment >= leb_size {
            return Err(Error::BadGeometry(format!("bad alignment {alignment}")));
        }
        Ok((leb_size - leb_size % alignment) as usize)
    };
    let max_volumes = opts.max_volumes(leb_size);

    // Cross-volume checks (ubinize main).
    let mut autoresize = false;
    for (i, v) in vols.iter().enumerate() {
        if v.vol_id >= max_volumes {
            return Err(Error::BadGeometry(format!(
                "too high volume id {}, max is {max_volumes}",
                v.vol_id
            )));
        }
        for w in vols.iter().take(i) {
            if v.vol_id == w.vol_id {
                return Err(Error::BadGeometry(format!(
                    "volume id {} is not unique",
                    v.vol_id
                )));
            }
            if v.vol_name == w.vol_name {
                return Err(Error::BadGeometry(format!(
                    "volume name {:?} is not unique",
                    v.vol_name
                )));
            }
        }
        match v.vol_flags {
            Some(VolFlags::Autoresize) => {
                if autoresize {
                    return Err(Error::BadGeometry(
                        "only one volume may have the autoresize flag".into(),
                    ));
                }
                autoresize = true;
            }
            Some(VolFlags::SkipCheck) if v.vol_type != VolType::Static => {
                return Err(Error::BadGeometry(
                    "skip-check is only valid for static volumes".into(),
                ));
            }
            _ => {}
        }
    }

    // The volume table: max_volumes records; empty ones still carry a
    // CRC (ubigen_create_vtbl).
    let mut vtbl = vec![VtblRecord::empty(); max_volumes as usize];
    for v in vols {
        let data_pad = leb_size % v.vol_alignment;
        vtbl[v.vol_id as usize] = VtblRecord {
            reserved_pebs: v.bytes.div_ceil(leb_size as u64) as u32,
            alignment: v.vol_alignment,
            data_pad,
            vol_type: match v.vol_type {
                VolType::Dynamic => UBI_VID_DYNAMIC,
                VolType::Static => UBI_VID_STATIC,
            },
            upd_marker: 0,
            name_len: v.vol_name.len() as u16,
            name: {
                let mut n = [0u8; 128];
                n[..v.vol_name.len()].copy_from_slice(v.vol_name.as_bytes());
                n
            },
            flags: match v.vol_flags {
                Some(VolFlags::Autoresize) => crate::ubi::UBI_VTBL_AUTORESIZE_FLG,
                Some(VolFlags::SkipCheck) => UBI_VTBL_SKIP_CRC_CHECK_FLG,
                None => 0,
            },
        };
    }

    // Volumes after the two layout PEBs, in configuration order.
    let mut out: Vec<u8> = vec![0xFF; 2 * peb];
    let ec = opts.ec;
    for v in vols {
        let data_pad = leb_size % v.vol_alignment;
        let usable = usable_leb(v.vol_alignment)?;
        let data = v.image.as_deref().unwrap_or(&[]);
        let mut pos = 0usize;
        let mut lnum = 0u32;
        while pos < data.len() {
            let len = usable.min(data.len() - pos);
            let vh = VidHeader {
                vol_type: match v.vol_type {
                    VolType::Dynamic => UBI_VID_DYNAMIC,
                    VolType::Static => UBI_VID_STATIC,
                },
                copy_flag: 0,
                compat: 0,
                vol_id: v.vol_id,
                lnum,
                data_size: if v.vol_type == VolType::Static {
                    len as u32
                } else {
                    0
                },
                used_ebs: if v.vol_type == VolType::Static {
                    data.len().div_ceil(usable) as u32
                } else {
                    0
                },
                data_pad,
                data_crc: if v.vol_type == VolType::Static {
                    crc32(&data[pos..pos + len])
                } else {
                    0
                },
            };
            write_peb(&mut out, &geom, opts, &vh, Some(&data[pos..pos + len]), ec);
            pos += len;
            lnum += 1;
        }
    }

    // The layout volume, last, into PEBs 0 and 1 (both with the same
    // EC; the VID carries compat = REJECT).
    let vtbl_bytes: Vec<u8> = vtbl.iter().flat_map(|r| r.to_bytes()).collect();
    for lnum in 0..2u32 {
        let vh = VidHeader {
            vol_type: UBI_VID_DYNAMIC,
            copy_flag: 0,
            compat: crate::ubi::UBI_COMPAT_REJECT,
            vol_id: UBI_LAYOUT_VOLUME_ID,
            lnum,
            data_size: 0,
            used_ebs: 0,
            data_pad: 0,
            data_crc: 0,
        };
        let base = lnum as usize * peb;
        let mut leb = vec![0xFF; peb];
        leb[data_offs..data_offs + vtbl_bytes.len()].copy_from_slice(&vtbl_bytes);
        write_peb_at(
            &mut out[base..base + peb],
            &geom,
            opts,
            &vh,
            &leb[data_offs..],
            ec,
        );
        let _ = vid_offs;
    }

    Ok(out)
}

/// Append one PEB to `out` (the volume write path of ubigen).
fn write_peb(
    out: &mut Vec<u8>,
    geom: &UbiGeometry,
    opts: &Options,
    vh: &VidHeader,
    data: Option<&[u8]>,
    ec: u64,
) {
    let peb = geom.peb_size as usize;
    let base = out.len();
    out.resize(base + peb, 0xFF);
    let data_offs = geom.data_offset as usize;
    let mut leb = vec![0xFF; peb];
    if let Some(d) = data {
        leb[data_offs..data_offs + d.len()].copy_from_slice(d);
    }
    write_peb_at(
        &mut out[base..base + peb],
        geom,
        opts,
        vh,
        &leb[data_offs..],
        ec,
    );
}

/// Fill one PEB buffer: EC header at 0, VID header at vid_hdr_offset,
/// payload at data_offset, 0xFF elsewhere.
fn write_peb_at(
    buf: &mut [u8],
    geom: &UbiGeometry,
    opts: &Options,
    vh: &VidHeader,
    leb_data: &[u8],
    ec: u64,
) {
    let peb = geom.peb_size as usize;
    debug_assert_eq!(buf.len(), peb);
    buf.fill(0xFF);
    let ec_hdr = crate::ubi::EcHeader {
        ec,
        vid_hdr_offset: geom.vid_hdr_offset,
        data_offset: geom.data_offset,
        image_seq: opts.image_seq,
    };
    buf[..UBI_EC_HDR_SIZE].copy_from_slice(&ec_hdr.to_bytes());
    let voff = geom.vid_hdr_offset as usize;
    buf[voff..voff + UBI_VID_HDR_SIZE].copy_from_slice(&vh.to_bytes());
    let doff = geom.data_offset as usize;
    buf[doff..doff + leb_data.len()].copy_from_slice(leb_data);
}
