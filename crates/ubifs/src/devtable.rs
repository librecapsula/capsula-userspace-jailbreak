//! The mkfs.ubifs device table (`-D/--devtable=FILE`): a way to create
//! nodes the source tree does not have and to override ownership/mode
//! of the ones it has.
//!
//! Each line is
//! `path type mode uid gid major minor start inc count` (whitespace
//! separated, `#` comments), where type is one of `f` (regular file —
//! override only), `d` (directory), `c`/`b` (character/block device),
//! `p` (FIFO) and `l` (symlink). With `count > 1` the name gets a
//! running number appended and the minor device number advances by
//! `inc` per entry.

use crate::error::{Error, Result};
use crate::tree::{Inode, Kind};
use crate::walk::Plan;

/// The entry type of a device-table line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevKind {
    /// A regular file — may only override attributes, never create.
    File,
    /// A directory.
    Dir,
    /// A character device.
    Char,
    /// A block device.
    Block,
    /// A FIFO.
    Fifo,
    /// A symbolic link (created with the decimal `minor` as its target,
    /// like mkfs.ubifs).
    Symlink,
}

/// One parsed device-table line.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Absolute path inside the image (leading `/`, no trailing `/`, no
    /// `.`/`..` components).
    pub path: String,
    /// The entry type.
    pub kind: DevKind,
    /// Mode with or without S_IFMT (mkfs.ubifs expects plain 0xxx).
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Device major number.
    pub major: u32,
    /// Device minor number (start of the series when `count > 1`).
    pub minor: u32,
    /// Series start number.
    pub start: u32,
    /// Minor increment per series step.
    pub inc: u32,
    /// Series length.
    pub count: u32,
}

/// Parse a device table (the whole file as text).
pub fn parse(text: &str) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let bad = || Error::Other(format!("bad device table line {}: {raw:?}", n + 1));
        if f.len() != 10 {
            return Err(bad());
        }
        let path = f[0].to_string();
        if !path.starts_with('/') || path.ends_with('/') || path.contains("//") {
            return Err(Error::Other(format!(
                "bad path {path:?} (must be absolute, without trailing '/')"
            )));
        }
        if path.split('/').any(|c| c == "." || c == "..") {
            return Err(Error::Other(format!(
                "bad path {path:?} ('.'/'..' not allowed)"
            )));
        }
        let kind = match f[1] {
            "f" => DevKind::File,
            "d" => DevKind::Dir,
            "c" => DevKind::Char,
            "b" => DevKind::Block,
            "p" => DevKind::Fifo,
            "l" => DevKind::Symlink,
            _ => return Err(bad()),
        };
        let num = |s: &str| -> Result<u32> {
            if let Some(hex) = s.strip_suffix('h').or_else(|| s.strip_suffix('H')) {
                u32::from_str_radix(hex, 16).map_err(|_| bad())
            } else {
                s.parse::<u32>().map_err(|_| bad())
            }
        };
        let mode =
            u32::from_str_radix(f[2].trim_start_matches('0').max("0"), 8).map_err(|_| bad())?;
        if mode > 0o7777 {
            return Err(bad());
        }
        if kind == DevKind::Symlink && mode != 0o777 {
            return Err(Error::Other(format!(
                "line {}: symlink mode must be 0777",
                n + 1
            )));
        }
        out.push(Entry {
            path,
            kind,
            mode,
            uid: num(f[3])?,
            gid: num(f[4])?,
            major: num(f[5])?,
            minor: num(f[6])?,
            start: num(f[7])?,
            inc: num(f[8])?,
            count: num(f[9])?,
        });
    }
    Ok(out)
}

/// One expanded device-table record (a series line yields many).
#[derive(Debug, Clone)]
pub struct Create {
    /// The components of the absolute path, e.g. `["dev", "tty0"]`.
    pub components: Vec<String>,
    /// Entry type.
    pub kind: DevKind,
    /// Mode (plain, without S_IFMT).
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Device major.
    pub major: u32,
    /// Device minor.
    pub minor: u32,
}

/// Expand a parsed table into concrete records (`count > 1` becomes a
/// series `nameN` with the minor advancing by `inc`).
pub fn expand(entries: &[Entry]) -> Result<Vec<Create>> {
    let mut out = Vec::new();
    for e in entries {
        let comps: Vec<String> = e
            .path
            .trim_start_matches('/')
            .split('/')
            .map(String::from)
            .collect();
        if comps.is_empty() || comps[0].is_empty() {
            return Err(Error::Other(format!("bad path {:?}", e.path)));
        }
        let (base, dir_comps) = comps.split_last().unwrap();
        if e.count > 1 && e.kind != DevKind::File {
            for i in 0..e.count {
                let n = e.start + i;
                let minor = e.minor + i * e.inc;
                let mut c = dir_comps.to_vec();
                c.push(format!("{base}{n}"));
                out.push(Create {
                    components: c,
                    kind: e.kind,
                    mode: e.mode,
                    uid: e.uid,
                    gid: e.gid,
                    major: e.major,
                    minor,
                });
            }
            continue;
        }
        let mut c = dir_comps.to_vec();
        c.push(base.to_string());
        out.push(Create {
            components: c,
            kind: e.kind,
            mode: e.mode,
            uid: e.uid,
            gid: e.gid,
            major: e.major,
            minor: e.minor,
        });
    }
    Ok(out)
}

/// Apply an expanded table to a [`Plan`]: override the attributes of
/// existing nodes (never of existing device nodes) and create missing
/// directories/devices/FIFOs. Created nodes inherit the timestamps
/// `root_times`, like mkfs.ubifs copies the root `stat` into
/// device-table entries.
pub fn apply(plan: &mut Plan, creates: &[Create], root_times: (i64, i64, i64)) -> Result<()> {
    for c in creates {
        // Navigate to the parent, creating intermediate directories as
        // root-owned 0755.
        let mut node = &mut plan.root;
        let (last, parents) = c.components.split_last().unwrap();
        for p in parents {
            let children = match &mut node.kind {
                Kind::Dir(ch) => ch,
                _ => {
                    return Err(Error::Other(format!(
                        "device table path {} collides with a non-directory",
                        c.components.join("/")
                    )))
                }
            };
            let idx = match children.iter().position(|(n, _)| n == p) {
                Some(i) => i,
                None => {
                    children.push((
                        p.clone(),
                        Inode::with_kind(0o040755, Kind::Dir(Vec::new()))
                            .with_times_nsec(root_times.0, 0),
                    ));
                    children.len() - 1
                }
            };
            node = &mut children[idx].1;
        }
        let name = last.clone();
        let children = match &mut node.kind {
            Kind::Dir(ch) => ch,
            _ => {
                return Err(Error::Other(format!(
                    "device table path {} collides with a non-directory",
                    c.components.join("/")
                )))
            }
        };
        match children.iter().position(|(n, _)| *n == name) {
            Some(i) => {
                let existing = &mut children[i].1;
                // mkfs.ubifs never overrides attributes of existing
                // device nodes.
                if matches!(existing.kind, Kind::Dev { .. }) {
                    continue;
                }
                existing.uid = c.uid;
                existing.gid = c.gid;
                if c.kind != DevKind::File {
                    // A type change (e.g. creating a FIFO over an
                    // existing regular file) is allowed for the
                    // non-override kinds in mkfs.ubifs only when the
                    // node does not exist; here keep the existing kind
                    // and only patch the mode.
                    existing.mode = (existing.mode & 0o170000) | (c.mode & 0o7777);
                } else {
                    existing.mode = (existing.mode & 0o170000) | (c.mode & 0o7777);
                }
            }
            None => {
                if c.kind == DevKind::File {
                    return Err(Error::Other(format!(
                        "device table cannot create regular file {}",
                        c.components.join("/")
                    )));
                }
                let kind = match c.kind {
                    DevKind::Dir => Kind::Dir(Vec::new()),
                    // glibc makedev encoding, as mkfs.ubifs writes it.
                    DevKind::Char | DevKind::Block => Kind::Dev {
                        rdev: makedev(c.major, c.minor),
                    },
                    DevKind::Fifo => Kind::Fifo,
                    DevKind::Symlink => Kind::Symlink(format!("{}", c.minor).into_bytes()),
                    DevKind::File => unreachable!(),
                };
                let mode = match c.kind {
                    DevKind::Dir => 0o040000 | (c.mode & 0o7777),
                    DevKind::Char => 0o020000 | (c.mode & 0o7777),
                    DevKind::Block => 0o060000 | (c.mode & 0o7777),
                    DevKind::Fifo => 0o010000 | (c.mode & 0o7777),
                    DevKind::Symlink => 0o120777,
                    DevKind::File => unreachable!(),
                };
                let ino = Inode::with_kind(mode, kind).with_times_nsec(root_times.0, 0);
                let ino = Inode {
                    uid: c.uid,
                    gid: c.gid,
                    ..ino
                };
                children.push((name, ino));
            }
        }
    }
    Ok(())
}

/// The glibc `makedev` encoding (`((minor & 0xff) | ((major & 0xfff) <<
/// 8) | ((minor & !0xff) << 12) | ((major & !0xfff) << 32))`).
pub fn makedev(major: u32, minor: u32) -> u64 {
    let major = major as u64;
    let minor = minor as u64;
    (minor & 0xff)
        | ((major & 0xfff) << 8)
        | ((minor & !0xffu64) << 12)
        | ((major & !0xfffu64) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lines_and_series() {
        let tbl =
            parse("# a comment\n/dev/null c 666 0 0 1 3 0 0 0\n/dev/tty c 622 0 0 5 0 0 1 3\n")
                .unwrap();
        assert_eq!(tbl.len(), 2);
        assert_eq!(tbl[0].kind, DevKind::Char);
        assert_eq!(tbl[0].major, 1);
        assert_eq!(tbl[0].minor, 3);

        let ex = expand(&tbl).unwrap();
        // The second line expands into tty0..tty2 with minors 0,1,2.
        let ttys: Vec<&Create> = ex
            .iter()
            .filter(|c| c.components.last().unwrap() == "tty0")
            .collect();
        assert_eq!(ttys.len(), 1);
        let all: Vec<&str> = ex
            .iter()
            .map(|c| c.components.last().unwrap().as_str())
            .collect();
        assert!(all.contains(&"tty1") && all.contains(&"tty2"));
    }

    #[test]
    fn rejects_bad_lines() {
        assert!(parse("no-slash f 644 0 0 0 0 0 0 0").is_err());
        assert!(parse("/a/../b d 755 0 0 0 0 0 0 0").is_err());
        assert!(parse("/a q 755 0 0 0 0 0 0 0").is_err());
        assert!(parse("/a f 644 0 0 0 0 0 0").is_err());
    }

    #[test]
    fn applies_creates_and_overrides() {
        let plan = &mut Plan::from_tree(Inode::dir(
            0o755,
            vec![(
                "etc".into(),
                Inode::dir(
                    0o755,
                    vec![("conf".into(), Inode::file(0o600, b"x".to_vec()))],
                ),
            )],
        ));
        let entries =
            parse("/dev/nullc c 666 0 0 1 3 0 0 0\n/etc/conf f 644 1000 100 0 0 0 0 0\n").unwrap();
        apply(plan, &expand(&entries).unwrap(), (1700000000, 0, 0)).unwrap();

        let Kind::Dir(root) = &plan.root.kind else {
            panic!()
        };
        let dev = root.iter().find(|(n, _)| n == "dev").unwrap();
        let Kind::Dir(dev_children) = &dev.1.kind else {
            panic!()
        };
        let nullc = &dev_children.iter().find(|(n, _)| n == "nullc").unwrap().1;
        assert!(matches!(nullc.kind, Kind::Dev { rdev: 259 })); // makedev(1,3)
        assert_eq!(nullc.mode, 0o020666);

        let etc = root.iter().find(|(n, _)| n == "etc").unwrap();
        let Kind::Dir(etc_children) = &etc.1.kind else {
            panic!()
        };
        let conf = &etc_children.iter().find(|(n, _)| n == "conf").unwrap().1;
        assert_eq!(conf.uid, 1000);
        assert_eq!(conf.gid, 100);
        assert_eq!(conf.mode & 0o7777, 0o644);
    }

    #[test]
    fn makedev_glibc_encoding() {
        assert_eq!(makedev(1, 3), 259); // /dev/null
        assert_eq!(makedev(1, 5), 261); // /dev/console
        assert_eq!(makedev(7, 0), 0x700);
        assert_eq!(makedev(254, 4096), (4096u64 << 12) | (254 << 8));
    }
}
