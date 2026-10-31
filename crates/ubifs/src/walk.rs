//! Building a [`Plan`] (the mkfs input model) — from an in-memory tree
//! or by walking a real directory, mkfs.ubifs `-r DIR` style.

use crate::error::{Error, Result};
use crate::tree::{Inode, Kind};

/// The mkfs input: a tree plus the hard-link structure that a tree
/// alone cannot express.
///
/// Fields are plain data — build one by hand, with [`Plan::from_tree`]
/// or with [`from_directory`], then feed it to
/// [`mkfs_plan`](crate::mkfs::mkfs_plan).
#[derive(Debug, Clone)]
pub struct Plan {
    /// The tree; hard-linked files appear once (at the first occurrence)
    /// and later occurrences are [`Kind::Hardlink`] markers.
    pub root: Inode,
    /// The deferred (hard-linked) files. mkfs.ubifs writes their content
    /// after the whole tree walk, ordered by `order_key`.
    pub link_groups: Vec<LinkGroup>,
}

/// One hard-linked file (or any file with `st_nlink > 1`, which mkfs.ubifs
/// always defers): where its first occurrence lives and when to write it.
#[derive(Debug, Clone)]
pub struct LinkGroup {
    /// The tree path of the first occurrence, e.g. `["usr", "bin",
    /// "tool"]`.
    pub tree_path: Vec<String>,
    /// The number of links *inside* the image (mkfs.ubifs counts
    /// `use_nlink` the same way).
    pub nlink: u32,
    /// The write-order key. `from_directory` encodes mkfs.ubifs's hash
    /// table walk — bucket `host inode % 10099` ascending, and inside a
    /// bucket the reverse insertion order (`(bucket << 32) | (u32::MAX -
    /// seq)`); extraction-based plans use the original on-flash node
    /// order directly. Groups are written in ascending key order.
    pub order_key: u64,
}

impl Plan {
    /// A plan without hard links.
    pub fn from_tree(root: Inode) -> Plan {
        Plan {
            root,
            link_groups: Vec::new(),
        }
    }
}

/// Options of [`from_directory`].
#[derive(Debug, Clone, Default)]
pub struct WalkOptions {
    /// Make every object owned by root (mkfs.ubifs `-U`).
    pub squash_uids: bool,
    /// Read extended attributes of the source files (`user.*` etc.)
    /// into [`Inode::xattrs`]. Requires the `xattr` feature; mkfs.ubifs
    /// does this by default when built `WITH_XATTR`.
    pub xattrs: bool,
}

/// The mkfs.ubifs inum hash table size (`HASH_TABLE_SIZE`); the deferred
/// content write order derives from it.
pub const HASH_TABLE_SIZE: u64 = 10099;

/// Walk a directory tree, mkfs.ubifs `-r` style: metadata from lstat,
/// file contents read block-wise (holes are handled at mkfs time),
/// symlinks/devices/fifos/sockets preserved, hard links deduplicated
/// into [`Plan::link_groups`] (any non-directory with `st_nlink > 1` is
/// deferred, exactly like mkfs.ubifs).
///
/// Note: mkfs.ubifs writes timestamps without nanoseconds and this
/// walker mirrors that. Directory traversal follows `readdir` order of
/// the host filesystem, like mkfs.ubifs — build the image on the same
/// machine/filesystem for reproducibility.
///
/// Unix-only.
#[cfg(unix)]
pub fn from_directory(root: &std::path::Path, opts: &WalkOptions) -> Result<Plan> {
    use std::collections::HashMap;
    use std::os::unix::fs::MetadataExt;

    struct Ctx {
        squash: bool,
        xattrs: bool,
        /// (dev, ino) → (first tree path, group index).
        seen: HashMap<(u64, u64), (Vec<String>, usize)>,
        groups: Vec<(Vec<String>, u32, u64 /*host ino*/, u32 /*seq*/)>,
        seq: u32,
    }

    fn meta_to_inode(md: &std::fs::Metadata, ctx: &Ctx, path: &std::path::Path) -> Inode {
        let kind = match md.mode() & 0o170000 {
            0o040000 => Kind::Dir(Vec::new()),
            0o100000 => Kind::File(Vec::new()),
            0o120000 => Kind::Symlink(
                std::fs::read_link(path)
                    .map(|p| p.to_string_lossy().into_owned().into_bytes())
                    .unwrap_or_default(),
            ),
            0o020000 | 0o060000 => Kind::Dev { rdev: md.rdev() },
            0o010000 => Kind::Fifo,
            0o140000 => Kind::Socket,
            _ => Kind::File(Vec::new()),
        };
        let mut ino = Inode::with_kind(md.mode(), kind);
        // mkfs.ubifs zeroes the nanoseconds.
        ino.atime_sec = md.atime();
        ino.ctime_sec = md.ctime();
        ino.mtime_sec = md.mtime();
        ino.atime_nsec = 0;
        ino.ctime_nsec = 0;
        ino.mtime_nsec = 0;
        ino.nlink = md.nlink() as u32;
        if ctx.squash {
            ino.uid = 0;
            ino.gid = 0;
        } else {
            ino.uid = md.uid();
            ino.gid = md.gid();
        }
        if ctx.xattrs {
            ino.xattrs = read_xattrs(path);
        }
        ino
    }

    #[cfg(feature = "xattr")]
    fn read_xattrs(path: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        // llistxattr order, like mkfs.ubifs.
        for name in xattr::list(path).unwrap_or_default() {
            let name = name.to_string_lossy().into_owned();
            if name == "user.image-inode-number" {
                // Host-side mkfs.ubifs bookkeeping; not image content.
                continue;
            }
            if let Some(v) = xattr::get(path, &name).unwrap_or_default() {
                out.push((name, v));
            }
        }
        out
    }
    #[cfg(not(feature = "xattr"))]
    fn read_xattrs(_path: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        Vec::new()
    }

    fn walk(dir: &std::path::Path, path: &[String], ctx: &mut Ctx) -> Result<Inode> {
        let md = std::fs::metadata(dir)
            .map_err(|e| Error::Other(format!("cannot stat {}: {e}", dir.display())))?;
        if !md.is_dir() {
            return Err(Error::Other(format!(
                "{} is not a directory",
                dir.display()
            )));
        }
        let mut ino = meta_to_inode(&md, ctx, dir);
        let mut children: Vec<(String, Inode)> = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(|e| Error::Other(format!("read_dir: {e}")))? {
            let entry = entry.map_err(|e| Error::Other(format!("readdir: {e}")))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "." || name == ".." {
                continue;
            }
            let mut child_path = path.to_vec();
            child_path.push(name.clone());
            let full = dir.join(&name);
            let cmd = std::fs::symlink_metadata(&full)
                .map_err(|e| Error::Other(format!("lstat {}: {e}", full.display())))?;

            if cmd.is_dir() {
                let child = walk(&full, &child_path, ctx)?;
                children.push((name, child));
                continue;
            }

            // A non-directory: hard-link detection on (dev, ino).
            let key = (cmd.dev(), cmd.ino());
            if cmd.nlink() > 1 {
                ctx.seq += 1;
                if let Some((first_path, group_idx)) = ctx.seen.get(&key).cloned() {
                    ctx.groups[group_idx].1 += 1;
                    children.push((
                        name,
                        Inode::with_kind(cmd.mode(), Kind::Hardlink { target: first_path }),
                    ));
                    continue;
                }
                let idx = ctx.groups.len();
                ctx.seen.insert(key, (child_path.clone(), idx));
                ctx.groups.push((child_path.clone(), 1, cmd.ino(), ctx.seq));
            }

            let mut child = meta_to_inode(&cmd, ctx, &full);
            if let Kind::File(_) = &child.kind {
                let data = std::fs::read(&full)
                    .map_err(|e| Error::Other(format!("read {}: {e}", full.display())))?;
                child.kind = Kind::File(data);
            }
            children.push((name, child));
        }
        ino.kind = Kind::Dir(children);
        Ok(ino)
    }

    let mut ctx = Ctx {
        squash: opts.squash_uids,
        xattrs: opts.xattrs,
        seen: HashMap::new(),
        groups: Vec::new(),
        seq: 0,
    };
    let root_ino = walk(root, &[], &mut ctx)?;
    // mkfs.ubifs hash-table walk order: bucket = host ino % 10099
    // ascending, inside a bucket the reverse insertion order.
    let link_groups = ctx
        .groups
        .into_iter()
        .map(|(tree_path, nlink, host_ino, seq)| LinkGroup {
            tree_path,
            nlink,
            order_key: ((host_ino % HASH_TABLE_SIZE) << 32) | (u32::MAX - seq) as u64,
        })
        .collect();
    Ok(Plan {
        root: root_ino,
        link_groups,
    })
}
