//! The filesystem tree: the input for mkfs and the result of extraction
//! when reading. The metadata mirrors the fields of a UBIFS inode node.

use crate::error::{Error, Result};
use crate::media::{
    UBIFS_ITYPE_BLK, UBIFS_ITYPE_CHR, UBIFS_ITYPE_DIR, UBIFS_ITYPE_FIFO, UBIFS_ITYPE_LNK,
    UBIFS_ITYPE_REG, UBIFS_ITYPE_SOCK,
};

/// The object type plus its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// A regular file.
    File(Vec<u8>),
    /// A directory (children in insertion order — like readdir order at
    /// mkfs time).
    Dir(Vec<(String, Inode)>),
    /// A symbolic link (the target, ≤ `UBIFS_MAX_INO_DATA` bytes).
    Symlink(Vec<u8>),
    /// A device node (block or character, per the mode's S_IFMT bits).
    Dev {
        /// The device number in `makedev` encoding.
        rdev: u64,
    },
    /// A FIFO.
    Fifo,
    /// A unix socket.
    Socket,
}

/// A filesystem object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inode {
    /// The full mode with S_IFMT (for directories/files the `Kind` is
    /// enough and 0o755/0o644-style values suffice; the S_IFMT constant
    /// is filled in automatically).
    pub mode: u32,
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Access time, seconds.
    pub atime_sec: i64,
    /// Creation time, seconds.
    pub ctime_sec: i64,
    /// Modification time, seconds.
    pub mtime_sec: i64,
    /// Access time, nanoseconds.
    pub atime_nsec: u32,
    /// Creation time, nanoseconds.
    pub ctime_nsec: u32,
    /// Modification time, nanoseconds.
    pub mtime_nsec: u32,
    /// The object type and content.
    pub kind: Kind,
}

impl Inode {
    /// A directory with mode `mode` (without S_IFMT).
    pub fn dir(mode: u32, children: Vec<(String, Inode)>) -> Inode {
        Inode {
            mode: (mode & 0o7777) | 0o040000,
            uid: 0,
            gid: 0,
            atime_sec: 0,
            ctime_sec: 0,
            mtime_sec: 0,
            atime_nsec: 0,
            ctime_nsec: 0,
            mtime_nsec: 0,
            kind: Kind::Dir(children),
        }
    }

    /// A file with mode `mode` (without S_IFMT).
    pub fn file(mode: u32, data: Vec<u8>) -> Inode {
        Inode {
            mode: (mode & 0o7777) | 0o100000,
            uid: 0,
            gid: 0,
            atime_sec: 0,
            ctime_sec: 0,
            mtime_sec: 0,
            atime_nsec: 0,
            ctime_nsec: 0,
            mtime_nsec: 0,
            kind: Kind::File(data),
        }
    }

    /// A symbolic link.
    pub fn symlink(target: impl Into<Vec<u8>>) -> Inode {
        Inode {
            mode: 0o120777,
            uid: 0,
            gid: 0,
            atime_sec: 0,
            ctime_sec: 0,
            mtime_sec: 0,
            atime_nsec: 0,
            ctime_nsec: 0,
            mtime_nsec: 0,
            kind: Kind::Symlink(target.into()),
        }
    }

    /// Set all three timestamps to `t` (seconds).
    pub fn with_times(mut self, t: i64) -> Inode {
        self.atime_sec = t;
        self.ctime_sec = t;
        self.mtime_sec = t;
        self
    }

    /// Set all three timestamps (`sec`, `nsec`).
    pub fn with_times_nsec(mut self, sec: i64, nsec: u32) -> Inode {
        self.atime_sec = sec;
        self.ctime_sec = sec;
        self.mtime_sec = sec;
        self.atime_nsec = nsec;
        self.ctime_nsec = nsec;
        self.mtime_nsec = nsec;
        self
    }

    /// The on-flash type (`UBIFS_ITYPE_*`).
    pub fn itype(&self) -> u8 {
        match self.kind {
            Kind::File(_) => UBIFS_ITYPE_REG,
            Kind::Dir(_) => UBIFS_ITYPE_DIR,
            Kind::Symlink(_) => UBIFS_ITYPE_LNK,
            Kind::Fifo => UBIFS_ITYPE_FIFO,
            Kind::Socket => UBIFS_ITYPE_SOCK,
            Kind::Dev { .. } => {
                // CHR/BLK are told apart by the mode.
                if self.mode & 0o170000 == 0o060000 {
                    UBIFS_ITYPE_BLK
                } else {
                    UBIFS_ITYPE_CHR
                }
            }
        }
    }

    /// Recursively validate names (≤ 255 bytes, no '/' and no NUL) and
    /// inline data sizes.
    pub fn validate(&self) -> Result<()> {
        fn walk(name: &str, ino: &Inode) -> Result<()> {
            let bytes = name.as_bytes();
            if bytes.len() > crate::media::UBIFS_MAX_NLEN {
                return Err(Error::Overflow(format!(
                    "name '{name}' is longer than 255 bytes"
                )));
            }
            if bytes.contains(&b'/') || bytes.contains(&0) {
                return Err(Error::Other(format!("invalid character in name '{name}'")));
            }
            match &ino.kind {
                Kind::Dir(children) => {
                    for (n, c) in children {
                        walk(n, c)?;
                    }
                }
                Kind::Symlink(target) if target.len() > crate::media::UBIFS_MAX_INO_DATA => {
                    return Err(Error::Overflow("symlink target is too long".into()));
                }
                _ => {}
            }
            Ok(())
        }
        // The root is always a directory without a name.
        if !matches!(self.kind, Kind::Dir(_)) {
            return Err(Error::Other("fs root must be a directory".into()));
        }
        for (n, c) in match &self.kind {
            Kind::Dir(children) => children,
            _ => unreachable!(),
        } {
            walk(n, c)?;
        }
        Ok(())
    }
}
