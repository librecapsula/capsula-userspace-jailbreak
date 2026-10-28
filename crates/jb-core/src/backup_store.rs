//! Backup directory: a layout byte-compatible with the bash v1
//! (NN_<name>.img, .gpt.bin, partition_table.tsv, SHA256SUMS.txt,
//! SUCCESS.txt). Opening/verification — for the userdata overlay step.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("no valid backup at {0} — run backup first")]
    Missing(String),
    #[error("backup is incomplete: no SUCCESS.txt (interrupted?) — rerun backup")]
    Incomplete,
    #[error("checksum: {0}")]
    Checksum(String),
    #[error("file {path}: {reason}")]
    Bad { path: PathBuf, reason: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Partition name -> image file (NN_<safe>.img).
#[derive(Debug, Clone)]
pub struct BackupStore {
    pub dir: PathBuf,
    files: BTreeMap<String, PathBuf>,
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect()
}

impl BackupStore {
    /// Partition image file name, legacy format.
    pub fn image_name(idx: u32, name: &str) -> String {
        format!("{:02}_{}.img", idx, sanitize(name))
    }

    /// Open an existing backup: SUCCESS.txt is mandatory; the file map
    /// comes from partition_table.tsv (if present) or the NN_*.img mask.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        if !dir.is_dir() {
            return Err(StoreError::Missing(dir.display().to_string()));
        }
        if !dir.join("SUCCESS.txt").is_file() {
            return Err(StoreError::Incomplete);
        }
        let mut files = BTreeMap::new();
        let tsv = dir.join("partition_table.tsv");
        if tsv.is_file() {
            for line in std::fs::read_to_string(&tsv)?.lines() {
                let mut it = line.split('\t');
                if let (Some(idx), Some(name)) = (it.next(), it.next()) {
                    if let (Ok(idx), Some(name)) = (idx.parse::<u32>(), it.next().map(|_| name)) {
                        let f = dir.join(Self::image_name(idx, name));
                        if f.is_file() {
                            files.insert(name.to_string(), f);
                        }
                    }
                }
            }
        } else {
            for e in std::fs::read_dir(dir)? {
                let p = e?.path();
                if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                    if n.ends_with(".img")
                        && n.len() >= 6
                        && n.as_bytes()[0].is_ascii_digit()
                        && n.as_bytes()[1].is_ascii_digit()
                        && n.as_bytes()[2] == b'_'
                    {
                        let part = n[3..n.len() - 4].to_string();
                        files.insert(part, p);
                    }
                }
            }
        }
        Ok(BackupStore {
            dir: dir.to_path_buf(),
            files,
        })
    }

    pub fn find(&self, partition: &str) -> Option<&Path> {
        self.files.get(partition).map(|v| v.as_path())
    }

    pub fn parts(&self) -> impl Iterator<Item = (&String, &PathBuf)> {
        self.files.iter()
    }

    /// Verify SHA256SUMS.txt (every line, sha256sum format: hex + two
    /// spaces + name). Fails on the first mismatch.
    pub fn verify(&self) -> Result<(), StoreError> {
        let sums = self.dir.join("SHA256SUMS.txt");
        if !sums.is_file() {
            return Err(StoreError::Checksum("no SHA256SUMS.txt".into()));
        }
        for line in std::fs::read_to_string(&sums)?.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            let (hexpart, name) = line
                .split_once("  ")
                .ok_or_else(|| StoreError::Checksum(format!("malformed line: {line}")))?;
            let f = self.dir.join(name);
            if !f.is_file() {
                return Err(StoreError::Checksum(format!(
                    "file from the sums is missing: {name}"
                )));
            }
            let got = file_sha256(&f)?;
            if got != hexpart.to_lowercase() {
                return Err(StoreError::Checksum(format!("SHA256 mismatch: {name}")));
            }
        }
        Ok(())
    }
}

/// SHA256 of a file, streamed.
pub fn file_sha256(path: &Path) -> Result<String, StoreError> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Append a line to SHA256SUMS.txt (sha256sum format).
pub fn append_sha256_line(dir: &Path, file_name: &str, hex: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("SHA256SUMS.txt"))?;
    writeln!(f, "{hex}  {file_name}")
}

/// A new capture owns its directory; it never reopens an older backup
/// for writing. Shared file operations, independent of GPT or NAND.
pub(crate) struct CaptureDirectory {
    path: PathBuf,
}

impl CaptureDirectory {
    pub(crate) fn create(parent: &Path, prefix: &str) -> std::io::Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        safe_capture_name(prefix)?;
        std::fs::create_dir_all(parent)?;
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _ in 0..64 {
            let path = parent.join(format!(
                "{prefix}-{time}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "cannot allocate capture directory",
        ))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn create_file(&self, name: &str) -> std::io::Result<std::fs::File> {
        safe_capture_name(name)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(self.path.join(name))
    }
    pub(crate) fn write_file(&self, name: &str, data: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        self.require_absent(name)?;
        let partial = format!("{name}.partial");
        let mut file = self.create_file(&partial)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        self.publish_partial(&partial, name)
    }
    pub(crate) fn replace_file(&self, name: &str, data: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        safe_capture_name(name)?;
        let temp = format!(".{name}.tmp");
        let mut file = self.create_file(&temp)?;
        let result = (|| {
            file.write_all(data)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(self.path.join(&temp), self.path.join(name))
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(self.path.join(&temp));
        }
        result
    }
    pub(crate) fn publish_partial(&self, partial: &str, name: &str) -> std::io::Result<()> {
        safe_capture_name(partial)?;
        self.require_absent(name)?;
        if !std::fs::symlink_metadata(self.path.join(partial))?
            .file_type()
            .is_file()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "capture source is not a regular file",
            ));
        }
        std::fs::rename(self.path.join(partial), self.path.join(name))
    }

    fn require_absent(&self, name: &str) -> std::io::Result<()> {
        safe_capture_name(name)?;
        match std::fs::symlink_metadata(self.path.join(name)) {
            Ok(_) => Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "capture file already exists",
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

pub(crate) fn safe_capture_name(name: &str) -> std::io::Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid capture filename",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CaptureParent(PathBuf);
    impl CaptureParent {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!("jb-capture-{}-{nonce}", std::process::id())))
        }
    }
    impl Drop for CaptureParent {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn capture_directories_and_files_are_exclusive() {
        let parent = CaptureParent::new();
        let first = CaptureDirectory::create(&parent.0, "amlogic").unwrap();
        let second = CaptureDirectory::create(&parent.0, "amlogic").unwrap();
        assert_ne!(first.path(), second.path());
        first.write_file("boot.bin", b"old").unwrap();
        assert!(first.write_file("boot.bin", b"new").is_err());
        assert_eq!(
            std::fs::read(first.path().join("boot.bin")).unwrap(),
            b"old"
        );
    }

    #[test]
    fn capture_manifest_replace_is_atomic_and_reusable() {
        let parent = CaptureParent::new();
        let capture = CaptureDirectory::create(&parent.0, "amlogic").unwrap();
        capture.replace_file("manifest.json", b"running").unwrap();
        capture.replace_file("manifest.json", b"failed").unwrap();
        assert_eq!(
            std::fs::read(capture.path().join("manifest.json")).unwrap(),
            b"failed"
        );
        assert_eq!(std::fs::read_dir(capture.path()).unwrap().count(), 1);
    }

    #[test]
    fn capture_filenames_cannot_escape_directory() {
        let parent = CaptureParent::new();
        let capture = CaptureDirectory::create(&parent.0, "amlogic").unwrap();
        for name in [
            "",
            ".",
            "..",
            "../outside",
            "/absolute",
            "nested/file",
            "windows\\file",
        ] {
            assert_eq!(
                capture.create_file(name).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(std::fs::read_dir(capture.path()).unwrap().count(), 0);
    }

    #[test]
    fn capture_partial_publish_never_clobbers_existing_file() {
        use std::io::Write;
        let parent = CaptureParent::new();
        let capture = CaptureDirectory::create(&parent.0, "amlogic").unwrap();
        capture.write_file("boot.bin", b"old").unwrap();
        let mut file = capture.create_file("boot.bin.partial").unwrap();
        file.write_all(b"new").unwrap();
        drop(file);
        assert!(capture
            .publish_partial("boot.bin.partial", "boot.bin")
            .is_err());
        assert_eq!(
            std::fs::read(capture.path().join("boot.bin")).unwrap(),
            b"old"
        );
        assert_eq!(
            std::fs::read(capture.path().join("boot.bin.partial")).unwrap(),
            b"new"
        );
    }

    #[test]
    fn capture_failed_manifest_replace_cleans_only_its_temp_file() {
        let parent = CaptureParent::new();
        let capture = CaptureDirectory::create(&parent.0, "amlogic").unwrap();
        std::fs::create_dir(capture.path().join("manifest.json")).unwrap();
        assert!(capture.replace_file("manifest.json", b"complete").is_err());
        assert!(capture.path().join("manifest.json").is_dir());
        assert!(!capture.path().join(".manifest.json.tmp").exists());
    }

    #[test]
    fn sanitize_matches_legacy() {
        // legacy: sed 's/[^A-Za-z0-9._-]/_/g' | cut -c1-80
        assert_eq!(sanitize("boot_a"), "boot_a");
        assert_eq!(sanitize("систем/ный:раздел"), "_________________"); // 17 chars
        assert_eq!(sanitize(&"x".repeat(100)).len(), 80);
    }

    #[test]
    fn image_name_format() {
        assert_eq!(BackupStore::image_name(3, "boot_a"), "03_boot_a.img");
        assert_eq!(BackupStore::image_name(11, "userdata"), "11_userdata.img");
    }

    #[test]
    fn open_requires_success_and_finds_parts() {
        let tmp = std::env::temp_dir().join(format!("jb-store-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // without SUCCESS.txt — Incomplete
        std::fs::write(tmp.join("11_userdata.img"), b"x").unwrap();
        assert!(matches!(
            BackupStore::open(&tmp),
            Err(StoreError::Incomplete)
        ));
        std::fs::write(tmp.join("SUCCESS.txt"), "SUCCESS").unwrap();
        std::fs::write(
            tmp.join("partition_table.tsv"),
            "11\tuserdata\t280992\t166463\n",
        )
        .unwrap();
        let st = BackupStore::open(&tmp).unwrap();
        assert!(st.find("userdata").is_some());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
