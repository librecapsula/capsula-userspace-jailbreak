//! Backup directory: a legacy-compatible layout
//! (NN_<name>.img, .gpt.bin, partition_table.tsv, SHA256SUMS.txt,
//! SUCCESS.txt). Opening/verification — for the userdata overlay step.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("в {0} нет валидного бэкапа — сначала снимите дамп (backup)")]
    Missing(String),
    #[error("бэкап неполный: нет SUCCESS.txt (прерван?) — повторите дамп")]
    Incomplete,
    #[error("контрольные суммы: {0}")]
    Checksum(String),
    #[error("файл {path}: {reason}")]
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

    /// Backup directory name for a device serial (`backup/<dir_name>`).
    /// The serial is USB-reported and normally hex-ish; sanitize anyway.
    /// An empty serial maps to "unknown" — defensive only: bring_up
    /// refuses unidentified personas, so the CLI never writes there.
    pub fn dir_name(serial: &str) -> String {
        let s = sanitize(serial.trim());
        if s.is_empty() {
            "unknown".to_string()
        } else {
            s
        }
    }

    /// Is there a complete (SUCCESS.txt) and checksum-valid backup at
    /// `dir`? The cheap gate for "skip the dump, go straight to the
    /// userdata write".
    pub fn exists_verified(dir: &Path) -> bool {
        Self::open(dir).and_then(|s| s.verify()).is_ok()
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
    /// spaces + name) AND that the sums cover the whole partition map —
    /// an interrupted re-dump leaves stale SUCCESS.txt with partial
    /// sums, which must not pass as a valid backup. Fails on the first
    /// problem.
    pub fn verify(&self) -> Result<(), StoreError> {
        let sums = self.dir.join("SHA256SUMS.txt");
        if !sums.is_file() {
            return Err(StoreError::Checksum("нет SHA256SUMS.txt".into()));
        }
        let mut covered: std::collections::HashSet<String> = Default::default();
        for line in std::fs::read_to_string(&sums)?.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            let (hexpart, name) = line
                .split_once("  ")
                .ok_or_else(|| StoreError::Checksum(format!("битая строка: {line}")))?;
            let f = self.dir.join(name);
            if !f.is_file() {
                return Err(StoreError::Checksum(format!("нет файла из сумм: {name}")));
            }
            let got = file_sha256(&f)?;
            if got != hexpart.to_lowercase() {
                return Err(StoreError::Checksum(format!("SHA256 не сошёлся: {name}")));
            }
            covered.insert(name.to_string());
        }
        for (part, path) in self.files.iter() {
            let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !covered.contains(fname) {
                return Err(StoreError::Checksum(format!(
                    "нет суммы для раздела {part} — дамп неполный (прерван?)"
                )));
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn dir_name_sanitizes_serials() {
        assert_eq!(
            BackupStore::dir_name("01139EB3613ABD80"),
            "01139EB3613ABD80"
        );
        assert_eq!(
            BackupStore::dir_name("e5fe5a07c23ce39a"),
            "e5fe5a07c23ce39a"
        );
        assert_eq!(BackupStore::dir_name("../evil/serial"), ".._evil_serial");
        assert_eq!(BackupStore::dir_name("  "), "unknown");
        assert_eq!(BackupStore::dir_name(""), "unknown");
    }

    #[test]
    fn exists_verified_gates_on_success_and_checksums() {
        let tmp = std::env::temp_dir().join(format!("jb-store-ev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // empty dir -> false
        assert!(!BackupStore::exists_verified(&tmp));
        // SUCCESS but no sums -> false
        std::fs::write(tmp.join("SUCCESS.txt"), "SUCCESS").unwrap();
        assert!(!BackupStore::exists_verified(&tmp));
        // complete: one image + matching sum -> true
        let img = b"partition-bytes".to_vec();
        std::fs::write(tmp.join("01_sec.img"), &img).unwrap();
        let hex = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&img);
            hex::encode(h.finalize())
        };
        std::fs::write(tmp.join("SHA256SUMS.txt"), format!("{hex}  01_sec.img\n")).unwrap();
        assert!(BackupStore::exists_verified(&tmp));
        // corrupt the image -> false (checksum mismatch)
        std::fs::write(tmp.join("01_sec.img"), b"tampered").unwrap();
        assert!(!BackupStore::exists_verified(&tmp));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn stale_success_with_partial_sums_is_not_verified() {
        // interrupted re-dump scenario: SUCCESS.txt survived from an
        // earlier run, but the sums only cover part of the table — the
        // userdata image from the old dump must not be trusted
        let tmp = std::env::temp_dir().join(format!("jb-store-partial-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("SUCCESS.txt"), "SUCCESS").unwrap();
        std::fs::write(
            tmp.join("partition_table.tsv"),
            "1\tsec\t512\t1\n2\tdata\t513\t3\n",
        )
        .unwrap();
        let img1 = b"one".to_vec();
        std::fs::write(tmp.join("01_sec.img"), &img1).unwrap();
        std::fs::write(tmp.join("02_data.img"), b"old-userdata").unwrap();
        let hex = {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, &img1);
            hex::encode(h.finalize())
        };
        // only the FIRST partition made it into the sums
        std::fs::write(tmp.join("SHA256SUMS.txt"), format!("{hex}  01_sec.img\n")).unwrap();
        assert!(!BackupStore::exists_verified(&tmp));
        let _ = std::fs::remove_dir_all(&tmp);
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
