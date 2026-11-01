//! The platform-agnostic jailbreak scenario. One skeleton drives the
//! flow — prepare (session + backup) → measure the data partition →
//! confirm → build the image → write → finish — and a platform fills in
//! the device-specific steps through the [`Platform`] trait. The CLI
//! backends implement the trait; the same skeleton also runs the
//! backup-only flow.
//!
//! Nothing is verified after the write on any platform (the write is
//! the last touching of the device), matching the established
//! rockchip flow.

use crate::overlay::{self, OverlayFile};
use crate::progress::ProgressFn;
use anyhow::{bail, Result};
use std::path::PathBuf;
use std::time::Duration;

/// Run modifiers, straight from the CLI flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct Params {
    /// Build the image from scratch even when a verified base exists
    /// (--format-userdata): the partition content does not survive.
    pub format_userdata: bool,
    /// Skip both the check and the capture of the backup (--no-backup).
    pub no_backup: bool,
    /// Deadline for the device to appear on the bus; None = wait forever.
    pub wait: Option<Duration>,
}

/// What [`Platform::prepare`] delivers: the device is up and the
/// backup decision is made.
pub struct Prepared {
    /// Verified capture of the data partition usable as the patch base.
    /// None = build from scratch (no capture, a capture that cannot
    /// serve as a base, or --no-backup).
    pub base: Option<PathBuf>,
    /// A new capture was taken this run (false = a verified capture for
    /// this column already existed, or none was taken).
    pub dumped: bool,
    /// The capture directory, for the backup-only report. None when no
    /// capture was considered (--no-backup).
    pub dir: Option<PathBuf>,
    /// The capture is fully intact; false = taken with caveats the
    /// platform warns about (the first-generation 0xCC mask, bad
    /// blocks...).
    pub complete: bool,
}

/// The write about to happen, as the confirmation prompt sees it. The
/// platform wording (filesystem, what survives) is baked into `mode`
/// by [`Platform::describe_write`].
pub struct WritePlan {
    /// The partition name as the platform calls it (userdata on
    /// rockchip, data on amlogic).
    pub partition: &'static str,
    /// Image size in bytes — exactly the partition size: the image must
    /// cover the partition and fit it.
    pub size: u64,
    /// The image is built from scratch: the current partition content
    /// does not survive.
    pub fresh: bool,
    /// --no-backup run.
    pub no_backup: bool,
    /// The plan restores the verified capture instead of writing a
    /// patched image (the confirm line says "восстановление").
    pub restore: bool,
    /// The full human description of the write mode.
    pub mode: String,
}

/// Confirmation callback: log the prompt and ask; an error aborts the
/// run before anything is written. Skipped entirely by the caller when
/// --yes is given.
pub type Confirm<'a> = &'a dyn Fn(&WritePlan) -> Result<()>;

/// The device-specific steps of the scenario, implemented by the CLI
/// backends over their transports. Every hook may talk to the device
/// (and, on amlogic, go through reconnect windows) — the skeleton only
/// fixes the order.
pub trait Platform {
    /// Bring the device into a working state and settle the backup:
    /// capture it (a checkpoint loop where the platform needs one) or
    /// find the verified capture of this column. `no_backup` skips both
    /// the check and the capture; the session the hooks run over is
    /// kept in the platform state.
    fn prepare(
        &mut self,
        no_backup: bool,
        wait: Option<Duration>,
        progress: ProgressFn,
    ) -> Result<Prepared>;

    /// Logical size of the data partition, bytes (the size the image
    /// must be built to).
    fn data_size(&mut self, progress: ProgressFn) -> Result<u64>;

    /// The partition name as the platform calls it (userdata on
    /// rockchip, data on amlogic) — for the confirmation line.
    fn data_partition(&self) -> &'static str;

    /// The write-mode description for the confirmation line.
    fn describe_write(&self, fresh: bool, no_backup: bool) -> String;

    /// The restore-mode description (writing the verified capture back
    /// over the current content) for the confirmation line.
    fn describe_restore(&self) -> String;

    /// Build the data partition image with the overlay files: EXACTLY
    /// `size` bytes, patching `base` when given (and `fresh` is false),
    /// from scratch otherwise.
    fn build_data_image(
        &self,
        base: Option<&std::path::Path>,
        out: &std::path::Path,
        size: u64,
        files: &[OverlayFile],
        progress: ProgressFn,
    ) -> Result<()>;

    /// Write the image built by [`Self::build_data_image`] to the
    /// device. The image is exactly the partition size; nothing is
    /// read back afterwards.
    fn write_data_image(&mut self, image: &std::path::Path, progress: ProgressFn) -> Result<()>;

    /// Reboot the device and print the platform's final instructions.
    fn finish(&mut self, progress: ProgressFn) -> Result<()>;

    /// The backup-only flow's result line (platform wording: what was
    /// captured, where, and the caveats).
    fn report_backup(&self, prepared: &Prepared);
}

/// The jailbreak flow over any platform. The overlay file set (adbd +
/// the gadget flag + the jailbreak marker) is platform-independent and
/// built here.
pub fn jailbreak(
    platform: &mut dyn Platform,
    params: &Params,
    confirm: Confirm,
    progress: ProgressFn,
) -> Result<()> {
    let prepared = platform.prepare(params.no_backup, params.wait, progress)?;
    let size = platform.data_size(progress)?;
    let fresh = params.format_userdata || params.no_backup || prepared.base.is_none();
    let plan = WritePlan {
        partition: platform.data_partition(),
        size,
        fresh,
        no_backup: params.no_backup,
        restore: false,
        mode: platform.describe_write(fresh, params.no_backup),
    };
    // Nothing has been written at this point, so a refusal is safe.
    confirm(&plan)?;

    let base = if fresh { None } else { prepared.base.as_deref() };
    let files = overlay::overlay_files(overlay_marker());
    let out = std::path::Path::new("work").join("userdata.img");
    platform.build_data_image(base, &out, size, &files, progress)?;
    platform.write_data_image(&out, progress)?;
    platform.finish(progress)?;
    Ok(())
}

/// The restore flow: write the verified capture of the data partition
/// back to the device — the exact inverse of the jailbreak's write
/// step. The overlay and everything written after the capture do not
/// survive; the capture's own content (session files included) does.
/// `--no-backup` is rejected by the CLI for this subcommand.
pub fn restore(
    platform: &mut dyn Platform,
    wait: Option<Duration>,
    confirm: Confirm,
    progress: ProgressFn,
) -> Result<()> {
    let prepared = platform.prepare(false, wait, progress)?;
    let Some(base) = prepared.base.as_deref() else {
        bail!(
            "восстановление невозможно: нет верифицированного захвата {} \
             для этой колонки{}; сначала снимите его — capsula-jb backup",
            platform.data_partition(),
            if prepared.complete {
                String::new()
            } else {
                String::from(" (захват этой колонки нецелостный — восстановить его нельзя)")
            }
        );
    };
    // Sanity: the capture must fit the partition as it is now.
    let size = platform.data_size(progress)?;
    let base_len = std::fs::metadata(base)?.len();
    if base_len > size {
        bail!(
            "захват {} ({} байт) больше текущего раздела ({} байт) — \
             бед-блоки прибавились, восстановление такого образа не влезет",
            base.display(),
            base_len,
            size
        );
    }
    let plan = WritePlan {
        partition: platform.data_partition(),
        size: base_len,
        fresh: false,
        no_backup: false,
        restore: true,
        mode: platform.describe_restore(),
    };
    // Nothing has been written at this point, so a refusal is safe.
    confirm(&plan)?;
    platform.write_data_image(base, progress)?;
    platform.finish(progress)?;
    Ok(())
}

/// The backup-only flow: prepare (session + capture, never writes to
/// the column) and report. `--no-backup` is rejected by the CLI for
/// this subcommand, so `no_backup` is always false here.
pub fn backup(
    platform: &mut dyn Platform,
    wait: Option<Duration>,
    progress: ProgressFn,
) -> Result<()> {
    let prepared = platform.prepare(false, wait, progress)?;
    platform.report_backup(&prepared);
    Ok(())
}

/// The jailbreak marker written into the overlay: the tool and the run
/// time, so a booted column can tell who unlocked it.
fn overlay_marker() -> String {
    format!("capsula-jb userspace {}\n", utc_now_iso())
}

/// The current UTC time as 2026-11-01T12:34:56Z (no external crates).
fn utc_now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, m, s) = (rem / 3600, (rem / 60) % 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::Progress;
    use std::cell::RefCell;
    use std::path::Path;

    /// A recording platform: every hook appends to `calls`; the
    /// configurable fields drive the skeleton's branches.
    struct MockPlatform {
        base: Option<PathBuf>,
        size: u64,
        calls: RefCell<Vec<&'static str>>,
        /// The base the build hook actually received.
        got_base: RefCell<Option<PathBuf>>,
        /// The image the write hook actually received.
        written_image: RefCell<Option<PathBuf>>,
    }

    impl MockPlatform {
        fn new(base: Option<PathBuf>) -> Self {
            MockPlatform {
                base,
                size: 4096,
                calls: RefCell::new(vec![]),
                got_base: RefCell::new(None),
                written_image: RefCell::new(None),
            }
        }

        fn mark(&self, what: &'static str) {
            self.calls.borrow_mut().push(what);
        }
    }

    impl Platform for MockPlatform {
        fn prepare(
            &mut self,
            no_backup: bool,
            _wait: Option<Duration>,
            _progress: ProgressFn,
        ) -> Result<Prepared> {
            self.mark("prepare");
            let base = if no_backup { None } else { self.base.clone() };
            Ok(Prepared {
                base,
                dumped: true,
                dir: self.base.as_ref().map(|b| b.parent().unwrap().to_path_buf()),
                complete: true,
            })
        }

        fn data_size(&mut self, _progress: ProgressFn) -> Result<u64> {
            self.mark("data_size");
            Ok(self.size)
        }

        fn data_partition(&self) -> &'static str {
            "testpart"
        }

        fn describe_write(&self, fresh: bool, _no_backup: bool) -> String {
            if fresh { "fresh" } else { "patch" }.to_string()
        }

        fn describe_restore(&self) -> String {
            "restore".to_string()
        }

        fn build_data_image(
            &self,
            base: Option<&Path>,
            _out: &Path,
            size: u64,
            _files: &[OverlayFile],
            _progress: ProgressFn,
        ) -> Result<()> {
            self.mark("build");
            assert_eq!(size, self.size);
            *self.got_base.borrow_mut() = base.map(|p| p.to_path_buf());
            Ok(())
        }

        fn write_data_image(&mut self, image: &Path, _progress: ProgressFn) -> Result<()> {
            self.mark("write");
            *self.written_image.borrow_mut() = Some(image.to_path_buf());
            Ok(())
        }

        fn finish(&mut self, _progress: ProgressFn) -> Result<()> {
            self.mark("finish");
            Ok(())
        }

        fn report_backup(&self, _prepared: &Prepared) {
            self.mark("report");
        }
    }

    fn noop(_ev: Progress) {}

    #[test]
    fn jailbreak_runs_hooks_in_order_and_confirms_before_any_write() {
        let base = PathBuf::from("/tmp/never/userdata.img");
        let mut p = MockPlatform::new(Some(base.clone()));
        jailbreak(
            &mut p,
            &Params::default(),
            &|plan| {
                assert_eq!((plan.size, plan.fresh, plan.no_backup), (4096, false, false));
                assert_eq!(plan.mode, "patch");
                Ok(())
            },
            &noop,
        )
        .unwrap();
        assert_eq!(
            *p.calls.borrow(),
            vec!["prepare", "data_size", "build", "write", "finish"]
        );
        assert_eq!(p.got_base.borrow().as_deref(), Some(base.as_path()));
    }

    #[test]
    fn jailbreak_builds_fresh_when_the_base_is_missing_or_disabled() {
        // no base at all
        let mut p = MockPlatform::new(None);
        jailbreak(&mut p, &Params::default(), &|_| Ok(()), &noop).unwrap();
        assert!(p.got_base.borrow().is_none());
        assert_eq!(*p.calls.borrow(), vec!["prepare", "data_size", "build", "write", "finish"]);

        // a base exists but --no-backup drops it
        let mut p = MockPlatform::new(Some(PathBuf::from("/tmp/never/u.img")));
        jailbreak(
            &mut p,
            &Params { no_backup: true, ..Default::default() },
            &|plan| {
                assert!(plan.fresh && plan.no_backup);
                Ok(())
            },
            &noop,
        )
        .unwrap();
        assert!(p.got_base.borrow().is_none());
    }

    #[test]
    fn jailbreak_stops_when_the_confirmation_refuses() {
        let mut p = MockPlatform::new(None);
        let err = jailbreak(&mut p, &Params::default(), &|_| anyhow::bail!("прервано"), &noop)
            .unwrap_err();
        assert_eq!(err.to_string(), "прервано");
        // nothing was built or written
        assert_eq!(*p.calls.borrow(), vec!["prepare", "data_size"]);
    }

    #[test]
    fn restore_writes_the_capture_back() {
        let base = std::env::temp_dir().join(format!("jb-scenario-r1-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let base = base.join("data.bin");
        std::fs::write(&base, b"capture").unwrap();
        let mut p = MockPlatform::new(Some(base.clone()));
        let confirmed = std::cell::RefCell::new(None);
        restore(&mut p, None, &|plan| {
            assert!(plan.restore);
            assert_eq!(plan.size, 7);
            *confirmed.borrow_mut() = Some(plan.mode.clone());
            Ok(())
        }, &noop)
        .unwrap();
        assert_eq!(confirmed.borrow().as_deref(), Some("restore"));
        assert_eq!(
            *p.calls.borrow(),
            vec!["prepare", "data_size", "write", "finish"]
        );
        assert_eq!(p.written_image.borrow().as_deref(), Some(base.as_path()));
    }

    #[test]
    fn restore_without_a_base_refuses() {
        let mut p = MockPlatform::new(None);
        let err = restore(&mut p, None, &|_| Ok(()), &noop).unwrap_err();
        assert!(err.to_string().contains("восстановление невозможно"), "{err}");
        // nothing was written
        assert_eq!(*p.calls.borrow(), vec!["prepare"]);
    }

    #[test]
    fn restore_stops_when_the_confirmation_refuses() {
        let base = std::env::temp_dir().join(format!("jb-scenario-r2-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let base = base.join("data.bin");
        std::fs::write(&base, b"capture").unwrap();
        let mut p = MockPlatform::new(Some(base));
        let err = restore(&mut p, None, &|_| anyhow::bail!("прервано"), &noop).unwrap_err();
        assert_eq!(err.to_string(), "прервано");
        assert_eq!(*p.calls.borrow(), vec!["prepare", "data_size"]);
    }

    #[test]
    fn backup_reports_and_never_writes() {
        let mut p = MockPlatform::new(Some(PathBuf::from("/tmp/never/cap/userdata.img")));
        backup(&mut p, None, &noop).unwrap();
        assert_eq!(*p.calls.borrow(), vec!["prepare", "report"]);
    }
}
