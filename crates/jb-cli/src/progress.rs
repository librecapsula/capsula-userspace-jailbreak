//! CLI progress: step lines to stdout, partitions as indicatif bars.

use indicatif::{ProgressBar, ProgressStyle};
use jb_core::session::Progress;
use std::cell::RefCell;

pub struct CliProgress {
    bar: RefCell<Option<ProgressBar>>,
}

impl CliProgress {
    pub fn new() -> Self {
        CliProgress {
            bar: RefCell::new(None),
        }
    }

    pub fn handle(&self, p: Progress) {
        match p {
            Progress::Step(msg) => {
                self.finish_bar();
                println!("{msg}");
            }
            Progress::TransferStart { name, bytes } => {
                self.finish_bar();
                let pb = ProgressBar::new(bytes);
                pb.set_style(
                    ProgressStyle::with_template(
                        "{msg} [{elapsed_precise}] {bar:30.cyan/blue} {bytes}/{total_bytes}",
                    )
                    .unwrap(),
                );
                pb.set_message(name);
                *self.bar.borrow_mut() = Some(pb);
            }
            Progress::PartitionStart { name, sectors } => {
                self.finish_bar();
                let pb = ProgressBar::new(sectors);
                pb.set_style(
                    ProgressStyle::with_template(
                        "{msg} [{elapsed_precise}] {bar:30.cyan/blue} {pos}/{len} sectors",
                    )
                    .unwrap(),
                );
                pb.set_message(name);
                *self.bar.borrow_mut() = Some(pb);
            }
            Progress::PartitionProgress { done, total, .. }
            | Progress::TransferProgress { done, total, .. } => {
                if let Some(b) = self.bar.borrow().as_ref() {
                    b.set_position(done.min(total));
                }
            }
            Progress::PartitionDone { .. } | Progress::TransferDone { .. } => {
                self.finish_bar();
            }
        }
    }

    fn finish_bar(&self) {
        if let Some(b) = self.bar.borrow_mut().take() {
            b.finish_and_clear();
        }
    }
}

impl Default for CliProgress {
    fn default() -> Self {
        Self::new()
    }
}
