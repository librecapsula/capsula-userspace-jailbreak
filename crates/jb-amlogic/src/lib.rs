//! The amlogic platform (A113X, Capsula Mini late revisions, board
//! MRC02B): the domain (u-boot env capture, the checkpoint NAND
//! capture over the short download windows, the UBIFS data-image
//! repack, the chunked window write) plus the
//! [`jb_core::backend::Backend`] and [`jb_core::scenario::Platform`]
//! implementations that drive the shared scenario skeleton over this
//! hardware.
//!
//! The stock u-boot raises `1b8e:c003` at every power-on for ~450 ms;
//! the session caught inside lives while the work goes on (an identify
//! keepalive between chunks resets the idle timer) and dies on idle.
//! Every session death is a checkpoint: the capture resumes from the
//! manifest + `.partial` files, the write resumes after re-erasing the
//! unfinished tail. A warm cycle does not re-raise the gadget (measured
//! on a live board) — reconnecting means a power cycle.

pub mod capture;
pub mod data_image;
pub mod diag;
pub mod env;
pub mod platform;
pub mod write;
