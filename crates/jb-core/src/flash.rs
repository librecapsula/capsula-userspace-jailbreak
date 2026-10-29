//! Flashing a partition back to the device. The only operation of the
//! tool that writes to flash: userdata (unsigned, freely rewritable).
//! Partition addresses come from the device GPT.

use crate::backup::CHUNK_SECTORS;
use crate::gpt::Gpt;
use crate::session::{Progress, ProgressFn};
use rockusb::loader::LoaderSession;
use rockusb::{Error as UsbError, Transport};
use std::path::Path;

/// Write an image into a partition: the image is zero-padded up to the
/// partition size. An image larger than the partition is an error.
/// The write is chunked so progress reporting works during the transfer.
pub fn write_partition_padded<T: Transport>(
    s: &mut LoaderSession<T>,
    gpt: &Gpt,
    part: &str,
    image: &Path,
    progress: ProgressFn,
) -> rockusb::Result<()> {
    let e = gpt
        .find(part)
        .ok_or_else(|| UsbError::Loader(format!("в GPT колонки нет раздела {part}")))?;
    let psize = e.sectors as usize * 512;
    let fsize = std::fs::metadata(image)
        .map_err(|err| UsbError::Loader(format!("{}: {err}", image.display())))?
        .len() as usize;
    if fsize > psize {
        return Err(UsbError::Loader(format!(
            "{part}: образ {} больше раздела ({psize} байт)",
            image.display()
        )));
    }
    progress(Progress::PartitionStart {
        name: part.to_string(),
        sectors: e.sectors,
    });
    let mut data = vec![0u8; psize];
    data[..fsize].copy_from_slice(&std::fs::read(image)?);

    let mut done: u64 = 0;
    while done < e.sectors {
        let n = ((e.sectors - done) as u32).min(CHUNK_SECTORS) as u64;
        let off = (done * 512) as usize;
        s.write_lba(
            (e.first_lba + done) as u32,
            &data[off..off + (n * 512) as usize],
        )?;
        done += n;
        progress(Progress::PartitionProgress {
            name: part.to_string(),
            done,
            total: e.sectors,
        });
    }

    progress(Progress::PartitionDone {
        name: part.to_string(),
    });
    Ok(())
}
