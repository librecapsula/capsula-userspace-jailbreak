//! Flashing a partition back to the device. The only operation of the
//! tool that writes to flash: userdata (unsigned, freely rewritable).
//! Partition addresses come from the device GPT.

use crate::backup::CHUNK_SECTORS;
use crate::gpt::Gpt;
use crate::session::{Progress, ProgressFn};
use rockusb::loader::LoaderSession;
use rockusb::{Error as UsbError, Transport};
use std::io::Read;
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
    let psize = e.sectors * 512;
    let fsize = std::fs::metadata(image)
        .map_err(|err| UsbError::Loader(format!("{}: {err}", image.display())))?
        .len();
    if fsize > psize {
        return Err(UsbError::Loader(format!(
            "{part}: образ {} больше раздела ({psize} байт)",
            image.display()
        )));
    }
    let psize = usize::try_from(psize)
        .map_err(|_| UsbError::Loader(format!("{part}: раздел не влезает в память")))?;
    progress(Progress::PartitionStart {
        name: part.to_string(),
        sectors: e.sectors,
    });
    // Stream the image into the head of the padded buffer: no second
    // full-size copy of the file, and no size TOCTOU between metadata
    // and read (a truncated file fails cleanly with UnexpectedEof).
    let mut data = vec![0u8; psize];
    let mut f = std::fs::File::open(image)?;
    f.read_exact(&mut data[..fsize as usize])?;

    let mut done: u64 = 0;
    while done < e.sectors {
        let n = (e.sectors - done).min(CHUNK_SECTORS as u64) as usize;
        let lba = u32::try_from(e.first_lba + done)
            .map_err(|_| UsbError::Loader(format!("{part}: LBA за пределами u32-протокола")))?;
        let off = done as usize * 512;
        s.write_lba(lba, &data[off..off + n * 512])?;
        done += n as u64;
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
