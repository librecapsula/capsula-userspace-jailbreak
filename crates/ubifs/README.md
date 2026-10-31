# ubifs

Pure-Rust [UBIFS](https://en.wikipedia.org/wiki/UBIFS) and [UBI](https://en.wikipedia.org/wiki/Unsorted_Block_Image)
support: read existing images, build new ones, modify them — no kernel,
no C libraries, no mounting.

The crate follows the Linux kernel's `fs/ubifs/ubifs-media.h` and
mtd-utils (`ubifs-utils`) as the format specification. The image builder
is a careful port of `mkfs.ubifs` and produces **byte-identical** output
(for `-x none`) — verified against the real mtd-utils tool in Docker by
[`tests/mkfs-parity.sh`](tests/mkfs-parity.sh).

There is no other UBIFS implementation on crates.io; if you need to
inspect, extract, generate or repack UBIFS/UBI images from Rust (firmware
tooling, embedded flashing pipelines, forensics), this is the place.

## What it can do

- **Read** committed UBIFS volumes: superblock/master, the LPT
  (including sparse trees written by kernel commits and big-LPT), the
  TNC index, path lookup, file reads with NONE/ZLIB/LZO decompression
  and a full tree extraction.
- **Build** images from scratch — a byte-exact port of `mkfs.ubifs`:
  same node order, sqnums, 8-byte alignment, LPT layout, watermarks and
  log/orphan areas.
- **Modify** images with `ubifs::modify`: extract the tree, apply a
  closure over it, repack with the same geometry.
- **UBI layer**: parse raw UBI partition dumps (EC/VID headers, the
  volume table), extract volume LEBs, and build UBI images with volumes
  (a minimal `ubinize` equivalent).

## Example

Build an image:

```rust
use ubifs::{mkfs, tree::Inode};

let root = Inode::dir(0o755, vec![
    ("etc".into(), Inode::dir(0o755, vec![
        ("marker".into(), Inode::file(0o644, b"marker\n".to_vec())),
    ])),
    ("hello.txt".into(), Inode::file(0o644, b"hello\n".to_vec())),
]);
// -m 2048 -e 126976 -c 128: a typical 128 KiB PEB / 2 KiB page NAND
let opts = mkfs::Options::new(2048, 126976, 128);
let image = mkfs::mkfs(&root, &opts)?;
std::fs::write("data.ubifs", image.to_vec())?;
```

Read a UBI partition dump and extract everything:

```rust
use ubifs::{reader, ubi};

let geom = ubi::UbiGeometry::from_peb_size(128 * 1024, 2048);
let dump = ubi::Dump::parse(&raw, geom)?;
let fs = reader::Ubifs::new(dump.volume_lebs(0))?;
let tree = fs.extract()?; // tree::Inode, mirrors the on-flash metadata
```

See `examples/` for ready-to-run command-line tools: `extract`
(image → directory), `ubinfo` (image inspection).

## Testing

```sh
cargo test                    # unit tests, doc tests, offline
bash tests/mkfs-parity.sh     # byte parity vs real mkfs.ubifs in Docker
```

The parity harness builds a fixture tree with pinned metadata, makes
reference images with the **real** mtd-utils `mkfs.ubifs` (Docker,
`alpine:3.20`, mtd-utils 2.2.0) for two flash geometries, rebuilds them
with this crate and byte-compares (the superblock UUID is masked —
mkfs.ubifs generates a random one).

A real-world volume can be plugged into `tests/stock_dump.rs` via the
`UBIFS_STOCK_DUMP` environment variable (any UBI dump; the test checks
structural invariants and a full extract → repack → reopen round-trip
and skips when the variable is not set).

## Format notes that are easy to break

These properties are load-bearing for byte parity; changes to the
builder must keep the parity harness green:

- the LPT bitstream starts **after** the 2-byte CRC16; missing LPT
  branches mean empty LEBs (free = leb_size);
- lprops are packed in units of 8 bytes; nodes inside a LEB are aligned
  to 8 bytes, the tail is a pad node/`0xCE` up to min_io and `0xFF` to
  the end;
- a dent node ends with a NUL after the name;
- the write order is children → dent → the directory's ino (the root
  ino goes last); inode and node sqnums come from a single counter;
- the SB node is followed by a 64-byte zeroed SIG node with node_type 0.

## Limitations

- Write-side compression produces **valid but not byte-identical**
  streams: mkfs.ubifs compresses with zlib (raw deflate, 2 KiB window,
  memLevel 8) and GPL-only `lzo1x_999`; this crate uses pure-Rust codecs
  (miniz_oxide and lzo1x-1, as the kernel write path does). `-x none`
  images remain byte-identical.
- Committed state only: the journal is not replayed (images with a dirty
  journal are read at their last commit).
- Reading ZSTD-compressed data needs the `zstd` feature (it pulls in the
  C libzstd; everything else is pure Rust).
- No encrypted (format 5) or authenticated images.
- Bad-block and wear-leveling management is out of scope (that is UBI's
  job on the device).

## Licensing

MIT. The Linux kernel and mtd-utils sources (GPL-2.0) were used as the
*format specification* only — no code from them is included in, or
derived into, this crate.
