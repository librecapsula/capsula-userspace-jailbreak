# ubifs

Pure-Rust [UBIFS](https://en.wikipedia.org/wiki/UBIFS) and [UBI](https://en.wikipedia.org/wiki/Unsorted_Block_Image)
support: read existing images, build new ones, check and modify them —
no kernel, no C libraries (one optional feature aside), no mounting.

The format follows the Linux kernel's `fs/ubifs/ubifs-media.h` and
mtd-utils (`ubifs-utils`) as the specification. The image builders are
careful ports of `mkfs.ubifs` and `ubinize` and produce
**byte-identical** output (for `-x none`), verified against the real
tools in Docker and, offline, against a committed corpus they
generated.

There is no other UBIFS implementation on crates.io; if you need to
inspect, extract, generate, check or repack UBIFS/UBI images from Rust
(firmware tooling, embedded flashing pipelines, forensics), this is the
place.

## Feature matrix vs the official tools

| Capability | mtd-utils | this crate | byte parity |
|---|---|---|---|
| Read committed volumes (SB/MST/LPT incl. big-LPT and sparse kernel-commit trees, TNC, xattrs, special files) | mount | ✅ | — |
| Read ZLIB/LZO-compressed data | mount | ✅ (pure Rust) | — |
| Read ZSTD-compressed data | mount | ✅ `zstd` feature (C libzstd) | — |
| Journal replay (post-crash state), orphan area | mount | ✅ | semantics |
| mkfs: `-m/-e/-c/-f/-j/-l/-x none/-p/-U/-R/-k/-X/-F` | mkfs.ubifs | ✅ | **byte-identical** |
| mkfs: xattrs, hard links, holes, devices, fifos, sockets, devtable | mkfs.ubifs | ✅ | **byte-identical** |
| mkfs: compressed writes (`-x lzo/zlib`, `favor_lzo`) | mkfs.ubifs | ✅ | valid, not byte-identical¹ |
| mkfs: `-x zstd` | mkfs.ubifs | ✅ `zstd` feature | valid, not byte-identical¹ |
| mkfs from a directory (`-r`) | mkfs.ubifs | ✅ `walk::from_directory` | — |
| Build UBI images (ini configs, dynamic/static volumes, alignment, autoresize/skip-check, image-seq) | ubinize | ✅ | **byte-identical** |
| Parse UBI dumps (volume table, EC/VID, static CRCs, `ubinfo` view) | ubinfo | ✅ | — |
| Consistency check (the fsck.ubifs problem table, detection + repair-mode classification) | fsck.ubifs | ✅ detection | semantics |
| fsck repair (`-a/-y/-yb`, lost+found, rebuild) | fsck.ubifs | ❌ planned | — |
| Encrypted (format 5) volumes | mount/fsck | ❌ refused explicitly | — |
| Authenticated volumes | — (fsck refuses) | ❌ refused explicitly | — |

¹ mkfs.ubifs compresses with zlib (raw deflate, 2 KiB window, memLevel
8) and GPL-only `lzo1x_999`; this crate uses pure-Rust codecs (miniz
deflate, lzo1x-1 — the same algorithm the kernel write path uses). The
streams are valid and kernel-readable, but not byte-identical. There is
no legal way to reach byte parity here.

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

Read a UBI partition dump, check it and extract everything:

```rust
use ubifs::{reader, ubi};

let geom = ubi::UbiGeometry::from_peb_size(128 * 1024, 2048);
let dump = ubi::Dump::parse(&raw, geom)?;
let fs = reader::Ubifs::new(dump.volume_lebs(0))?; // post-journal-replay state
for p in fs.check().problems {
    eprintln!("{:?}: {}", p.kind, p.detail);
}
let tree = fs.extract()?; // tree::Inode, mirrors the on-flash metadata
```

Build a UBI image from an ini configuration (an `ubinize` equivalent):

```rust
let ini = ubifs::ubinize::parse_config(r#"
[data]
mode=ubi
image=data.ubifs
vol_id=0
vol_size=8MiB
vol_type=dynamic
vol_name=data
"#)?;
```

See `examples/` for ready-to-run command-line tools: `extract`
(image → directory), `ubinfo` (image inspection) and `ubinize`
(ini → UBI image).

## Testing

```sh
cargo test                       # everything offline (unit, corpus, corruption matrix)
bash tests/mkfs-parity.sh        # byte parity vs real mkfs.ubifs (docker)
bash tests/ubinize-parity.sh     # byte parity vs real ubinize (docker)
bash tests/data/gen.sh           # regenerate the committed corpus (docker)
```

The committed corpus (`tests/data/`) was produced by the **real**
tools: mkfs.ubifs v2.3.1 built from git with `--with-xattr` (distro
packages ship it without xattr support) over a full-feature fixture
tree — regular/sparse/empty/incompressible files, a symlink, hard
links, char/block devices, a fifo, a socket and xattrs — at three
geometries × four compression modes, plus ubinize images. The offline
tests extract every image against a tree spec (sha256-verified) and
rebuild the `-x none` images byte-for-byte. A corruption matrix in the
spirit of the official `fsck_bad_image` suite damages the corpus image
in 32 precise ways (CRCs recomputed, exactly like the official images)
and asserts the checker classifies each one per the fsck.ubifs problem
table.

A real-world volume can be plugged into `tests/stock_dump.rs` via the
`UBIFS_STOCK_DUMP` environment variable (any UBI dump; skips without
it).

## Format notes that are easy to break

These properties are load-bearing for byte parity; changes to the
builders must keep the parity harnesses green:

- the LPT bitstream starts **after** the 2-byte CRC16; missing LPT
  branches mean empty LEBs (free = leb_size);
- lprops are packed in units of 8 bytes; nodes inside a LEB are aligned
  to 8 bytes, the tail is a pad node/`0xCE` up to min_io and `0xFF` to
  the end;
- a dent node ends with a NUL after the name; the xent layout matches
  the dent layout;
- the write order is children → dent → the directory's ino (the root
  ino goes last); inode and node sqnums come from a single counter;
  hard-linked files are written once, after the whole tree walk, in
  mkfs.ubifs's hash-table order (the writer models it exactly);
- xattr pairs are `xent + xattr inode` with the accounting formulas of
  `CALC_DENT_SIZE`/`CALC_XATTR_BYTES`; the xattr inode carries the
  host's timestamps with zero nanoseconds;
- the SB node is followed by a 64-byte zeroed SIG node with node_type 0;
- UBIFS zlib payloads are **raw deflate** streams (kernel crypto API
  windowBits = -11), not zlib-wrapped ones;
- device numbers ride inline in the inode as the glibc `makedev`
  encoding; device/fifo/socket inodes have size 0;
- `UBIFS_LAYOUT_VOLUME_ID` is `0x7FFFFFFF − 0x1000`; empty volume-table
  records still carry a CRC.

## Limitations

- fsck-style **repairs** (lost+found, rebuild) are not implemented —
  the checker detects and classifies, it does not rewrite.
- Encrypted (format 5 / double-hash) volumes are refused with a clear
  error; reading them is planned.
- The `zstd` feature links the C libzstd; everything else is pure Rust.
- Bad-block and wear-leveling management is out of scope (that is
  UBI's job on the device).
- `walk::from_directory` is Unix-only.

## Licensing

MIT. The Linux kernel and mtd-utils sources (GPL-2.0) were used as the
*format specification* only — no code from them is included in, or
derived into, this crate. The committed test corpus consists of
outputs of those tools over this crate's own fixture trees (tool output
is not covered by the GPL, as with a compiler).

## Repository

Development happens in
[capsula-userspace-jailbreak](https://github.com/librecapsula/capsula-userspace-jailbreak)
(`crates/ubifs`); the crate is a standalone workspace there and moves
to its own repository on publication.
