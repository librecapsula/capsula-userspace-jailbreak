#!/usr/bin/env bash
# Generate the official-tools test corpus (committed to tests/data/).
#
# Every image is produced by the REAL mtd-utils: mkfs.ubifs v2.3.1 built
# from git with --with-xattr (distro packages ship it without xattr
# support) and the alpine 3.20 ubinize (2.2.0). The fixture tree (with
# device nodes, hard links, sockets and xattrs) only builds on a real
# Linux filesystem, so the whole generation runs inside one container;
# the host only receives plain output files.
#
# The corpus is byte-reproducible (pinned metadata, pinned -Q); outputs
# are zlib-compressed and committed together with a tree spec and a
# manifest of hashes. Regenerate with: bash tests/data/gen.sh
set -euo pipefail
CRATE="$(cd "$(dirname "$0")/../.." && pwd)"
DATA="$CRATE/tests/data"
WORK="$CRATE/work/corpus"
IMAGE_TAG="ubifs-corpus-builder"

rm -rf "$WORK"
mkdir -p "$WORK/out"

# ---------------------------------------------------------------------------
# The builder image: mtd-utils v2.3.1 from git, with xattr support.
# ---------------------------------------------------------------------------
mkdir -p "$WORK/docker"
cat > "$WORK/docker/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN apk add --no-cache git build-base automake autoconf libtool pkgconf \
      zlib-dev lzo-dev zstd-dev util-linux-dev attr-dev acl-dev \
      e2fsprogs-dev linux-headers python3 coreutils mtd-utils attr && \
    git clone --branch v2.3.1 https://git.infraroot.at/mtd-utils.git /src && \
    cd /src && ./autogen.sh && ./configure --with-xattr && \
    make -j"$(nproc)" mkfs.ubifs && \
    cp mkfs.ubifs /usr/local/bin/mkfs.ubifs-xattr && \
    rm -rf /src
EOF
docker build -q -t "$IMAGE_TAG" "$WORK/docker" >/dev/null
echo "== builder image ready (mtd-utils v2.3.1 + xattr) =="

# ---------------------------------------------------------------------------
# One container run: build the fixture tree, emit the tree spec, and run
# the whole mkfs.ubifs/ubinize matrix over it.
# ---------------------------------------------------------------------------
docker run --rm -i -v "$WORK/out:/out" "$IMAGE_TAG" sh -s <<'OUTER'
set -e

# --- The fixture tree -------------------------------------------------------
python3 - <<'EOF'
import os, socket, stat

root = "/tmp/tree"
t = 1700000000

def wfile(p, data, mode=0o644):
    open(p, "wb").write(data)
    os.chmod(p, mode)
    os.utime(p, (t, t))

for d in ("", "/regular", "/meta", "/attrs"):
    os.makedirs(root + d, exist_ok=True)
    os.utime(root + d, (t, t))

wfile(f"{root}/regular/big.bin", bytes((i % 251) for i in range(200_000)), 0o755)
# Deterministic "random" (LCG): does not compress.
x = 0x12345678
rnd = bytearray()
for _ in range(8192):
    x = (x * 1103515245 + 12345) & 0xFFFFFFFF
    rnd.append((x >> 16) & 0xFF)
wfile(f"{root}/regular/random.bin", bytes(rnd))
wfile(f"{root}/regular/small.txt", b"hello\n")
wfile(f"{root}/regular/empty.bin", b"")
holes = bytearray(3 * 4096)
holes[4096:4196] = b"A" * 100
wfile(f"{root}/regular/holes.bin", bytes(holes))

os.symlink("/regular/small.txt", f"{root}/meta/link")
os.utime(f"{root}/meta/link", (t, t), follow_symlinks=False)
os.link(f"{root}/regular/big.bin", f"{root}/meta/hard1.bin")
os.link(f"{root}/regular/big.bin", f"{root}/meta/hard2.bin")
os.mknod(f"{root}/meta/nullc", stat.S_IFCHR | 0o666, os.makedev(1, 3)); os.utime(f"{root}/meta/nullc", (t, t))
os.mknod(f"{root}/meta/loopb", stat.S_IFBLK | 0o600, os.makedev(7, 0)); os.utime(f"{root}/meta/loopb", (t, t))
os.mkfifo(f"{root}/meta/pipe"); os.utime(f"{root}/meta/pipe", (t, t))
s = socket.socket(socket.AF_UNIX); s.bind(f"{root}/meta/sock"); s.close(); os.utime(f"{root}/meta/sock", (t, t))

wfile(f"{root}/attrs/notes.txt", b"attributes live here\n" * 100)
os.setxattr(f"{root}/attrs/notes.txt", "user.test", b"hello")
os.setxattr(f"{root}/attrs/notes.txt", "user.other", b"xyz")

print("tree ready")
EOF

# --- The tree spec (what the reader must reproduce) ------------------------
python3 - <<'EOF'
import hashlib, os

root = "/tmp/tree"

def kind_of(md):
    m = md.st_mode & 0o170000
    return {0o040000: "dir", 0o100000: "reg", 0o120000: "lnk",
            0o020000: "chr", 0o060000: "blk", 0o010000: "fifo",
            0o140000: "sock"}[m]

rows = []
def walk(path):
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        md = os.lstat(full)
        k = kind_of(md)
        row = [full[len(root):], k, oct(md.st_mode & 0o7777)[2:],
               str(md.st_uid), str(md.st_gid)]
        if k == "lnk":
            row += ["0", "-", os.readlink(full)]
        elif k == "reg":
            row += [str(md.st_size), hashlib.sha256(open(full, "rb").read()).hexdigest(), "-"]
        elif k in ("chr", "blk"):
            row += ["0", "-", f"{os.major(md.st_rdev)}:{os.minor(md.st_rdev)}"]
        else:
            row += ["0", "-", "-"]
        xa = []
        for n in os.listxattr(full, follow_symlinks=False):
            v = os.getxattr(full, n, follow_symlinks=False)
            xa.append(f"{n}={v.decode() if v.isascii() else '<binary>'}")
        row.append(";".join(sorted(xa)))
        rows.append("\t".join(row))
        if k == "dir":
            walk(full)

walk(root)
with open("/out/spec.tsv", "w") as f:
    f.write("# path\tkind\tmode\tuid\tgid\tsize\tsha256\ttarget_or_rdev\txattrs\n")
    f.write("\n".join(rows) + "\n")
print("spec ready")
EOF

# --- The mkfs.ubifs matrix ---------------------------------------------------
mkfs() {
  echo "== mkfs.ubifs $1: -m $2 -e $3 -c $4 -x $5 =="
  mkfs.ubifs-xattr -m "$2" -e "$3" -c "$4" -x "$5" -j 8MiB -r /tmp/tree -o "/out/$1.ubifs"
}
mkfs g1-none 2048 126976 2212 none
mkfs g1-lzo 2048 126976 2212 lzo
mkfs g1-zlib 2048 126976 2212 zlib
mkfs g1-favor 2048 126976 2212 favor_lzo
mkfs g2-none 4096 253952 2048 none
mkfs g2-zlib 4096 253952 2048 zlib
mkfs g3-none 2048 126976 64 none

# --- The ubinize matrix (alpine's own 2.2.0) --------------------------------
head -c 65536 /tmp/tree/regular/big.bin > /out/fw.bin
cat > /out/ub-dyn.ini <<'INI'
[ubifs-vol]
mode=ubi
image=/out/g3-none.ubifs
vol_id=0
vol_size=8MiB
vol_type=dynamic
vol_name=ubifs
vol_flags=autoresize
INI
echo "== ubinize ub-dyn =="
ubinize -p 128KiB -m 2048 -Q 0x11223344 -o /out/ub-dyn.img /out/ub-dyn.ini

cat > /out/ub-mix.ini <<'INI'
[data]
mode=ubi
image=/out/g3-none.ubifs
vol_id=0
vol_size=8MiB
vol_type=dynamic
vol_name=data

[firmware]
mode=ubi
image=/out/fw.bin
vol_id=1
vol_size=4MiB
vol_type=static
vol_name=firmware
vol_alignment=128
vol_flags=skip-check
INI
echo "== ubinize ub-mix =="
ubinize -p 128KiB -m 2048 -Q 0x11223344 -o /out/ub-mix.img /out/ub-mix.ini
OUTER

# ---------------------------------------------------------------------------
# Package on the host: zlib-compress (level 9) + manifest. Only the
# generated artifacts are replaced; the generator itself stays.
# ---------------------------------------------------------------------------
cd "$CRATE"
python3 - "$WORK/out" "$DATA" <<'EOF'
import hashlib, os, shutil, sys, zlib

src, dst = sys.argv[1], sys.argv[2]
os.makedirs(dst, exist_ok=True)
owned = {".zlib", ".tsv", ".ini", "fw.bin"}
for old in os.listdir(dst):
    if old == "gen.sh" or (old != "fw.bin" and os.path.splitext(old)[1] not in owned):
        continue
    os.remove(os.path.join(dst, old))
manifest = []
for name in sorted(os.listdir(src)):
    if not (name.endswith(".ubifs") or name.endswith(".img")):
        continue
    raw = open(f"{src}/{name}", "rb").read()
    comp = zlib.compress(raw, 9)
    open(f"{dst}/{name}.zlib", "wb").write(comp)
    manifest.append((name, hashlib.sha256(raw).hexdigest(), str(len(raw)), str(len(comp))))
for extra in ("spec.tsv", "ub-dyn.ini", "ub-mix.ini", "fw.bin"):
    shutil.copy(f"{src}/{extra}", f"{dst}/{extra}")
with open(f"{dst}/MANIFEST.tsv", "w") as f:
    f.write("# name\tsha256(raw)\traw_bytes\tzlib_bytes\n")
    for row in manifest:
        f.write("\t".join(row) + "\n")
print(f"packaged {len(manifest)} images")
EOF

echo "== corpus written to tests/data/ =="
ls -l "$DATA" | awk '{print $5, $9}' | tail -n +2
