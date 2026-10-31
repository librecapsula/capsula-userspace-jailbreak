#!/usr/bin/env bash
# Cross-validation of the UBIFS builder against the real mkfs.ubifs
# (mtd-utils), for two flash geometries:
#   1) build a fixture tree with pinned metadata -> reference image via
#      real mkfs.ubifs in docker (alpine:3.20, mtd-utils 2.2.0);
#   2) rebuild the same image with our mkfs (the original write order is
#      restored from the on-flash node positions) via examples/parity_build;
#   3) byte-for-byte comparison (the SB UUID is masked — mkfs.ubifs
#      generates a random one).
# Case "full" adds hard links, device nodes, a FIFO and a socket (the
# tree is built inside the container: bind mounts reject mknod, and
# alpine's mtd-utils is built without xattr support). Case "zlib" checks
# that we can read a ZLIB-compressed reference image back (content, not
# bytes — our deflate output is valid but not byte-identical).
# Everything lives inside the crate: work/parity/ (git-ignored).
set -euo pipefail
CRATE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$CRATE/work/parity"
DOCKER_IMAGE="alpine:3.20"  # mtd-utils 2.2.0

compare() {
  python3 - "$1" "$2" <<'EOF'
import sys
d, leb = sys.argv[1], int(sys.argv[2])
ref = open(f"{d}/ref.ubifs", "rb").read()
ours = open(f"{d}/ours.ubifs", "rb").read()
assert len(ref) == len(ours), (len(ref), len(ours))
bad = 0
for i in range(len(ref) // leb):
    a, b = ref[i*leb:(i+1)*leb], ours[i*leb:(i+1)*leb]
    if i == 0:
        # The UUID is random; mask it and the CRC computed over it.
        a = a[:4] + b"\0"*4 + a[8:108] + b"\0"*16 + a[124:]
        b = b[:4] + b"\0"*4 + b[8:108] + b"\0"*16 + b[124:]
    if a != b:
        diffs = [j for j in range(leb) if a[j] != b[j]]
        print(f"LEB {i}: {len(diffs)} diffs at {diffs[:12]}")
        bad += 1
print(f"{d}: FULL BYTE-FOR-BYTE MATCH (except the SB UUID)" if bad == 0 else f"{d}: {bad} LEBs differ")
raise SystemExit(1 if bad else 0)
EOF
}

run_case() {
  local name=$1 min_io=$2 leb=$3 max_leb=$4 journal=$5
  echo "== case $name: -m $min_io -e $leb -c $max_leb -j $journal =="
  mkdir -p "$WORK/$name"
  docker run --rm -v "$WORK/$name:/w" -v "$WORK/root:/root" "$DOCKER_IMAGE" sh -c \
    "apk add -q mtd-utils && mkfs.ubifs -m $min_io -e $leb -c $max_leb -x none -j $journal -r /root -o /w/ref.ubifs" >/dev/null

  (cd "$CRATE" && cargo run --quiet --example parity_build -- \
    "$WORK/$name/ref.ubifs" "$WORK/$name/ours.ubifs" "$min_io" "$leb" "$max_leb" "$journal")

  compare "$WORK/$name" "$leb"
}

# The fixture tree: pinned metadata, exercised content kinds (sparse
# file with holes, an empty file, a large pattern file, a symlink).
mkdir -p "$WORK/root/usr/bin" "$WORK/root/etc"
python3 - "$WORK/root" <<'EOF'
import os, sys
root = sys.argv[1]
t = 1700000000
def wfile(p, data, mode=0o644):
    open(p, "wb").write(data); os.chmod(p, mode); os.utime(p, (t, t))
def wdir(p):
    os.utime(p, (t, t))
wdir(root); wdir(f"{root}/usr"); wdir(f"{root}/usr/bin"); wdir(f"{root}/etc")
wfile(f"{root}/usr/bin/tool", bytes((i % 251) for i in range(200_000)), 0o755)
wfile(f"{root}/etc/marker", b"marker\n")
wfile(f"{root}/small.txt", b"hello")
wfile(f"{root}/empty.bin", b"")
d = bytearray(3 * 4096); d[4096:4196] = b"A" * 100
wfile(f"{root}/holes.bin", bytes(d))
if not os.path.islink(f"{root}/link"):
    os.symlink("/etc/marker", f"{root}/link")
os.utime(f"{root}/link", (t, t), follow_symlinks=False)
print("tree ready")
EOF

# 128 KiB PEB / 2 KiB page NAND; 256 KiB PEB / 4 KiB page NAND.
run_case nand-2k 2048 126976 2212 8MiB
run_case nand-4k 4096 253952 2048 4MiB

# Full-feature case: hard links + device nodes + fifo + socket, built
# inside the container (root, native fs).
echo "== case full: hardlinks + devices + fifo + socket =="
mkdir -p "$WORK/full"
docker run --rm -v "$WORK/full:/w" "$DOCKER_IMAGE" sh -c '
  apk add -q mtd-utils python3
  python3 - <<"EOF"
import os, socket, stat, sys
root = "/tmp/root"
t = 1700000000
def wfile(p, data, mode=0o644):
    open(p, "wb").write(data); os.chmod(p, mode); os.utime(p, (t, t))
os.makedirs(f"{root}/etc", exist_ok=True); os.makedirs(f"{root}/dev", exist_ok=True)
os.makedirs(f"{root}/usr/bin", exist_ok=True)
os.utime(root, (t, t)); os.utime(f"{root}/etc", (t, t)); os.utime(f"{root}/dev", (t, t)); os.utime(f"{root}/usr/bin", (t, t))
wfile(f"{root}/etc/conf", b"key=value\n" * 400)
wfile(f"{root}/usr/bin/hello", b"hello hardlink\n", 0o755)
os.link(f"{root}/usr/bin/hello", f"{root}/usr/bin/hello-copy")
wfile(f"{root}/usr/bin/tool", bytes((i % 251) for i in range(120_000)), 0o755)
os.mknod(f"{root}/dev/nullc", stat.S_IFCHR | 0o666, os.makedev(1, 3)); os.utime(f"{root}/dev/nullc", (t, t))
os.mknod(f"{root}/dev/loopb", stat.S_IFBLK | 0o600, os.makedev(7, 0)); os.utime(f"{root}/dev/loopb", (t, t))
os.mkfifo(f"{root}/dev/pipe"); os.utime(f"{root}/dev/pipe", (t, t))
s = socket.socket(socket.AF_UNIX); s.bind(f"{root}/dev/sock"); s.close(); os.utime(f"{root}/dev/sock", (t, t))
print("full tree ready")
EOF
  mkfs.ubifs -m 2048 -e 126976 -c 2212 -x none -j 8MiB -r /tmp/root -o /w/ref.ubifs
'
(cd "$CRATE" && cargo run --quiet --example parity_build -- \
  "$WORK/full/ref.ubifs" "$WORK/full/ours.ubifs" 2048 126976 2212 8MiB)
compare "$WORK/full" 126976

# ZLIB content round-trip: read a compressed reference image back and
# compare the extracted files with the source tree.
echo "== case zlib: compressed image content round-trip =="
mkdir -p "$WORK/zlib"
docker run --rm -v "$WORK/zlib:/w" -v "$WORK/root:/root" "$DOCKER_IMAGE" sh -c \
  "apk add -q mtd-utils && mkfs.ubifs -m 2048 -e 126976 -c 2212 -x zlib -j 8MiB -r /root -o /w/ref.ubifs" >/dev/null
(cd "$CRATE" && cargo run --quiet --example extract -- "$WORK/zlib/ref.ubifs" "$WORK/zlib/out")
python3 - "$WORK/zlib/out" "$WORK/root" <<'EOF'
import hashlib, os, sys
out, src = sys.argv[1], sys.argv[2]
def md5(p):
    return hashlib.md5(open(p, "rb").read()).hexdigest()
pairs = [
    ("usr/bin/tool", "usr/bin/tool"),
    ("etc/marker", "etc/marker"),
    ("small.txt", "small.txt"),
    ("empty.bin", "empty.bin"),
    ("holes.bin", "holes.bin"),
]
for a, b in pairs:
    ha, hb = md5(f"{out}/{a}"), md5(f"{src}/{b}")
    assert ha == hb, f"{a}: {ha} != {hb}"
link = os.readlink(f"{out}/link")
assert link == "/etc/marker", link
print("zlib content round-trip: OK")
EOF

echo "ALL PARITY CASES PASS"
