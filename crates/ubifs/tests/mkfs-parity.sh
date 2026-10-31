#!/usr/bin/env bash
# Cross-validation of the UBIFS builder against the real mkfs.ubifs
# (mtd-utils), for two flash geometries:
#   1) build a fixture tree with pinned metadata -> reference image via
#      real mkfs.ubifs in docker (alpine:3.20, mtd-utils 2.2.0);
#   2) rebuild the same image with our mkfs (the child order is
#      restored from the reference — container readdir order is not
#      reproducible) via examples/parity_build;
#   3) byte-for-byte comparison (the SB UUID is masked — mkfs.ubifs
#      generates a random one).
# Everything lives inside the crate: work/parity/ (git-ignored).
set -euo pipefail
CRATE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$CRATE/work/parity"
DOCKER_IMAGE="alpine:3.20"  # mtd-utils 2.2.0

run_case() {
  local name=$1 min_io=$2 leb=$3 max_leb=$4 journal=$5
  echo "== case $name: -m $min_io -e $leb -c $max_leb -j $journal =="
  mkdir -p "$WORK/$name"
  docker run --rm -v "$WORK/$name:/w" -v "$WORK/root:/root" "$DOCKER_IMAGE" sh -c \
    "apk add -q mtd-utils && mkfs.ubifs -m $min_io -e $leb -c $max_leb -x none -j $journal -r /root -o /w/ref.ubifs" >/dev/null

  (cd "$CRATE" && cargo run --quiet --example parity_build -- \
    "$WORK/$name/ref.ubifs" "$WORK/$name/ours.ubifs" "$min_io" "$leb" "$max_leb" "$journal")

  python3 - "$WORK/$name" "$leb" <<'EOF'
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

echo "ALL PARITY CASES PASS"
