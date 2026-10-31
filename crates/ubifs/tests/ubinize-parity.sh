#!/usr/bin/env bash
# Byte-for-byte cross-validation of the UBI image builder against the
# real ubinize (mtd-utils in docker, alpine:3.20 = mtd-utils 2.2.0).
# The image sequence number is pinned (-Q) — ubinize rolls a random one.
set -euo pipefail
CRATE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$CRATE/work/ubinize-parity"
DOCKER_IMAGE="alpine:3.20"  # mtd-utils 2.2.0

rm -rf "$WORK"
mkdir -p "$WORK"

# Payloads for the volumes.
dd if=/dev/zero of="$WORK/blob.bin" bs=1024 count=100 2>/dev/null
python3 - "$WORK/fw.txt" <<'EOF'
import sys
with open(sys.argv[1], "w") as f:
    for i in range(1, 501):
        f.write(f"firmware-payload-{i:064d}\n")
EOF

run_case() {
  local name=$1 cfg=$2; shift 2
  echo "== case $name: ubinize $* =="
  mkdir -p "$WORK/$name"
  cp "$WORK/config-$cfg.ini" "$WORK/$name/config.ini"
  cp "$WORK/blob.bin" "$WORK/fw.txt" "$WORK/$name/"
  docker run --rm -v "$WORK/$name:/w" "$DOCKER_IMAGE" sh -c \
    "apk add -q mtd-utils && cd /w && ubinize $* -Q 0x11223344 -o ref.img config.ini" >/dev/null
  (cd "$WORK/$name" && cargo run --quiet --manifest-path "$CRATE/Cargo.toml" \
    --example ubinize -- -o ours.img "$@" -Q 0x11223344 config.ini)
  cmp "$WORK/$name/ref.img" "$WORK/$name/ours.img" && echo "$name: BYTE-FOR-BYTE MATCH"
}

# 1. One dynamic volume, autoresize.
cat > "$WORK/config-dyn.ini" <<'EOF'
[ubifs-vol]
mode=ubi
image=blob.bin
vol_id=0
vol_size=256KiB
vol_type=dynamic
vol_name=ubifs
vol_flags=autoresize
EOF
run_case dyn dyn -p 128KiB -m 2048

# 2. Static + dynamic volumes, alignment and skip-check.
cat > "$WORK/config-mix.ini" <<'EOF'
[ubifs-vol]
mode=ubi
image=blob.bin
vol_id=0
vol_size=256KiB
vol_type=dynamic
vol_name=ubifs
vol_alignment=1

[firmware]
mode=ubi
image=fw.txt
vol_id=1
vol_size=48KiB
vol_type=static
vol_name=firmware
vol_alignment=128
vol_flags=skip-check
EOF
run_case mix mix -p 128KiB -m 2048

# 3. Sub-page size and a custom VID header offset.
run_case offs dyn -p 128KiB -m 2048 -s 512 -O 1024

# 4. A different geometry (256 KiB PEB / 4 KiB pages).
run_case nand4k mix -p 256KiB -m 4096

echo "ALL UBINIZE PARITY CASES PASS"
