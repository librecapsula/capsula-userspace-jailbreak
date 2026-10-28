#!/usr/bin/env bash
# Package the release archive for the current matrix job.
# Env: TARGET, ARCHIVE (tar.gz|zip), TAG; DRIVER_URL/DRIVER_SHA256 and
# ZADIG_URL/ZADIG_SHA256 on Windows.
set -euo pipefail

tag="${TAG#v}"          # 0.1.0
name="capsula-jb-${TAG}-${TARGET}"
stage="staging/${name}"

rm -rf staging dist
mkdir -p "${stage}" dist

bin="target/${TARGET}/release/capsula-jb"
if [[ "$TARGET" == *-windows-* ]]; then
    bin="${bin}.exe"
fi
cp "$bin" "${stage}/"
cp README.md LICENSE "${stage}/"
cp resources/packaging/QUICKSTART.txt "${stage}/"
# Agent manual for flashing (the root AGENTS.md is the dev guide and
# intentionally does not ship).
cp resources/packaging/AGENTS.md "${stage}/"

case "$TARGET" in
    *-windows-*)
        # Two USB driver components, both downloaded and SHA256-verified
        # at build time, shipped inside the archive:
        #   RockchipUSBDriver.zip — vendor DriverAssistant (the "Rockusb"
        #     driver used by RKDevTool/upgrade_tool; also the way back
        #     after switching the device to WinUSB);
        #   zadig-2.9.exe — Zadig, to rebind the board to WinUSB, which
        #     is the driver capsula-jb itself opens the device through.
        # See resources/packaging/windows-DRIVER-SETUP.txt.
        curl -fsSL "$DRIVER_URL" -o "${stage}/RockchipUSBDriver.zip"
        echo "${DRIVER_SHA256}  ${stage}/RockchipUSBDriver.zip" | sha256sum -c
        curl -fsSL "$ZADIG_URL" -o "${stage}/zadig-2.9.exe"
        echo "${ZADIG_SHA256}  ${stage}/zadig-2.9.exe" | sha256sum -c
        cp resources/packaging/windows-DRIVER-SETUP.txt "${stage}/DRIVER-SETUP.txt"
        ;;
    *-linux-*)
        cp resources/udev/99-capsula-jailbreak.rules "${stage}/"
        ;;
esac

case "$ARCHIVE" in
    tar.gz)
        tar -C staging -czf "dist/${name}.tar.gz" "${name}"
        ;;
    zip)
        if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]]; then
            # Windows: Compress-Archive (bsdtar -a produces zips that
            # unzip flags as having stray leading bytes)
            powershell.exe -NoProfile -Command \
                "Compress-Archive -Path 'staging/${name}' -DestinationPath 'dist/${name}.zip'"
        else
            # macOS bsdtar picks the format by extension
            tar -C staging -a -cf "dist/${name}.zip" "${name}"
        fi
        ;;
esac

sum_tool="sha256sum"
command -v sha256sum >/dev/null 2>&1 || sum_tool="shasum -a 256"
$sum_tool dist/* | tee "dist/${name}-SHA256SUMS.txt"

ls -la dist/
