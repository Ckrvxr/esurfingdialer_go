#!/usr/bin/env bash
set -euo pipefail

APP="esurfingdialer"
OUTDIR="build"

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

TARGETS=(
  "linux/amd64"
  "linux/armv6"
  "linux/armv7"
  "linux/arm64"
  "linux/mips"
  "linux/mipsle"
  "linux/loong64"
  "linux/riscv64"
  "windows/amd64"
  "windows/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "freebsd/amd64"
  "freebsd/arm64"
)

for target in "${TARGETS[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  ext=""
  [ "$os" = "windows" ] && ext=".exe"

  # Map custom names to Go arch values
  goarch="$arch"
  namearch="$arch"
  armver=""
  case "$arch" in
    armv6) goarch="arm"; namearch="armv6"; armver=6 ;;
    armv7) goarch="arm"; namearch="armv7"; armver=7 ;;
    *) ;;
  esac

  name="${APP}-${os}-${namearch}${ext}"
  echo "==> $name"

  export GOOS="$os" GOARCH="$goarch" GOARM="$armver"
  unset GOMIPS
  [ "$goarch" = "mips" ] || [ "$goarch" = "mipsle" ] && GOMIPS=softfloat

  go build -tags="nethttpomithttp2" -ldflags="-s -w" -trimpath -o "$OUTDIR/$name" .

  case "$os" in
    linux|windows) upx --lzma "$OUTDIR/$name" 2>/dev/null || true ;;
  esac
done

echo "==> done"
ls -lh "$OUTDIR"
