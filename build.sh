#!/usr/bin/env bash
set -euo pipefail

APP="esurfingdialer"
OUTDIR="build"

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "linux/arm"
  "linux/mips"
  "linux/riscv64"
  "windows/amd64"
  "darwin/amd64"
  "darwin/arm64"
)

for target in "${TARGETS[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  ext=""
  [ "$os" = "windows" ] && ext=".exe"
  name="${APP}-${os}-${arch}${ext}"
  echo "==> $name"

  export GOOS="$os" GOARCH="$arch"
  unset GOMIPS
  [ "$arch" = "mips" ] || [ "$arch" = "mipsle" ] && GOMIPS=softfloat

  go build -tags="nethttpomithttp2" -ldflags="-s -w" -trimpath -o "$OUTDIR/$name" ./cmd/esurfingdialer/

  case "$os" in
    linux|windows) upx --lzma "$OUTDIR/$name" 2>/dev/null || true ;;
  esac
done

echo "==> done"
ls -lh "$OUTDIR"
