#!/usr/bin/env bash
# Build internal/web/static/css/app.css with the official Tailwind standalone CLI.
#
# The CLI version is pinned and its SHA-256 checked against the values below
# (from the release's sha256sums.txt, cross-checked with GitHub's asset
# digests) before it runs. Re-run after changing classes in templates or
# handlers; CI fails if app.css is out of date.
set -euo pipefail

VERSION=v3.4.19

# Plain case statement rather than an associative array: macOS ships bash 3.2.
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    platform=linux-x64
    want=4af3198c015616ea7d6617974ec3d70d987ecc00c1ca8463b0a30fd65cc7c06e ;;
  Linux-aarch64 | Linux-arm64)
    platform=linux-arm64
    want=e5b2d27694daa80cc52ec29553ba2c6bd43d86bd51a9d633ed24058b9c05a676 ;;
  Darwin-x86_64)
    platform=macos-x64
    want=a597f407e0f1f03535731f5b42f1576a8152cb5fffc2f38e754722bc0c280045 ;;
  Darwin-arm64)
    platform=macos-arm64
    want=7fdeb00818b6214a337383063282b2361ecb08bbc08f8c8a7ba97ee1e2eaa4fe ;;
  *) echo "build-css: unsupported platform $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

cache="${XDG_CACHE_HOME:-$HOME/.cache}/eraser/tailwindcss-$VERSION"
bin="$cache/tailwindcss-$platform"

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

if [[ ! -x "$bin" || "$(sha256 "$bin")" != "$want" ]]; then
  mkdir -p "$cache"
  tmp="$(mktemp "$cache/download.XXXXXX")"
  trap 'rm -f "$tmp"' EXIT
  curl -sSfL -o "$tmp" "https://github.com/tailwindlabs/tailwindcss/releases/download/$VERSION/tailwindcss-$platform"
  got="$(sha256 "$tmp")"
  if [[ "$got" != "$want" ]]; then
    echo "build-css: checksum mismatch for tailwindcss-$platform: got $got" >&2
    exit 1
  fi
  chmod +x "$tmp"
  mv "$tmp" "$bin"
fi

cd "$(dirname "$0")/../internal/web"
"$bin" --config tailwind.config.js --input tailwind.input.css --output static/css/app.css --minify
