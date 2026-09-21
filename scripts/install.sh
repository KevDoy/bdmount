#!/bin/bash
# Build bdmount and install it to ~/.local/bin.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN_DIR="$HOME/.local/bin"
BIN="$BIN_DIR/bdmount"

if [[ ! -e /Applications/MakeMKV.app/Contents/lib/libmmbd_new.dylib ]]; then
    echo "error: MakeMKV is not installed at /Applications/MakeMKV.app (libmmbd_new.dylib missing)" >&2
    exit 1
fi

echo "==> building release binary"
unset CARGO_TARGET_DIR
cargo build --release

echo "==> installing to $BIN"
mkdir -p "$BIN_DIR"
install -m 755 target/release/bdmount "$BIN"

echo "done. Run: $BIN mount   (or add $BIN_DIR to your PATH)"
