#!/bin/bash
# Unmount any decrypted views and remove the installed binary.
# Leaves the repository and MakeMKV untouched.
set -uo pipefail

BIN="$HOME/.local/bin/bdmount"

echo "==> unmounting decrypted views"
if [[ -x "$BIN" ]]; then
    "$BIN" unmount --all || true
fi

echo "==> removing $BIN"
rm -f "$BIN"
rmdir "$HOME/BluRay Decrypted" 2>/dev/null || true

echo "done."
