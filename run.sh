#!/usr/bin/env bash
# ----------------------------------------------------------------------------
# Convenience launcher for the Data Link Layer project.
# It checks that tshark is present (PyShark needs it), then runs the full demo.
# ----------------------------------------------------------------------------
set -e

# Move to the folder this script lives in, then into src/.
cd "$(dirname "$0")/src"

# Friendly check for the tshark binary that PyShark depends on.
if ! command -v tshark >/dev/null 2>&1; then
    echo "WARNING: 'tshark' was not found on your PATH."
    echo "         PyShark needs it. Install with e.g.:"
    echo "             sudo apt-get install -y tshark"
    echo ""
fi

echo "Running the complete data link layer demonstration..."
echo ""
python3 main.py
