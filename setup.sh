#!/bin/bash
# MRRA Scanner — setup script
# Creates venv if needed, installs dependencies, verifies installation.

set -e

VENV_DIR=".venv"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Create venv if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate
source "$VENV_DIR/bin/activate"

# Install with all optional dependencies
echo "Installing dependencies..."
pip install -e ".[dev,pdf]" --quiet

# Verify
echo ""
echo "Verifying installation..."
znextscan --version
echo ""
znextscan list-controls | tail -1
echo ""
echo "Setup complete. Activate with: source $VENV_DIR/bin/activate"
echo ""
echo "Quick start:"
echo "  znextscan scan --mock tests/fixtures --html report.html"
echo "  znextscan scan -H zos.example.com -u MRRASCN --html report.html"
