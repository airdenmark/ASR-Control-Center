#!/bin/bash
# compiler_asr.sh – build ASR Control Center as a single console‑free .exe

# 1. Ensure the icon exists
if [ ! -f "icon.ico" ]; then
    echo "❌ icon.ico not found. Run 'python icon.py' first."
    exit 1
fi

# 2. PyInstaller command (mirrors downloader's compiler.sh)
python -m PyInstaller \
    --noconsole \
    --onefile \
    --collect-all customtkinter \
    --add-data "icon.ico;." \
    --icon="icon.ico" \
    --name "ASR Control Center" \
    --clean \
    ASR-ControlCenter.py

echo "✅ Build complete! Look in ./dist/ASR Control Center.exe"