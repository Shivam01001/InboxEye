#!/bin/bash
echo "Starting InboxEye..."
cd "$(dirname "$0")"

if [ -f "venv/bin/python" ]; then
    venv/bin/python MainGUI.py
else
    echo "Virtual environment not found. Please run ./setup.sh first."
fi
