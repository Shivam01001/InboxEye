#!/bin/bash
echo "Setting up InboxEye..."
cd "$(dirname "$0")"

# Check if python3-tk is installed, which is required for Tkinter on Linux
if ! dpkg -s python3-tk >/dev/null 2>&1; then
    echo "python3-tk is not installed. Attempting to install it (requires sudo)..."
    sudo apt update && sudo apt install -y python3-tk python3-venv
fi

echo "Creating virtual environment..."
python3 -m venv venv

echo "Installing dependencies..."
venv/bin/pip install -r requirements.txt

echo "Setup complete! You can now run the application using ./run.sh"
