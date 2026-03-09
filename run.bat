@echo off
echo Starting InboxEye...
cd /d "%~dp0"
if exist "venv\Scripts\python.exe" (
    venv\Scripts\python.exe MainGUI.py
) else (
    echo Virtual environment not found. Please run setup first or check your Python installation.
    pause
)
