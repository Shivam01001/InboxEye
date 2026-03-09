@echo off
echo Setting up InboxEye...
cd /d "%~dp0"

echo Creating virtual environment...
python -m venv venv

echo Installing dependencies...
venv\Scripts\pip install -r requirements.txt

echo.
echo Setup complete! You can now run the application using run.bat
pause
