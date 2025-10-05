@echo off
echo "Installing dependencies..."
pip install -r requirements.txt

echo "Building executable..."
pyinstaller --name="ContentSafety" --onefile --windowed --icon=NONE app.py

echo "Build complete. Executable is in the dist/ folder."
pause