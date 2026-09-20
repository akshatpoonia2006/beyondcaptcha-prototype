@echo off
title BeyondCAPTCHA Prototype - SIH Edition
echo ====================================================================
echo Starting BeyondCAPTCHA Prototype (SIH Edition)
echo Accessible, Adaptive Human Verification Infrastructure
echo ====================================================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your PATH.
    echo Please install Python 3.10 or higher.
    pause
    exit /b 1
)

echo [1/3] Verifying dependencies...
pip install -r requirements.txt --quiet

echo [2/3] Initializing local database & demo seed data...
python seed_demo.py

echo [3/3] Launching web browser...
start http://127.0.0.1:5000

echo.
echo ====================================================================
echo Verification Server running at http://127.0.0.1:5000
echo Demo Pages:
echo   - Citizen Services Demo: http://127.0.0.1:5000/
echo   - Security Defense Lab:  http://127.0.0.1:5000/security-lab
echo   - Integration Demo:      http://127.0.0.1:5000/embed-demo
echo   - Audit Events View:     http://127.0.0.1:5000/audit
echo.
echo Press Ctrl+C to stop the server.
echo ====================================================================
echo.

python app.py
pause
