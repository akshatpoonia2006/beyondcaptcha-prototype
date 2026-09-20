#!/usr/bin/env bash
echo "===================================================================="
echo "Starting BeyondCAPTCHA Prototype (SIH Edition)"
echo "Accessible, Adaptive Human Verification Infrastructure"
echo "===================================================================="
echo ""

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed or not in your PATH."
    exit 1
fi

echo "[1/3] Verifying dependencies..."
python3 -m pip install -r requirements.txt --quiet

echo "[2/3] Initializing local database & demo seed data..."
python3 seed_demo.py

echo "[3/3] Opening browser..."
if command -v xdg-open &> /dev/null; then
    xdg-open http://127.0.0.1:5000 &
elif command -v open &> /dev/null; then
    open http://127.0.0.1:5000 &
fi

echo ""
echo "===================================================================="
echo "Verification Server running at http://127.0.0.1:5000"
echo "Demo Pages:"
echo "  - Citizen Services Demo: http://127.0.0.1:5000/"
echo "  - Security Defense Lab:  http://127.0.0.1:5000/security-lab"
echo "  - Integration Demo:      http://127.0.0.1:5000/embed-demo"
echo "  - Audit Events View:     http://127.0.0.1:5000/audit"
echo "===================================================================="
echo ""

python3 app.py
