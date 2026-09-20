# -*- coding: utf-8 -*-
"""
Suite 4: Fairness & Demographic Robustness Verification (Section 27.4)
Ensures slow typists, keyboard-only users, mobile devices, and touch devices
are NEVER falsely classified as bots.
"""
import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_slow_human_typist_allowed(client):
    payload = {
        "sessionId": "sess_slow_human",
        "isAccessibleMode": False,
        "telemetry": {
            "dwellTime": 42000,       # 42 seconds of deliberation
            "typingVariance": 120.5,  # natural human pauses
            "mouseCurvature": 0.45,
            "mouseEntropy": 0.60,
            "mouseEventCount": 18,
            "screenWidth": 1920,
            "screenHeight": 1080,
            "isWebDriver": False,
            "honeypot": ""
        }
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['decision'] == 'ALLOW'
    assert data['risk_score'] <= 15.0

def test_keyboard_only_user_allowed(client):
    payload = {
        "sessionId": "sess_keyboard_only",
        "isAccessibleMode": False,
        "telemetry": {
            "dwellTime": 3200,
            "typingVariance": 45.0,
            "mouseEventCount": 0,     # No mouse used (pure Tab/Enter/Arrows)
            "mouseCurvature": 0.0,
            "mouseEntropy": 0.0,
            "keyboardNavigation": True,
            "screenWidth": 1366,
            "screenHeight": 768,
            "isWebDriver": False,
            "honeypot": ""
        }
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['decision'] == 'ALLOW'
    assert data['risk_score'] <= 15.0

def test_mobile_touch_user_allowed(client):
    payload = {
        "sessionId": "sess_mobile_touch",
        "isAccessibleMode": False,
        "telemetry": {
            "dwellTime": 2400,
            "touchEventCount": 8,
            "isTouchDevice": True,
            "mouseEventCount": 0,
            "typingVariance": 55.0,
            "screenWidth": 390,
            "screenHeight": 844,      # Typical mobile resolution
            "isWebDriver": False,
            "honeypot": ""
        }
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['decision'] == 'ALLOW'
    assert data['risk_score'] <= 15.0
