# -*- coding: utf-8 -*-
"""
Suite 1: Normal Flow Verification (Section 27.1)
Ensures natural human telemetry yields ALLOW with low risk score and fast latency.
"""
import pytest
import time
from app import app
from database import init_db, get_recent_logs

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_normal_human_flow_allows_access(client):
    payload = {
        "sessionId": "sess_human_normal_01",
        "isAccessibleMode": False,
        "telemetry": {
            "mouseCurvature": 0.55,
            "mouseEntropy": 0.72,
            "mouseEventCount": 24,
            "typingVariance": 35.4,
            "dwellTime": 1650,
            "screenWidth": 1920,
            "screenHeight": 1080,
            "isWebDriver": False,
            "honeypot": ""
        }
    }
    response = client.post('/api/verify', json=payload)
    assert response.status_code == 200
    data = response.get_json()
    
    assert data['decision'] == 'ALLOW'
    assert data['risk_score'] <= 15.0
    assert data['confidence'] in ('HIGH', 'MEDIUM')
    assert any('human' in r.lower() or 'validated' in r.lower() for r in data['reasons'])
    assert data['latency_ms'] < 200.0

def test_normal_flow_logged_in_audit(client):
    sid = f"sess_audit_test_{int(time.time()*1000)}"
    payload = {
        "sessionId": sid,
        "isAccessibleMode": False,
        "telemetry": {
            "mouseCurvature": 0.60,
            "mouseEntropy": 0.80,
            "mouseEventCount": 30,
            "typingVariance": 40.0,
            "dwellTime": 2100,
            "screenWidth": 1440,
            "screenHeight": 900,
            "isWebDriver": False,
            "honeypot": ""
        }
    }
    client.post('/api/verify', json=payload)
    logs = get_recent_logs(limit=10)
    matching = [l for l in logs if l.get('session_id') == sid]
    assert len(matching) == 1
    assert matching[0]['decision'] == 'ALLOW'
