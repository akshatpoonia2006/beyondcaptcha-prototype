# -*- coding: utf-8 -*-
"""
Suite 3: Bot Simulation & OWASP Defense (Section 27.3)
Tests Honeypot, Headless Browser, Robotic Timing, and Replay Defense.
Strict Rule: Bots receive BLOCK and NEVER receive accessible challenge fallback.
"""
import pytest
from app import app
from challenge_service import ChallengeService

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_honeypot_trap_blocks_immediately(client):
    payload = {
        "sessionId": "sess_bot_honeypot",
        "isAccessibleMode": False,
        "telemetry": {
            "honeypot": "spam_bot_input",
            "mouseCurvature": 0.5,
            "dwellTime": 2000
        }
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['decision'] in ('REJECT', 'BLOCK')
    assert data['risk_score'] >= 90.0
    assert any("honeypot" in r.lower() for r in data['reasons'])

def test_headless_browser_blocks_immediately(client):
    payload = {
        "sessionId": "sess_bot_headless",
        "isAccessibleMode": False,
        "telemetry": {
            "isWebDriver": True,
            "screenWidth": 0,
            "screenHeight": 0,
            "dwellTime": 1500
        }
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['decision'] in ('REJECT', 'BLOCK')
    assert data['risk_score'] >= 80.0
    assert any("webdriver" in r.lower() or "headless" in r.lower() or "automation" in r.lower() for r in data['reasons'])

def test_robotic_timing_blocks_immediately(client):
    payload = {
        "sessionId": "sess_bot_robotic",
        "isAccessibleMode": False,
        "telemetry": {
            "dwellTime": 45,
            "typingVariance": 0.0,
            "mouseCurvature": 0.0,
            "mouseEntropy": 0.0
        }
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['decision'] in ('REJECT', 'BLOCK')
    assert data['risk_score'] >= 80.0

def test_replay_attack_rejected(client):
    start_res = client.post('/api/accessibility/start', json={"sessionId": "sess_replay_target"})
    ctx_id = start_res.get_json()['contextId']

    chal_res = client.post('/api/challenge/new', json={
        "sessionId": "sess_replay_target",
        "contextId": ctx_id
    })
    cid = chal_res.get_json()['challengeId']
    expected = ChallengeService.get_challenge(cid)['expected_answer']
    
    # 1. First submission succeeds
    res1 = client.post('/api/verify', json={
        "sessionId": "sess_replay_target",
        "isAccessibleMode": True,
        "contextId": ctx_id,
        "challengeId": cid,
        "answer": expected
    })
    assert res1.get_json()['decision'] == 'ALLOW'
    
    # 2. Replay attempt with same challenge token
    res2 = client.post('/api/verify', json={
        "sessionId": "sess_replay_attacker",
        "isAccessibleMode": True,
        "contextId": ctx_id,
        "challengeId": cid,
        "answer": expected
    })
    data2 = res2.get_json()
    assert data2['decision'] == 'REJECT'
    assert any("already consumed" in r.lower() or "invalid" in r.lower() or "session" in r.lower() for r in data2['reasons'])

def test_suspicious_bot_never_receives_accessibility_challenge(client):
    """Ensures high-risk bots attempting to claim accessibility are strictly REJECTED with no challenge issued."""
    payload = {
        "sessionId": "sess_bot_claiming_a11y",
        "isAccessibleMode": True,
        "telemetry": {
            "isWebDriver": True,
            "honeypot": "spam_bot_fill",
            "screenWidth": 0,
            "screenHeight": 0
        }
    }
    res = client.post('/api/verify', json=payload)
    data = res.get_json()
    assert data['decision'] == 'REJECT'
    assert data['risk_score'] == 100.0
    assert data['controls']['challenge'] == '— Not issued'
