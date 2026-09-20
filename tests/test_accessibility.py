# -*- coding: utf-8 -*-
"""
Suite 2: Accessibility Mode Verification (Section 27.2 & Part A, Section 1)
Validates server-controlled accessibility context initiation, token lifecycle,
cross-session anti-tampering, correct/incorrect challenges, and tracking deactivation.
"""
import time
import pytest
from app import app
from challenge_service import ChallengeService
from database import save_accessibility_context

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_accessibility_start_creates_valid_context(client):
    """Verifies that activating accessibility creates a server-authoritative context."""
    res = client.post('/api/accessibility/start', json={"sessionId": "sess_a11y_init"})
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'contextId' in data
    assert data['tracking'] == 'OFF'
    assert data['sessionId'] == "sess_a11y_init"
    assert data['expiresAt'] > time.time()

def test_challenge_generation_requires_valid_context(client):
    """Ensures /api/challenge/new strictly requires a server-issued context."""
    # 1. Calling without contextId must be rejected
    res_no_ctx = client.post('/api/challenge/new', json={"sessionId": "sess_a11y_gen"})
    assert res_no_ctx.status_code == 403
    assert res_no_ctx.get_json()['decision'] == 'REJECT'

    # 2. Starting context first succeeds
    start_res = client.post('/api/accessibility/start', json={"sessionId": "sess_a11y_gen"})
    ctx_id = start_res.get_json()['contextId']

    res = client.post('/api/challenge/new', json={
        "sessionId": "sess_a11y_gen",
        "contextId": ctx_id
    })
    assert res.status_code == 200
    data = res.get_json()
    assert "challenge_id" in data or "challengeId" in data
    assert "prompt" in data
    assert "What is" in data["prompt"]
    assert "options" in data
    assert len(data["options"]) == 4

def test_accessibility_context_expiry_rejected(client):
    """Ensures expired accessibility contexts are rejected."""
    expired_ctx = "actx_expired_test_token"
    # Create an already expired context in the database
    save_accessibility_context(expired_ctx, "sess_expired", ttl_seconds=-10)

    res = client.post('/api/challenge/new', json={
        "sessionId": "sess_expired",
        "contextId": expired_ctx
    })
    assert res.status_code == 403
    assert "expired" in res.get_json()['error'].lower()

def test_accessibility_context_session_tampering_rejected(client):
    """Ensures a context bound to Session A cannot be claimed by Session B."""
    start_res = client.post('/api/accessibility/start', json={"sessionId": "sess_legit_user"})
    ctx_id = start_res.get_json()['contextId']

    # Attacker tries using the legitimate user's contextId
    res = client.post('/api/challenge/new', json={
        "sessionId": "sess_attacker_hijack",
        "contextId": ctx_id
    })
    assert res.status_code == 403
    assert "mismatch" in res.get_json()['error'].lower() or "tampering" in res.get_json()['error'].lower()

def test_correct_answer_allows_access(client):
    """Verifies that an authorized context and correct challenge answer yields ALLOW."""
    start_res = client.post('/api/accessibility/start', json={"sessionId": "sess_a11y_correct"})
    ctx_id = start_res.get_json()['contextId']

    chal_res = client.post('/api/challenge/new', json={
        "sessionId": "sess_a11y_correct",
        "contextId": ctx_id
    })
    cid = chal_res.get_json()['challengeId']
    expected = ChallengeService.get_challenge(cid)['expected_answer']

    payload = {
        "sessionId": "sess_a11y_correct",
        "isAccessibleMode": True,
        "contextId": ctx_id,
        "challengeId": cid,
        "answer": expected,
        "telemetry": {
            "honeypot": "",
            "isWebDriver": False
        }
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['decision'] == 'ALLOW'
    assert data['risk_score'] == 0.0
    assert data['confidence'] == 'HIGH'
    assert any("accessible verification passed" in r.lower() for r in data['reasons'])

def test_incorrect_answer_triggers_retry(client):
    """Verifies that an incorrect answer triggers ACCESSIBILITY_VERIFY retry."""
    start_res = client.post('/api/accessibility/start', json={"sessionId": "sess_a11y_retry"})
    ctx_id = start_res.get_json()['contextId']

    chal_res = client.post('/api/challenge/new', json={
        "sessionId": "sess_a11y_retry",
        "contextId": ctx_id
    })
    cid = chal_res.get_json()['challengeId']
    expected = int(ChallengeService.get_challenge(cid)['expected_answer'])
    wrong = expected + 99

    payload = {
        "sessionId": "sess_a11y_retry",
        "isAccessibleMode": True,
        "contextId": ctx_id,
        "challengeId": cid,
        "answer": wrong
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['decision'] == 'ACCESSIBILITY_VERIFY'
    assert data.get('attempts_left', 0) == 2

def test_max_retries_exceeded_blocks(client):
    """Verifies that exceeding maximum retry attempts results in REJECT."""
    start_res = client.post('/api/accessibility/start', json={"sessionId": "sess_a11y_exhaust"})
    ctx_id = start_res.get_json()['contextId']

    chal_res = client.post('/api/challenge/new', json={
        "sessionId": "sess_a11y_exhaust",
        "contextId": ctx_id
    })
    cid = chal_res.get_json()['challengeId']

    # Exhaust all 3 attempts
    for _ in range(3):
        res = client.post('/api/verify', json={
            "sessionId": "sess_a11y_exhaust",
            "isAccessibleMode": True,
            "contextId": ctx_id,
            "challengeId": cid,
            "answer": "9999"
        })
    data = res.get_json()
    assert data['decision'] == 'REJECT'
    assert data['risk_score'] == 100.0

def test_behavioral_tracking_completely_disabled(client):
    """Verifies that zero mouse/typing movement is not penalized during accessible verification."""
    start_res = client.post('/api/accessibility/start', json={"sessionId": "sess_a11y_notrack"})
    ctx_id = start_res.get_json()['contextId']

    chal_res = client.post('/api/challenge/new', json={
        "sessionId": "sess_a11y_notrack",
        "contextId": ctx_id
    })
    cid = chal_res.get_json()['challengeId']
    expected = ChallengeService.get_challenge(cid)['expected_answer']

    payload = {
        "sessionId": "sess_a11y_notrack",
        "isAccessibleMode": True,
        "contextId": ctx_id,
        "challengeId": cid,
        "answer": expected,
        "telemetry": {
            "mouseCurvature": 0.0,
            "mouseEntropy": 0.0,
            "mouseEventCount": 0,
            "typingVariance": 0.0,
            "dwellTime": 0,
            "honeypot": ""
        }
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['decision'] == 'ALLOW'
    assert data['risk_score'] == 0.0

def test_client_cannot_fake_accessibility_mode_without_server_context(client):
    """
    Ensures that sending isAccessibleMode=True without a valid server context
    results in rejection (Requirement 21 & 24).
    """
    payload = {
        "sessionId": "sess_fake_a11y_bot",
        "isAccessibleMode": True,
        "contextId": None
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['decision'] == 'REJECT'
    assert any("accessibility authorization failure" in r.lower() or "missing" in r.lower() for r in data['reasons'])

def test_automatic_accessibility_routing_clean_signals_returns_verify_mode(client):
    """
    Verifies that clean accessibility-compatible interactions automatically route
    to ACCESSIBILITY_VERIFY with tracking: OFF, contextId issued, and safe terminology.
    """
    payload = {
        "sessionId": "sess_a11y_auto_clean",
        "flowType": "automatic_accessibility",
        "accessibility_compatible": True,
        "dwellTime": 1500,
        "timeOnPage": 1500,
        "keystrokes": 18,
        "typingVariance": 35.0,
        "honeypot": "",
        "isAccessibleMode": False
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()

    assert data['decision'] == 'ACCESSIBILITY_VERIFY'
    assert data['verification_mode'] == 'accessibility'
    assert data['accessibility_required'] is True
    assert data['tracking'] == 'OFF'
    assert data['reason_code'] == 'ACCESSIBILITY_PATH_SELECTED'
    assert 'contextId' in data and data['contextId'].startswith('actx_')
    assert data['flowType'] == 'automatic_accessibility'
    assert data['risk_score'] < 70.0

    # Non-Negotiable Principle: Safe terminology, no disability inference
    all_text = " ".join(data.get('reasons', [])) + " " + " ".join(str(e) for e in data.get('evaluations', []))
    assert "disability" not in all_text.lower()
    assert "handicapped" not in all_text.lower()
    assert "medical" not in all_text.lower()

def test_automatic_accessibility_routing_bot_rejected_with_no_fallback(client):
    """
    Absolute Rule: Bots with high risk (webdriver / honeypot) NEVER receive
    an accessibility challenge or bypass even if claiming accessibility compatibility.
    """
    payload = {
        "sessionId": "sess_a11y_bot_trap",
        "flowType": "automatic_accessibility",
        "accessibility_compatible": True,
        "honeypot": "bot_crawler_injected",
        "browserFlags": {"webdriver": True, "screenWidth": 0, "screenHeight": 0},
        "dwellTime": 50,
        "isAccessibleMode": False
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()

    assert data['decision'] == 'REJECT'
    assert data['risk_score'] >= 80.0
    assert data['decision'] != 'ACCESSIBILITY_VERIFY'
    assert data['controls']['challenge'] == "— Not issued"

def test_automatic_accessibility_flow_complete_challenge_solve(client):
    """
    End-to-end automatic accessibility routing flow:
    Initial submission -> ACCESSIBILITY_VERIFY (with contextId) ->
    /api/challenge/new -> solve challenge -> ALLOW logged as automatic_accessibility.
    """
    from config import Config
    sess_id = "sess_a11y_e2e_routing"

    # Step 1: Initial form submit triggers automatic routing
    res1 = client.post('/api/verify', json={
        "sessionId": sess_id,
        "flowType": "automatic_accessibility",
        "accessibility_compatible": True,
        "dwellTime": 1200,
        "keystrokes": 15,
        "typingVariance": 30.0,
        "honeypot": "",
        "isAccessibleMode": False
    })
    assert res1.status_code == 200
    data1 = res1.get_json()
    assert data1['decision'] == 'ACCESSIBILITY_VERIFY'
    ctx_id = data1['contextId']

    # Step 2: Request arithmetic challenge using the server-issued contextId
    chal_res = client.post('/api/challenge/new', json={
        "sessionId": sess_id,
        "contextId": ctx_id,
        "type": "math"
    })
    assert chal_res.status_code == 200
    chal_data = chal_res.get_json()
    cid = chal_data['challengeId']
    expected_ans = ChallengeService.get_challenge(cid)['expected_answer']

    # Step 3: Submit challenge solution
    res2 = client.post('/api/verify', json={
        "sessionId": sess_id,
        "contextId": ctx_id,
        "challengeId": cid,
        "answer": expected_ans,
        "isAccessibleMode": True,
        "flowType": "automatic_accessibility"
    })
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert data2['decision'] == 'ALLOW'
    assert data2['risk_score'] == 0.0
    assert data2['controls']['challenge'] == '✓ Solved'

    # Step 4: Validate audit log records flow_type: automatic_accessibility
    audit_res = client.get('/api/admin/logs', headers={'X-Admin-Key': Config.ADMIN_API_KEY})
    assert audit_res.status_code == 200
    logs = audit_res.get_json()['logs']
    matching_logs = [l for l in logs if l['session_id'] == sess_id]
    assert len(matching_logs) >= 1
    assert matching_logs[0]['flow_type'] == 'automatic_accessibility'
    assert matching_logs[0]['decision'] == 'ALLOW'


