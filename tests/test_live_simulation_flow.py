# -*- coding: utf-8 -*-
"""
Suite 8: Live Attack Simulation & Replay Protection (Parts H through V)
Validates:
1. Demo Page simulation banner, simulated cursor, 8-stage timeline, and warning card.
2. Security Lab controller links to demo page simulations.
3. Backend evaluation for Honeypot, Headless, Robotic Timing, and Replay vectors.
4. Absolute rule: Suspicious requests are REJECTED directly and NEVER receive an accessibility challenge.
5. Replay Attack genuine 2-step single-use nonce invalidation.
"""
import pytest
from app import app
from challenge_service import ChallengeService

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_demo_page_simulation_elements_present(client):
    """Checks that the Demo page has all required visual simulation controls (Parts L, M, S, T, U, V)."""
    res = client.get('/?simulate=headless')
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # Simulation Banner & Simulated Cursor
    assert 'id="simulation-banner"' in html
    assert 'CONTROLLED ATTACK SIMULATION' in html
    assert 'id="simulated-cursor"' in html
    assert 'id="cursor-label"' in html

    # Live Activity Panel (Requirement 8)
    assert 'id="simulation-activity-panel"' in html
    assert 'Current Activity:' in html

    # 8-Stage Timeline
    assert 'id="simulation-pipeline"' in html
    for i in range(1, 9):
        assert f'id="pipe-step-{i}"' in html

    # 2-Step Replay Sequence Banner
    assert 'id="replay-flow-banner"' in html
    assert '2-Step Replay Attack Sequence' in html

    # Human-readable Warning Card
    assert 'id="attack-warning-card"' in html
    assert 'Suspicious Automated Activity Detected' in html
    assert 'Accessibility challenge:' in html
    assert 'NOT ISSUED' in html
    assert 'Accessibility is not a second-chance path for bots' in html

    # Server Defense Verdict & Progressive Details
    assert 'id="defense-verdict-card"' in html
    assert 'SERVER DEFENSE VERDICT' in html
    assert 'id="raw-json-inspector"' in html

def test_security_lab_controller_links_to_demo_form(client):
    """Checks that Security Lab cards direct to the live Demo form with ?simulate=<type> (Parts I & J)."""
    res = client.get('/security-lab')
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    assert '/?simulate=honeypot' in html
    assert '/?simulate=headless' in html
    assert '/?simulate=robotic' in html
    assert '/?simulate=replay' in html
    assert '/?simulate=accessibility' in html

def test_honeypot_simulation_backend_verdict(client):
    """Validates real backend evaluation for Honeypot attack simulation (Part O)."""
    payload = {
        "sessionId": "sim_test_hp",
        "honeypot": "bot_crawler_spam_payload",
        "timeOnPage": 400,
        "dwellTime": 400,
        "isAccessibleMode": False
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()

    assert data['decision'] == 'REJECT'
    assert data['risk_score'] == 100.0
    assert any("honeypot" in r.lower() for r in data['reasons'])
    assert data['controls']['challenge'] == "— Not issued"

def test_headless_simulation_backend_verdict(client):
    """Validates real backend evaluation for Headless Browser simulation (Part P)."""
    payload = {
        "sessionId": "sim_test_headless",
        "honeypot": "",
        "browserFlags": {
            "webdriver": True,
            "screenWidth": 0,
            "screenHeight": 0
        },
        "isWebDriver": True,
        "isAccessibleMode": False
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()

    assert data['decision'] == 'REJECT'
    assert data['risk_score'] >= 80.0
    assert any("webdriver" in r.lower() or "automated" in r.lower() for r in data['reasons'])
    assert data['controls']['challenge'] == "— Not issued"

def test_robotic_timing_simulation_backend_verdict(client):
    """Validates real backend evaluation for Robotic Timing simulation (Part Q)."""
    payload = {
        "sessionId": "sim_test_robotic",
        "honeypot": "",
        "dwellTime": 38,
        "typingVariance": 0.0,
        "isAccessibleMode": False
    }
    res = client.post('/api/verify', json=payload)
    assert res.status_code == 200
    data = res.get_json()

    assert data['decision'] == 'REJECT'
    assert data['risk_score'] >= 80.0
    assert data['controls']['challenge'] == "— Not issued"

def test_replay_attack_two_step_demonstration(client):
    """
    Validates genuine 2-step replay defense (Part R):
    Request 1 with valid challenge -> ALLOW (nonce consumed)
    Request 2 with SAME session & challenge -> REJECT (Challenge already consumed)
    """
    test_session = "sess_replay_test_2step"

    # 1. Establish context
    start_res = client.post('/api/accessibility/start', json={"sessionId": test_session})
    assert start_res.status_code == 200
    ctx_id = start_res.get_json()['contextId']

    # 2. Get challenge
    chal_res = client.post('/api/challenge/new', json={"sessionId": test_session, "contextId": ctx_id})
    assert chal_res.status_code == 200
    cid = chal_res.get_json()['challengeId']
    expected_ans = ChallengeService.get_challenge(cid)['expected_answer']

    # 3. Request #1: Legitimate verification succeeds
    res1 = client.post('/api/verify', json={
        "sessionId": test_session,
        "challengeId": cid,
        "contextId": ctx_id,
        "answer": expected_ans,
        "isAccessibleMode": True
    })
    assert res1.status_code == 200
    data1 = res1.get_json()
    assert data1['decision'] == 'ALLOW'
    assert data1['controls']['challenge'] == "✓ Solved"

    # 4. Request #2: Same session & challenge reused -> REJECT
    res2 = client.post('/api/verify', json={
        "sessionId": test_session,
        "challengeId": cid,
        "contextId": ctx_id,
        "answer": expected_ans,
        "isAccessibleMode": True
    })
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert data2['decision'] == 'REJECT'
    assert any("already consumed" in r.lower() or "anti-replay" in r.lower() for r in data2['reasons'])

def test_accessibility_simulation_backend_verdict(client):
    """Validates real backend evaluation for Automatic Accessibility simulation (Scenario 5)."""
    payload = {
        "sessionId": "sim_test_a11y_flow",
        "flowType": "automatic_accessibility",
        "accessibility_compatible": True,
        "keyboardNavigation": True,
        "dwellTime": 2200,
        "timeOnPage": 2200,
        "keystrokes": 26,
        "typingVariance": 42.0,
        "browserFlags": {"webdriver": False, "screenWidth": 1920, "screenHeight": 1080},
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

