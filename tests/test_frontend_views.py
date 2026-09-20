# -*- coding: utf-8 -*-
"""
Suite 7: Frontend Views & Prototype Structure
Validates the sober student-built prototype UI:
- Demo view: Status banner, progressive disclosure, no hardcoded inputs
- Security lab: Controlled Attack Simulation header, no fake KPI boxes, 4 attack cards, 2-step replay callout, NOT ISSUED badge
- Audit view: Filter buttons (All, Allow, Reject), table headers, admin auth integration
- Integration view: Collapsed integration code fold
"""
import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_homepage_structure_and_disclosure(client):
    res = client.get('/')
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # Clean hero & architecture paths
    assert "BeyondCAPTCHA" in html
    assert "Human verification, without the accessibility barrier." in html
    assert "NORMAL" in html and "Passive verification" in html
    assert "ACCESSIBILITY" in html and "Tracking OFF" in html
    assert "BOT" in html and "Risk detection" in html

    # Citizen Services Form & Credential Hygiene
    assert "Citizen Services Portal" in html
    assert 'name="username"' in html
    assert 'name="password"' in html
    assert 'value=""' in html
    assert 'DEMO ONLY: Enter any test credentials' in html

    # Status Banner & Progressive Disclosure
    assert 'id="status-summary-banner"' in html
    assert 'Waiting for verification' in html
    assert 'View Technical Details' in html
    assert 'id="raw-json-inspector"' in html
    assert 'Developer Details' in html

def test_security_lab_structure_and_no_fake_kpis(client):
    res = client.get('/security-lab')
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # Header must be clean and sober
    assert "Controlled Attack Simulation" in html
    assert "Run controlled attacks against the live verification backend." in html
    assert "hero-stats" not in html  # No fake KPI metric boxes

    # 4 Scenarios
    assert "Honeypot Trap" in html
    assert "Headless Browser" in html
    assert "Robotic Timing" in html
    assert "Replay Attack" in html

    # 6-step pipeline & 2-step replay sequence
    assert 'id="simulation-pipeline"' in html
    assert 'id="pipe-step-1"' in html
    assert 'id="pipe-step-6"' in html
    assert 'id="replay-flow-banner"' in html
    assert "2-Step Replay Attack Sequence" in html

    # Server Defense Verdict & NOT ISSUED badge
    assert "SERVER DEFENSE VERDICT" in html
    assert "Accessibility challenge:" in html
    assert "NOT ISSUED" in html
    assert "Suspicious automated traffic is rejected directly" in html

    # Progressive disclosure
    assert "View Technical Details" in html
    assert "Developer / Debug JSON" in html
    assert 'id="eval-raw-json"' in html

def test_audit_page_structure(client):
    res = client.get('/audit')
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    assert "Recent Verification Events" in html
    assert 'data-filter="all"' in html
    assert 'data-filter="ALLOW"' in html
    assert 'data-filter="REJECT"' in html
    assert "Timestamp" in html
    assert "Decision" in html
    assert "Mode" in html
    assert "Reason" in html
    assert "Risk Score" in html
    assert "Data-Minimized IP Hash" in html
    # Must send X-Admin-Key in fetch
    assert "X-Admin-Key" in html

def test_widget_embed_example(client):
    res = client.get('/embed-demo')
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    assert "Existing HTML Form + BeyondCAPTCHA Widget" in html
    assert "[ View Integration Code ]" in html
    assert "BeyondCaptcha.mount" in html
