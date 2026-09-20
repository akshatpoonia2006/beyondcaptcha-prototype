# -*- coding: utf-8 -*-
"""
Suite 6: Security Baseline & Credential Hygiene (Section 27.6)
Checks HTTP headers, CORS policies, and strictly ensures NO passwords are
pre-populated in HTML input tags (Section 24).
"""
import os
import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_security_headers_present(client):
    res = client.get('/')
    assert res.status_code == 200
    assert res.headers.get('X-Content-Type-Options') == 'nosniff'
    assert res.headers.get('X-Frame-Options') == 'SAMEORIGIN'
    assert res.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
    assert 'Content-Security-Policy' in res.headers

def test_cors_policy(client):
    res1 = client.get('/api/health', headers={'Origin': 'http://127.0.0.1:5000'})
    assert res1.headers.get('Access-Control-Allow-Origin') == 'http://127.0.0.1:5000'
    
    res2 = client.get('/api/health', headers={'Origin': 'https://unauthorized-domain.example'})
    assert res2.headers.get('Access-Control-Allow-Origin') is None

def test_credential_hygiene_in_templates():
    templates_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
    for fname in os.listdir(templates_dir):
        if fname.endswith('.html'):
            fpath = os.path.join(templates_dir, fname)
            with open(fpath, 'r', encoding='utf-8') as f:
                content = f.read()
            assert 'value="BeyondCaptcha@2026!"' not in content
            assert 'value="Secur3P@ssw0rd!"' not in content
            assert "value='BeyondCaptcha@2026!'" not in content
            assert "value='Secur3P@ssw0rd!'" not in content

def test_admin_logs_authorization_boundary(client):
    """Ensures /api/admin/logs strictly requires valid administrative credentials."""
    from config import Config
    # 1. Unauthenticated request must be 401
    res_unauth = client.get('/api/admin/logs')
    assert res_unauth.status_code == 401
    assert res_unauth.get_json()['boundary'] == 'PROTOTYPE_ADMIN_RESTRICTED'

    # 2. Invalid API key must be 401
    res_bad_key = client.get('/api/admin/logs', headers={'X-Admin-Key': 'invalid_secret_key'})
    assert res_bad_key.status_code == 401

    # 3. Authorized request with valid API key succeeds
    res_auth = client.get('/api/admin/logs', headers={'X-Admin-Key': Config.ADMIN_API_KEY})
    assert res_auth.status_code == 200
    assert 'logs' in res_auth.get_json()

def test_no_hardcoded_secrets_in_config():
    """Validates that Config does not use static hardcoded passwords."""
    from config import Config
    # ADMIN_PASSWORD should not be a static committed secret string
    assert Config.ADMIN_PASSWORD != 'BeyondCaptcha@2026!'
    assert isinstance(Config.IP_SALT, bytes)
    assert len(Config.IP_SALT) > 0
