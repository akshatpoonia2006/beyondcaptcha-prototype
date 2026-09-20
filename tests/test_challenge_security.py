# -*- coding: utf-8 -*-
"""
Suite 5: Challenge Security & Rate Limiting Verification (Section 27.5)
Verifies nonce single-use, atomic invalidation, and rate limiter enforcement.
"""
import pytest
from app import app
from challenge_service import ChallengeService

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_challenge_token_single_use():
    c = ChallengeService.generate_math_challenge("sess_single_use")
    cid = c['challenge_id']
    ans = ChallengeService.get_challenge(cid)['expected_answer']
    
    r1 = ChallengeService.verify_answer(cid, ans)
    assert r1['success'] is True
    
    r2 = ChallengeService.verify_answer(cid, ans)
    assert r2['success'] is False
    assert "consumed" in r2['reason'].lower()

def test_rate_limiting_enforcement(client):
    ip_header = {'X-Forwarded-For': '198.51.100.88'}
    responses = []
    for _ in range(35):
        res = client.post('/api/challenge/new', json={"sessionId": "flood"}, headers=ip_header)
        responses.append(res.status_code)
    
    assert 429 in responses
