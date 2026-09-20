# -*- coding: utf-8 -*-
"""
BeyondCAPTCHA Standalone Prototype Server (SIH Edition)
High-performance, minimal, self-contained Flask application.
"""
from flask import Flask, request, jsonify, render_template, send_from_directory
import os
import time
import secrets
from config import Config
from database import (
    init_db, save_verification_log, get_recent_logs, check_rate_limit, hash_ip,
    save_accessibility_context, validate_accessibility_context, mark_accessibility_context_consumed
)
from scoring_engine import ScoringEngine
from decision_engine import DecisionEngine
from challenge_service import ChallengeService

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = Config.SECRET_KEY

# Initialize database and print environment notice
init_db()
Config.check_credentials_warning()

# -------------------------------------------------------------
# Middleware: Security Headers & CORS Preflight (Section 23)
# -------------------------------------------------------------
@app.before_request
def handle_preflight_and_ratelimit():
    origin = request.headers.get('Origin')
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        if origin in Config.ALLOWED_ORIGINS:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-Admin-Key'
            response.headers['Access-Control-Max-Age'] = '86400'
        return response, 204

    # Apply rate limiting to API endpoints
    if request.path.startswith('/api/'):
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
        client_key = hash_ip(client_ip)
        limit = 1000 if (app.config.get('TESTING') and client_ip == '127.0.0.1') else Config.RATE_LIMIT_PER_MINUTE
        allowed, remaining, retry_after = check_rate_limit(client_key, max_requests=limit, window_seconds=60)
        if not allowed:
            return jsonify({
                "decision": "REJECT",
                "risk_score": 100.0,
                "reasons": ["Rate limit exceeded. Please wait before retrying."]
            }), 429

@app.after_request
def add_security_headers(response):
    origin = request.headers.get('Origin')
    if origin in Config.ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'

    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self';"
    )
    return response

# -------------------------------------------------------------
# Favicon Route (Returns 200 OK without 405 error)
# -------------------------------------------------------------
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/x-icon')

# -------------------------------------------------------------
# User-Facing Views (Sections 18, 19, 20, 21)
# -------------------------------------------------------------
@app.route('/')
def home_demo():
    """Citizen Services Portal Demo (Section 19)"""
    return render_template('index.html')

@app.route('/security-lab')
def security_lab():
    """Security Demo Testbench (Section 14 & 15)"""
    return render_template('security-lab.html')

@app.route('/embed-demo')
def embed_demo():
    """Integration Demo (Section 20)"""
    return render_template('widget-embed-example.html')

@app.route('/admin')
@app.route('/audit')
def audit_view():
    """Compact Simple Audit View with Demo Access Key (Section 21 & Part A)"""
    return render_template('audit.html', admin_api_key=Config.ADMIN_API_KEY)

# -------------------------------------------------------------
# API Endpoints
# -------------------------------------------------------------
@app.route('/api/accessibility/start', methods=['POST'])
def start_accessibility():
    """
    Server-Authoritative Accessibility Context Initiation (Part A, Section 1).
    User explicitly activates accessible verification.
    Server creates short-lived, session-bound context and deactivates tracking.
    """
    data = request.get_json() or {}
    session_id = data.get('sessionId', f"sess_{secrets.token_hex(8)}")
    context_id = f"actx_{secrets.token_urlsafe(16)}"
    
    save_accessibility_context(context_id, session_id, ttl_seconds=Config.ACCESSIBILITY_CONTEXT_TTL)
    
    return jsonify({
        "success": True,
        "contextId": context_id,
        "sessionId": session_id,
        "expiresAt": time.time() + Config.ACCESSIBILITY_CONTEXT_TTL,
        "ttlSeconds": Config.ACCESSIBILITY_CONTEXT_TTL,
        "tracking": "OFF",
        "message": "Accessible verification context established. Behavioral tracking disabled."
    })

@app.route('/api/challenge/new', methods=['POST'])
def new_challenge():
    """
    Issues accessible arithmetic challenge.
    Strictly requires a valid, server-created accessibility context (Part A, Section 1).
    """
    data = request.get_json() or {}
    session_id = data.get('sessionId', f"sess_{secrets.token_hex(8)}")
    context_id = data.get('contextId') or data.get('context_id')

    if not context_id and not app.config.get('TESTING_ALLOW_CONTEXTLESS_CHALLENGE'):
        return jsonify({
            "decision": "REJECT",
            "risk_score": 100.0,
            "error": "Missing accessibility contextId. Call /api/accessibility/start first.",
            "reasons": ["Unauthenticated accessibility challenge request rejected."]
        }), 403

    if context_id:
        is_valid, reason = validate_accessibility_context(context_id, session_id)
        if not is_valid:
            return jsonify({
                "decision": "REJECT",
                "risk_score": 100.0,
                "error": f"Accessibility context invalid: {reason}",
                "reasons": [reason]
            }), 403

    try:
        challenge = ChallengeService.generate_math_challenge(session_id, context_id=context_id)
        challenge['contextId'] = context_id
        return jsonify(challenge)
    except Exception as e:
        return jsonify({
            "decision": "REJECT",
            "risk_score": 100.0,
            "error": str(e)
        }), 400

@app.route('/api/verify', methods=['POST'])
def verify():
    t0 = time.perf_counter()
    data = request.get_json() or {}
    session_id = data.get('sessionId', f"sess_{secrets.token_hex(8)}")
    challenge_id = data.get('challengeId') or data.get('challenge_id')
    context_id = data.get('contextId') or data.get('context_id')
    user_answer = data.get('answer')
    is_a11y = bool(data.get('isAccessibleMode', False)) or (challenge_id is not None)
    flow_type = data.get('flowType', 'accessible_math' if is_a11y else 'normal_passive')

    # Server-controlled accessibility context validation
    context_valid = False
    ctx_reason = None
    if is_a11y:
        if context_id:
            context_valid, ctx_reason = validate_accessibility_context(context_id, session_id)
        else:
            context_valid = False
            ctx_reason = "Missing server-issued contextId."

    challenge_result = None
    if challenge_id and user_answer is not None:
        challenge_result = ChallengeService.verify_answer(
            challenge_id, user_answer, session_id=session_id, context_id=context_id
        )

    # Evaluate scoring heuristics (evaluates honeypot, webdriver, timing)
    scoring_result = ScoringEngine.evaluate(data, is_accessible_flow=is_a11y)

    # Check for automatic accessibility routing
    is_a11y_routed = bool(
        data.get('accessibility_compatible') or
        data.get('accessibilityPreferred') or
        data.get('is_accessibility_routed') or
        data.get('isAccessibilityRouted') or
        scoring_result.get('is_accessibility_compatible') or
        flow_type in ('automatic_accessibility', 'accessibility_routing', 'accessibility_demo')
    )

    # Server-authoritative decision
    verdict = DecisionEngine.decide(
        session_context={"session_id": session_id},
        is_accessible_mode=is_a11y,
        scoring_result=scoring_result,
        challenge_result=challenge_result,
        context_valid=context_valid,
        context_reason=ctx_reason,
        is_accessibility_routed=is_a11y_routed
    )

    # If server policy routes to accessible verification, auto-generate server context if missing
    if verdict.get('decision') == 'ACCESSIBILITY_VERIFY':
        if not context_id:
            context_id = f"actx_{secrets.token_urlsafe(16)}"
            save_accessibility_context(context_id, session_id, ttl_seconds=Config.ACCESSIBILITY_CONTEXT_TTL)
        verdict['contextId'] = context_id
        verdict['verification_mode'] = 'accessibility'
        verdict['accessibility_required'] = True
        verdict['tracking'] = 'OFF'
        if 'reason_code' not in verdict:
            verdict['reason_code'] = 'ACCESSIBILITY_PATH_SELECTED'
        flow_type = 'automatic_accessibility'

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')

    # Save to data-minimized audit log (Section 22)
    save_verification_log(
        session_id=session_id,
        ip=client_ip,
        flow_type=flow_type,
        risk_score=verdict.get('risk_score', 0.0),
        decision=verdict.get('decision', 'REJECT'),
        reasons=verdict.get('reasons', [])
    )

    verdict['latency_ms'] = elapsed_ms
    verdict['flowType'] = flow_type
    verdict['isAccessibleMode'] = is_a11y or (verdict.get('decision') == 'ACCESSIBILITY_VERIFY')
    if context_id:
        verdict['contextId'] = context_id

    return jsonify(verdict)

@app.route('/api/admin/logs', methods=['GET'])
def admin_logs():
    # Authorization boundary check (Part A, Section 2)
    auth_key = request.headers.get('X-Admin-Key') or request.headers.get('Authorization') or request.args.get('api_key')
    if auth_key and auth_key.startswith('Bearer '):
        auth_key = auth_key[7:].strip()
    
    expected_key = Config.ADMIN_API_KEY
    if not auth_key or auth_key != expected_key:
        return jsonify({
            "error": "Unauthorized access to audit logs. Valid X-Admin-Key or Authorization required.",
            "boundary": "PROTOTYPE_ADMIN_RESTRICTED"
        }), 401

    limit = min(int(request.args.get('limit', 25)), 100)
    logs = get_recent_logs(limit=limit)
    return jsonify({"logs": logs, "total": len(logs)})

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "service": "BeyondCAPTCHA Prototype",
        "version": "1.0.0-sih"
    })

if __name__ == '__main__':
    print("=" * 65)
    print(" BeyondCAPTCHA Prototype - SIH Edition")
    print(" Running at: http://127.0.0.1:5000")
    print("=" * 65)
    app.run(host='127.0.0.1', port=5000, debug=False)
