# -*- coding: utf-8 -*-
"""
BeyondCAPTCHA Prototype Persistence Layer
SQLite with WAL mode and Data-Minimized Telemetry (Section 22)
Never stores passwords, OTP secrets, or raw form values.
"""
import sqlite3
import hashlib
import time
import json
from config import Config

def get_db():
    conn = sqlite3.connect(Config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for high concurrency
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn

def hash_ip(ip_str):
    """Hash IP address using salted SHA-256 for rate limiting without storing raw PII."""
    if not ip_str:
        return "unknown_client"
    return hashlib.sha256(Config.IP_SALT + ip_str.encode('utf-8')).hexdigest()[:24]

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Verification audit log (Data-minimized telemetry)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS verification_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        ip_hash TEXT NOT NULL,
        flow_type TEXT NOT NULL,
        risk_score REAL NOT NULL,
        decision TEXT NOT NULL,
        reasons_json TEXT NOT NULL,
        created_at REAL NOT NULL
    );
    """)
    
    # Server-Authoritative Accessibility Contexts (Section 1)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS accessibility_contexts (
        context_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        is_consumed INTEGER NOT NULL DEFAULT 0,
        expires_at REAL NOT NULL,
        created_at REAL NOT NULL
    );
    """)
    
    # Challenges store
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS challenges (
        challenge_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        challenge_type TEXT NOT NULL,
        prompt_text TEXT NOT NULL,
        expected_answer TEXT NOT NULL,
        attempts_left INTEGER NOT NULL,
        is_solved INTEGER NOT NULL DEFAULT 0,
        expires_at REAL NOT NULL,
        created_at REAL NOT NULL
    );
    """)
    
    # Rate limits store (sliding window)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        timestamp REAL NOT NULL
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rate_key_time ON rate_limits(key, timestamp);")

    # Dynamic system config
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_config (
        key TEXT PRIMARY KEY,
        value REAL NOT NULL
    );
    """)

    # Seed default config
    defaults = [
        ('allow_threshold', Config.DEFAULT_ALLOW_THRESHOLD),
        ('reject_threshold', Config.DEFAULT_REJECT_THRESHOLD)
    ]
    cursor.executemany("INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?);", defaults)

    conn.commit()
    conn.close()

def save_verification_log(session_id, ip, flow_type, risk_score, decision, reasons):
    conn = get_db()
    ip_h = hash_ip(ip)
    reasons_str = json.dumps(reasons if isinstance(reasons, list) else [str(reasons)])
    now = time.time()
    conn.execute(
        "INSERT INTO verification_logs (session_id, ip_hash, flow_type, risk_score, decision, reasons_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (session_id, ip_h, flow_type, float(risk_score), decision, reasons_str, now)
    )
    conn.commit()
    conn.close()

def get_recent_logs(limit=25):
    conn = get_db()
    rows = conn.execute(
        "SELECT session_id, ip_hash, flow_type, risk_score, decision, reasons_json, created_at FROM verification_logs ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        try:
            reasons = json.loads(r['reasons_json'])
        except Exception:
            reasons = [r['reasons_json']]
        result.append({
            'session_id': r['session_id'],
            'ip_hash': r['ip_hash'],
            'flow_type': r['flow_type'],
            'risk_score': r['risk_score'],
            'decision': r['decision'],
            'reasons': reasons,
            'timestamp': r['created_at'],
            'formatted_time': time.strftime('%H:%M:%S', time.localtime(r['created_at']))
        })
    return result

def save_challenge(challenge_id, session_id, ctype, prompt, answer, ttl_seconds):
    conn = get_db()
    now = time.time()
    expires = now + ttl_seconds
    conn.execute(
        "INSERT OR REPLACE INTO challenges (challenge_id, session_id, challenge_type, prompt_text, expected_answer, attempts_left, is_solved, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)",
        (challenge_id, session_id, ctype, prompt, str(answer).strip().lower(), Config.CHALLENGE_MAX_ATTEMPTS, expires, now)
    )
    conn.commit()
    conn.close()

def get_challenge(challenge_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,)).fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def mark_challenge_solved(challenge_id):
    conn = get_db()
    conn.execute("UPDATE challenges SET is_solved = 1 WHERE challenge_id = ?", (challenge_id,))
    conn.commit()
    conn.close()

def update_challenge_attempts(challenge_id, attempts_left):
    conn = get_db()
    conn.execute("UPDATE challenges SET attempts_left = ? WHERE challenge_id = ?", (attempts_left, challenge_id))
    conn.commit()
    conn.close()

def check_rate_limit(key, max_requests=60, window_seconds=60):
    conn = get_db()
    now = time.time()
    cutoff = now - window_seconds
    # Prune old records
    conn.execute("DELETE FROM rate_limits WHERE key = ? AND timestamp < ?", (key, cutoff))
    # Count current window requests
    row = conn.execute("SELECT COUNT(*) as count FROM rate_limits WHERE key = ? AND timestamp >= ?", (key, cutoff)).fetchone()
    current_count = row['count'] if row else 0

    if current_count >= max_requests:
        conn.close()
        return False, 0, int(window_seconds)

    conn.execute("INSERT INTO rate_limits (key, timestamp) VALUES (?, ?)", (key, now))
    conn.commit()
    conn.close()
    return True, max_requests - current_count - 1, 0

def get_system_config():
    conn = get_db()
    rows = conn.execute("SELECT key, value FROM system_config").fetchall()
    conn.close()
    cfg = {}
    for r in rows:
        cfg[r['key']] = r['value']
    return cfg

# -----------------------------------------------------------------------------
# Accessibility Context Lifecycle Management (Section 1)
# -----------------------------------------------------------------------------
def save_accessibility_context(context_id, session_id, ttl_seconds=300):
    conn = get_db()
    now = time.time()
    expires = now + ttl_seconds
    conn.execute(
        "INSERT OR REPLACE INTO accessibility_contexts (context_id, session_id, is_consumed, expires_at, created_at) VALUES (?, ?, 0, ?, ?)",
        (str(context_id).strip(), str(session_id).strip(), expires, now)
    )
    conn.commit()
    conn.close()

def get_accessibility_context(context_id):
    if not context_id:
        return None
    conn = get_db()
    row = conn.execute("SELECT * FROM accessibility_contexts WHERE context_id = ?", (str(context_id).strip(),)).fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def mark_accessibility_context_consumed(context_id):
    if not context_id:
        return
    conn = get_db()
    conn.execute("UPDATE accessibility_contexts SET is_consumed = 1 WHERE context_id = ?", (str(context_id).strip(),))
    conn.commit()
    conn.close()

def validate_accessibility_context(context_id, session_id=None):
    """
    Validates that an accessibility context exists, is active, has not expired,
    matches the bound session, and has not already been consumed.
    Returns: (bool is_valid, str reason)
    """
    if not context_id:
        return False, "Missing accessibility context token. Request /api/accessibility/start first."
    
    ctx = get_accessibility_context(context_id)
    if not ctx:
        return False, "Accessibility context not found or invalid."
    
    now = time.time()
    if now > ctx.get('expires_at', 0):
        return False, "Accessibility context has expired. Please re-enable accessible mode."
    
    if ctx.get('is_consumed') or ctx.get('is_consumed') == 1:
        return False, "Accessibility context already consumed."
    
    if session_id and str(ctx.get('session_id')).strip() != str(session_id).strip():
        return False, "Accessibility context session binding mismatch (Tampering detected)."
    
    return True, "Valid accessibility context."

