# -*- coding: utf-8 -*-
"""
BeyondCAPTCHA Prototype Configuration
SIH Prototype Edition - Credential Hygiene & Environment-First Settings
No hardcoded production secrets or static passwords.
"""
import os
import secrets

class Config:
    # Ephemeral or environment-configured secrets (zero static hardcoded passwords)
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')  # None if unset; startup warns developer
    ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY') or secrets.token_hex(16)
    
    # Cryptographic salt for data-minimized IP hashing (ephemeral fallback if unset)
    IP_SALT = (os.environ.get('IP_SALT') or secrets.token_hex(16)).encode('utf-8')
    
    DB_PATH = os.environ.get('DB_PATH', 'beyondcaptcha_prototype.db')
    
    # Accessibility session and challenge parameters
    ACCESSIBILITY_CONTEXT_TTL = 300  # 5 minutes
    CHALLENGE_EXPIRATION_SECONDS = 300
    CHALLENGE_MAX_ATTEMPTS = 3
    RATE_LIMIT_PER_MINUTE = 30
    RATE_LIMIT_PER_HOUR = 600
    
    DEFAULT_ALLOW_THRESHOLD = 35.0
    DEFAULT_REJECT_THRESHOLD = 65.0
    
    DEMO_MODE = os.environ.get('DEMO_MODE', 'true').lower() == 'true'
    DATA_MINIMIZATION_ENABLED = True
    
    ALLOWED_ORIGINS = [
        'http://127.0.0.1:5000',
        'http://localhost:5000',
        'http://127.0.0.1:3000',
        'http://localhost:3000'
    ]

    @classmethod
    def check_credentials_warning(cls):
        """Notifies developer on startup if optional environment variables are missing."""
        if not os.environ.get('ADMIN_PASSWORD'):
            print("[BeyondCAPTCHA Prototype] NOTICE: ADMIN_PASSWORD environment variable is unset.")
            print("[BeyondCAPTCHA Prototype] Privileged audit API endpoints require ADMIN_API_KEY.")

