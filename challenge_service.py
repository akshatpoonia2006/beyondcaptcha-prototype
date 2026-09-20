# -*- coding: utf-8 -*-
"""
BeyondCAPTCHA Prototype Accessible Challenge Service (Section 13)
Server-Generated, Random, Session-Bound, Short-Lived, Single-Use, Attempt-Limited
Enforces deterministic anti-replay: first use -> ALLOW, second use -> REJECT
"""
import random
import secrets
import time
from config import Config
from database import (
    save_challenge, get_challenge, update_challenge_attempts, mark_challenge_solved,
    mark_accessibility_context_consumed, validate_accessibility_context
)

class ChallengeService:
    # Mirror dictionary for direct test inspection
    _active_challenges = {}

    @classmethod
    def generate_math_challenge(cls, session_id, context_id=None):
        if context_id is not None:
            valid, reason = validate_accessibility_context(context_id, session_id)
            if not valid:
                raise ValueError(f"Accessibility Context Invalid: {reason}")
        challenge_id = f"mc_{secrets.token_urlsafe(16)}"
        op = random.choice(["+", "-"])

        if op == "+":
            a = random.randint(3, 9)
            b = random.randint(2, 9)
            ans = a + b
            prompt = f"What is {a} + {b}?"
            tts = f"What is {a} plus {b}?"
        else:
            a = random.randint(9, 18)
            b = random.randint(2, 8)
            ans = a - b
            prompt = f"What is {a} - {b}?"
            tts = f"What is {a} minus {b}?"

        save_challenge(challenge_id, session_id, "math", prompt, str(ans), Config.CHALLENGE_EXPIRATION_SECONDS)

        # Mirror for in-memory / direct test access
        cls._active_challenges[challenge_id] = {
            "challenge_id": challenge_id,
            "session_id": session_id,
            "type": "math",
            "prompt": prompt,
            "answer": ans,
            "expected_answer": str(ans),
            "attempts_left": Config.CHALLENGE_MAX_ATTEMPTS,
            "is_solved": False
        }

        # Multi-choice options (1 correct + 3 random distractors)
        distractors = set()
        while len(distractors) < 3:
            d = ans + random.choice([-3, -2, -1, 1, 2, 3, 4])
            if d != ans and d >= 0:
                distractors.add(str(d))
        options = [str(ans)] + list(distractors)
        random.shuffle(options)

        return {
            "challenge_id": challenge_id,
            "challengeId": challenge_id,
            "type": "math",
            "prompt": prompt,
            "tts_prompt": tts,
            "options": options,
            "expires_in_seconds": Config.CHALLENGE_EXPIRATION_SECONDS
        }

    @classmethod
    def get_challenge(cls, challenge_id):
        ch = get_challenge(challenge_id)
        if ch:
            return ch
        return cls._active_challenges.get(challenge_id)

    @classmethod
    def verify_answer(cls, challenge_id, user_answer, session_id=None, context_id=None):
        if not challenge_id or user_answer is None:
            return {"success": False, "reason": "Missing challenge identifier or answer", "attempts_left": 0}

        challenge = cls.get_challenge(challenge_id)
        if not challenge:
            return {"success": False, "reason": "Invalid or non-existent challenge identifier", "attempts_left": 0}

        now = time.time()
        expires_at = challenge.get('expires_at', now + 300)
        if now > expires_at:
            return {"success": False, "reason": "Challenge has expired. Please request a new challenge.", "attempts_left": 0}

        # Anti-Replay Defense: Single-use check
        if challenge.get('is_solved') or challenge.get('is_solved') == 1:
            return {
                "success": False,
                "reason": "Challenge already consumed (Anti-Replay Violation)",
                "attempts_left": 0
            }

        # Session binding check (Cross-session replay prevention)
        if session_id and challenge.get('session_id'):
            if str(challenge['session_id']).strip() != str(session_id).strip():
                return {
                    "success": False,
                    "reason": "Session binding mismatch (Cross-Session Challenge Tampering)",
                    "attempts_left": 0
                }

        attempts_left = challenge.get('attempts_left', 3)
        if attempts_left <= 0:
            return {
                "success": False,
                "reason": "Maximum attempts exceeded. Please request a new challenge.",
                "attempts_left": 0
            }

        expected = str(challenge.get('expected_answer', challenge.get('answer'))).strip().lower()
        cleaned_user = str(user_answer).strip().lower()

        if cleaned_user == expected:
            mark_challenge_solved(challenge_id)
            if challenge_id in cls._active_challenges:
                cls._active_challenges[challenge_id]['is_solved'] = True
            if context_id:
                mark_accessibility_context_consumed(context_id)
            return {
                "success": True,
                "reason": "Verification successful."
            }
        else:
            new_attempts = attempts_left - 1
            update_challenge_attempts(challenge_id, new_attempts)
            if challenge_id in cls._active_challenges:
                cls._active_challenges[challenge_id]['attempts_left'] = new_attempts
                
            if new_attempts > 0:
                return {
                    "success": False,
                    "reason": f"Incorrect answer. {new_attempts} attempt{'s' if new_attempts > 1 else ''} remain.",
                    "attempts_left": new_attempts
                }
            else:
                return {
                    "success": False,
                    "reason": "Maximum attempts exceeded. Verification rejected.",
                    "attempts_left": 0
                }
