# -*- coding: utf-8 -*-
"""
BeyondCAPTCHA Prototype Decision Engine (Section 12)
Server-Authoritative Policy Evaluation
Outputs: ALLOW | REJECT | ACCESSIBILITY_VERIFY
Absolute rule: Bots NEVER receive accessible challenge as a fallback!
"""
from config import Config
from database import get_system_config

class DecisionEngine:
    @classmethod
    def decide(cls, session_context, is_accessible_mode, scoring_result, challenge_result=None, context_valid=True, context_reason=None, is_accessibility_routed=False):
        config = get_system_config()
        reject_threshold = config.get('reject_threshold', Config.DEFAULT_REJECT_THRESHOLD)
        risk_score = scoring_result.get('risk_score', 0.0)
        confidence = scoring_result.get('confidence', 'MEDIUM')
        reasons = list(scoring_result.get('reasons', []))

        # 1. Absolute Security Rule: Malicious bots NEVER receive accessibility bypass!
        if risk_score >= reject_threshold:
            hp_triggered = any('honeypot' in r.lower() for r in reasons)
            if not reasons:
                reasons.append(f"Automated risk detected (Score: {risk_score:.1f} >= threshold {reject_threshold})")
            return {
                "decision": "REJECT",
                "risk_score": risk_score,
                "confidence": confidence,
                "reasons": reasons,
                "evaluations": scoring_result.get('evaluations', []),
                "controls": {
                    "honeypot": "⚠️ Triggered" if hp_triggered else "✓ Clean",
                    "replay": "✓ Protected",
                    "challenge": "— Not issued"
                }
            }

        # 2. Explicit Accessible Mode Path (Server-Authoritative Context Required)
        if is_accessible_mode:
            if not context_valid:
                reason = f"Accessibility authorization failure: {context_reason}" if context_reason else "Accessibility authorization failure: missing or invalid server accessibility context."
                is_consumed = "consumed" in (context_reason or "").lower() or "replay" in (context_reason or "").lower()
                return {
                    "decision": "REJECT",
                    "risk_score": 100.0,
                    "confidence": "HIGH",
                    "reasons": [reason],
                    "controls": {
                        "honeypot": "✓ Clean",
                        "replay": "⚠️ Replay Detected (Nonce Reused)" if is_consumed else "✓ Protected",
                        "challenge": "⚠️ Context Already Consumed (Anti-Replay)" if is_consumed else "⚠️ Unauthorized Context"
                    }
                }

            if challenge_result:
                if challenge_result.get('success'):
                    return {
                        "decision": "ALLOW",
                        "risk_score": 0.0,
                        "confidence": "HIGH",
                        "reasons": ["Accessible verification passed (Math Challenge)"],
                        "evaluations": [{
                            "signal": "accessible_challenge",
                            "value_or_state": "SOLVED",
                            "risk_contribution": 0.0,
                            "confidence": "HIGH",
                            "reason_code": "ACCESSIBLE_CHALLENGE_PASSED",
                            "security_control": "Single-Use Cryptographic Nonce"
                        }],
                        "controls": {
                            "honeypot": "✓ Clean",
                            "replay": "✓ Protected",
                            "challenge": "✓ Solved"
                        }
                    }
                else:
                    attempts_left = challenge_result.get('attempts_left', 0)
                    reason_msg = challenge_result.get('reason', 'Verification challenge failed')
                    if attempts_left > 0:
                        return {
                            "decision": "ACCESSIBILITY_VERIFY",
                            "verification_mode": "accessibility",
                            "accessibility_required": True,
                            "tracking": "OFF",
                            "reason_code": "CHALLENGE_RETRY_REQUIRED",
                            "risk_score": 50.0,
                            "confidence": "MEDIUM",
                            "reasons": [reason_msg],
                            "attempts_left": attempts_left,
                            "controls": {
                                "honeypot": "✓ Clean",
                                "replay": "✓ Protected",
                                "challenge": f"⚠️ Retry ({attempts_left} left)"
                            }
                        }
                    else:
                        return {
                            "decision": "REJECT",
                            "risk_score": 100.0,
                            "confidence": "HIGH",
                            "reasons": [reason_msg],
                            "controls": {
                                "honeypot": "✓ Clean",
                                "replay": "✓ Protected",
                                "challenge": "⚠️ Exhausted"
                            }
                        }

            # If no answer submitted yet, issue accessible challenge prompt
            return {
                "decision": "ACCESSIBILITY_VERIFY",
                "verification_mode": "accessibility",
                "accessibility_required": True,
                "tracking": "OFF",
                "reason_code": "ACCESSIBILITY_PATH_SELECTED",
                "risk_score": 0.0,
                "confidence": "HIGH",
                "reasons": ["Accessible Mode Active: Presenting non-visual text challenge"],
                "controls": {
                    "honeypot": "✓ Clean",
                    "replay": "✓ Protected",
                    "challenge": "Active"
                }
            }

        # 3. Automatic Server-Authoritative Accessibility Routing Path
        if is_accessibility_routed or scoring_result.get('is_accessibility_compatible'):
            evaluations = list(scoring_result.get('evaluations', []))
            evaluations.append({
                "signal": "Accessibility Compatibility",
                "value_or_state": "COMPATIBLE",
                "risk_contribution": 0.0,
                "confidence": "HIGH",
                "reason_code": "ACCESSIBILITY_PATH_SELECTED",
                "reason": "Accessibility-compatible interaction detected — transitioning to accessible verification mode",
                "security_control": "Accessibility Policy Router"
            })
            return {
                "decision": "ACCESSIBILITY_VERIFY",
                "verification_mode": "accessibility",
                "accessibility_required": True,
                "tracking": "OFF",
                "reason_code": "ACCESSIBILITY_PATH_SELECTED",
                "risk_score": risk_score,
                "confidence": confidence,
                "reasons": ["Accessibility-compatible interaction detected — transitioning to accessible verification mode"],
                "evaluations": evaluations,
                "controls": {
                    "honeypot": "✓ Clean",
                    "replay": "✓ Protected",
                    "challenge": "Active (Accessibility Path)"
                }
            }

        # 4. Normal Passive Flow
        if not reasons:
            reasons.append("Verified Human: Passive interaction validated within normal variance")

        return {
            "decision": "ALLOW",
            "risk_score": risk_score,
            "confidence": confidence,
            "reasons": reasons,
            "evaluations": scoring_result.get('evaluations', []),
            "controls": {
                "honeypot": "✓ Clean",
                "replay": "✓ Protected",
                "challenge": "— Not issued"
            }
        }
