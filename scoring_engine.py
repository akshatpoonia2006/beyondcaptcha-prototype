# -*- coding: utf-8 -*-
"""
BeyondCAPTCHA Prototype Explainable Scoring Engine (SIH Edition)
Adheres strictly to the Fairness Principle: "Signal Absence != Bot" (Part 19)
Only anomalous PRESENT evidence contributes to risk score.
Includes explicit security_control and reason descriptions for progressive disclosure.
"""
import math
from config import Config
from database import get_system_config

class ScoringEngine:
    @classmethod
    def evaluate(cls, raw_signals, is_accessible_flow=False):
        reasons = []
        sub_scores = {}
        evaluations = []
        total_risk = 0.0

        signals = dict(raw_signals or {})
        # Unpack nested telemetry if provided
        if isinstance(signals.get('telemetry'), dict):
            for k, v in signals['telemetry'].items():
                if k not in signals:
                    signals[k] = v
        if isinstance(signals.get('signals'), dict):
            for k, v in signals['signals'].items():
                if k not in signals:
                    signals[k] = v

        # ===================================================================
        # 1. HONEYPOT TRAP (Part 17 - Evaluated First)
        # ===================================================================
        honeypot_val = signals.get('honeypot') or signals.get('honeypot_value') or ''
        if honeypot_val and str(honeypot_val).strip() != '':
            sub_scores['honeypot'] = 100.0
            reasons.append("Honeypot trap triggered: Hidden bot field was populated")
            evaluations.append({
                "signal": "Honeypot Trap",
                "value_or_state": "TRAP_TRIGGERED",
                "risk_contribution": 100.0,
                "confidence": "HIGH",
                "reason": "Hidden bot field was populated by automated scraper",
                "security_control": "Honeypot Sensor"
            })
            return {
                "risk_score": 100.0,
                "confidence": "HIGH",
                "reasons": reasons,
                "sub_scores": sub_scores,
                "evaluations": evaluations
            }
        else:
            sub_scores['honeypot'] = 0.0
            evaluations.append({
                "signal": "Honeypot Trap",
                "value_or_state": "CLEAN",
                "risk_contribution": 0.0,
                "confidence": "HIGH",
                "reason": "Trap input untouched",
                "security_control": "Honeypot Sensor"
            })

        # ===================================================================
        # 2. BROWSER AUTOMATION SIGNALS (Part 17 - Evaluated Before A11y)
        # ===================================================================
        browser_risk = 0.0
        browser_flags = signals.get('browserFlags', {})
        if not isinstance(browser_flags, dict):
            browser_flags = {}

        is_webdriver = (
            browser_flags.get('webdriver') is True or
            signals.get('webdriver') is True or
            signals.get('isWebDriver') is True or
            signals.get('headless') is True
        )

        if is_webdriver:
            browser_risk += 100.0
            reasons.append("Automated browser detected (navigator.webdriver = true)")
            evaluations.append({
                "signal": "WebDriver Automation",
                "value_or_state": "DETECTED",
                "risk_contribution": 100.0,
                "confidence": "HIGH",
                "reason": "navigator.webdriver = true (Selenium/Puppeteer crawler)",
                "security_control": "Browser Automation Heuristics"
            })

        screen_w = browser_flags.get('screenWidth', signals.get('screenWidth', 1920))
        screen_h = browser_flags.get('screenHeight', signals.get('screenHeight', 1080))
        if screen_w == 0 or screen_h == 0:
            browser_risk += 60.0
            reasons.append("Headless display dimensions detected (0x0)")
            evaluations.append({
                "signal": "Display Dimensions",
                "value_or_state": f"{screen_w}x{screen_h}",
                "risk_contribution": 60.0,
                "confidence": "HIGH",
                "reason": "Headless display dimensions detected (0x0)",
                "security_control": "Browser Display Heuristics"
            })

        sub_scores['browser_automation'] = min(browser_risk, 100.0)
        if browser_risk >= 80.0:
            return {
                "risk_score": 100.0,
                "confidence": "HIGH",
                "reasons": reasons,
                "sub_scores": sub_scores,
                "evaluations": evaluations
            }

        # ===================================================================
        # 3. EXPLICIT ACCESSIBILITY MODE (Part 18)
        # Legitimate humans in Accessible Mode have behavioral tracking disabled.
        # ===================================================================
        if is_accessible_flow or signals.get('isAccessibleMode', False):
            return {
                "risk_score": 0.0,
                "confidence": "HIGH",
                "reasons": ["Accessible Mode Active: Passive behavioral tracking disabled"],
                "sub_scores": {"accessible_mode": 0.0},
                "evaluations": [{
                    "signal": "Accessibility Mode",
                    "value_or_state": "ACTIVE",
                    "risk_contribution": 0.0,
                    "confidence": "HIGH",
                    "reason": "Behavioral tracking disabled (WCAG Protection)",
                    "security_control": "Accessibility Privacy Layer"
                }]
            }

        # ===================================================================
        # 4. INTERACTION TIMING (Dwell Time / timeOnPage)
        # ===================================================================
        time_on_page = signals.get('timeOnPage')
        if time_on_page is None:
            time_on_page = signals.get('dwellTime')
        if time_on_page is None:
            time_on_page = signals.get('dwell_time')
        if time_on_page is None:
            time_on_page = 1800

        timing_risk = 0.0
        if time_on_page <= 400:
            timing_risk = 90.0
            reasons.append(f"Superhuman submission speed ({time_on_page}ms from load to submit)")
            evaluations.append({
                "signal": "Submission Dwell Time",
                "value_or_state": f"{time_on_page}ms",
                "risk_contribution": 90.0,
                "confidence": "HIGH",
                "reason": f"Superhuman submission speed ({time_on_page}ms < 400ms)",
                "security_control": "Dwell Timing Guard"
            })
        elif time_on_page < 800:
            timing_risk = 25.0
            evaluations.append({
                "signal": "Submission Dwell Time",
                "value_or_state": f"{time_on_page}ms",
                "risk_contribution": 25.0,
                "confidence": "MEDIUM",
                "reason": "Rapid interaction",
                "security_control": "Dwell Timing Guard"
            })
        else:
            evaluations.append({
                "signal": "Submission Dwell Time",
                "value_or_state": f"{time_on_page}ms",
                "risk_contribution": 0.0,
                "confidence": "HIGH",
                "reason": "Natural human deliberation (Fairness for slow users)",
                "security_control": "Dwell Timing Guard"
            })

        sub_scores['timing'] = timing_risk
        total_risk += timing_risk * 0.30

        # ===================================================================
        # 4. KEYSTROKE CADENCE (Part 19 Fairness: missing keystrokes == neutral)
        # ===================================================================
        keystroke_risk = 0.0
        typing_variance = signals.get('typingVariance')
        keystrokes = signals.get('keystrokes', 0)
        intervals = signals.get('keystrokeIntervals', [])

        if typing_variance is not None:
            if typing_variance == 0.0 and time_on_page <= 400:
                keystroke_risk = 90.0
                reasons.append("Robotic typing cadence: zero typing jitter")
                evaluations.append({
                    "signal": "Keystroke Jitter",
                    "value_or_state": "0.0ms",
                    "risk_contribution": 90.0,
                    "confidence": "HIGH",
                    "reason": "Robotic typing cadence: zero typing jitter (programmatic input)",
                    "security_control": "Typing Cadence Analyzer"
                })
            else:
                evaluations.append({
                    "signal": "Keystroke Jitter",
                    "value_or_state": f"{typing_variance}ms",
                    "risk_contribution": 0.0,
                    "confidence": "HIGH",
                    "reason": "Natural human typing variance",
                    "security_control": "Typing Cadence Analyzer"
                })
        elif keystrokes > 0 and len(intervals) >= 2:
            mean_int = sum(intervals) / len(intervals)
            variance = sum((x - mean_int) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)

            if std_dev < 3.0:
                keystroke_risk = 90.0
                reasons.append(f"Robotic typing cadence: zero typing jitter (std dev = {std_dev:.1f}ms)")
                evaluations.append({
                    "signal": "Keystroke Jitter",
                    "value_or_state": f"std_dev={std_dev:.1f}ms",
                    "risk_contribution": 90.0,
                    "confidence": "HIGH",
                    "reason": "Robotic typing cadence: zero typing jitter",
                    "security_control": "Typing Cadence Analyzer"
                })
            else:
                evaluations.append({
                    "signal": "Keystroke Jitter",
                    "value_or_state": f"std_dev={std_dev:.1f}ms",
                    "risk_contribution": 0.0,
                    "confidence": "HIGH",
                    "reason": "Natural typing jitter",
                    "security_control": "Typing Cadence Analyzer"
                })
        else:
            # PART 19 FAIRNESS: Missing keystrokes == neutral (Autofill, password managers)
            evaluations.append({
                "signal": "Keystroke Jitter",
                "value_or_state": "ABSENT_OR_AUTOFILL",
                "risk_contribution": 0.0,
                "confidence": "NEUTRAL",
                "reason": "Keystroke absence (Password manager / Autofill neutral)",
                "security_control": "Fairness Exemption"
            })

        sub_scores['keystrokes'] = keystroke_risk
        total_risk += keystroke_risk * 0.15

        # ===================================================================
        # 5. MOUSE TRAJECTORY (Part 19 Fairness: missing mouse == neutral)
        # ===================================================================
        mouse_moves = signals.get('mouseMoves', signals.get('mouseEventCount', 0))
        is_touch = signals.get('isTouchDevice', False) or signals.get('touchEventCount', 0) > 0
        is_keyboard_nav = signals.get('keyboardNavigation', False)
        mouse_risk = 0.0

        if is_touch or is_keyboard_nav:
            evaluations.append({
                "signal": "Mouse Trajectory",
                "value_or_state": "TOUCH_OR_KEYBOARD",
                "risk_contribution": 0.0,
                "confidence": "HIGH",
                "reason": "Touch / Keyboard-only user (Exempt from cursor tracking)",
                "security_control": "Fairness Exemption"
            })
        elif mouse_moves >= 5:
            curvature = signals.get('mouseCurvature', 0.5)
            entropy = signals.get('mouseEntropy', 0.6)
            if curvature > 0.15 and entropy > 0.2:
                evaluations.append({
                    "signal": "Mouse Trajectory",
                    "value_or_state": f"curvature={curvature:.2f}",
                    "risk_contribution": 0.0,
                    "confidence": "HIGH",
                    "reason": "Natural human cursor entropy & curvature",
                    "security_control": "Trajectory Analyzer"
                })
            else:
                mouse_risk = 30.0
                evaluations.append({
                    "signal": "Mouse Trajectory",
                    "value_or_state": "linear_vector",
                    "risk_contribution": 30.0,
                    "confidence": "MEDIUM",
                    "reason": "Suspicious linear trajectory",
                    "security_control": "Trajectory Analyzer"
                })
        else:
            # PART 19 FAIRNESS: Mouse missing == neutral
            evaluations.append({
                "signal": "Mouse Trajectory",
                "value_or_state": "LOW_OR_ABSENT",
                "risk_contribution": 0.0,
                "confidence": "NEUTRAL",
                "reason": "Mouse absence (Keyboard-only / assistive neutral)",
                "security_control": "Fairness Exemption"
            })

        sub_scores['mouse'] = mouse_risk
        total_risk += mouse_risk * 0.15

        # Hard Bot Multiplier: Direct block for webdriver or robotic burst
        if browser_risk >= 60.0:
            final_risk = 100.0
            confidence = "HIGH"
        elif time_on_page <= 400 and (keystroke_risk >= 80.0 or (typing_variance is not None and typing_variance == 0.0)):
            final_risk = 100.0
            confidence = "HIGH"
        else:
            final_risk = min(max(total_risk, 0.0), 100.0)
            confidence = "HIGH" if final_risk <= 15.0 else "MEDIUM"

        # Check for accessibility compatibility signals (WCAG / Assistive profile)
        # Note: Under Fairness Principle, accessibility signals never increase risk score
        is_a11y_compatible = bool(
            signals.get('accessibility_compatible') is True or
            signals.get('accessibilityPreferred') is True or
            signals.get('isAccessibilityRouted') is True or
            signals.get('is_accessibility_routed') is True or
            signals.get('assistiveTechnology') is True or
            signals.get('flowType') in ('automatic_accessibility', 'accessibility_routing', 'accessibility_demo')
        )

        if not reasons and final_risk <= 20.0:
            reasons.append("Natural human interaction validated")

        return {
            "risk_score": round(final_risk, 1),
            "confidence": confidence,
            "reasons": reasons,
            "sub_scores": sub_scores,
            "evaluations": evaluations,
            "is_accessibility_compatible": is_a11y_compatible
        }
