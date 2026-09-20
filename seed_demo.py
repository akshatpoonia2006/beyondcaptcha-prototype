# -*- coding: utf-8 -*-
"""
Seed realistic demonstration records into SQLite for BeyondCAPTCHA Prototype.
"""
from database import init_db, save_verification_log

def seed():
    init_db()
    demo_events = [
        ("sess_normal_01", "192.168.1.10", "normal_passive", 0.0, "ALLOW", ["Verified Human: Passive interaction validated within normal variance"]),
        ("sess_a11y_01", "192.168.1.15", "accessible_math", 0.0, "ALLOW", ["Accessible verification passed"]),
        ("sess_bot_hp", "10.0.0.50", "bot_simulation", 100.0, "REJECT", ["Honeypot trap triggered: Hidden bot field was populated"]),
        ("sess_bot_headless", "10.0.0.51", "bot_simulation", 100.0, "REJECT", ["Automated browser detected (navigator.webdriver = true)"]),
        ("sess_bot_replay", "10.0.0.52", "bot_simulation", 100.0, "REJECT", ["Challenge already consumed (Anti-Replay Violation)"])
    ]
    for s_id, ip, flow, score, dec, reasons in demo_events:
        save_verification_log(s_id, ip, flow, score, dec, reasons)
    print("Successfully seeded baseline demonstration events.")

if __name__ == "__main__":
    seed()
