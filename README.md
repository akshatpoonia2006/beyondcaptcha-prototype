# BeyondCAPTCHA — Accessible, Adaptive Human Verification
### SIH Prototype Edition (Student-Built Working Cybersecurity Prototype)

> **Protect public digital infrastructure and citizen services without imposing inaccessible visual puzzles or collecting intrusive biometric surveillance.**

---

## 1. Quick Start

### Windows
Double-click `run_app.bat` or run:
```cmd
run_app.bat
```

### Linux / macOS
```bash
chmod +x run_app.sh
./run_app.sh
```

### Manual Setup
```bash
# 1. Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Configure environment variables
# Copy .env.example to .env or set ADMIN_API_KEY
copy .env.example .env

# 4. Seed database and start Flask server
python seed_demo.py
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

---

## 2. Interactive Walk-Through Guide

### Flow 1: Normal Human Verification (`/`)
1. Open `http://127.0.0.1:5000/`.
2. See the **Citizen Services Portal** sign-in form.
3. Enter test credentials (`citizen@services.example` / any password).
4. Click **`Continue`**.
5. **Observed Defense**: Unobtrusive passive telemetry verifies natural typing cadence and human interaction.
6. The status banner updates to **`✓ Verified`** (Decision: `ALLOW`, Latency: `<25 ms`).
7. Click **`View Technical Details`** to inspect the evidence breakdown and collapsed **`Developer Details [ Raw JSON ]`**.

### Flow 2: Accessibility-First Verification (`/`)
1. **Option A (Manual Choice)**: Click **`♿ Use accessible verification`**.
   - Live status updates immediately: **`✓ Accessible verification active`** &bull; **`Behavioral tracking: OFF`**.
   - Server issues short-lived session context (`/api/accessibility/start`).
   - Accessible arithmetic challenge appears with optional Web Speech audio readout.
   - Solve challenge &rarr; **`✓ Verified`** (Behavioral tracking completely disabled).
2. **Option B (Automatic Server Routing)**: Assistive / accessibility-compatible interactions without bot anomalies are automatically routed by server policy to accessible verification:
   - Server returns `decision: "ACCESSIBILITY_VERIFY"`, `verification_mode: "accessibility"`, `tracking: "OFF"`, `reason_code: "ACCESSIBILITY_PATH_SELECTED"`.
   - Client widget transitions automatically, presents cognitive challenge, and records `flow_type: "automatic_accessibility"`.
   - Non-Negotiable Principle: Safe terminology used throughout; never infers medical or disability status.

### Flow 3: Controlled Live Attack & Defense Simulation (`/security-lab` &rarr; Demo Form)
1. Open **`Security Lab`** (`/security-lab`). The lab acts as a **Threat & Accessibility Controller**.
2. Select any of the **5 Scenarios**:
   - **01. Honeypot Trap**: Indiscriminate bot crawler filling hidden inputs &rarr; Redirects to Demo with `?simulate=honeypot`.
   - **02. Headless Browser**: Automation script with `navigator.webdriver=true` &rarr; Redirects to Demo with `?simulate=headless`.
   - **03. Robotic Timing**: Superhuman submission in <50ms with 0ms typing variance &rarr; Redirects to Demo with `?simulate=robotic`.
   - **04. Replay Attack**: 2-step replay sequence demonstrating cryptographic nonce invalidation &rarr; Redirects to Demo with `?simulate=replay`.
   - **05. Automatic Accessibility Routing**: Live demonstration of assistive profile detection &rarr; server routes to `ACCESSIBILITY_VERIFY` &rarr; tracking OFF &rarr; challenge solved &rarr; `ALLOW` (`?simulate=accessibility`).
3. **Live Demonstration Engine on Demo Form**:
   - **Simulated Cursor**: An animated pointer visibly moves across fields and clicks them (not instant teleportation; respects `prefers-reduced-motion`).
   - **Character-by-Character Typing**: Field values are typed in real time before submission.
   - **8-Stage Pipeline Timeline**: Real-time progress tracker (`Client Request` &rarr; `Session & Nonce` &rarr; `Trap Evaluation` &rarr; `Passive Telemetry` &rarr; `Decision Matrix` &rarr; `Accessibility Audit` &rarr; `Server Verdict` &rarr; `Audit Log`).
   - **Replay 2-Step Sequence**: Request #1 legitimate solve (`ALLOW`, token consumed) followed immediately by Request #2 replay of the same token (`REJECT`).
   - **Prominent Warning Card**: Plain-language detection summary, security controls triggered, and confirmation that `Accessibility challenge: NOT ISSUED`.
   - **Progressive Disclosure**: Human-readable verdict &rarr; Technical Details expandable drawer &rarr; Collapsed Developer Details (`[ Raw JSON ]`).

### Flow 4: Security Audit View (`/audit`)
1. Open **`Audit`** (`/audit`).
2. Review the compact log of verification sessions stored in SQLite.
3. Filter by **`All`**, **`Allow`**, or **`Reject`**.
4. Shows salted SHA-256 IP hashes, timestamps, verification modes, and plain-language reasons.
5. Privileged administrative log access is protected by `X-Admin-Key` header authentication.

---

## 3. Architecture & Defense Pipeline

```
Normal Citizen Flow:
[ Web Form ] ──► [ Passive Telemetry ] ──► [ Heuristics Engine ] ──► [ ALLOW ]

Accessible Flow:
[ ♿ Select A11y ] ──► [ Tracking: OFF ] ──► [ Session Context ] ──► [ Challenge Solve ] ──► [ ALLOW ]

Adversarial Bot Flow:
[ Bot / Crawler ] ──► [ Trap / Automation Flag ] ──► [ REJECT ] (Challenge NOT ISSUED)
```

### Core Components
- **`app.py`**: Flask backend providing `/api/verify`, `/api/challenge/new`, `/api/accessibility/start`, and authenticated `/api/admin/logs`.
- **`scoring_engine.py`**: Heuristic evaluation engine enforcing honeypot and automation traps **before** considering accessibility claims (defeats bot spoofing).
- **`decision_engine.py`**: Server-authoritative 3-way decision matrix (`ALLOW`, `REJECT`, `ACCESSIBILITY_VERIFY`).
- **`challenge_service.py`**: Single-use arithmetic challenge generator with atomic consumption.
- **`database.py`**: SQLite storage with salted SHA-256 IP hashing and accessibility context tracking.
- **`beyondcaptcha-widget.js`**: Lightweight, WCAG 2.2 AA compliant client library.

---

## 4. Security & Credential Hygiene

- **No Hardcoded Passwords**: All form input fields enforce `value=""`. No static credentials are committed to source code or HTML templates.
- **Admin Authorization Boundary**: Privileged endpoints require `X-Admin-Key` (configured via `.env` or generated ephemerally on startup).
- **Data Minimization**: Passwords, biometric mouse trajectories, and raw IP addresses are never persisted. IP hashes use cryptographic salting.
- **Security Headers**: Includes `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Content-Security-Policy`.

---

## 5. Automated Test Suite

The prototype includes a comprehensive test suite (43 tests) covering all security invariants, accessibility guarantees, fairness, live simulation flows, and frontend templates.

Run tests:
```bash
python -m pytest tests/ -v
```

### Test Coverage Summary:
- `tests/test_live_simulation_flow.py` (7 tests): Demo form simulation elements, Security Lab controller redirection, real backend verdicts for Honeypot, Headless, Robotic Timing, 2-step Replay defense sequence, and Scenario 5 Automatic Accessibility Routing.
- `tests/test_accessibility.py` (11 tests): Session context generation, expiry, tampering prevention, attempt limits, tracking disabled, automatic server routing, bot rejection precedence, and end-to-end challenge completion.
- `tests/test_bot_simulation.py` (5 tests): Honeypot, headless, robotic timing, 2-step replay defense, bot accessibility spoofing prevention.
- `tests/test_challenge_security.py` (2 tests): Single-use token invalidation, rate limiting.
- `tests/test_fairness.py` (3 tests): Slow human typists, keyboard-only navigation, mobile touch users.
- `tests/test_normal_flow.py` (2 tests): Passive human verification, audit logging.
- `tests/test_sdk.py` (3 tests): SDK lifecycle, WCAG ARIA attributes, theme system.
- `tests/test_security_baseline.py` (5 tests): Security headers, CORS policy, credential hygiene, admin auth boundary, config secrets.
- `tests/test_frontend_views.py` (4 tests): Template structure, progressive disclosure, absence of fake metric boxes.
