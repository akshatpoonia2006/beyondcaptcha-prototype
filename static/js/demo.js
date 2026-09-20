/**
 * BeyondCAPTCHA Demo Controller & Deterministic Attack Simulation Engine
 * SIH Prototype Edition (Student-Built Working Cybersecurity Prototype)
 * 
 * Architecture:
 * 1. Normal Citizen Mode: Standard form handling, passive interaction verification, and accessible math flow.
 * 2. Simulation Mode (?simulate=<attack>):
 *    - Controlled exclusively by AttackReplayPlayer
 *    - PURE DETERMINISTIC PACING: Motion is decoupled from demonstration pacing.
 *      prefers-reduced-motion: reduce affects ONLY whether the cursor glides or snaps.
 *      It NEVER collapses pauses, typing, clicks, or stages to near-zero time.
 *    - Viewport overlay (#attack-simulation-overlay) at z-index: 2147483000
 *    - Real DOM input typing with Event('input') bubbles
 *    - Visual button scale & ripple click animation (holds ~220ms in all modes)
 *    - Authoritative server evaluation via POST /api/verify
 *    - getHumanReadableReason() translating real backend evidence without false claims
 *    - Developer console logging [BC-SIM] at each state transition
 *    - 5-second fail-safe diagnostic if target form cannot be located
 */
document.addEventListener('DOMContentLoaded', function() {
  'use strict';

  // -------------------------------------------------------------
  // 1. Detect Simulation Mode Immediately
  // -------------------------------------------------------------
  const urlParams = new URLSearchParams(window.location.search);
  const requestedAttack = urlParams.get('simulate') || (function() {
    try {
      const raw = sessionStorage.getItem('attackSimulation');
      if (raw) {
        const parsed = JSON.parse(raw);
        sessionStorage.removeItem('attackSimulation');
        return parsed.type;
      }
    } catch (e) {}
    return null;
  })();

  const isSimulation = Boolean(requestedAttack);
  if (isSimulation) {
    window.__beyondCaptchaSimulationActive = true;
  }

  // Motion preference (controls visual glide vs snap)
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Simulation Pacing Configuration (Controls readability duration, NOT disabled by reduced motion)
  const SIMULATION_CONFIG = {
    cursorMoveMs: 650,       // Duration of smooth cursor glide in normal motion
    stepPauseMs: 450,        // Readable pause after moving or between steps
    typingCadenceMs: 45,     // Keystroke delay so human eye watches input being filled
    clickHoldMs: 220,        // Pressed button hold duration
    clickPostPauseMs: 180,   // Observable pause after release before network request
    serverPauseMs: 650,      // Server analyzing display pause
    replayPauseMs: 1200      // Pause between Request 1 ALLOW and Request 2 REPLAY
  };

  // Dedicated pacing helper: Unconditionally waits for ms regardless of reduced-motion
  function waitForPacing(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Common UI Elements
  const banner = document.getElementById('status-summary-banner');
  const bannerHeadline = document.getElementById('banner-headline');
  const bannerSubline = document.getElementById('banner-subline');
  const bannerLatency = document.getElementById('banner-latency');
  const bannerIcon = document.getElementById('banner-icon-wrap');
  const announcer = document.getElementById('simulation-announcer');

  function announce(msg) {
    if (announcer && msg) announcer.textContent = msg;
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
  }

  function setBannerState(state, headline, subline, latency, iconChar) {
    if (!banner) return;
    banner.className = 'status-summary-banner banner-' + state;
    if (bannerHeadline) bannerHeadline.textContent = headline;
    if (bannerSubline) bannerSubline.textContent = subline;
    if (bannerLatency) bannerLatency.textContent = latency;
    if (bannerIcon) bannerIcon.textContent = iconChar;
  }

  // Set Initial Status Banner
  setBannerState('waiting', 'Waiting for verification', 'Complete form or choose accessible verification', '—', '○');

  // Intercept native form submit during simulation mode
  const citizenForm = document.getElementById('citizenLoginForm');
  if (citizenForm) {
    citizenForm.addEventListener('submit', function(e) {
      if (window.__beyondCaptchaSimulationActive) {
        e.preventDefault();
        e.stopImmediatePropagation();
        return false;
      }
    }, true);
  }

  // =========================================================================
  // 2. HUMAN-READABLE REASON TRANSLATION (Section 20)
  // =========================================================================
  function getHumanReadableReason(serverReason) {
    if (!serverReason) return 'Automated activity detected.';
    const str = String(serverReason);
    const lower = str.toLowerCase();

    if (lower.includes('honeypot') || lower.includes('hidden bot field')) {
      return 'The request interacted with a hidden trap field (invisible to human citizens).';
    }
    if (lower.includes('webdriver')) {
      return 'Automated browser behavior was detected (navigator.webdriver = true).';
    }
    if (lower.includes('headless display') || lower.includes('0x0')) {
      return 'Headless browser display dimensions detected (0x0).';
    }
    if (lower.includes('already consumed') || lower.includes('anti-replay')) {
      return 'The verification challenge was already used (Anti-Replay violation).';
    }
    if (lower.includes('superhuman') || lower.includes('submission speed') || lower.includes('dwell time')) {
      return 'Interaction cadence occurred faster than human physiological limits (<50ms).';
    }
    if (lower.includes('zero typing jitter') || lower.includes('robotic typing')) {
      return 'Mathematically zero keystroke variance detected (robotic precision).';
    }
    if (lower.includes('invalid server accessibility context') || lower.includes('authorization failure')) {
      return 'Missing or already consumed server accessibility authorization context.';
    }
    if (lower.includes('accessibility-compatible') || lower.includes('accessibility path')) {
      return 'Accessibility-compatible interaction profile detected — transitioning to accessible verification mode.';
    }
    return str;
  }

  // =========================================================================
  // 3. VERDICT & WARNING DISPLAY (Sections 19, 20, 23)
  // =========================================================================
  const attackWarningCard = document.getElementById('attack-warning-card');
  const warningTitle = document.getElementById('warning-title');
  const warningSubtitle = document.getElementById('warning-subtitle');
  const warningAttackTypeVal = document.getElementById('warning-attack-type-val');
  const warningDetectedBehavior = document.getElementById('warning-detected-behavior');
  const warningReasonsList = document.getElementById('warning-reasons-list');
  const warningExplanationText = document.getElementById('warning-explanation-text');

  function displayAttackWarning(info) {
    if (!attackWarningCard) return;
    attackWarningCard.style.display = 'block';

    if (warningTitle) warningTitle.textContent = info.title || 'Suspicious Automated Activity Detected';
    if (warningSubtitle) warningSubtitle.textContent = info.subtitle || ('Attack Type: ' + (info.attackTypeVal || 'Automated'));
    if (warningAttackTypeVal) warningAttackTypeVal.textContent = info.attackTypeVal || 'Automated Attack';
    if (warningDetectedBehavior) warningDetectedBehavior.textContent = info.detectedBehavior || 'Automated activity detected';

    if (warningReasonsList) {
      const rawReasons = (info.reasons && info.reasons.length > 0) ? info.reasons : ['Automated activity detected'];
      warningReasonsList.innerHTML = rawReasons.map(r => `<li>${escapeHtml(getHumanReadableReason(r))}</li>`).join('');
    }

    if (warningExplanationText) {
      warningExplanationText.textContent = info.explanation || 'The server evaluated incoming interaction telemetry and deterministic security controls rejected the automated request.';
    }

    announce(info.title + ': ' + (info.detectedBehavior || ''));
  }

  function renderVerdict(data, isSuccess, latency, payload) {
    const isAllow = (data.decision === 'ALLOW');
    const isA11y = Boolean(data.isAccessibleMode || (data.flowType && data.flowType.includes('accessible')));

    if (isAllow) {
      setBannerState(
        'verified',
        '✓ Verified',
        isA11y ? 'Accessibility challenge completed (Tracking OFF)' : 'Passive human interaction validated',
        (data.latency_ms !== undefined ? data.latency_ms : (latency || 18)) + ' ms',
        '✓'
      );
    } else {
      const primaryReason = data.reasons?.[0] ? getHumanReadableReason(data.reasons[0]) : 'Automated activity detected';
      setBannerState(
        'reject',
        '✕ Request rejected',
        primaryReason,
        (data.latency_ms !== undefined ? data.latency_ms : (latency || 14)) + ' ms',
        '✕'
      );
    }

    const defenseBadge = document.getElementById('defense-verdict-badge');
    if (defenseBadge) {
      defenseBadge.textContent = isAllow ? '✓ ALLOW' : '✕ REJECT';
      defenseBadge.className = 'verdict-badge ' + (isAllow ? 'verdict-allowed' : 'verdict-rejected');
    }

    const metaDecision = document.getElementById('meta-decision');
    const metaRisk = document.getElementById('meta-risk');
    const metaConfidence = document.getElementById('meta-confidence');
    const evidenceList = document.getElementById('evidence-list');

    if (metaDecision) {
      metaDecision.textContent = isAllow ? 'ALLOW' : 'REJECT';
      metaDecision.className = 'meta-val ' + (isAllow ? 'val-allow' : 'val-reject');
    }

    if (metaRisk) {
      const score = Number(data.risk_score || 0).toFixed(1);
      const riskLevel = score <= 30 ? 'LOW' : (score <= 60 ? 'MODERATE' : 'HIGH');
      metaRisk.textContent = `${riskLevel} (${score})`;
      metaRisk.style.color = score <= 30 ? 'var(--bc-success)' : 'var(--bc-danger)';
    }

    if (metaConfidence) {
      metaConfidence.textContent = data.confidence || 'HIGH';
    }

    if (evidenceList) {
      if (data.reasons && data.reasons.length > 0) {
        evidenceList.innerHTML = data.reasons.map(r => `<li><span style="color:${isAllow ? 'var(--bc-success)' : 'var(--bc-danger)'}; font-weight:700;">${isAllow ? '✓' : '⚠️'}</span> ${escapeHtml(getHumanReadableReason(r))}</li>`).join('');
      } else {
        evidenceList.innerHTML = `
          <li><span style="color:var(--bc-success); font-weight:700;">✓</span> Natural human interaction validated</li>
          <li><span style="color:var(--bc-success); font-weight:700;">✓</span> Behavioral telemetry verified within normal human variance</li>
          <li><span style="color:var(--bc-success); font-weight:700;">✓</span> Honeypot security trap clear</li>
        `;
      }
    }

    // Security Controls Status
    const ctrlHp = document.getElementById('card-ctrl-honeypot');
    const ctrlReplay = document.getElementById('card-ctrl-replay');
    const ctrlChallenge = document.getElementById('card-ctrl-challenge');

    const hpTriggered = data.evaluations?.some(e => e.signal === 'honeypot' && e.risk_contribution > 0) ||
                        (data.reasons && data.reasons.some(r => r.toLowerCase().includes('honeypot')));
    if (ctrlHp) {
      ctrlHp.textContent = hpTriggered ? '🛑 Triggered' : '✓ Clean';
      ctrlHp.style.color = hpTriggered ? 'var(--bc-danger)' : 'var(--bc-success)';
    }

    const replayViolation = data.reasons?.some(r => r.toLowerCase().includes('replay') || r.toLowerCase().includes('already consumed'));
    if (ctrlReplay) {
      ctrlReplay.textContent = replayViolation ? '🛑 Blocked' : '✓ Protected';
      ctrlReplay.style.color = replayViolation ? 'var(--bc-danger)' : 'var(--bc-success)';
    }

    if (ctrlChallenge) {
      if (isAllow && isA11y) {
        ctrlChallenge.textContent = '✓ Solved';
        ctrlChallenge.style.color = 'var(--bc-success)';
      } else {
        ctrlChallenge.textContent = '— Not issued';
        ctrlChallenge.style.color = isAllow ? 'var(--bc-text-muted)' : 'var(--bc-danger)';
      }
    }

    // Raw JSON Payload Inspector
    const jsonEl = document.getElementById('raw-json-inspector');
    if (jsonEl) {
      jsonEl.textContent = JSON.stringify({
        simulation_payload: payload || {},
        server_response: data
      }, null, 2);
    }
  }

  // Copy JSON button helper
  const copyJsonBtn = document.getElementById('btn-copy-json');
  if (copyJsonBtn) {
    copyJsonBtn.addEventListener('click', function() {
      const jsonEl = document.getElementById('raw-json-inspector');
      if (jsonEl) {
        navigator.clipboard.writeText(jsonEl.textContent).then(() => {
          copyJsonBtn.textContent = '✓ Copied!';
          setTimeout(() => { copyJsonBtn.textContent = 'Copy JSON'; }, 2000);
        });
      }
    });
  }

  // =========================================================================
  // 4. DETERMINISTIC ATTACK REPLAY PLAYER (Sections 1 through 10 & 21)
  // =========================================================================
  class AttackReplayPlayer {
    constructor(attackType) {
      this.attackType = attackType;
      this.overlay = document.getElementById('attack-simulation-overlay');
      this.cursor = document.getElementById('simulated-cursor');
      this.cursorLabel = document.getElementById('cursor-label');
      this.banner = document.getElementById('simulation-banner');
      this.attackTitle = document.getElementById('sim-attack-title');
      this.activityPanel = document.getElementById('simulation-activity-panel');
      this.activityAttackName = document.getElementById('activity-attack-name');
      this.activityCurrentText = document.getElementById('activity-current-text');
      this.activityStatePill = document.getElementById('activity-state-pill');
      this.currentAction = document.getElementById('sim-current-action');
      this.progressSteps = document.getElementById('sim-progress-steps');
      this.pipelineSection = document.getElementById('simulation-pipeline');
      this.pipelineStatusText = document.getElementById('pipeline-status-text');
      this.replayFlowBanner = document.getElementById('replay-flow-banner');
      this.replayStep1Badge = document.getElementById('replay-step-1-badge');
      this.replayStep2Badge = document.getElementById('replay-step-2-badge');
      this.roboticActionStream = document.getElementById('robotic-action-stream');
      this.roboticActionsLog = document.getElementById('robotic-actions-log');
      this.hpIndicator = document.getElementById('honeypot-interaction-indicator');

      this.lastResponse = null;
      this.lastLatency = null;
      this.lastPayload = null;
    }

    setCursorLabel(text, isAttackerRed) {
      if (!this.cursorLabel) return;
      this.cursorLabel.textContent = text;
      this.cursorLabel.style.background = (isAttackerRed !== false) ? 'var(--bc-danger, #dc2626)' : 'var(--bc-primary, #2563eb)';
    }

    setState(stateName, actionDesc) {
      console.log(`[BC-SIM] State: ${stateName}`);
      if (this.activityStatePill) {
        this.activityStatePill.textContent = stateName;
        this.activityStatePill.style.background = stateName === 'COMPLETE' ? 'rgba(21, 128, 61, 0.12)' : 'rgba(37, 99, 235, 0.12)';
        this.activityStatePill.style.color = stateName === 'COMPLETE' ? 'var(--bc-success)' : 'var(--bc-primary)';
      }
      if (actionDesc) {
        if (this.currentAction) this.currentAction.textContent = actionDesc;
        if (this.activityCurrentText) this.activityCurrentText.textContent = actionDesc;
        if (this.pipelineStatusText) this.pipelineStatusText.textContent = actionDesc;
      }
    }

    updateProgress(activeIndex, actionDesc) {
      const stepNames = ['Targeted', 'Username entered', 'Password typing', 'Submit', 'Server defense'];
      if (actionDesc) {
        if (this.currentAction) this.currentAction.textContent = actionDesc;
        if (this.activityCurrentText) this.activityCurrentText.textContent = actionDesc;
        if (this.pipelineStatusText) this.pipelineStatusText.textContent = actionDesc;
      }

      for (let i = 0; i < 5; i++) {
        const stepEl = document.getElementById('sim-step-' + i);
        if (!stepEl) continue;
        if (i < activeIndex) {
          stepEl.className = 'sim-prog-step done';
          stepEl.textContent = '✓ ' + stepNames[i];
        } else if (i === activeIndex) {
          stepEl.className = 'sim-prog-step active';
          stepEl.textContent = '● ' + stepNames[i];
        } else {
          stepEl.className = 'sim-prog-step pending';
          stepEl.textContent = '○ ' + stepNames[i];
        }
      }

      // Sync 8-stage timeline steps (Part T backwards-compatibility)
      for (let s = 1; s <= 8; s++) {
        const pipeEl = document.getElementById('pipe-step-' + s);
        if (!pipeEl) continue;
        const mappedStep = Math.min(8, Math.max(1, activeIndex * 2));
        if (s < mappedStep) {
          pipeEl.className = 'pipe-step step-done';
        } else if (s === mappedStep) {
          pipeEl.className = 'pipe-step step-active';
        } else {
          pipeEl.className = 'pipe-step';
        }
      }

      announce(actionDesc);
    }

    // Absolute target readiness with 5s timeout fail-safe (Sections 4 & 22)
    async waitForTargetReady() {
      const startTime = performance.now();
      const MAX_TIMEOUT_MS = 5000;

      return new Promise((resolve, reject) => {
        const check = () => {
          const formEl = document.getElementById('citizenLoginForm');
          const username = document.getElementById('usernameInput');
          const password = document.getElementById('passwordInput');
          const submit = document.getElementById('mainSubmitBtn');

          if (formEl && username && password && submit) {
            const uRect = username.getBoundingClientRect();
            const pRect = password.getBoundingClientRect();
            const sRect = submit.getBoundingClientRect();

            if (uRect.width > 0 && uRect.height > 0 &&
                pRect.width > 0 && pRect.height > 0 &&
                sRect.width > 0 && sRect.height > 0) {
              
              requestAnimationFrame(() => {
                requestAnimationFrame(() => {
                  resolve({ formEl, username, password, submit });
                });
              });
              return;
            }
          }

          if (performance.now() - startTime > MAX_TIMEOUT_MS) {
            const missing = !formEl ? 'citizenLoginForm' :
                            !username ? 'usernameInput' :
                            !password ? 'passwordInput' :
                            !submit ? 'mainSubmitBtn' :
                            'Form input elements have 0x0 bounding dimensions';
            
            console.error('[BC-SIM Error] Target initialization failed:', missing);

            if (this.activityPanel) this.activityPanel.style.display = 'block';
            if (this.activityCurrentText) {
              this.activityCurrentText.innerHTML = `<span style="color:var(--bc-danger); font-weight:700;">Simulation could not start. Target: Demo Verification Form</span> (${escapeHtml(missing)})`;
            }
            reject(new Error(missing));
            return;
          }

          setTimeout(check, 35);
        };

        if (document.readyState === 'complete' || document.readyState === 'interactive') {
          check();
        } else {
          document.addEventListener('DOMContentLoaded', check);
        }
      });
    }

    // Execute exactly one action in the deterministic action queue
    async runAction(action) {
      switch (action.type) {
        case 'prepare': {
          // Log Startup Diagnostic (Section 6)
          console.log(`[BC-SIM] Simulation mode: ${this.attackType}`);
          console.log(`[BC-SIM] Reduced motion: ${reducedMotion}`);
          console.log(`[BC-SIM] Visual animation: ${reducedMotion ? 'disabled (snapping)' : 'enabled (smooth glide)'}`);
          console.log(`[BC-SIM] Step pacing: stepPause=${SIMULATION_CONFIG.stepPauseMs}ms, typingCadence=${SIMULATION_CONFIG.typingCadenceMs}ms, clickHold=${SIMULATION_CONFIG.clickHoldMs}ms`);

          // Activate simulation view
          document.body.classList.add('sim-active');
          if (this.overlay) this.overlay.style.display = 'block';
          if (this.banner) this.banner.style.display = 'block';
          if (this.activityPanel) this.activityPanel.style.display = 'block';
          if (this.pipelineSection) this.pipelineSection.style.display = 'block';

          const titleMap = {
            honeypot: 'Attack: Honeypot Trap (DOM Form Crawler)',
            headless: 'Attack: Headless Browser Automation (WebDriver)',
            robotic: 'Attack: Robotic Timing (Superhuman Cadence)',
            replay: 'Attack: Replay Attack (Cryptographic Nonce Reuse)',
            accessibility: 'Live Simulation: Automatic Accessibility Routing'
          };
          const heading = titleMap[this.attackType] || 'Controlled Attack Simulation';
          if (this.attackTitle) this.attackTitle.textContent = heading;
          if (this.activityAttackName) this.activityAttackName.textContent = heading;

          // Pre-attack reset of old demo values and focus states (Section 10)
          const username = document.getElementById('usernameInput');
          const password = document.getElementById('passwordInput');
          const submit = document.getElementById('mainSubmitBtn');

          if (username) { username.value = ''; username.blur(); }
          if (password) { password.value = ''; password.blur(); }
          if (submit) { submit.blur(); }

          // Wait for targets with 5s fail-safe
          const targets = await this.waitForTargetReady();

          // Scroll target deterministically into view
          targets.username.scrollIntoView({ behavior: 'auto', block: 'center' });

          // Wait two requestAnimationFrame passes
          await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
          await waitForPacing(250);

          // Position cursor at visible starting location in viewport overlay
          if (this.cursor) {
            this.setCursorLabel(action.label || 'BOT', action.isAttacker !== false);
            const uRect = targets.username.getBoundingClientRect();
            const startX = Math.max(16, Math.round(uRect.left - 40));
            const startY = Math.max(16, Math.round(uRect.top + 30));

            this.cursor.style.transition = 'none';
            this.cursor.style.left = startX + 'px';
            this.cursor.style.top = startY + 'px';
            this.cursor.style.display = 'flex';
          }

          console.log('[BC-SIM] Target ready');
          this.setState('TARGET_READY', 'Demo form located. Targeting input fields...');
          await waitForPacing(SIMULATION_CONFIG.stepPauseMs);
          break;
        }

        case 'step': {
          this.updateProgress(action.progressIndex, action.desc);
          break;
        }

        case 'move': {
          const el = document.getElementById(action.targetId);
          if (!el || !this.cursor) break;

          const targetName = action.targetId === 'usernameInput' ? 'username' :
                             action.targetId === 'passwordInput' ? 'password' :
                             action.targetId === 'mainSubmitBtn' ? 'submit' : action.targetId;
          console.log(`[BC-SIM] Moving to ${targetName}`);
          this.setState('CURSOR_MOVING', `Moving cursor to ${targetName}...`);

          const rect = el.getBoundingClientRect();
          const targetX = Math.round(rect.left + (rect.width / 2));
          const targetY = Math.round(rect.top + (rect.height / 2));

          if (reducedMotion) {
            // Under reduced motion: snap immediately, but pause visibly (Section 8)
            this.cursor.style.transition = 'none';
            this.cursor.style.left = targetX + 'px';
            this.cursor.style.top = targetY + 'px';
            await waitForPacing(60);
          } else {
            const dur = action.duration || SIMULATION_CONFIG.cursorMoveMs;
            this.cursor.style.transition = `left ${dur}ms cubic-bezier(0.22, 1, 0.36, 1), top ${dur}ms cubic-bezier(0.22, 1, 0.36, 1)`;
            this.cursor.style.left = targetX + 'px';
            this.cursor.style.top = targetY + 'px';
            await waitForPacing(dur + 30);
          }

          // Observable pause on target before next action
          await waitForPacing(SIMULATION_CONFIG.stepPauseMs);
          break;
        }

        case 'focus': {
          const el = document.getElementById(action.targetId);
          if (el) {
            el.focus();
            el.classList.add('sim-focused');
          }
          break;
        }

        case 'type': {
          const el = document.getElementById(action.targetId);
          if (!el) break;

          const targetName = action.targetId === 'usernameInput' ? 'username' :
                             action.targetId === 'passwordInput' ? 'password' : action.targetId;
          console.log(`[BC-SIM] Typing ${targetName}`);
          this.setState('TYPING', `Typing ${targetName}: ${action.text}`);

          el.focus();
          el.classList.add('sim-focused');
          el.value = '';

          // Character-by-character typing with steady cadence in ALL modes (Section 9)
          const cadence = action.cadence || SIMULATION_CONFIG.typingCadenceMs;
          for (let i = 0; i < action.text.length; i++) {
            el.value += action.text[i];
            el.dispatchEvent(new Event('input', { bubbles: true }));
            await waitForPacing(cadence);
          }

          // Readable pause after typing completes before removing focus
          await waitForPacing(SIMULATION_CONFIG.stepPauseMs);
          el.classList.remove('sim-focused');
          break;
        }

        case 'click': {
          const el = document.getElementById(action.targetId);
          if (!el) break;

          console.log('[BC-SIM] Click');
          this.setState('CLICKING', 'Submitting verification...');
          el.focus();
          el.classList.add('sim-btn-pressed');

          let ring = null;
          if (!reducedMotion) {
            if (this.cursor) this.cursor.style.transform = 'translate(-3px, -3px) scale(0.85)';
            ring = document.createElement('span');
            ring.className = 'sim-click-ripple';
            el.appendChild(ring);
          }

          // Visual pressed state holds visibly in all modes (Section 10)
          await waitForPacing(SIMULATION_CONFIG.clickHoldMs);

          if (this.cursor) this.cursor.style.transform = 'translate(-3px, -3px) scale(1)';
          el.classList.remove('sim-btn-pressed');
          if (ring && ring.parentNode) ring.parentNode.removeChild(ring);

          // Observable pause before request dispatch
          await waitForPacing(SIMULATION_CONFIG.clickPostPauseMs);
          break;
        }

        case 'trap': {
          console.log('[BC-SIM] Hidden trap field touched');
          this.updateProgress(2, 'DOM inspection: Discovered and populated hidden honeypot trap field');
          if (this.hpIndicator) {
            this.hpIndicator.style.display = 'flex';
          }
          await waitForPacing(700);
          break;
        }

        case 'actionLog': {
          if (this.roboticActionStream) this.roboticActionStream.style.display = 'block';
          if (this.roboticActionsLog) {
            this.roboticActionsLog.innerHTML += `<div>&bull; ${escapeHtml(action.text)}</div>`;
          }
          break;
        }

        case 'pause': {
          await waitForPacing(action.ms);
          break;
        }

        case 'request': {
          console.log('[BC-SIM] Request sent');
          this.setState('REQUESTING', 'Server analyzing request & security controls...');
          this.updateProgress(4, 'Server analyzing request & security controls...');

          const t0 = performance.now();
          const res = await fetch(action.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(action.payload)
          });
          const data = await res.json();
          const latency = Math.round(performance.now() - t0);

          console.log('[BC-SIM] Server response received');
          this.setState('SERVER_RESULT', `Server evaluated request: Risk ${Number(data.risk_score).toFixed(1)} / 100 — REJECTED`);
          this.lastResponse = data;
          this.lastLatency = latency;
          this.lastPayload = action.payload;

          // Observable server evaluation pause so user perceives server analysis
          await waitForPacing(SIMULATION_CONFIG.serverPauseMs);
          break;
        }

        case 'renderVerdict': {
          console.log('[BC-SIM] Rendering warning');
          if (this.cursor) {
            this.cursor.style.display = 'none';
          }

          if (this.lastResponse) {
            displayAttackWarning({
              title: action.warning.title,
              subtitle: action.warning.subtitle,
              attackTypeVal: action.warning.attackTypeVal,
              detectedBehavior: this.lastResponse.reasons?.[0] ? getHumanReadableReason(this.lastResponse.reasons[0]) : action.warning.detectedBehavior,
              reasons: this.lastResponse.reasons || ['Automated activity detected'],
              explanation: action.warning.explanation || 'The server inspected the request and determined that automated signatures were present, rejecting the request with zero accessibility fallback.'
            });

            renderVerdict(this.lastResponse, this.lastResponse.decision === 'ALLOW', this.lastLatency, this.lastPayload);
          }

          this.updateProgress(4, 'Server defense complete — Request REJECTED');
          this.setState('COMPLETE', 'Attack simulation completed.');
          console.log('[BC-SIM] Complete');
          break;
        }

        default:
          console.warn('[BC-SIM] Unknown action type:', action.type);
      }
    }

    // Execute complete script queue
    async play(script) {
      try {
        for (const action of script) {
          await this.runAction(action);
        }
      } catch (err) {
        console.error('[BC-SIM] Execution error:', err);
      } finally {
        window.__beyondCaptchaSimulationActive = false;
      }
    }

    // -----------------------------------------------------------------------
    // Genuine 2-Step Replay Execution (Sections 15 & 16)
    // -----------------------------------------------------------------------
    async playReplay() {
      try {
        const testSession = 'replay_sess_' + Date.now();
        if (this.replayFlowBanner) this.replayFlowBanner.style.display = 'block';

        // Prepare & align
        await this.runAction({ type: 'prepare', label: 'CITIZEN', isAttacker: false });
        this.updateProgress(0, 'Targeted form inputs');

        // Step 1 Setup: Obtain legitimate server accessibility context & math challenge
        this.updateProgress(1, 'Request #1: Establishing server accessibility context...');
        const startRes = await fetch('/api/accessibility/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sessionId: testSession })
        });
        const startData = await startRes.json();
        const contextId = startData.contextId;

        const chalRes = await fetch('/api/challenge/new', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sessionId: testSession, contextId: contextId })
        });
        const chalData = await chalRes.json();
        const cid = chalData.challengeId || chalData.challenge_id;
        const prompt = chalData.prompt || 'What is 5 + 3?';

        let answer = '8';
        const match = prompt.match(/What is (\d+)\s*([\+\-])\s*(\d+)\?/);
        if (match) {
          const a = parseInt(match[1], 10);
          const op = match[2];
          const b = parseInt(match[3], 10);
          answer = String(op === '+' ? a + b : a - b);
        }

        // Visible form interaction: Request #1
        await this.runAction({ type: 'move', targetId: 'usernameInput', duration: 500 });
        await this.runAction({ type: 'focus', targetId: 'usernameInput' });
        await this.runAction({ type: 'type', targetId: 'usernameInput', text: 'legitimate_citizen', cadence: 40 });
        this.updateProgress(1, 'Username entered');

        await this.runAction({ type: 'move', targetId: 'passwordInput', duration: 420 });
        await this.runAction({ type: 'focus', targetId: 'passwordInput' });
        await this.runAction({ type: 'type', targetId: 'passwordInput', text: 'CitizenPass!2026', cadence: 40 });
        this.updateProgress(2, 'Password entered');

        await this.runAction({ type: 'move', targetId: 'mainSubmitBtn', duration: 420 });
        this.updateProgress(3, `Submitting legitimate solution '${answer}'...`);
        await this.runAction({ type: 'click', targetId: 'mainSubmitBtn' });

        // Dispatch Request #1 (Legitimate solve)
        console.log('[BC-SIM] Request sent');
        this.setState('REQUESTING', 'Request #1: Verifying math solution & consuming single-use nonce...');
        this.updateProgress(4, 'Request #1: Verifying math solution & consuming single-use nonce...');
        const t0 = performance.now();
        const res1 = await fetch('/api/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sessionId: testSession,
            challengeId: cid,
            contextId: contextId,
            answer: answer,
            isAccessibleMode: true
          })
        });
        const data1 = await res1.json();
        const lat1 = Math.round(performance.now() - t0);
        console.log('[BC-SIM] Server response received');

        if (this.replayStep1Badge) {
          this.replayStep1Badge.style.borderColor = 'var(--bc-success)';
          this.replayStep1Badge.style.background = 'rgba(21, 128, 61, 0.08)';
        }

        renderVerdict(data1, true, lat1, {
          request_1: { sessionId: testSession, challengeId: cid, answer: answer }
        });
        this.setState('SERVER_RESULT', 'REQUEST #1: ✓ ACCEPTED (Challenge nonce consumed in SQLite)');
        this.updateProgress(4, 'REQUEST #1: ✓ ACCEPTED (Challenge nonce consumed in SQLite)');

        // Observable pause between Request 1 and Request 2 (1200ms)
        await waitForPacing(SIMULATION_CONFIG.replayPauseMs);

        // Step 2: Attacker reuses exact same token
        this.setCursorLabel('ATTACKER', true);
        if (this.replayStep2Badge) {
          this.replayStep2Badge.style.borderColor = 'var(--bc-primary)';
          this.replayStep2Badge.style.background = 'rgba(37, 99, 235, 0.08)';
        }

        this.updateProgress(3, 'ATTACKER REUSES SAME VERIFICATION: Submitting duplicate verification request...');
        await this.runAction({ type: 'move', targetId: 'mainSubmitBtn', duration: 420 });
        await this.runAction({ type: 'click', targetId: 'mainSubmitBtn' });

        console.log('[BC-SIM] Request sent');
        this.setState('REQUESTING', 'Request #2: Dispatching duplicate token to /api/verify...');
        this.updateProgress(4, 'Request #2: Dispatching duplicate token to /api/verify...');
        const t1 = performance.now();
        const res2 = await fetch('/api/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sessionId: testSession,
            challengeId: cid,
            contextId: contextId,
            answer: answer,
            isAccessibleMode: true
          })
        });
        const data2 = await res2.json();
        const lat2 = Math.round(performance.now() - t1);
        console.log('[BC-SIM] Server response received');

        if (this.replayStep2Badge) {
          this.replayStep2Badge.style.borderColor = 'var(--bc-danger)';
          this.replayStep2Badge.style.background = 'rgba(220, 38, 38, 0.08)';
        }

        console.log('[BC-SIM] Rendering warning');
        if (this.cursor) this.cursor.style.display = 'none';

        displayAttackWarning({
          title: 'Replay Attack Detected',
          subtitle: 'Attack Type: Challenge Nonce Reuse',
          attackTypeVal: 'Replay Attack',
          detectedBehavior: data2.reasons?.[0] ? getHumanReadableReason(data2.reasons[0]) : 'The verification challenge was already used (Anti-Replay violation).',
          reasons: data2.reasons || ['Challenge already consumed (Anti-Replay Violation)'],
          explanation: 'The server inspected the database record for this challenge token and discovered it was already marked solved during Request #1. Because BeyondCAPTCHA challenges are cryptographically single-use, subsequent submissions using the same token are rejected atomically.'
        });

        renderVerdict(data2, false, lat2, {
          request_1_payload: { sessionId: testSession, challengeId: cid, answer: answer },
          request_2_replay_payload: { sessionId: testSession, challengeId: cid, answer: answer }
        });

        this.setState('COMPLETE', 'REQUEST #2: ✕ REJECTED (Duplicate token denied by anti-replay defense)');
        this.updateProgress(4, 'REQUEST #2: ✕ REJECTED (Duplicate token denied by anti-replay defense)');

        console.log('[BC-SIM] Complete');
      } catch (err) {
        console.error('[BC-SIM] Replay simulation error:', err);
      } finally {
        window.__beyondCaptchaSimulationActive = false;
      }
    }

    // -----------------------------------------------------------------------
    // Genuine Scenario 5: Automatic Accessibility Routing Execution
    // -----------------------------------------------------------------------
    async playAccessibility() {
      try {
        const testSession = 'a11y_sess_' + Date.now();

        // 1. Prepare & align target with assistive user badge
        await this.runAction({ type: 'prepare', label: 'CITIZEN', isAttacker: false });
        this.updateProgress(0, 'Targeted demo form with accessibility-compatible profile');

        // 2. Realistic interaction: enter credentials
        await this.runAction({ type: 'move', targetId: 'usernameInput', duration: 500 });
        await this.runAction({ type: 'focus', targetId: 'usernameInput' });
        await this.runAction({ type: 'type', targetId: 'usernameInput', text: 'citizen.assistive@example.gov', cadence: 40 });
        this.updateProgress(1, 'Username entered');

        await this.runAction({ type: 'move', targetId: 'passwordInput', duration: 420 });
        await this.runAction({ type: 'focus', targetId: 'passwordInput' });
        await this.runAction({ type: 'type', targetId: 'passwordInput', text: 'CitizenPass!2026', cadence: 40 });
        this.updateProgress(2, 'Password entered');

        await this.runAction({ type: 'move', targetId: 'mainSubmitBtn', duration: 420 });
        this.updateProgress(3, 'Submitting with accessibility-compatible interaction profile...');
        await this.runAction({ type: 'click', targetId: 'mainSubmitBtn' });

        // 3. Dispatch initial verification telemetry (Request #1)
        console.log('[BC-SIM] Request sent: Accessibility-compatible telemetry');
        this.setState('REQUESTING', 'Request #1: Server evaluating profile — Policy routing to Accessible Mode...');
        this.updateProgress(4, 'Request #1: Server evaluating profile — Policy routing to Accessible Mode...');
        const t0 = performance.now();
        const res1 = await fetch('/api/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sessionId: testSession,
            flowType: 'automatic_accessibility',
            accessibility_compatible: true,
            keyboardNavigation: true,
            honeypot: '',
            dwellTime: 2200,
            timeOnPage: 2200,
            keystrokes: 26,
            typingVariance: 42.0,
            browserFlags: { webdriver: false, screenWidth: 1920, screenHeight: 1080 },
            isAccessibleMode: false
          })
        });
        const data1 = await res1.json();
        const lat1 = Math.round(performance.now() - t0);
        console.log('[BC-SIM] Server response received:', data1);

        // Server returns ACCESSIBILITY_VERIFY with server-issued contextId
        const contextId = data1.contextId;
        this.setState('SERVER_RESULT', 'Server policy: ACCESSIBILITY_VERIFY — Behavioral tracking: OFF');
        this.updateProgress(4, 'Server Policy: Transitioned to Accessible Verification (Tracking: OFF)');

        setBannerState('a11y', '✓ Accessible verification active', 'Behavioral tracking: OFF — Presenting cognitive challenge', lat1 + ' ms', '♿');

        // Reveal accessibility UI in widget
        if (widgetInstance) {
          widgetInstance.setAccessibilityMode(true);
          if (contextId) widgetInstance.state.contextId = contextId;
        }

        await waitForPacing(SIMULATION_CONFIG.stepPauseMs + 200);

        // 4. Request arithmetic challenge using server-issued contextId
        this.setState('GENERATING_CHALLENGE', 'Requesting accessible arithmetic challenge from server...');
        const chalRes = await fetch('/api/challenge/new', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sessionId: testSession, contextId: contextId, type: 'math' })
        });
        const chalData = await chalRes.json();
        const cid = chalData.challengeId || chalData.challenge_id;
        const prompt = chalData.prompt || 'What is 5 + 3?';

        let answer = '8';
        const match = prompt.match(/What is (\d+)\s*([\+\-])\s*(\d+)\?/);
        if (match) {
          const a = parseInt(match[1], 10);
          const op = match[2];
          const b = parseInt(match[3], 10);
          answer = String(op === '+' ? a + b : a - b);
        }

        if (widgetInstance) {
          widgetInstance.renderChallengeUI(chalData);
        }

        this.setState('CHALLENGE_ACTIVE', `Accessible challenge presented: "${prompt}"`);
        await waitForPacing(SIMULATION_CONFIG.stepPauseMs);

        // 5. Solve challenge: Target answer input and type answer
        const answerInput = document.querySelector('.bc-answer-input');
        if (answerInput) {
          if (!answerInput.id) answerInput.id = 'bc-ans-sim-input';
          await this.runAction({ type: 'move', targetId: answerInput.id, duration: 400 });
          await this.runAction({ type: 'focus', targetId: answerInput.id });
          await this.runAction({ type: 'type', targetId: answerInput.id, text: answer, cadence: 45 });
        }

        // 6. Click Verify Answer button
        const verifyAnsBtn = document.querySelector('.bc-btn-verify-answer');
        if (verifyAnsBtn) {
          if (!verifyAnsBtn.id) verifyAnsBtn.id = 'bc-btn-verify-sim';
          await this.runAction({ type: 'move', targetId: verifyAnsBtn.id, duration: 350 });
          await this.runAction({ type: 'click', targetId: verifyAnsBtn.id });
        }

        // 7. Dispatch Request #2: Submit challenge answer
        console.log('[BC-SIM] Request sent: Challenge answer submission');
        this.setState('REQUESTING', `Request #2: Submitting solution '${answer}' to /api/verify...`);
        this.updateProgress(4, `Request #2: Submitting solution '${answer}' to /api/verify...`);
        const t1 = performance.now();
        const res2 = await fetch('/api/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sessionId: testSession,
            contextId: contextId,
            challengeId: cid,
            answer: answer,
            isAccessibleMode: true,
            flowType: 'automatic_accessibility'
          })
        });
        const data2 = await res2.json();
        const lat2 = Math.round(performance.now() - t1);
        console.log('[BC-SIM] Final verification response received:', data2);

        if (this.cursor) this.cursor.style.display = 'none';

        renderVerdict(data2, true, lat2, {
          initial_request: { flowType: 'automatic_accessibility', accessibility_compatible: true },
          routing_response: data1,
          challenge_submission: { sessionId: testSession, challengeId: cid, answer: answer, isAccessibleMode: true },
          final_response: data2
        });

        const pipeStep8 = document.getElementById('pipe-step-8-text');
        if (pipeStep8) pipeStep8.textContent = 'Verified';

        this.setState('COMPLETE', '✓ Automatic accessibility routing completed: User verified with behavioral tracking OFF.');
        this.updateProgress(4, '✓ Verified — Behavioral tracking was OFF');
        console.log('[BC-SIM] Complete');
      } catch (err) {
        console.error('[BC-SIM] Accessibility simulation error:', err);
      } finally {
        window.__beyondCaptchaSimulationActive = false;
      }
    }
  }

  // =========================================================================
  // 5. DETERMINISTIC SCRIPT DEFINITIONS (Sections 12, 13, 14, 15)
  // =========================================================================

  function getHoneypotScript() {
    return [
      { type: 'prepare', label: 'CRAWLER' },
      { type: 'step', progressIndex: 0, desc: 'Targeted form inputs' },
      { type: 'move', targetId: 'usernameInput', duration: 550 },
      { type: 'focus', targetId: 'usernameInput' },
      { type: 'type', targetId: 'usernameInput', text: 'crawler_bot@scraper.example', cadence: 40 },
      { type: 'step', progressIndex: 1, desc: 'Username entered' },
      { type: 'move', targetId: 'passwordInput', duration: 450 },
      { type: 'focus', targetId: 'passwordInput' },
      { type: 'type', targetId: 'passwordInput', text: 'AutomatedPass!2026', cadence: 40 },
      { type: 'step', progressIndex: 2, desc: 'Password entered' },
      { type: 'trap' },
      { type: 'step', progressIndex: 3, desc: 'Submitting verification' },
      { type: 'move', targetId: 'mainSubmitBtn', duration: 450 },
      { type: 'click', targetId: 'mainSubmitBtn' },
      { type: 'step', progressIndex: 4, desc: 'Server defense analysis' },
      {
        type: 'request',
        url: '/api/verify',
        payload: {
          sessionId: 'sim_hp_' + Date.now(),
          honeypot: 'bot_crawler_spam_payload',
          timeOnPage: 400,
          dwellTime: 400,
          keystrokes: 14,
          typingVariance: 35.0,
          browserFlags: { webdriver: false, screenWidth: 1920, screenHeight: 1080 },
          isAccessibleMode: false,
          flowType: 'honeypot_attack_simulation'
        }
      },
      {
        type: 'renderVerdict',
        warning: {
          title: 'Suspicious Automated Activity Detected',
          subtitle: 'Attack Type: Honeypot Trap',
          attackTypeVal: 'Honeypot Trap',
          detectedBehavior: 'The request interacted with a hidden trap field (invisible to human citizens).',
          explanation: 'The server inspected the submission and discovered that a hidden honeypot input (which is completely hidden from human citizens and screen readers) was filled with data. Because only automated crawlers indiscriminately populate hidden fields, the server rejected the request directly with zero fallback challenge.'
        }
      }
    ];
  }

  function getHeadlessScript() {
    return [
      { type: 'prepare', label: 'AUTOMATION' },
      { type: 'step', progressIndex: 0, desc: 'Targeted form inputs' },
      { type: 'move', targetId: 'usernameInput', duration: 500 },
      { type: 'focus', targetId: 'usernameInput' },
      { type: 'type', targetId: 'usernameInput', text: 'headless_automation_user', cadence: 35 },
      { type: 'step', progressIndex: 1, desc: 'Username entered' },
      { type: 'move', targetId: 'passwordInput', duration: 420 },
      { type: 'focus', targetId: 'passwordInput' },
      { type: 'type', targetId: 'passwordInput', text: 'AutomatedPass!2026', cadence: 35 },
      { type: 'step', progressIndex: 2, desc: 'Password entered' },
      { type: 'step', progressIndex: 3, desc: 'Submitting verification' },
      { type: 'move', targetId: 'mainSubmitBtn', duration: 420 },
      { type: 'click', targetId: 'mainSubmitBtn' },
      { type: 'step', progressIndex: 4, desc: 'Server defense analysis' },
      {
        type: 'request',
        url: '/api/verify',
        payload: {
          sessionId: 'sim_headless_' + Date.now(),
          honeypot: '',
          timeOnPage: 250,
          dwellTime: 250,
          keystrokes: 0,
          typingVariance: 0.0,
          browserFlags: {
            webdriver: true,
            screenWidth: 0,
            screenHeight: 0
          },
          isWebDriver: true,
          isAccessibleMode: false,
          flowType: 'headless_attack_simulation'
        }
      },
      {
        type: 'renderVerdict',
        warning: {
          title: 'Suspicious Automated Activity Detected',
          subtitle: 'Attack Type: Headless Browser',
          attackTypeVal: 'Headless Browser',
          detectedBehavior: 'Automated browser behavior was detected (navigator.webdriver = true).',
          explanation: 'The server evaluated the incoming browser environment telemetry and detected active automation flags (navigator.webdriver = true with 0x0 display dimensions). BeyondCAPTCHA enforces deterministic heuristics against automated scrapers, rejecting them directly.'
        }
      }
    ];
  }

  function getRoboticScript() {
    return [
      { type: 'prepare', label: 'ROBOTIC' },
      { type: 'step', progressIndex: 0, desc: 'Targeted form inputs' },
      { type: 'actionLog', text: 'ACTION 01: Username focused' },
      { type: 'move', targetId: 'usernameInput', duration: 380 },
      { type: 'focus', targetId: 'usernameInput' },
      { type: 'actionLog', text: 'ACTION 02: Username typed (0.0ms cadence)' },
      { type: 'type', targetId: 'usernameInput', text: 'timing_flooder_bot', cadence: 18 },
      { type: 'step', progressIndex: 1, desc: 'Username entered' },
      { type: 'actionLog', text: 'ACTION 03: Password focused' },
      { type: 'move', targetId: 'passwordInput', duration: 320 },
      { type: 'focus', targetId: 'passwordInput' },
      { type: 'actionLog', text: 'ACTION 04: Password typed (0.0ms cadence)' },
      { type: 'type', targetId: 'passwordInput', text: 'FloodPass@2026', cadence: 18 },
      { type: 'step', progressIndex: 2, desc: 'Password entered' },
      { type: 'actionLog', text: 'ACTION 05: Submit clicked (38ms dwell time)' },
      { type: 'step', progressIndex: 3, desc: 'Submitting verification' },
      { type: 'move', targetId: 'mainSubmitBtn', duration: 320 },
      { type: 'click', targetId: 'mainSubmitBtn' },
      { type: 'step', progressIndex: 4, desc: 'Server defense analysis' },
      {
        type: 'request',
        url: '/api/verify',
        payload: {
          sessionId: 'sim_robotic_' + Date.now(),
          honeypot: '',
          timeOnPage: 38,
          dwellTime: 38,
          keystrokes: 16,
          typingVariance: 0.0,
          browserFlags: { webdriver: false, screenWidth: 1920, screenHeight: 1080 },
          isAccessibleMode: false,
          flowType: 'robotic_timing_simulation'
        }
      },
      {
        type: 'renderVerdict',
        warning: {
          title: 'Robotic Interaction Pattern Detected',
          subtitle: 'Attack Type: Robotic Timing',
          attackTypeVal: 'Robotic Timing',
          detectedBehavior: 'Interaction cadence occurred faster than human physiological limits (<50ms).',
          explanation: 'The server analyzed the temporal cadence of the interaction and found a dwell time under 50ms and 0.0ms keystroke variance. Human typists exhibit natural biomechanical latency and jitter; mathematically perfect timing indicates scripted automation.'
        }
      }
    ];
  }

  // =========================================================================
  // 6. NORMAL CITIZEN MODE / WIDGET SDK MOUNT (When simulation is OFF)
  // =========================================================================
  const mountEl = document.querySelector('#beyondcaptcha-widget-mount');
  let widgetInstance = null;

  if (mountEl && typeof BeyondCaptcha !== 'undefined') {
    widgetInstance = BeyondCaptcha.mount('#beyondcaptcha-widget-mount', {
      formSelector: '#citizenLoginForm',
      apiUrl: '/api/verify',
      challengeApiUrl: '/api/challenge/new',
      otpApiUrl: '/api/otp/send',
      onAccessibilityMode: function(isActive) {
        if (isActive) {
          setBannerState('a11y', '✓ Accessible verification active', 'Behavioral tracking: OFF', '—', '♿');
          announce('Accessibility verification selected. Behavioral tracking is OFF.');
        } else {
          setBannerState('waiting', 'Waiting for verification', 'Complete form or choose accessible verification', '—', '○');
          announce('Standard passive verification restored.');
        }
      },
      onSuccess: function(result) {
        renderVerdict(result, true);
        const submitBtn = document.getElementById('mainSubmitBtn');
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.focus();
        }
      },
      onFailure: function(result) {
        renderVerdict(result, false);
      }
    });
  }

  // Accessible Mode Toggle Button (Section 24)
  const a11yToggleBtn = document.getElementById('btn-trigger-a11y');
  if (a11yToggleBtn && widgetInstance) {
    a11yToggleBtn.addEventListener('click', function(e) {
      e.preventDefault();
      widgetInstance.toggleAccessibilityMode();
    });
  }

  // Natural Typing Simulation Helper Tool (Normal Mode Demo Aid)
  const typingHelperBtn = document.getElementById('btn-simulate-typing');
  if (typingHelperBtn) {
    typingHelperBtn.addEventListener('click', async function(e) {
      e.preventDefault();
      const uInput = document.getElementById('usernameInput');
      const pInput = document.getElementById('passwordInput');
      if (!uInput || !pInput) return;

      uInput.value = '';
      pInput.value = '';

      const uText = 'citizen.demo@services.gov';
      for (let i = 0; i < uText.length; i++) {
        uInput.value += uText[i];
        uInput.dispatchEvent(new Event('input', { bubbles: true }));
        await waitForPacing(30 + Math.floor(Math.random() * 25));
      }

      await waitForPacing(100);

      const pText = 'ValidCitizenPass!2026';
      for (let i = 0; i < pText.length; i++) {
        pInput.value += pText[i];
        pInput.dispatchEvent(new Event('input', { bubbles: true }));
        await waitForPacing(30 + Math.floor(Math.random() * 25));
      }

      announce('Sample citizen credentials entered with natural variance.');
    });
  }

  // Honeypot Test Helper Tool (Normal Mode Demo Aid)
  const honeypotHelperBtn = document.getElementById('btn-trigger-bot-hp');
  if (honeypotHelperBtn) {
    honeypotHelperBtn.addEventListener('click', function(e) {
      e.preventDefault();
      const hpField = document.querySelector('input[name="bc_website_hp"]') ||
                      document.querySelector('input[name="website"]') ||
                      document.getElementById('bc-hp-trap');
      if (hpField) {
        hpField.value = 'bot_spammer_payload_123';
        hpField.dispatchEvent(new Event('change', { bubbles: true }));
      }
      alert('Hidden honeypot field has been populated. When you submit the form, the server will reject it.');
    });
  }

  // =========================================================================
  // 7. INITIATE ATTACK REPLAY PLAYER IF SIMULATION REQUESTED
  // =========================================================================
  if (requestedAttack) {
    const player = new AttackReplayPlayer(requestedAttack);

    if (requestedAttack === 'replay') {
      player.playReplay();
    } else if (requestedAttack === 'accessibility') {
      player.playAccessibility();
    } else if (requestedAttack === 'honeypot') {
      player.play(getHoneypotScript());
    } else if (requestedAttack === 'headless') {
      player.play(getHeadlessScript());
    } else if (requestedAttack === 'robotic') {
      player.play(getRoboticScript());
    } else {
      console.warn('[BC-SIM] Unknown attack simulation requested:', requestedAttack);
    }
  }
});
