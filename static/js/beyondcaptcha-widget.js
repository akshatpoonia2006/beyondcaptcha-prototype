/**
 * BeyondCAPTCHA JavaScript SDK (v2.3.0 Enterprise)
 * Accessible, Instance-Based, Production-Grade Human Verification
 * 
 * Non-Negotiable Architecture:
 * - Normal Human: Passive privacy-conscious telemetry -> ALLOW
 * - Accessible User: Explicit user choice -> Tracking OFF -> Accessible Challenge -> ALLOW
 * - Malicious Bot: Evaluated present anomalies -> REJECT (strictly ZERO fallback)
 */
(function(window, document) {
  'use strict';

  let instanceCounter = 0;

  function BeyondCaptchaInstance(targetElement, userConfig) {
    this.target = targetElement;
    this.form = targetElement.tagName.toLowerCase() === 'form' 
      ? targetElement 
      : targetElement.closest('form') || targetElement;

    this.config = Object.assign({
      apiUrl: '/api/verify',
      challengeApiUrl: '/api/challenge/new',
      otpApiUrl: '/api/otp/send',
      onReady: null,
      onSuccess: null,
      onFailure: null,
      onAccessibilityMode: null,
      onDecision: null,
      onVerified: null,
      onError: null
    }, userConfig || {});

    this.uid = 'bc_' + (++instanceCounter) + '_' + Math.random().toString(36).substring(2, 7);

    this.state = {
      isVerified: false,
      isAccessibleMode: false,
      trackingEnabled: true,
      currentChallenge: null,
      activeTabType: 'math',
      startTime: Date.now(),
      mouseMoves: 0,
      mouseTrajectory: [],
      keystrokes: 0,
      keystrokeIntervals: [],
      lastKeyTime: null,
      sessionId: 'sess_' + this.uid + '_' + Date.now().toString(36)
    };

    this._eventRemovers = [];
    this.renderWidget();
    this.attachTelemetry();
    this.attachFormInterception();

    if (typeof this.config.onReady === 'function') {
      try { this.config.onReady(this); } catch (e) { console.error(e); }
    }
  }

  BeyondCaptchaInstance.prototype.renderWidget = function() {
    const uid = this.uid;

    // 1. Inject Honeypot Field (aria-hidden, tabIndex=-1, hidden from sighted & screen readers)
    this.honeypotInput = document.createElement('input');
    this.honeypotInput.type = 'text';
    this.honeypotInput.name = 'bc_website_security_token';
    this.honeypotInput.id = 'bc_hp_' + uid;
    this.honeypotInput.className = 'bc-trap-field';
    this.honeypotInput.tabIndex = -1;
    this.honeypotInput.setAttribute('aria-hidden', 'true');
    this.honeypotInput.setAttribute('autocomplete', 'new-password');
    if (this.form && this.form.insertBefore) {
      this.form.insertBefore(this.honeypotInput, this.form.firstChild);
    }

    // 2. Build Widget Container
    this.container = document.createElement('div');
    this.container.className = 'beyondcaptcha-container';
    this.container.setAttribute('role', 'region');
    this.container.setAttribute('aria-label', 'Human Verification Security Check');

    const panelId = 'bc-panel-' + uid;
    const tabMathId = 'bc-tab-math-' + uid;
    const tabWordId = 'bc-tab-word-' + uid;
    const toggleId = 'bc-toggle-' + uid;
    const announcerId = 'bc-announcer-' + uid;

    this.container.innerHTML = `
      <div class="bc-widget-header">
        <div class="bc-shield-badge">
          <svg class="bc-shield-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <span>BeyondCAPTCHA Protected</span>
        </div>

        <button type="button" class="bc-accessible-toggle-btn" id="${toggleId}" aria-expanded="false" aria-controls="${panelId}">
          <span aria-hidden="true">♿</span> Use accessible verification
        </button>
      </div>

      <div class="bc-status-box" aria-live="polite">
        <span class="bc-status-text">Passive human check active. Submitting the form verifies automatically.</span>
      </div>

      <div class="bc-alert bc-alert-error bc-sr-only" role="alert"></div>

      <!-- Accessible Challenge Panel ("WOW MOMENT" - Part 8) -->
      <div class="bc-challenge-panel" id="${panelId}" hidden>
        <div class="bc-a11y-active-banner">
          <div class="bc-a11y-header-row">
            <span class="bc-a11y-title">
              <span aria-hidden="true">♿</span> Accessible Verification
            </span>
            <span class="bc-tracking-off-badge" style="background: rgba(16, 185, 129, 0.15); color: #059669; border: 1px solid rgba(16, 185, 129, 0.3); padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 12px;">
              <span aria-hidden="true">✓</span> Behavioral tracking: <strong>OFF</strong>
            </span>
          </div>

          <p class="bc-a11y-desc" style="margin: 6px 0 0 0; font-size: 13px; color: var(--bc-text-muted);">
            Behavioral tracking is OFF. No behavioral interaction analysis is used in this mode.
          </p>
        </div>

        <!-- WAI-ARIA APG Tabs Pattern for Challenge Modalities -->
        <div class="bc-tabs" role="tablist" aria-label="Verification Challenge Modalities">
          <button type="button" role="tab" aria-selected="true" aria-controls="${panelId}-body" id="${tabMathId}" class="bc-tab-btn" data-type="math" tabindex="0">
            Simple Math
          </button>
          <button type="button" role="tab" aria-selected="false" aria-controls="${panelId}-body" id="${tabWordId}" class="bc-tab-btn" data-type="word" tabindex="-1">
            Word Verification
          </button>
        </div>

        <div class="bc-tabpanel" role="tabpanel" id="${panelId}-body" aria-labelledby="${tabMathId}" tabindex="0">
          <div class="bc-challenge-content"></div>
        </div>
      </div>

      <!-- Polite Live Announcer for Screen Readers -->
      <div class="bc-sr-only bc-live-announcer" id="${announcerId}" aria-live="polite"></div>
    `;

    // Mount inside target element or form
    if (this.target === this.form) {
      const submitBtn = this.form.querySelector('button[type="submit"], input[type="submit"]');
      if (submitBtn && submitBtn.parentNode) {
        submitBtn.parentNode.insertBefore(this.container, submitBtn);
      } else {
        this.form.appendChild(this.container);
      }
    } else {
      this.target.appendChild(this.container);
    }

    this.bindWidgetEvents();
  };

  BeyondCaptchaInstance.prototype.announce = function(message) {
    const announcer = this.container.querySelector('.bc-live-announcer');
    if (announcer) {
      announcer.textContent = '';
      setTimeout(() => { announcer.textContent = message; }, 50);
    }
  };

  BeyondCaptchaInstance.prototype.attachTelemetry = function() {
    const self = this;
    let lastMoveTime = 0;

    const onMouseMove = function(e) {
      if (!self.state.trackingEnabled) return;
      self.state.mouseMoves++;
      const now = Date.now();
      if (now - lastMoveTime > 50 && self.state.mouseTrajectory.length < 50) {
        lastMoveTime = now;
        self.state.mouseTrajectory.push({
          x: e.clientX,
          y: e.clientY,
          t: now - self.state.startTime
        });
      }
    };

    const onKeyDown = function(e) {
      if (!self.state.trackingEnabled) return;
      if (['Shift', 'Control', 'Alt', 'Meta', 'Tab'].includes(e.key)) return;

      self.state.keystrokes++;
      const now = Date.now();
      if (self.state.lastKeyTime) {
        const delta = now - self.state.lastKeyTime;
        if (self.state.keystrokeIntervals.length < 50) {
          self.state.keystrokeIntervals.push(delta);
        }
      }
      self.state.lastKeyTime = now;
    };

    window.addEventListener('mousemove', onMouseMove, { passive: true });
    window.addEventListener('keydown', onKeyDown, { passive: true });

    this._eventRemovers.push(() => {
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('keydown', onKeyDown);
    });
  };

  BeyondCaptchaInstance.prototype.bindWidgetEvents = function() {
    const self = this;
    const toggleBtn = this.container.querySelector('.bc-accessible-toggle-btn');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', function() {
        const currentlyOpen = self.state.isAccessibleMode;
        self.setAccessibilityMode(!currentlyOpen);
      });
    }

    // WAI-ARIA APG Tabs Implementation (Keyboard Arrow Navigation)
    const tablist = this.container.querySelector('[role="tablist"]');
    if (tablist) {
      const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));

      tabs.forEach((tab, index) => {
        tab.addEventListener('click', () => {
          self.switchChallengeTab(tab, tabs);
        });

        tab.addEventListener('keydown', (e) => {
          let targetTab = null;

          if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
            e.preventDefault();
            targetTab = tabs[(index + 1) % tabs.length];
          } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
            e.preventDefault();
            targetTab = tabs[(index - 1 + tabs.length) % tabs.length];
          } else if (e.key === 'Home') {
            e.preventDefault();
            targetTab = tabs[0];
          } else if (e.key === 'End') {
            e.preventDefault();
            targetTab = tabs[tabs.length - 1];
          }

          if (targetTab) {
            targetTab.focus();
            self.switchChallengeTab(targetTab, tabs);
          }
        });
      });
    }
  };

  BeyondCaptchaInstance.prototype.switchChallengeTab = function(selectedTab, allTabs) {
    const type = selectedTab.getAttribute('data-type');
    this.state.activeTabType = type;

    allTabs.forEach(tab => {
      const isSelected = (tab === selectedTab);
      tab.setAttribute('aria-selected', isSelected ? 'true' : 'false');
      tab.tabIndex = isSelected ? 0 : -1;
    });

    const panelBody = this.container.querySelector('.bc-tabpanel');
    if (panelBody) {
      panelBody.setAttribute('aria-labelledby', selectedTab.id);
    }

    this.loadChallenge(type);
  };

  BeyondCaptchaInstance.prototype.setAccessibilityMode = function(enabled) {
    const self = this;
    if (enabled) {
      // WCAG MANDATE: Immediately disarm passive behavioral tracking
      this.state.isAccessibleMode = true;
      this.state.trackingEnabled = false;
      this.state.mouseMoves = 0;
      this.state.mouseTrajectory = [];
      this.state.keystrokeIntervals = [];

      const panel = this.container.querySelector('.bc-challenge-panel');
      const toggleBtn = this.container.querySelector('.bc-accessible-toggle-btn');
      const statusText = this.container.querySelector('.bc-status-text');

      if (panel) panel.removeAttribute('hidden');
      if (toggleBtn) {
        toggleBtn.setAttribute('aria-expanded', 'true');
        toggleBtn.innerHTML = '<span aria-hidden="true">✓</span> Accessible Mode Active';
      }
      if (statusText) {
        statusText.textContent = 'Accessible verification active — Behavioral tracking: OFF';
      }

      this.announce('Accessible verification active. Behavioral tracking is OFF. Establishing secure session context.');

      // Server-Authoritative Accessibility Context Initiation (Part A, Section 1)
      fetch('/api/accessibility/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId: self.state.sessionId })
      })
      .then(res => res.json())
      .then(data => {
        if (data.success && data.contextId) {
          self.state.contextId = data.contextId;
        }
        self.loadChallenge(self.state.activeTabType || 'math');
      })
      .catch(err => {
        console.warn('[BeyondCAPTCHA] Accessibility context creation deferred:', err);
        self.loadChallenge(self.state.activeTabType || 'math');
      });

      if (typeof this.config.onAccessibilityMode === 'function') {
        try { this.config.onAccessibilityMode(true); } catch (e) { console.error(e); }
      }
    } else {
      // Restore normal passive tracking
      this.state.isAccessibleMode = false;
      this.state.trackingEnabled = true;
      this.state.startTime = Date.now();

      const panel = this.container.querySelector('.bc-challenge-panel');
      const toggleBtn = this.container.querySelector('.bc-accessible-toggle-btn');
      const statusText = this.container.querySelector('.bc-status-text');

      if (panel) panel.setAttribute('hidden', '');
      if (toggleBtn) {
        toggleBtn.setAttribute('aria-expanded', 'false');
        toggleBtn.innerHTML = '<span aria-hidden="true">♿</span> Use accessible verification';
      }
      if (statusText) {
        statusText.textContent = 'Passive human check active. Submitting the form verifies automatically.';
      }

      this.announce('Standard passive verification restored.');

      if (typeof this.config.onAccessibilityMode === 'function') {
        try { this.config.onAccessibilityMode(false); } catch (e) { console.error(e); }
      }
    }
  };

  BeyondCaptchaInstance.prototype.activateAccessibleMode = function() {
    this.setAccessibilityMode(true);
  };

  BeyondCaptchaInstance.prototype.toggleAccessibilityMode = function() {
    this.setAccessibilityMode(!this.state.isAccessibleMode);
  };

  BeyondCaptchaInstance.prototype.loadChallenge = function(challengeType) {
    const self = this;
    const content = this.container.querySelector('.bc-challenge-content');
    if (!content) return;
    content.innerHTML = '<div class="bc-status-box"><span class="bc-spinner" aria-hidden="true"></span><span>Generating accessible challenge...</span></div>';

    fetch(self.config.challengeApiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: challengeType,
        sessionId: self.state.sessionId,
        contextId: self.state.contextId
      })
    })
    .then(res => res.json())
    .then(data => {
      self.state.currentChallenge = data;
      self.renderChallengeUI(data);
    })
    .catch(err => {
      content.innerHTML = `<div class="bc-alert bc-alert-error" role="alert">Unable to connect to verification service. Please retry.</div>`;
    });
  };

  BeyondCaptchaInstance.prototype.renderChallengeUI = function(challenge) {
    const self = this;
    const content = this.container.querySelector('.bc-challenge-content');
    if (!content) return;

    const answerInputId = 'bc-ans-' + this.uid;
    const audioBtnId = 'bc-audio-btn-' + this.uid;
    const rememberId = 'bc-rem-' + this.uid;

    content.innerHTML = `
      <div class="bc-challenge-body">
        <div class="bc-prompt-block">
          <span class="bc-question-tag" style="font-weight: 800; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--bc-primary);">Accessible Text Challenge</span>
          <div class="bc-prompt-row">
            <h4 class="bc-challenge-prompt" id="bc-prompt-text-${this.uid}">
              ${challenge.prompt}
            </h4>

            <button type="button" class="bc-audio-btn" id="${audioBtnId}" aria-label="Listen to question prompt">
              <span aria-hidden="true">🔊</span> Listen
            </button>
          </div>
        </div>

        <div class="bc-input-row">
          <label for="${answerInputId}" class="bc-answer-label">Answer</label>
          <div class="bc-input-actions">
            <input type="text" id="${answerInputId}" class="bc-answer-input" placeholder="Type answer here" autocomplete="off" aria-describedby="bc-prompt-text-${this.uid}" />
            <button type="button" class="bc-btn-verify-answer">Verify</button>
            <button type="button" class="bc-btn-refresh-challenge">New challenge</button>
          </div>
        </div>

        <div class="bc-challenge-options">
          <label class="bc-remember-label">
            <input type="checkbox" id="${rememberId}" />
            <span>Remember this device for 30 days</span>
          </label>
        </div>

        <div class="bc-challenge-feedback" aria-live="polite" role="status"></div>
      </div>
    `;

    // Bind Audio Playback via Web Speech API
    const audioBtn = content.querySelector('#' + audioBtnId);
    if (audioBtn) {
      audioBtn.addEventListener('click', () => {
        self.playTTS(challenge.tts_prompt || challenge.prompt);
      });
    }

    // Bind Refresh Challenge
    const refreshBtn = content.querySelector('.bc-btn-refresh-challenge');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        self.loadChallenge(challenge.type);
      });
    }

    // Bind Answer Submit
    const verifyBtn = content.querySelector('.bc-btn-verify-answer');
    const answerInput = content.querySelector('#' + answerInputId);

    const submitAnswer = () => {
      const val = answerInput.value.trim();
      if (!val) {
        answerInput.focus();
        return;
      }
      const remember = content.querySelector('#' + rememberId)?.checked || false;
      self.submitChallengeAnswer(challenge.challenge_id, val, remember);
    };

    if (verifyBtn) verifyBtn.addEventListener('click', submitAnswer);
    if (answerInput) {
      answerInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          submitAnswer();
        }
      });
      // WCAG Focus Management: Shift focus to input upon generation
      setTimeout(() => answerInput.focus(), 100);
    }
  };

  BeyondCaptchaInstance.prototype.playTTS = function(text) {
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.rate = 0.9;
      utterance.pitch = 1.0;
      window.speechSynthesis.speak(utterance);
    } else {
      this.announce('Text to speech is not supported in this browser: ' + text);
    }
  };

  BeyondCaptchaInstance.prototype.submitChallengeAnswer = function(challengeId, answer, rememberDevice) {
    const self = this;
    const feedback = this.container.querySelector('.bc-challenge-feedback');
    const statusBox = this.container.querySelector('.bc-status-box');
    const alertBox = this.container.querySelector('.bc-alert');

    if (feedback) feedback.innerHTML = '<span class="bc-spinner"></span> Checking answer...';

    fetch(self.config.apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sessionId: self.state.sessionId,
        contextId: self.state.contextId,
        challengeId: challengeId,
        answer: answer,
        rememberDevice: rememberDevice,
        isAccessibleMode: true,
        flowType: 'accessible_' + (self.state.activeTabType || 'math')
      })
    })
    .then(res => res.json())
    .then(data => {
      if (data.decision === 'ALLOW') {
        self.state.isVerified = true;
        if (feedback) {
          feedback.innerHTML = '<div style="background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.3); padding: 12px; border-radius: 6px; color: #059669; font-weight: 700;"><span style="font-size: 15px;">✓ Verification successful</span><br><small style="font-weight: 500; opacity: 0.9; color: var(--bc-text-muted);">Behavioral tracking was OFF.</small></div>';
        }
        if (statusBox) {
          statusBox.innerHTML = '<span style="color: var(--bc-success, #16a34a); font-weight: 700;">✓ Accessible verification completed (Behavioral tracking was OFF)</span>';
        }
        self.announce('Accessible verification completed. Behavioral tracking was OFF.');

        // WCAG Focus Management: Advance focus to primary submit button upon completion
        const submitBtn = self.form.querySelector('button[type="submit"], input[type="submit"]');
        if (submitBtn) {
          setTimeout(() => submitBtn.focus(), 150);
        }

        if (typeof self.config.onSuccess === 'function') self.config.onSuccess(data);
        if (typeof self.config.onVerified === 'function') self.config.onVerified(data);
        if (typeof self.config.onDecision === 'function') self.config.onDecision(data);
      } else {
        self.state.isVerified = false;
        const attemptsLeft = data.attempts_left !== undefined ? data.attempts_left : 0;
        const msg = data.reasons?.[0] || 'Incorrect answer. Please retry.';

        if (feedback) {
          feedback.innerHTML = `<span style="color: var(--bc-error, #dc2626); font-weight: 600;">${msg}</span>`;
        }
        self.announce(msg);

        // WCAG Focus Management: Return focus to answer input for fast correction
        if (attemptsLeft > 0) {
          const ansInput = self.container.querySelector('#bc-ans-' + self.uid);
          if (ansInput) {
            setTimeout(() => {
              ansInput.focus();
              ansInput.select();
            }, 100);
          }
        } else {
          if (alertBox) {
            alertBox.className = 'bc-alert bc-alert-error';
            alertBox.textContent = 'Maximum attempts exceeded. Verification rejected.';
          }
          if (statusBox) {
            statusBox.innerHTML = '<span style="color: var(--bc-error, #dc2626); font-weight: 700;">❌ Verification rejected</span>';
          }
        }

        if (typeof self.config.onFailure === 'function') self.config.onFailure(data);
        if (typeof self.config.onError === 'function') self.config.onError(data);
        if (typeof self.config.onDecision === 'function') self.config.onDecision(data);
      }
    })
    .catch(err => {
      if (feedback) feedback.innerHTML = '<span style="color: var(--bc-error, #dc2626);">Connection error. Please retry.</span>';
    });
  };

  BeyondCaptchaInstance.prototype.attachFormInterception = function() {
    const self = this;

    const onSubmit = function(e) {
      // Prevent widget from interfering or racing during controlled attack simulation (Requirement 11 & 12)
      if (window.__beyondCaptchaSimulationActive) {
        e.preventDefault();
        e.stopImmediatePropagation();
        return false;
      }

      if (self.state.isVerified) {
        return; // Verified, allow submission
      }

      e.preventDefault();

      if (self.state.isAccessibleMode) {
        self.announce('Please answer the verification challenge to proceed.');
        const ans = self.container.querySelector('.bc-answer-input');
        if (ans) ans.focus();
        return;
      }

      // Normal passive verification
      self.verify();
    };

    if (this.form && this.form.addEventListener) {
      this.form.addEventListener('submit', onSubmit);
      this._eventRemovers.push(() => {
        this.form.removeEventListener('submit', onSubmit);
      });
    }
  };

  BeyondCaptchaInstance.prototype.verify = function() {
    const self = this;
    const statusBox = this.container.querySelector('.bc-status-box');
    const alertBox = this.container.querySelector('.bc-alert');

    if (statusBox) {
      statusBox.innerHTML = '<span class="bc-spinner" aria-hidden="true"></span><span>Verifying human interaction...</span>';
    }

    const honeypotVal = this.honeypotInput ? this.honeypotInput.value : '';
    const dwellTime = Date.now() - this.state.startTime;

    const telemetryPayload = {
      sessionId: this.state.sessionId,
      flowType: 'normal_passive',
      timeOnPage: dwellTime,
      honeypot: honeypotVal,
      keystrokes: this.state.keystrokes,
      keystrokeIntervals: this.state.keystrokeIntervals,
      mouseMoves: this.state.mouseMoves,
      mouseTrajectory: this.state.mouseTrajectory,
      isTouchDevice: ('ontouchstart' in window) || (navigator.maxTouchPoints > 0),
      browserFlags: {
        webdriver: navigator.webdriver || false,
        screenWidth: window.screen ? window.screen.width : 0,
        screenHeight: window.screen ? window.screen.height : 0,
        pluginsCount: navigator.plugins ? navigator.plugins.length : 0
      },
      userAgent: navigator.userAgent || ''
    };

    fetch(self.config.apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(telemetryPayload)
    })
    .then(res => res.json())
    .then(data => {
      if (typeof self.config.onDecision === 'function') {
        try { self.config.onDecision(data); } catch (e) { console.error(e); }
      }

      if (data.decision === 'ALLOW') {
        self.state.isVerified = true;
        if (statusBox) {
          statusBox.innerHTML = '<span style="color: var(--bc-success, #16a34a); font-weight: 700;">✓ Human verification completed</span>';
        }
        self.announce('Human verification passed.');

        if (typeof self.config.onSuccess === 'function') self.config.onSuccess(data);
        if (typeof self.config.onVerified === 'function') self.config.onVerified(data);
      } else if (data.decision === 'ACCESSIBILITY_VERIFY') {
        // Automatic Server-Authoritative Accessibility Routing
        self.state.isAccessibleMode = true;
        self.state.trackingEnabled = false;
        self.state.mouseMoves = 0;
        self.state.mouseTrajectory = [];
        self.state.keystrokes = 0;
        self.state.keystrokeIntervals = [];

        if (data.contextId) {
          self.state.contextId = data.contextId;
        }

        const panel = self.container.querySelector('.bc-challenge-panel');
        const toggleBtn = self.container.querySelector('.bc-accessible-toggle-btn');
        const statusText = self.container.querySelector('.bc-status-text');

        if (panel) panel.removeAttribute('hidden');
        if (toggleBtn) {
          toggleBtn.setAttribute('aria-expanded', 'true');
          toggleBtn.innerHTML = '<span aria-hidden="true">✓</span> Accessible Mode Active';
        }
        if (statusText) {
          statusText.textContent = 'Accessible verification active — Behavioral tracking: OFF';
        }

        self.announce('Accessible verification selected by server policy. Behavioral tracking is OFF. Please complete the accessible challenge.');

        if (typeof self.config.onAccessibilityMode === 'function') {
          try { self.config.onAccessibilityMode(true); } catch (e) { console.error(e); }
        }

        if (self.state.contextId) {
          self.loadChallenge(self.state.activeTabType || 'math');
        } else {
          fetch('/api/accessibility/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sessionId: self.state.sessionId })
          })
          .then(res => res.json())
          .then(startData => {
            if (startData.success && startData.contextId) {
              self.state.contextId = startData.contextId;
            }
            self.loadChallenge(self.state.activeTabType || 'math');
          })
          .catch(err => {
            self.loadChallenge(self.state.activeTabType || 'math');
          });
        }
      } else {
        self.state.isVerified = false;
        if (statusBox) {
          statusBox.innerHTML = '<span style="color: var(--bc-error, #dc2626); font-weight: 700;">❌ Verification failed</span>';
        }
        if (alertBox) {
          alertBox.className = 'bc-alert bc-alert-error';
          alertBox.textContent = 'Verification blocked: ' + (data.reasons?.[0] || 'Automated activity detected');
        }
        self.announce('Verification failed. Automated activity detected.');

        if (typeof self.config.onFailure === 'function') self.config.onFailure(data);
        if (typeof self.config.onError === 'function') self.config.onError(data);
      }
    })
    .catch(err => {
      console.error('[BeyondCAPTCHA] Verification error:', err);
      if (statusBox) {
        statusBox.innerHTML = '<span style="color: var(--bc-error, #dc2626);">Network error during verification.</span>';
      }
    });
  };

  BeyondCaptchaInstance.prototype.destroy = function() {
    this._eventRemovers.forEach(fn => fn());
    this._eventRemovers = [];
    if (this.honeypotInput && this.honeypotInput.parentNode) {
      this.honeypotInput.parentNode.removeChild(this.honeypotInput);
    }
    if (this.container && this.container.parentNode) {
      this.container.parentNode.removeChild(this.container);
    }
    const idx = BeyondCaptcha.instances.indexOf(this);
    if (idx !== -1) BeyondCaptcha.instances.splice(idx, 1);
  };

  BeyondCaptchaInstance.prototype.reset = function() {
    this.state.isVerified = false;
    this.state.isAccessibleMode = false;
    this.state.trackingEnabled = true;
    this.state.mouseMoves = 0;
    this.state.mouseTrajectory = [];
    this.state.keystrokes = 0;
    this.state.keystrokeIntervals = [];
    this.state.startTime = Date.now();
    this.state.sessionId = 'sess_' + this.uid + '_' + Date.now().toString(36);
    this.state.currentChallenge = null;

    const panel = this.container.querySelector('.bc-challenge-panel');
    const toggleBtn = this.container.querySelector('.bc-accessible-toggle-btn');
    const statusText = this.container.querySelector('.bc-status-text');
    const alertBox = this.container.querySelector('.bc-alert');
    const feedback = this.container.querySelector('.bc-challenge-feedback');

    if (panel) panel.setAttribute('hidden', '');
    if (toggleBtn) {
      toggleBtn.setAttribute('aria-expanded', 'false');
      toggleBtn.innerHTML = '<span aria-hidden="true">♿</span> Use accessible verification';
    }
    if (statusText) statusText.textContent = 'Passive human check active. Submitting the form verifies automatically.';
    if (alertBox) {
      alertBox.className = 'bc-alert bc-alert-error bc-sr-only';
      alertBox.textContent = '';
    }
    if (feedback) feedback.textContent = '';
  };

  // --- GLOBAL SDK EXPORT ---
  const BeyondCaptcha = {
    instances: [],

    mount: function(target, userConfig) {
      const el = typeof target === 'string' ? document.querySelector(target) : target;
      if (!el) {
        console.warn('[BeyondCAPTCHA] Target element not found:', target);
        return null;
      }
      const instance = new BeyondCaptchaInstance(el, userConfig);
      this.instances.push(instance);
      this.state = instance.state;
      return instance;
    },

    init: function(userConfig) {
      const selector = userConfig?.formSelector || 'form';
      return this.mount(selector, userConfig);
    },

    activateAccessibleMode: function() {
      if (this.instances.length > 0) {
        this.instances[0].setAccessibilityMode(true);
      }
    },

    toggleAccessibilityMode: function() {
      if (this.instances.length > 0) {
        this.instances[0].toggleAccessibilityMode();
      }
    },

    announce: function(message) {
      if (this.instances.length > 0) {
        this.instances[0].announce(message);
      }
    }
  };

  window.BeyondCaptcha = BeyondCaptcha;

})(window, document);
