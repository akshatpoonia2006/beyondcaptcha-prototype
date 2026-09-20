/**
 * BeyondCAPTCHA Security Lab Controller
 * - Remembers selected attack simulation
 * - Navigates directly to the Main Demo Form with ?simulate=<attack>
 */
document.addEventListener('DOMContentLoaded', function() {
  'use strict';

  // Single navigation trigger: dispatch buttons only (Requirement 18)
  const dispatchButtons = document.querySelectorAll('.btn-scenario-dispatch');
  dispatchButtons.forEach(btn => {
    btn.addEventListener('click', function(e) {
      const attackType = this.getAttribute('data-attack') || 'honeypot';
      try {
        sessionStorage.setItem('attackSimulation', JSON.stringify({ type: attackType }));
      } catch (err) {}
      // Native <a> navigation to /?simulate=<attack> proceeds without race conditions
    });
  });
});
