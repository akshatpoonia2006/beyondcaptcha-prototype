/**
 * BeyondCAPTCHA Centralized Theme Controller (v2.4.0)
 * Single Source of Truth for Visual Theme: Light, Dark, System Default
 * WCAG 2.1 AA Compliant (WAI-ARIA Popover Menu, Focus Trap/Return, Polite Live Announcements)
 */
(function(window, document) {
  'use strict';

  const STORAGE_KEY = 'beyondcaptcha-theme';
  const LEGACY_STORAGE_KEY = 'bc_theme_pref';
  const PREFERENCES = ['system', 'light', 'dark'];

  // Professional SVG Icons matching BeyondCAPTCHA Design System
  const ICONS = {
    light: `<svg class="bc-theme-btn-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`,
    dark: `<svg class="bc-theme-btn-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`,
    system: `<svg class="bc-theme-btn-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>`
  };

  const ThemeController = {
    currentPreference: 'system', // 'system' | 'light' | 'dark'
    resolvedTheme: 'light',      // 'light' | 'dark'
    mql: null,

    init: function() {
      // 1. Read stored preference (migrating legacy key if found)
      let stored = null;
      try {
        if (window.localStorage) {
          stored = window.localStorage.getItem(STORAGE_KEY) || window.localStorage.getItem(LEGACY_STORAGE_KEY);
        }
      } catch (e) {}

      if (stored && PREFERENCES.includes(stored)) {
        this.currentPreference = stored;
      } else {
        this.currentPreference = 'system';
      }

      // 2. Resolve & apply theme immediately
      this.applyTheme(this.currentPreference, false);

      // 3. Listen to OS prefers-color-scheme
      this.bindSystemListener();

      // 4. Render the single compact theme control in all containers
      this.renderControls();

      // 5. Bind global dismissal events (outside click & Escape)
      this.bindGlobalEvents();
    },

    /**
     * Resolves preference ('system' | 'light' | 'dark') to concrete ('light' | 'dark')
     */
    resolveTheme: function(preference) {
      if (preference === 'light') return 'light';
      if (preference === 'dark') return 'dark';
      
      // Preference is 'system' - evaluate OS preference
      const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');
      return darkQuery.matches ? 'dark' : 'light';
    },

    /**
     * Applies resolved theme to documentElement and saves preference
     */
    setTheme: function(preference, shouldAnnounce = true) {
      if (!PREFERENCES.includes(preference)) return;

      this.currentPreference = preference;
      try {
        if (window.localStorage) {
          window.localStorage.setItem(STORAGE_KEY, preference);
          window.localStorage.removeItem(LEGACY_STORAGE_KEY);
        }
      } catch (e) {}

      this.applyTheme(preference, shouldAnnounce);
      this.updateUI();
    },

    /**
     * Core theme engine: sets dataset.theme and dataset.themePreference on <html>
     */
    applyTheme: function(preference, shouldAnnounce) {
      const resolved = this.resolveTheme(preference);
      this.resolvedTheme = resolved;

      const root = document.documentElement;
      // Single source of truth: dataset.theme is ALWAYS strictly 'light' or 'dark'
      root.dataset.theme = resolved;
      root.dataset.themePreference = preference;

      if (shouldAnnounce) {
        const prefLabel = preference === 'system' ? 'System Default' : (preference === 'light' ? 'Light' : 'Dark');
        const resolvedLabel = resolved === 'dark' ? 'Dark' : 'Light';
        if (preference === 'system') {
          this.announce(`Theme set to System Default. Current appearance is ${resolvedLabel}.`);
        } else {
          this.announce(`Theme set to ${prefLabel} mode.`);
        }
      }
    },

    /**
     * Listen to OS theme changes; only reacts if preference === 'system'
     */
    bindSystemListener: function() {
      this.mql = window.matchMedia('(prefers-color-scheme: dark)');
      const handler = (e) => {
        // STRICT RULE: Only update if the user has selected System Default
        if (this.currentPreference === 'system') {
          const newResolved = e.matches ? 'dark' : 'light';
          this.resolvedTheme = newResolved;
          document.documentElement.dataset.theme = newResolved;
          this.updateUI();
          this.announce(`System appearance changed to ${newResolved === 'dark' ? 'Dark' : 'Light'}. Application updated.`);
        }
      };

      if (this.mql.addEventListener) {
        this.mql.addEventListener('change', handler);
      } else if (this.mql.addListener) {
        this.mql.addListener(handler);
      }
    },

    /**
     * Screen-reader polite live announcer
     */
    announce: function(msg) {
      let announcer = document.getElementById('bc-theme-announcer');
      if (!announcer) {
        announcer = document.createElement('div');
        announcer.id = 'bc-theme-announcer';
        announcer.className = 'bc-sr-only';
        announcer.setAttribute('aria-live', 'polite');
        announcer.setAttribute('aria-atomic', 'true');
        document.body.appendChild(announcer);
      }
      announcer.textContent = '';
      setTimeout(() => { announcer.textContent = msg; }, 60);
    },

    /**
     * Render the single compact theme button & popover menu in all .bc-theme-switcher containers
     */
    renderControls: function() {
      const containers = document.querySelectorAll('.bc-theme-switcher');
      containers.forEach(container => {
        container.innerHTML = `
          <div class="bc-theme-control">
            <button
              type="button"
              class="bc-theme-btn"
              aria-label="Theme settings"
              aria-haspopup="menu"
              aria-expanded="false"
              title="Theme settings"
            >
              <span class="bc-theme-btn-icon" aria-hidden="true">
                ${ICONS[this.currentPreference] || ICONS.system}
              </span>
              <span class="bc-theme-btn-text">Theme</span>
              <span class="bc-theme-btn-arrow" aria-hidden="true">▾</span>
            </button>
            <div
              class="bc-theme-menu"
              role="menu"
              aria-label="Theme selection"
              tabindex="-1"
              hidden
            >
              <div class="bc-theme-menu-header">
                <span class="bc-theme-menu-title">Theme</span>
                <span class="bc-theme-menu-resolved">
                  Appearance: <strong class="bc-theme-resolved-name">${this.resolvedTheme === 'dark' ? 'Dark' : 'Light'}</strong>
                </span>
              </div>
              <div class="bc-theme-menu-list" role="presentation">
                <button
                  type="button"
                  class="bc-theme-menu-item"
                  role="menuitemradio"
                  aria-checked="${this.currentPreference === 'light'}"
                  data-theme-value="light"
                  tabindex="${this.currentPreference === 'light' ? '0' : '-1'}"
                >
                  <span class="bc-theme-radio-circle" aria-hidden="true">
                    <span class="bc-theme-radio-inner"></span>
                  </span>
                  <span class="bc-theme-item-icon" aria-hidden="true">${ICONS.light}</span>
                  <div class="bc-theme-item-text-wrap">
                    <span class="bc-theme-item-label">Light</span>
                  </div>
                </button>
                <button
                  type="button"
                  class="bc-theme-menu-item"
                  role="menuitemradio"
                  aria-checked="${this.currentPreference === 'dark'}"
                  data-theme-value="dark"
                  tabindex="${this.currentPreference === 'dark' ? '0' : '-1'}"
                >
                  <span class="bc-theme-radio-circle" aria-hidden="true">
                    <span class="bc-theme-radio-inner"></span>
                  </span>
                  <span class="bc-theme-item-icon" aria-hidden="true">${ICONS.dark}</span>
                  <div class="bc-theme-item-text-wrap">
                    <span class="bc-theme-item-label">Dark</span>
                  </div>
                </button>
                <button
                  type="button"
                  class="bc-theme-menu-item"
                  role="menuitemradio"
                  aria-checked="${this.currentPreference === 'system'}"
                  data-theme-value="system"
                  tabindex="${this.currentPreference === 'system' ? '0' : '-1'}"
                >
                  <span class="bc-theme-radio-circle" aria-hidden="true">
                    <span class="bc-theme-radio-inner"></span>
                  </span>
                  <span class="bc-theme-item-icon" aria-hidden="true">${ICONS.system}</span>
                  <div class="bc-theme-item-text-wrap">
                    <span class="bc-theme-item-label">System Default</span>
                    <span class="bc-theme-item-sub bc-theme-os-hint">
                      (Matches OS: ${this.mql && this.mql.matches ? 'Dark' : 'Light'})
                    </span>
                  </div>
                </button>
              </div>
            </div>
          </div>
        `;

        this.bindControlEvents(container);
      });
    },

    /**
     * Binds click and keyboard handlers for a specific theme switcher container
     */
    bindControlEvents: function(container) {
      const btn = container.querySelector('.bc-theme-btn');
      const menu = container.querySelector('.bc-theme-menu');
      if (!btn || !menu) return;

      const items = Array.from(menu.querySelectorAll('.bc-theme-menu-item'));

      // Toggle menu open/close
      const toggleMenu = (open) => {
        const isOpen = (typeof open === 'boolean') ? open : menu.hasAttribute('hidden');
        if (isOpen) {
          // Close any other open menus first
          document.querySelectorAll('.bc-theme-menu').forEach(m => {
            if (m !== menu) {
              m.setAttribute('hidden', '');
              const parentBtn = m.parentElement ? m.parentElement.querySelector('.bc-theme-btn') : null;
              if (parentBtn) parentBtn.setAttribute('aria-expanded', 'false');
            }
          });
          menu.removeAttribute('hidden');
          btn.setAttribute('aria-expanded', 'true');
          // Focus the currently checked item
          const checkedItem = items.find(i => i.getAttribute('aria-checked') === 'true') || items[0];
          if (checkedItem) checkedItem.focus();
        } else {
          menu.setAttribute('hidden', '');
          btn.setAttribute('aria-expanded', 'false');
        }
      };

      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleMenu();
      });

      // Item selection via click
      items.forEach((item, index) => {
        item.addEventListener('click', (e) => {
          e.stopPropagation();
          const chosen = item.getAttribute('data-theme-value');
          this.setTheme(chosen, true);
          toggleMenu(false);
          btn.focus();
        });

        // WAI-ARIA Menu Keyboard Navigation
        item.addEventListener('keydown', (e) => {
          if (e.key === 'ArrowDown' || e.key === 'ArrowRight') {
            e.preventDefault();
            const nextIdx = (index + 1) % items.length;
            items[nextIdx].focus();
          } else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') {
            e.preventDefault();
            const prevIdx = (index - 1 + items.length) % items.length;
            items[prevIdx].focus();
          } else if (e.key === 'Home') {
            e.preventDefault();
            items[0].focus();
          } else if (e.key === 'End') {
            e.preventDefault();
            items[items.length - 1].focus();
          } else if (e.key === 'Escape') {
            e.preventDefault();
            toggleMenu(false);
            btn.focus();
          } else if (e.key === 'Tab') {
            // Close menu and let focus advance naturally
            toggleMenu(false);
          }
        });
      });
    },

    /**
     * Binds document-level outside click and Escape key listeners
     */
    bindGlobalEvents: function() {
      document.addEventListener('click', (e) => {
        if (!e.target.closest('.bc-theme-control')) {
          document.querySelectorAll('.bc-theme-menu').forEach(menu => {
            menu.setAttribute('hidden', '');
            const parentBtn = menu.parentElement ? menu.parentElement.querySelector('.bc-theme-btn') : null;
            if (parentBtn) parentBtn.setAttribute('aria-expanded', 'false');
          });
        }
      });

      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          const openMenus = document.querySelectorAll('.bc-theme-menu:not([hidden])');
          openMenus.forEach(menu => {
            menu.setAttribute('hidden', '');
            const parentBtn = menu.parentElement ? menu.parentElement.querySelector('.bc-theme-btn') : null;
            if (parentBtn) {
              parentBtn.setAttribute('aria-expanded', 'false');
              parentBtn.focus();
            }
          });
        }
      });
    },

    /**
     * Synchronizes UI across all rendered theme controls on the page
     */
    updateUI: function() {
      const controls = document.querySelectorAll('.bc-theme-control');
      const osIsDark = this.mql && this.mql.matches;
      const resolvedName = this.resolvedTheme === 'dark' ? 'Dark' : 'Light';

      controls.forEach(ctrl => {
        // 1. Update button icon
        const btnIcon = ctrl.querySelector('.bc-theme-btn-icon');
        if (btnIcon) {
          btnIcon.innerHTML = ICONS[this.currentPreference] || ICONS.system;
        }

        // 2. Update resolved appearance text
        const resolvedEl = ctrl.querySelector('.bc-theme-resolved-name');
        if (resolvedEl) {
          resolvedEl.textContent = resolvedName;
        }

        // 3. Update OS hint text on System Default item
        const osHint = ctrl.querySelector('.bc-theme-os-hint');
        if (osHint) {
          osHint.textContent = `(Matches OS: ${osIsDark ? 'Dark' : 'Light'})`;
        }

        // 4. Update radio states & roving tabindex
        const items = ctrl.querySelectorAll('.bc-theme-menu-item');
        items.forEach(item => {
          const val = item.getAttribute('data-theme-value');
          const isSelected = (val === this.currentPreference);
          item.setAttribute('aria-checked', isSelected ? 'true' : 'false');
          item.setAttribute('tabindex', isSelected ? '0' : '-1');
        });
      });
    }
  };

  // Auto-init on DOMContentLoaded or immediately if DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => ThemeController.init());
  } else {
    ThemeController.init();
  }

  window.BeyondCaptchaTheme = ThemeController;
})(window, document);
