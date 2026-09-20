# -*- coding: utf-8 -*-
"""
Suite 7: SDK & Frontend Integrity Verification (Section 27.7)
Checks SDK lifecycle hooks, ARIA accessibility bindings, and theme script stability.
"""
import os
import pytest

def test_sdk_methods_and_lifecycle():
    sdk_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'js', 'beyondcaptcha-widget.js')
    assert os.path.exists(sdk_path)
    with open(sdk_path, 'r', encoding='utf-8') as f:
        js = f.read()
        
    assert 'mount:' in js
    assert 'init:' in js
    assert 'reset:' in js or 'reset' in js
    assert 'setAccessibilityMode:' in js or 'setAccessibilityMode' in js

def test_sdk_wcag_aria_compliance():
    sdk_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'js', 'beyondcaptcha-widget.js')
    with open(sdk_path, 'r', encoding='utf-8') as f:
        js = f.read()
        
    assert 'aria-live' in js
    assert 'aria-label' in js
    assert 'speechSynthesis' in js

def test_theme_system_js_integrity():
    theme_js = os.path.join(os.path.dirname(__file__), '..', 'static', 'js', 'theme.js')
    assert os.path.exists(theme_js)
    with open(theme_js, 'r', encoding='utf-8') as f:
        js = f.read()
        
    assert 'setTheme' in js
    assert 'resolveTheme' in js
    assert 'prefers-color-scheme' in js
