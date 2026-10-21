/**
 * main.js — STRIDE Threat Model Analyzer
 * General UI utilities and interactions.
 */

'use strict';

// ── Mobile Navigation Toggle ───────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function () {
  var toggle = document.getElementById('navToggle');
  var links  = document.querySelector('.nav-links');
  if (toggle && links) {
    toggle.addEventListener('click', function () {
      links.classList.toggle('open');
    });
  }

  // Close nav on link click (mobile)
  if (links) {
    links.querySelectorAll('.nav-link').forEach(function (link) {
      link.addEventListener('click', function () {
        links.classList.remove('open');
      });
    });
  }

  // Auto-dismiss flash messages after 5s
  document.querySelectorAll('.flash').forEach(function (el) {
    setTimeout(function () {
      el.style.transition = 'opacity 0.5s';
      el.style.opacity = '0';
      setTimeout(function () { el.remove(); }, 500);
    }, 5000);
  });
});

// ── Toggle Detail Section (STRIDE cards on dashboard) ─────────────────────
function toggleDetail(id) {
  var el = document.getElementById(id);
  if (el) {
    el.classList.toggle('hidden');
  }
}
