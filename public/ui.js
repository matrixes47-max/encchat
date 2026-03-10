// ui.js — ინტერფეისის ლოგიკა (CSP-safe, გარე ფაილი)

window._libErrors = [];
window._libLoaded = {};

document.addEventListener('DOMContentLoaded', function() {

  // ── ბიბლიოთეკების შემოწმება ──────────────────────────────────
  if (window._libErrors.length > 0) {
    var el = document.getElementById('join-error');
    if (el) { el.textContent = window._libErrors.join(' | '); el.style.display = 'block'; }
  }

  // ── Privacy Notice ────────────────────────────────────────────
  var privBtn = document.getElementById('privacy-btn');
  var privContent = document.getElementById('privacy-content');
  if (privBtn && privContent) {
    privBtn.addEventListener('click', function() {
      if (privContent.style.display === 'none' || privContent.style.display === '') {
        privContent.style.display = 'block';
        privBtn.textContent = '[ ℹ️ Privacy Notice ▲ ]';
      } else {
        privContent.style.display = 'none';
        privBtn.textContent = '[ ℹ️ Privacy Notice ▼ ]';
      }
    });
  }

});
