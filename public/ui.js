// ui.js — ინტერფეისის ლოგიკა (CSP-safe, გარე ფაილი)
// v5: Browser Fingerprinting Protection დამატებულია

// ════════════════════════════════════════════════════════════════════
//  BROWSER FINGERPRINTING PROTECTION
//  Canvas, WebGL, AudioContext, Screen, Navigator — ყველა ფარავს
// ════════════════════════════════════════════════════════════════════

(function installFingerprintDefense() {
  'use strict';

  // ── 1. Canvas Fingerprint Noise ──────────────────────────────────
  // Canvas-ში render-ის დროს მიკრო-ნოიზი — hash-ი სხვადასხვა გამოდის
  const _origGetContext = HTMLCanvasElement.prototype.getContext;
  HTMLCanvasElement.prototype.getContext = function(type, opts) {
    const ctx = _origGetContext.call(this, type, opts);
    if (!ctx || (type !== '2d' && type !== 'webgl' && type !== 'webgl2' && type !== 'experimental-webgl')) {
      return ctx;
    }
    if (type === '2d') {
      const _origGetImageData = ctx.getImageData.bind(ctx);
      ctx.getImageData = function(x, y, w, h) {
        const data = _origGetImageData(x, y, w, h);
        // ყოველ 100-ე pixel-ს ვუმატებთ ±1 ნოიზს — თვალით შეუმჩნეველია
        for (let i = 0; i < data.data.length; i += 400) {
          data.data[i]   = Math.max(0, Math.min(255, data.data[i]   + (Math.random() > 0.5 ? 1 : -1)));
          data.data[i+1] = Math.max(0, Math.min(255, data.data[i+1] + (Math.random() > 0.5 ? 1 : -1)));
        }
        return data;
      };
    }
    return ctx;
  };

  // ── 2. WebGL Renderer / Vendor Spoofing ─────────────────────────
  // GPU ინფო ყველაზე უნიკალური fingerprint — ვმალავთ
  const _origGetParam = WebGLRenderingContext.prototype.getParameter;
  function spoofWebGL(original) {
    return function(param) {
      // UNMASKED_RENDERER_WEBGL = 37446, UNMASKED_VENDOR_WEBGL = 37445
      if (param === 37446) return 'Generic Renderer';
      if (param === 37445) return 'Generic Vendor';
      return original.call(this, param);
    };
  }
  WebGLRenderingContext.prototype.getParameter = spoofWebGL(_origGetParam);
  if (window.WebGL2RenderingContext) {
    WebGL2RenderingContext.prototype.getParameter = spoofWebGL(
      WebGL2RenderingContext.prototype.getParameter
    );
  }

  // ── 3. AudioContext Fingerprint Noise ───────────────────────────
  // AudioContext oscillator-ის output ოდნავ იცვლება — hash-ი სხვა
  if (window.AudioContext || window.webkitAudioContext) {
    const AC = window.AudioContext || window.webkitAudioContext;
    const _origCreateOscillator = AC.prototype.createOscillator;
    AC.prototype.createOscillator = function() {
      const osc = _origCreateOscillator.call(this);
      if (osc.frequency) {
        const origSetValue = osc.frequency.setValueAtTime.bind(osc.frequency);
        osc.frequency.setValueAtTime = function(val, time) {
          return origSetValue(val + (Math.random() - 0.5) * 0.0001, time);
        };
      }
      return osc;
    };
  }

  // ── 4. Screen Resolution Normalization ──────────────────────────
  // Screen-ის ზუსტი resolution + colorDepth + pixelDepth — fingerprint
  // ვამრგვალებთ საერთო მნიშვნელობებამდე
  try {
    const commonResolutions = [
      [1280, 720], [1366, 768], [1440, 900], [1536, 864],
      [1600, 900], [1920, 1080], [2560, 1440]
    ];
    const w = window.screen.width;
    const h = window.screen.height;
    // ყველაზე ახლოს მდებარე სტანდარტული რეზოლუცია
    const closest = commonResolutions.reduce((prev, curr) =>
      Math.abs(curr[0] - w) < Math.abs(prev[0] - w) ? curr : prev
    );
    Object.defineProperty(window.screen, 'width',       { get: () => closest[0] });
    Object.defineProperty(window.screen, 'height',      { get: () => closest[1] });
    Object.defineProperty(window.screen, 'availWidth',  { get: () => closest[0] });
    Object.defineProperty(window.screen, 'availHeight', { get: () => closest[1] - 40 });
    Object.defineProperty(window.screen, 'colorDepth',  { get: () => 24 });
    Object.defineProperty(window.screen, 'pixelDepth',  { get: () => 24 });
  } catch(e) { /* read-only env */ }

  // ── 5. Battery API Blocking ──────────────────────────────────────
  // Battery status გამოიყენება fingerprint-ად — ვბლოკავთ
  if (navigator.getBattery) {
    Object.defineProperty(navigator, 'getBattery', {
      get: () => () => Promise.reject(new Error('Blocked for privacy'))
    });
  }

  // ── 6. Timezone Normalization ────────────────────────────────────
  // Timezone offset-ი ვმალავთ — UTC ვაბრუნებთ
  try {
    const _origDateTZO = Date.prototype.getTimezoneOffset;
    Date.prototype.getTimezoneOffset = function() { return 0; };
    const _origIntlDTF = Intl.DateTimeFormat.prototype.resolvedOptions;
    Intl.DateTimeFormat.prototype.resolvedOptions = function() {
      const opts = _origIntlDTF.call(this);
      return { ...opts, timeZone: 'UTC' };
    };
  } catch(e) { /* read-only env */ }

  // ── 7. navigator.plugins / mimeTypes ────────────────────────────
  // Plugin სია უნიკალურია — ვმალავთ
  try {
    Object.defineProperty(navigator, 'plugins',   { get: () => [] });
    Object.defineProperty(navigator, 'mimeTypes', { get: () => [] });
  } catch(e) { /* read-only env */ }

  // ── 8. hardware concurrency / memory normalization ───────────────
  try {
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 4 });
    if ('deviceMemory' in navigator) {
      Object.defineProperty(navigator, 'deviceMemory', { get: () => 4 });
    }
  } catch(e) { /* read-only env */ }

  window._fingerprintDefense = true;
  console.log('[encchat] 🛡️ Fingerprint defense: active (canvas/webgl/audio/screen/battery/tz)');
})();


// ════════════════════════════════════════════════════════════════════

window._libErrors = [];
window._libLoaded = {};

document.addEventListener('DOMContentLoaded', function() {

  // ── ბიბლიოთეკების შემოწმება ──────────────────────────────────
  if (window._libErrors.length > 0) {
    var el = document.getElementById('join-error');
    if (el) { el.textContent = window._libErrors.join(' | '); el.style.display = 'block'; }
  }

  // ── Fingerprint Defense Status Badge ─────────────────────────
  var infoEl = document.getElementById('join-info');
  if (infoEl && window._fingerprintDefense) {
    var badge = document.createElement('span');
    badge.textContent = '— Fingerprint Defense: Canvas · WebGL · Audio · Screen · Battery';
    infoEl.appendChild(badge);
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
