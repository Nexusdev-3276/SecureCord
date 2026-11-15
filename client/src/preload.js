'use strict';
const { contextBridge, ipcRenderer } = require('electron');

// ---------------------------------------------------------------------------
// Anti-WebRTC IP leak: force relay-only
// ---------------------------------------------------------------------------
try {
  const OrigRTC = window.RTCPeerConnection;
  const PatchedRTC = function (config) {
    const cfg = config || {};
    cfg.iceTransportPolicy = 'relay';
    if (Array.isArray(cfg.iceServers)) {
      cfg.iceServers = cfg.iceServers.filter((s) => /turn:/i.test((s && s.urls) || ''));
    }
    return new OrigRTC(cfg);
  };
  PatchedRTC.prototype = OrigRTC.prototype;
  Object.keys(OrigRTC).forEach((k) => { PatchedRTC[k] = OrigRTC[k]; });
  window.RTCPeerConnection = PatchedRTC;
  window.webkitRTCPeerConnection = PatchedRTC;
} catch (e) {
  console.warn('webrtc patch failed', e);
}

// ---------------------------------------------------------------------------
// Anti-fingerprinting (Tor Browser-like uniformity)
// ---------------------------------------------------------------------------
(function () {
  // Uniform navigator properties (Tor Browser values)
  const overrides = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
    platform: 'Win32',
    language: 'en-US',
    languages: ['en-US', 'en'],
    hardwareConcurrency: 4,
    deviceMemory: 8,
    maxTouchPoints: 0,
    cookieEnabled: true,
    doNotTrack: '1',
    webdriver: false
  };
  for (const [k, v] of Object.entries(overrides)) {
    try { Object.defineProperty(navigator, k, { get: () => v, configurable: true }); } catch {}
  }
  try { Object.defineProperty(navigator, 'plugins', { get: () => [] }); } catch {}
  try { Object.defineProperty(navigator, 'mimeTypes', { get: () => [] }); } catch {}

  // Canvas fingerprint noise
  try {
    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function (x, y, w, h) {
      const img = origGetImageData.call(this, x, y, w, h);
      for (let i = 0; i < img.data.length; i += 4) {
        img.data[i] ^= (Math.random() * 2) | 0; // subtle noise
      }
      return img;
    };
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function (type) {
      const ctx = this.getContext('2d');
      if (ctx) {
        try {
          const img = ctx.getImageData(0, 0, this.width, this.height);
          for (let i = 0; i < img.data.length; i += 4) img.data[i] ^= 1;
          ctx.putImageData(img, 0, 0);
        } catch {}
      }
      return origToDataURL.apply(this, arguments);
    };
  } catch {}

  // WebGL fingerprint noise
  try {
    const getParam = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function (param) {
      // UNMASKED_VENDOR_WEBGL / UNMASKED_RENDERER_WEBGL
      if (param === 37445) return 'Intel Inc.';
      if (param === 37446) return 'Intel Iris OpenGL Engine';
      return getParam.call(this, param);
    };
    if (window.WebGL2RenderingContext) {
      const getParam2 = WebGL2RenderingContext.prototype.getParameter;
      WebGL2RenderingContext.prototype.getParameter = function (param) {
        if (param === 37445) return 'Intel Inc.';
        if (param === 37446) return 'Intel Iris OpenGL Engine';
        return getParam2.call(this, param);
      };
    }
  } catch {}

  // AudioContext fingerprint noise
  try {
    const OrigAudio = window.AudioContext || window.webkitAudioContext;
    if (OrigAudio) {
      const origCreateOsc = OrigAudio.prototype.createOscillator;
      // no-op hardening: leave API but normalize sampleRate
      Object.defineProperty(OrigAudio.prototype, 'sampleRate', { get: () => 44100 });
    }
  } catch {}

  // Screen / viewport uniformity (Tor Browser: 1000x1000 rounded)
  try {
    Object.defineProperty(screen, 'width', { get: () => 1920 });
    Object.defineProperty(screen, 'height', { get: () => 1080 });
    Object.defineProperty(screen, 'availWidth', { get: () => 1920 });
    Object.defineProperty(screen, 'availHeight', { get: () => 1040 });
    Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
    Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });
  } catch {}

  // Timezone spoof to UTC
  try {
    const origResolved = Intl.DateTimeFormat.prototype.resolvedOptions;
    Intl.DateTimeFormat.prototype.resolvedOptions = function () {
      const r = origResolved.call(this);
      r.timeZone = 'UTC';
      return r;
    };
  } catch {}

  // Battery API removal
  try { delete navigator.getBattery; } catch {}
})();

contextBridge.exposeInMainWorld('securecord', {
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (s) => ipcRenderer.invoke('save-settings', s),
  openExternal: (u) => ipcRenderer.invoke('open-external', u),
  newTorIdentity: () => ipcRenderer.invoke('tor-new-identity'),
  getStartupErrors: () => ipcRenderer.invoke('get-startup-errors'),
  getNetworkStatus: () => ipcRenderer.invoke('get-network-status'),
  onStatus: (cb) => ipcRenderer.on('status', (_e, m) => cb(m))
});
