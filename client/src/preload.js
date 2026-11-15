'use strict';
const { contextBridge, ipcRenderer } = require('electron');

// Anti WebRTC IP leak: replace RTCPeerConnection with a version that forces
// relay-only (TURN) candidates, preventing local IP disclosure.
try {
  const OrigRTC = window.RTCPeerConnection;
  const PatchedRTC = function (config) {
    const cfg = config || {};
    cfg.iceTransportPolicy = 'relay';
    // remove any stun servers that could leak
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

// Disable navigator plugins / mimeTypes fingerprinting noise
try {
  Object.defineProperty(navigator, 'plugins', { get: () => [] });
  Object.defineProperty(navigator, 'mimeTypes', { get: () => [] });
} catch {}

contextBridge.exposeInMainWorld('securecord', {
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (s) => ipcRenderer.invoke('save-settings', s),
  openExternal: (u) => ipcRenderer.invoke('open-external', u),
  newTorIdentity: () => ipcRenderer.invoke('tor-new-identity')
});
