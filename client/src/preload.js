'use strict';
const { contextBridge, ipcRenderer } = require('electron');

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

try {
  Object.defineProperty(navigator, 'plugins', { get: () => [] });
  Object.defineProperty(navigator, 'mimeTypes', { get: () => [] });
} catch {}

contextBridge.exposeInMainWorld('securecord', {
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (s) => ipcRenderer.invoke('save-settings', s),
  openExternal: (u) => ipcRenderer.invoke('open-external', u),
  newTorIdentity: () => ipcRenderer.invoke('tor-new-identity'),
  getStartupErrors: () => ipcRenderer.invoke('get-startup-errors'),
  getNetworkStatus: () => ipcRenderer.invoke('get-network-status'),
  onStatus: (cb) => ipcRenderer.on('status', (_e, m) => cb(m))
});
