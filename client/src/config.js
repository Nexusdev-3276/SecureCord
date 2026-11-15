'use strict';

const DEFAULT_SETTINGS = {
  routingMode: 'tor+vpn',
  tor: {
    enabled: true,
    socksHost: '127.0.0.1',
    socksPort: 9050,
    controlPort: 9051,
    bundled: true,
    bridges: false,
    newIdentityOnStart: false
  },
  vpn: {
    enabled: true,
    type: 'wireguard',
    configPath: '',
    interface: 'sc0',
    bindAddress: ''
  },
  chainOrder: 'vpn-then-tor',
  encryptedDns: true,
  dnsProvider: 'cloudflare-doh',
  blockWebRTC: true,
  disableQuic: true,
  disableTelemetry: true,
  strictCsp: true,
  sandbox: true,
  spoofUserAgent: true,
  clearDataOnQuit: true,
  blockTrackers: true,
  disableHardwareAccel: true,
  discordUrl: 'https://discord.com/app',
  vencord: false
};

const SUPPORTED_ROUTING_MODES = ['none', 'tor', 'tor+vpn', 'vpn+tor'];

function mergeSettings(base, patch) {
  const out = { ...base };
  if (!patch || typeof patch !== 'object') return out;
  for (const key of Object.keys(patch)) {
    if (patch[key] && typeof patch[key] === 'object' && !Array.isArray(patch[key]) &&
        base[key] && typeof base[key] === 'object' && !Array.isArray(base[key])) {
      out[key] = mergeSettings(base[key], patch[key]);
    } else if (patch[key] !== undefined) {
      out[key] = patch[key];
    }
  }
  return out;
}

function normalizeSettings(patch) {
  return mergeSettings(DEFAULT_SETTINGS, patch || {});
}

function resolveProxyUrl(settings, torAvailable) {
  if (!settings || settings.routingMode === 'none') return null;
  if (settings.routingMode === 'vpn') {
    // VPN-only app routing is not supported in app-only mode.
    return null;
  }
  if (settings.tor && settings.tor.enabled && torAvailable) {
    return `socks5h://${settings.tor.socksHost}:${settings.tor.socksPort}`;
  }
  return null;
}

function routingModeSupported(mode) {
  return SUPPORTED_ROUTING_MODES.includes(mode);
}

module.exports = {
  DEFAULT_SETTINGS,
  SUPPORTED_ROUTING_MODES,
  mergeSettings,
  normalizeSettings,
  resolveProxyUrl,
  routingModeSupported
};
