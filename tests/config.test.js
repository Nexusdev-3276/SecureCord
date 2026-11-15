'use strict';
const assert = require('assert');
const {
  DEFAULT_SETTINGS, mergeSettings, normalizeSettings,
  resolveProxyUrl, routingModeSupported, SUPPORTED_ROUTING_MODES
} = require('../client/src/config');

// mergeSettings deep merges nested objects without losing existing keys
{
  const base = { tor: { enabled: true, socksPort: 9050, bridges: false }, vpn: { enabled: true, type: 'wireguard' } };
  const patch = { tor: { bridges: true } };
  const out = mergeSettings(base, patch);
  assert.strictEqual(out.tor.enabled, true, 'tor.enabled preserved');
  assert.strictEqual(out.tor.socksPort, 9050, 'tor.socksPort preserved');
  assert.strictEqual(out.tor.bridges, true, 'tor.bridges updated');
  assert.strictEqual(out.vpn.enabled, true, 'vpn preserved');
  console.log('PASS deep merge');
}

// normalizeSettings fills missing values from defaults
{
  const s = normalizeSettings({ tor: { enabled: false } });
  assert.strictEqual(s.tor.enabled, false);
  assert.strictEqual(s.tor.socksPort, 9050, 'default socksPort filled');
  assert.strictEqual(s.vpn.type, 'wireguard', 'default vpn type filled');
  assert.strictEqual(s.routingMode, 'tor+vpn', 'default routingMode filled');
  console.log('PASS normalize');
}

// resolveProxyUrl uses socks5h and respects torAvailable
{
  const s = { routingMode: 'tor+vpn', tor: { enabled: true, socksHost: '127.0.0.1', socksPort: 9050 } };
  assert.strictEqual(resolveProxyUrl(s, true), 'socks5h://127.0.0.1:9050');
  assert.strictEqual(resolveProxyUrl(s, false), null);
  const none = { routingMode: 'none', tor: { enabled: true, socksHost: '127.0.0.1', socksPort: 9050 } };
  assert.strictEqual(resolveProxyUrl(none, true), null);
  console.log('PASS proxy url');
}

// unsupported routing modes
{
  assert.strictEqual(routingModeSupported('vpn'), false);
  assert.strictEqual(routingModeSupported('tor'), true);
  assert.strictEqual(routingModeSupported('none'), true);
  assert.ok(Array.isArray(SUPPORTED_ROUTING_MODES));
  console.log('PASS routing modes');
}

// settings.html references strictCsp id - ensure config default exists
{
  assert.strictEqual(DEFAULT_SETTINGS.strictCsp, true);
  console.log('PASS defaults');
}

console.log('All tests passed.');
