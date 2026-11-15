'use strict';
// Fetch/locate runtime binaries. For Tor, prefer system install; for VPN, wg/openvpn.
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

function which(bin) {
  try {
    const out = execSync(process.platform === 'win32' ? `where ${bin}` : `which ${bin}`, { stdio: ['ignore','pipe','ignore'] }).toString().trim();
    return out.split(/\r?\n/)[0];
  } catch { return null; }
}

console.log('Tor:', which('tor') || 'NOT FOUND (install Tor or place in resources/tor/)');
console.log('WireGuard (wg-quick):', which('wg-quick') || which('wg') || 'NOT FOUND');
console.log('OpenVPN:', which('openvpn') || 'NOT FOUND');
console.log('Done. Place bundled binaries under resources/ if needed.');
