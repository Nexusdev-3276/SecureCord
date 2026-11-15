'use strict';

const { app, BrowserWindow, session, ipcMain, shell, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const net = require('net');
const {
  mergeSettings, normalizeSettings, resolveProxyUrl,
  routingModeSupported, DEFAULT_SETTINGS
} = require('./config');

// ----------------------------------------------------------------------------
// SecureCord - main process
// Routes ONLY this app's Discord traffic through a chained Tor + VPN tunnel.
// The OS / other apps are never touched.
// ----------------------------------------------------------------------------

const isDev = process.argv.includes('--dev');
const USER_DATA = app.getPath('userData');
const SETTINGS_FILE = path.join(USER_DATA, 'settings.json');

if (DEFAULT_SETTINGS.disableHardwareAccel) {
  app.disableHardwareAcceleration();
}

function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      const raw = fs.readFileSync(SETTINGS_FILE, 'utf8');
      return normalizeSettings(JSON.parse(raw));
    }
  } catch (e) {
    console.error('settings load error', e);
  }
  return { ...DEFAULT_SETTINGS };
}

function saveSettings(s) {
  try {
    fs.mkdirSync(USER_DATA, { recursive: true });
    const merged = mergeSettings(settings, s);
    settings = normalizeSettings(merged);
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
    return true;
  } catch (e) {
    console.error('settings save error', e);
    return false;
  }
}

let settings = loadSettings();
let mainWindow = null;
let settingsWindow = null;
let torProc = null;
let vpnProc = null;
let torAvailable = true;
let startupErrors = [];

// ----------------------------------------------------------------------------
// Tor management (app-local only)
// ----------------------------------------------------------------------------
function torBinaryPath() {
  const bundled = path.join(process.resourcesPath || '', 'tor', 'tor.exe');
  if (fs.existsSync(bundled)) return bundled;
  return 'tor';
}

function tcpReady(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch {}
      resolve(ok);
    };
    sock.setTimeout(timeoutMs || 1000);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    try { sock.connect(port, host); } catch { finish(false); }
  });
}

function startTor() {
  if (!settings.tor.enabled) return Promise.resolve({ ok: true, skipped: true });
  return new Promise((resolve) => {
    const bin = torBinaryPath();
    const torrcPath = path.join(process.resourcesPath || '', 'tor', 'torrc');
    let args;
    if (fs.existsSync(torrcPath)) {
      args = ['-f', torrcPath];
    } else {
      args = [
        '--SocksPort', `${settings.tor.socksHost}:${settings.tor.socksPort}`,
        '--ControlPort', String(settings.tor.controlPort),
        '--CookieAuthentication', '1'
      ];
    }
    if (settings.vpn.enabled && settings.chainOrder === 'vpn-then-tor' && settings.vpn.bindAddress) {
      args.push('--OutboundBindAddress', settings.vpn.bindAddress);
    }
    let resolved = false;
    const finish = (ok, msg) => {
      if (resolved) return;
      resolved = true;
      if (!ok) { torAvailable = false; startupErrors.push(msg || 'Tor indisponible'); }
      else torAvailable = true;
      resolve({ ok, message: msg });
    };
    try {
      torProc = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
      torProc.stdout.on('data', (d) => console.log('[tor]', d.toString().trim()));
      torProc.stderr.on('data', (d) => console.error('[tor]', d.toString().trim()));
      torProc.on('error', (e) => {
        console.error('tor spawn error', e);
        finish(false, `Tor introuvable ou erreur de lancement: ${e.message}`);
      });
      torProc.on('exit', (code) => {
        if (!resolved && code !== 0 && code !== null) {
          finish(false, `Tor s'est arrêté (code ${code})`);
        }
      });
      const startedAt = Date.now();
      const poll = async () => {
        if (resolved) return;
        if (Date.now() - startedAt > 20000) {
          finish(false, 'Tor ne répond pas sur le port SOCKS dans les 20s');
          return;
        }
        const ok = await tcpReady(settings.tor.socksHost, settings.tor.socksPort, 1000);
        if (ok) finish(true);
        else setTimeout(poll, 1000);
      };
      setTimeout(poll, 1000);
    } catch (e) {
      console.error('tor start failed', e);
      finish(false, `Tor erreur: ${e.message}`);
    }
  });
}

function stopTor() {
  if (torProc) { try { torProc.kill(); } catch {} torProc = null; }
}

// ----------------------------------------------------------------------------
// VPN management (app-local tunnel, interface scoped)
// ----------------------------------------------------------------------------
function startVpn() {
  if (!settings.vpn.enabled || !settings.vpn.configPath) {
    return Promise.resolve({ ok: true, skipped: true });
  }
  return new Promise((resolve) => {
    let resolved = false;
    const finish = (ok, msg) => {
      if (resolved) return;
      resolved = true;
      if (!ok) startupErrors.push(msg || 'VPN indisponible');
      resolve({ ok, message: msg });
    };
    let bin, args;
    if (settings.vpn.type === 'wireguard') {
      bin = 'wg-quick';
      args = ['up', settings.vpn.configPath];
    } else {
      bin = 'openvpn';
      args = ['--config', settings.vpn.configPath];
    }
    try {
      vpnProc = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, shell: true });
      vpnProc.on('error', (e) => {
        finish(false, `VPN introuvable ou erreur de lancement (${bin}): ${e.message}`);
      });
      vpnProc.on('exit', (code) => {
        if (!resolved && code !== 0 && code !== null) {
          finish(false, `Le tunnel VPN s'est arrêté (code ${code})`);
        }
      });
      // VPN readiness is best-effort; resolve after a short delay if no error.
      setTimeout(() => finish(true), 4000);
    } catch (e) {
      finish(false, `VPN erreur: ${e.message}`);
    }
  });
}

function stopVpn() {
  if (vpnProc) { try { vpnProc.kill(); } catch {} vpnProc = null; }
}

// ----------------------------------------------------------------------------
// Routing mode validation
// ----------------------------------------------------------------------------
function validateRoutingMode() {
  if (!routingModeSupported(settings.routingMode)) {
    const msg = `Mode de routage non pris en charge: "${settings.routingMode}". Modes valides: ${routingModeSupported.toString() === '' ? '' : 'none, tor, tor+vpn, vpn+tor'}.`;
    startupErrors.push(msg);
    return false;
  }
  if (settings.routingMode === 'vpn') {
    startupErrors.push('Le mode "VPN uniquement" n\'est pas pris en charge en mode app-only (pas de proxy SOCKS). Utilisez "VPN puis Tor" ou "Tor puis VPN".');
    return false;
  }
  return true;
}

// ----------------------------------------------------------------------------
// Proxy (app-only)
// ----------------------------------------------------------------------------
function effectiveProxyUrl() {
  return resolveProxyUrl(settings, torAvailable);
}

async function applyProxyToSession() {
  const proxyUrl = effectiveProxyUrl();
  const ses = session.defaultSession;
  if (proxyUrl) {
    await ses.setProxy({ proxyRules: proxyUrl, proxyBypassRules: '<local>' });
  } else {
    await ses.setProxy({ proxyRules: 'direct://' });
  }
  if (settings.encryptedDns) {
    const dohMap = {
      'cloudflare-doh': 'https://cloudflare-dns.com/dns-query',
      'quad9-doh': 'https://dns.quad9.net/dns-query',
      'nextdns': 'https://dns.nextdns.io/dns-query'
    };
    const url = dohMap[settings.dnsProvider] || dohMap['cloudflare-doh'];
    try { app.commandLine.appendSwitch('dns-over-https-templates', url); } catch {}
  }
  if (settings.disableQuic) {
    try { app.commandLine.appendSwitch('disable-quic'); } catch {}
  }
}

// ----------------------------------------------------------------------------
// Hardening
// ----------------------------------------------------------------------------
function applyHardening() {
  app.commandLine.appendSwitch('disable-background-networking');
  app.commandLine.appendSwitch('disable-component-update');
  app.commandLine.appendSwitch('disable-sync');
  app.commandLine.appendSwitch('metrics-recording-only');
  app.commandLine.appendSwitch('no-first-run');
  app.commandLine.appendSwitch('no-default-browser-check');
  app.commandLine.appendSwitch('disable-dns-prefetch');
  app.commandLine.appendSwitch('disable-features', 'InterestCohortAPI,PrivacySandboxAdsAPIs,OptimizationHints');
  app.commandLine.appendSwitch('enable-strict-mixed-content-checking');
  if (settings.disableQuic) {
    app.commandLine.appendSwitch('disable-quic');
  }
  if (settings.encryptedDns) {
    const dohMap = {
      'cloudflare-doh': 'https://cloudflare-dns.com/dns-query',
      'quad9-doh': 'https://dns.quad9.net/dns-query',
      'nextdns': 'https://dns.nextdns.io/dns-query'
    };
    const url = dohMap[settings.dnsProvider] || dohMap['cloudflare-doh'];
    app.commandLine.appendSwitch('dns-over-https-templates', url);
  }
  if (settings.sandbox) {
    app.commandLine.appendSwitch('enable-features', 'Sandbox');
  }
}

// ----------------------------------------------------------------------------
// Anti-tracking
// ----------------------------------------------------------------------------
const TRACKER_HOSTS = [
  'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
  'sentry.io', 'crashlytics.com', 'segment.io', 'mixpanel.com',
  'amplitude.com', 'hotjar.com', 'fullstory.com'
];

function applyAntiTracking() {
  const ses = session.defaultSession;
  if (settings.blockTrackers) {
    ses.webRequest.onBeforeRequest((details, cb) => {
      try {
        const u = new URL(details.url);
        if (TRACKER_HOSTS.some((h) => u.hostname.includes(h))) {
          return cb({ cancel: true });
        }
      } catch {}
      cb({});
    });
  }
  if (settings.spoofUserAgent) {
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
    ses.webRequest.onBeforeSendHeaders((details, cb) => {
      details.requestHeaders['User-Agent'] = ua;
      delete details.requestHeaders['Referer'];
      cb({ requestHeaders: details.requestHeaders });
    });
    ses.setUserAgent(ua);
  }
}

// ----------------------------------------------------------------------------
// Tor control
// ----------------------------------------------------------------------------
function torNewIdentity() {
  return new Promise((resolve) => {
    if (!settings.tor.enabled) return resolve(false);
    const sock = new net.Socket();
    sock.on('connect', () => {
      sock.write('AUTHENTICATE ""\r\n');
      sock.write('SIGNAL NEWNYM\r\n');
      sock.write('QUIT\r\n');
    });
    sock.on('data', (d) => console.log('[tor-ctrl]', d.toString().trim()));
    sock.on('error', (e) => { console.error('tor ctrl error', e); resolve(false); });
    sock.on('close', () => resolve(true));
    try { sock.connect(settings.tor.controlPort, settings.tor.socksHost); } catch { resolve(false); }
    setTimeout(() => { try { sock.destroy(); } catch {} resolve(true); }, 2000);
  });
}

// ----------------------------------------------------------------------------
// Window
// ----------------------------------------------------------------------------
function createSettingsWindow() {
  if (settingsWindow) { settingsWindow.focus(); return; }
  settingsWindow = new BrowserWindow({
    width: 720,
    height: 760,
    title: 'SecureCord - Paramètres',
    backgroundColor: '#1e1f22',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  settingsWindow.loadFile(path.join(__dirname, 'settings.html'));
  settingsWindow.on('closed', () => { settingsWindow = null; });
}

function createWindow() {
  const menu = Menu.buildFromTemplate([
    { label: 'Fichier', submenu: [
      { label: 'Paramètres', click: createSettingsWindow },
      { type: 'separator' },
      { label: 'Quitter', click: () => app.quit() }
    ]},
    { label: 'Affichage', submenu: [
      { role: 'reload' }, { role: 'toggleDevTools' }
    ]}
  ]);
  Menu.setApplicationMenu(menu);

  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    title: 'SecureCord',
    backgroundColor: '#1e1f22',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false
    }
  });

  if (settings.strictCsp) {
    session.defaultSession.webRequest.onHeadersReceived((details, cb) => {
      cb({
        responseHeaders: {
          ...details.responseHeaders,
          'Content-Security-Policy': [
            "default-src 'self' https://discord.com https://*.discord.com https://*.discordapp.com https://*.discord.gg wss://*.discord.com wss://*.discord.gg; " +
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://discord.com https://*.discord.com; " +
            "style-src 'self' 'unsafe-inline' https://discord.com https://*.discord.com; " +
            "img-src 'self' data: https:; " +
            "connect-src 'self' https: wss:; " +
            "frame-src https://discord.com https://*.discord.com;"
          ]
        }
      });
    });
  }

  mainWindow.loadURL(settings.discordUrl);
  mainWindow.on('closed', () => { mainWindow = null; });
}

// ----------------------------------------------------------------------------
// IPC
// ----------------------------------------------------------------------------
ipcMain.handle('get-settings', () => ({ ...settings, startupErrors }));
ipcMain.handle('save-settings', (_e, s) => {
  const ok = saveSettings(s);
  return { ok, settings };
});
ipcMain.handle('open-external', (_e, url) => shell.openExternal(url));
ipcMain.handle('tor-new-identity', () => torNewIdentity());
ipcMain.handle('get-startup-errors', () => startupErrors);

// ----------------------------------------------------------------------------
// App lifecycle
// ----------------------------------------------------------------------------
app.whenReady().then(async () => {
  applyHardening();
  validateRoutingMode();
  const vpnRes = await startVpn();
  if (vpnRes && !vpnRes.ok && !vpnRes.skipped) console.error('VPN:', vpnRes.message);
  const torRes = await startTor();
  if (torRes && !torRes.ok && !torRes.skipped) console.error('Tor:', torRes.message);
  await applyProxyToSession();
  applyAntiTracking();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', async () => {
  if (settings.clearDataOnQuit) {
    try {
      await session.defaultSession.clearStorageData();
      await session.defaultSession.clearCache();
    } catch {}
  }
  stopTor();
  stopVpn();
});
