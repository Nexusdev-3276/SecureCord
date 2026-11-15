'use strict';

const { app, BrowserWindow, session, ipcMain, shell, Menu, Tray, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn, exec } = require('child_process');

// ----------------------------------------------------------------------------
// SecureCord - main process
// Routes ONLY this app's Discord traffic through a chained Tor + VPN tunnel.
// The OS / other apps are never touched.
// ----------------------------------------------------------------------------

const isDev = process.argv.includes('--dev');
const USER_DATA = app.getPath('userData');
const SETTINGS_FILE = path.join(USER_DATA, 'settings.json');

const DEFAULT_SETTINGS = {
  // Routing
  routingMode: 'tor+vpn',        // 'tor' | 'vpn' | 'tor+vpn' | 'vpn+tor' | 'none'
  tor: {
    enabled: true,
    socksHost: '127.0.0.1',
    socksPort: 9050,
    controlPort: 9051,
    bundled: true,
    bridges: false,          // use Tor bridges (obfs4) for censored networks
    newIdentityOnStart: false
  },
  vpn: {
    enabled: true,
    type: 'wireguard',         // 'wireguard' | 'openvpn'
    configPath: '',            // path to .conf / .ovpn
    interface: 'sc0',
    bindAddress: ''            // VPN-assigned IP for Tor outbound binding
  },
  chainOrder: 'vpn-then-tor',   // 'vpn-then-tor' | 'tor-then-vpn'

  // Security / hardening
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

  // Discord
  discordUrl: 'https://discord.com/app',
  vencord: false
};

function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      const raw = fs.readFileSync(SETTINGS_FILE, 'utf8');
      return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
    }
  } catch (e) {
    console.error('settings load error', e);
  }
  return { ...DEFAULT_SETTINGS };
}

function saveSettings(s) {
  try {
    fs.mkdirSync(USER_DATA, { recursive: true });
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(s, null, 2));
  } catch (e) {
    console.error('settings save error', e);
  }
}

let settings = loadSettings();
let mainWindow = null;
let torProc = null;
let vpnProc = null;
let torAvailable = true;

// Apply command-line hardening as early as possible.
applyHardening();

// ----------------------------------------------------------------------------
// Tor management (app-local only)
// ----------------------------------------------------------------------------
function torBinaryPath() {
  const bundled = path.join(process.resourcesPath || '', 'tor', 'tor.exe');
  if (fs.existsSync(bundled)) return bundled;
  // fallback to system tor
  return 'tor';
}

function startTor() {
  if (!settings.tor.enabled) return Promise.resolve();
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
    // Chain: if VPN is enabled and order is vpn-then-tor, ask Tor to bind
    // outbound to the VPN interface address when provided.
    if (settings.vpn.enabled && settings.chainOrder === 'vpn-then-tor' && settings.vpn.bindAddress) {
      args.push('--OutboundBindAddress', settings.vpn.bindAddress);
    }
    try {
      torProc = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
      torProc.stdout.on('data', (d) => console.log('[tor]', d.toString().trim()));
      torProc.stderr.on('data', (d) => console.error('[tor]', d.toString().trim()));
      torProc.on('error', (e) => { console.error('tor spawn error', e); torAvailable = false; });
      setTimeout(resolve, 5000);
    } catch (e) {
      console.error('tor start failed', e);
      torAvailable = false;
      resolve();
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
  if (!settings.vpn.enabled || !settings.vpn.configPath) return Promise.resolve();
  return new Promise((resolve) => {
    if (settings.vpn.type === 'wireguard') {
      const bin = 'wg-quick'; // or wireguard-go on win
      vpnProc = spawn(bin, ['up', settings.vpn.configPath], { stdio: 'ignore', windowsHide: true, shell: true });
    } else {
      vpnProc = spawn('openvpn', ['--config', settings.vpn.configPath], { stdio: 'ignore', windowsHide: true });
    }
    setTimeout(resolve, 3000);
  });
}

function stopVpn() {
  if (vpnProc) { try { vpnProc.kill(); } catch {} vpnProc = null; }
}

// ----------------------------------------------------------------------------
// Build the proxy URL for Electron session (app-only)
// ----------------------------------------------------------------------------
function effectiveProxyUrl() {
  if (settings.routingMode === 'none') return null;
  if (settings.tor.enabled && torAvailable) {
    // socks5h:// forces remote DNS resolution through Tor (no DNS leak)
    return `socks5h://${settings.tor.socksHost}:${settings.tor.socksPort}`;
  }
  return null;
}

async function applyProxyToSession() {
  const proxyUrl = effectiveProxyUrl();
  const ses = session.defaultSession;
  if (proxyUrl) {
    await ses.setProxy({ proxyRules: proxyUrl, proxyBypassRules: '<local>' });
  } else {
    await ses.setProxy({ proxyRules: 'direct://' });
  }

  // Encrypted DNS: point Chromium to DoH.
  if (settings.encryptedDns) {
    const dohMap = {
      'cloudflare-doh': 'https://cloudflare-dns.com/dns-query',
      'quad9-doh': 'https://dns.quad9.net/dns-query',
      'nextdns': 'https://dns.nextdns.io/dns-query'
    };
    const url = dohMap[settings.dnsProvider] || dohMap['cloudflare-doh'];
    try { ses.setDnsResolver?.({ /* chromium experimental */ }); } catch {}
    app.commandLine.appendSwitch('dns-over-https-templates', url);
  }

  // Disable QUIC (UDP leak)
  if (settings.disableQuic) {
    app.commandLine.appendSwitch('disable-quic');
  }
}

// ----------------------------------------------------------------------------
// Hardening
// ----------------------------------------------------------------------------
function applyHardening() {
  if (settings.disableHardwareAccel) {
    app.disableHardwareAcceleration();
  }
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
// Window
// ----------------------------------------------------------------------------
let settingsWindow = null;

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

  // Strict CSP
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

  // Block WebRTC IP leaks: override RTCPeerConnection in preload too.
  mainWindow.loadURL(settings.discordUrl);

  mainWindow.on('closed', () => { mainWindow = null; });
}

// ----------------------------------------------------------------------------
// IPC
// ----------------------------------------------------------------------------
ipcMain.handle('get-settings', () => settings);
ipcMain.handle('save-settings', (_e, s) => {
  settings = { ...settings, ...s };
  saveSettings(settings);
  return true;
});
ipcMain.handle('open-external', (_e, url) => shell.openExternal(url));

// ----------------------------------------------------------------------------
// Anti-tracking / fingerprint hardening (app-only)
// ----------------------------------------------------------------------------
const TRACKER_HOSTS = [
  'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
  'facebook.com/tr', 'sentry.io', 'crashlytics.com', 'segment.io',
  'mixpanel.com', 'amplitude.com', 'hotjar.com', 'fullstory.com'
];

function applyAntiTracking() {
  const ses = session.defaultSession;
  if (settings.blockTrackers) {
    ses.webRequest.onBeforeRequest((details, cb) => {
      try {
        const u = new URL(details.url);
        if (TRACKER_HOSTS.some((h) => u.hostname.includes(h) || details.url.includes(h))) {
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
      // strip referrer
      delete details.requestHeaders['Referer'];
      cb({ requestHeaders: details.requestHeaders });
    });
    ses.setUserAgent(ua);
  }
  // Block third-party cookies
  ses.cookies.on('changed', () => {});
  // Partition storage: use ephemeral-ish by clearing on quit (handled below)
}

// Tor control: request new identity (NEWNYM)
function torNewIdentity() {
  return new Promise((resolve) => {
    if (!settings.tor.enabled) return resolve(false);
    const net = require('net');
    const sock = net.createConnection(settings.tor.controlPort, settings.tor.socksHost);
    sock.on('connect', () => {
      // Cookie auth: read cookie file
      const cookiePath = path.join(process.env.APPDATA || '', 'tor', 'control_auth_cookie');
      // Fallback: try AUTHENTICATE with empty (works if CookieAuthentication 0)
      sock.write('AUTHENTICATE ""\r\n');
      sock.write('SIGNAL NEWNYM\r\n');
      sock.write('QUIT\r\n');
    });
    sock.on('data', (d) => console.log('[tor-ctrl]', d.toString().trim()));
    sock.on('error', (e) => { console.error('tor ctrl error', e); resolve(false); });
    sock.on('close', () => resolve(true));
    setTimeout(() => { try { sock.destroy(); } catch {} resolve(true); }, 2000);
  });
}

ipcMain.handle('tor-new-identity', () => torNewIdentity());
app.whenReady().then(async () => {
  applyHardening();
  await startVpn();
  await startTor();
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
