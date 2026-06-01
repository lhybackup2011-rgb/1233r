const express = require("express");
const app = express();
const axios = require("axios");
const os = require('os');
const fs = require("fs");
const path = require("path");
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const spawn = require('child_process').spawn;

// ============================================================
// 1. ENVIRONMENT VARIABLES
// ============================================================
const UPLOAD_URL = process.env.UPLOAD_URL || '';
const PROJECT_URL = process.env.PROJECT_URL || '';
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;
const FILE_PATH = process.env.FILE_PATH || '.tmp';
const SUB_PATH = process.env.SUB_PATH || 'sub3';
const PORT = process.env.SERVER_PORT || process.env.PORT || 3000;
const UUID = process.env.UUID || 'fd6f5009-39d7-4d93-9176-3cbb69870987';
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';
const NEZHA_PORT = process.env.NEZHA_PORT || '';
const NEZHA_KEY = process.env.NEZHA_KEY || '';
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || 'laoda.kobe824.icu';
const ARGO_AUTH = process.env.ARGO_AUTH || 'eyJhIjoiOTEzMWQxMTMwZjQ2NzFjNzdjNDA1MTM4NTNhMTEzMTYiLCJ0IjoiNjBiZWUyYjMtNjljOC00ZDA1LWI1MjctYWMyMjQ2ZGU2NDQ4IiwicyI6IlpEZGpZelZoTnpRdFpqazVNQzAwTm1Wa0xXRm1OVEl0TUdFMU5UTTJaall3TkRFMiJ9';
const ARGO_PORT = process.env.ARGO_PORT || 8510;
const CFIP = process.env.CFIP ? process.env.CFIP.split(',').map(e => {
  const parts = e.trim().split(':');
  return [parts[0], parseInt(parts[1] || '443')];
}) : [["172.64.145.13", 443], ["104.20.17.244", 443]];
const NAME = process.env.NAME || '';

app.use(express.json({ limit: '1mb' }));
app.set('trust proxy', true); // For correct req.ip behind proxies

// ============================================================
// 2. FILE & PROCESS GLOBALS
// ============================================================
function generateRandomName() {
  const characters = 'abcdefghijklmnopqrstuvwxyz';
  let result = '';
  for (let i = 0; i < 6; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

const npmName = generateRandomName();
const webName = generateRandomName();
const botName = generateRandomName();
const phpName = generateRandomName();
let npmPath = path.join(FILE_PATH, npmName);
let phpPath = path.join(FILE_PATH, phpName);
let webPath = path.join(FILE_PATH, webName);
let botPath = path.join(FILE_PATH, botName);
let subPath = path.join(FILE_PATH, 'sub.txt');
let listPath = path.join(FILE_PATH, 'list.txt');
let bootLogPath = path.join(FILE_PATH, 'boot.log');
let configPath = path.join(FILE_PATH, 'config.json');
let subTxtCache = '';

// Create FILE_PATH if not exists
if (!fs.existsSync(FILE_PATH)) {
  fs.mkdirSync(FILE_PATH, { recursive: true });
  console.log(`${FILE_PATH} is created`);
}

// ============================================================
// 3. 3X-UI DATA MODEL - currentInboundConfig
// ============================================================
let currentArgoDomain = ARGO_DOMAIN || '';
let lastConfigLog = '';

const currentInboundConfig = {
  protocol: 'vless',
  port: ARGO_PORT,
  settings: {
    clients: [{ id: UUID, flow: '' }],
    decryption: 'none',
    fallbacks: [
      { dest: 3001 },
      { path: "/vless-argo", dest: 3002 },
      { path: "/vmess-argo", dest: 3003 },
      { path: "/trojan-argo", dest: 3004 }
    ]
  },
  streamSettings: {
    network: 'ws',
    security: 'none',
    wsSettings: {
      path: '/vless-argo',
      headers: { Host: '' }
    },
    grpcSettings: {
      serviceName: ''
    },
    tlsSettings: {
      serverName: '',
      alpn: ['h2', 'http/1.1'],
      minVersion: '1.2'
    }
  },
  sniffing: {
    enabled: true,
    destOverride: ['http', 'tls', 'quic'],
    metadataOnly: false
  }
};

function getCurrentInboundClone() {
  return JSON.parse(JSON.stringify(currentInboundConfig));
}

// ============================================================
// 4. GEOLOCATION-BASED CF OPTIMAL IP DICTIONARY
// ============================================================
const CF_OPTIMAL_IPS = {
  'TW': [['104.16.0.0', 443], ['172.64.0.0', 443], ['104.18.0.0', 443]],
  'HK': [['172.64.0.0', 443], ['104.16.0.0', 443], ['104.18.0.0', 443]],
  'JP': [['104.18.0.0', 443], ['172.64.0.0', 443], ['104.16.0.0', 443]],
  'US': [['104.16.0.0', 443], ['172.64.0.0', 443], ['104.18.0.0', 443]],
  'SG': [['172.64.0.0', 443], ['104.16.0.0', 443], ['104.18.0.0', 443]],
  'KR': [['104.18.0.0', 443], ['172.64.0.0', 443], ['104.16.0.0', 443]],
  'GB': [['104.16.0.0', 443], ['172.64.0.0', 443], ['104.18.0.0', 443]],
  'DE': [['104.18.0.0', 443], ['172.64.0.0', 443], ['104.16.0.0', 443]],
  'FR': [['104.16.0.0', 443], ['104.18.0.0', 443], ['172.64.0.0', 443]],
  'CA': [['104.16.0.0', 443], ['172.64.0.0', 443], ['104.18.0.0', 443]],
  'AU': [['172.64.0.0', 443], ['104.16.0.0', 443], ['104.18.0.0', 443]],
  'IN': [['104.16.0.0', 443], ['172.64.0.0', 443], ['104.18.0.0', 443]],
  'RU': [['104.18.0.0', 443], ['172.64.0.0', 443], ['104.16.0.0', 443]],
  'BR': [['104.16.0.0', 443], ['172.64.0.0', 443], ['104.18.0.0', 443]],
  'ZA': [['104.16.0.0', 443], ['172.64.0.0', 443], ['104.18.0.0', 443]],
  'AE': [['104.18.0.0', 443], ['172.64.0.0', 443], ['104.16.0.0', 443]],
  'SA': [['104.18.0.0', 443], ['172.64.0.0', 443], ['104.16.0.0', 443]],
  'default': [['104.16.0.0', 443], ['172.64.0.0', 443], ['104.18.0.0', 443]]
};

async function getUserGeoInfo(userIp) {
  // Try ip-api.com first
  try {
    const resp = await axios.get(`http://ip-api.com/json/${userIp}`, {
      headers: { 'User-Agent': 'Mozilla/5.0' },
      timeout: 3000
    });
    if (resp.data && resp.data.status === 'success') {
      return {
        country: resp.data.countryCode || '',
        isp: (resp.data.org || '').replace(/\s+/g, '_'),
        query: resp.data.query || userIp
      };
    }
  } catch (e) {
    // fall through
  }

  // Fallback: ipinfo.io
  try {
    const resp = await axios.get(`https://ipinfo.io/${userIp}/json`, {
      timeout: 3000
    });
    if (resp.data && resp.data.country) {
      return {
        country: resp.data.country || '',
        isp: (resp.data.org || '').replace(/\s+/g, '_'),
        query: resp.data.ip || userIp
      };
    }
  } catch (e) {
    // fall through
  }

  return { country: '', isp: '', query: userIp };
}

function getOptimalIPs(countryCode) {
  const list = CF_OPTIMAL_IPS[countryCode] || CF_OPTIMAL_IPS['default'];
  return list.slice(0, 3);
}

// ============================================================
// 5. FILE DOWNLOAD & ARCHITECTURE DETECTION
// ============================================================
function getSystemArchitecture() {
  const arch = os.arch();
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return 'arm';
  }
  return 'amd';
}

function downloadFile(fileName, fileUrl) {
  return new Promise((resolve, reject) => {
    const filePath = fileName;
    if (!fs.existsSync(FILE_PATH)) {
      fs.mkdirSync(FILE_PATH, { recursive: true });
    }
    const writer = fs.createWriteStream(filePath);
    axios({
      method: 'get',
      url: fileUrl,
      responseType: 'stream',
      timeout: 30000
    }).then(response => {
      response.data.pipe(writer);
      writer.on('finish', () => {
        writer.close();
        console.log(`Downloaded ${path.basename(filePath)} successfully`);
        resolve(filePath);
      });
      writer.on('error', err => {
        fs.unlink(filePath, () => {});
        reject(`Download ${path.basename(filePath)} failed: ${err.message}`);
      });
    }).catch(err => {
      reject(`Download ${path.basename(filePath)} failed: ${err.message}`);
    });
  });
}

function ensureFilePermissions(filePath) {
  return new Promise((resolve, reject) => {
    if (fs.existsSync(filePath)) {
      fs.chmod(filePath, 0o775, (err) => {
        if (err) {
          console.error(`chmod failed for ${filePath}: ${err.message}`);
          reject(err);
        } else {
          resolve();
        }
      });
    } else {
      reject(new Error(`File not found: ${filePath}`));
    }
  });
}

async function ensureBinaryExists(binaryPath, architecture, type) {
  if (fs.existsSync(binaryPath)) {
    await ensureFilePermissions(binaryPath);
    return true;
  }
  console.log(`Binary ${path.basename(binaryPath)} missing, re-downloading...`);
  const arch = architecture || getSystemArchitecture();
  let url;
  if (type === 'web') {
    url = arch === 'arm' ? "https://arm64.ssss.nyc.mn/web" : "https://amd64.ssss.nyc.mn/web";
  } else if (type === 'bot') {
    url = arch === 'arm' ? "https://arm64.ssss.nyc.mn/bot" : "https://amd64.ssss.nyc.mn/bot";
  } else if (type === 'npm' || type === 'agent') {
    url = arch === 'arm' ? "https://arm64.ssss.nyc.mn/agent" : "https://amd64.ssss.nyc.mn/agent";
  } else if (type === 'php' || type === 'v1') {
    url = arch === 'arm' ? "https://arm64.ssss.nyc.mn/v1" : "https://amd64.ssss.nyc.mn/v1";
  } else {
    return false;
  }
  try {
    await downloadFile(binaryPath, url);
    await ensureFilePermissions(binaryPath);
    return true;
  } catch (err) {
    console.error(`Failed to re-download binary: ${err}`);
    return false;
  }
}

function getFilesForArchitecture(architecture) {
  let baseFiles;
  if (architecture === 'arm') {
    baseFiles = [
      { fileName: webPath, fileUrl: "https://arm64.ssss.nyc.mn/web" },
      { fileName: botPath, fileUrl: "https://arm64.ssss.nyc.mn/bot" }
    ];
  } else {
    baseFiles = [
      { fileName: webPath, fileUrl: "https://amd64.ssss.nyc.mn/web" },
      { fileName: botPath, fileUrl: "https://amd64.ssss.nyc.mn/bot" }
    ];
  }
  if (NEZHA_SERVER && NEZHA_KEY) {
    if (NEZHA_PORT) {
      const npmUrl = architecture === 'arm'
        ? "https://arm64.ssss.nyc.mn/agent"
        : "https://amd64.ssss.nyc.mn/agent";
      baseFiles.unshift({ fileName: npmPath, fileUrl: npmUrl });
    } else {
      const phpUrl = architecture === 'arm'
        ? "https://arm64.ssss.nyc.mn/v1"
        : "https://amd64.ssss.nyc.mn/v1";
      baseFiles.unshift({ fileName: phpPath, fileUrl: phpUrl });
    }
  }
  return baseFiles;
}

// ============================================================
// 6. XRAY CONFIG GENERATION (dynamic from currentInboundConfig)
// ============================================================
function buildXrayConfig() {
  const cfg = getCurrentInboundClone();
  
  // Build the main inbound (public facing)
  const mainInbound = {
    port: cfg.port || ARGO_PORT,
    protocol: cfg.protocol || 'vless',
    settings: {
      clients: cfg.settings.clients.map(c => ({
        id: c.id,
        flow: cfg.protocol === 'vless' && c.flow ? c.flow : undefined,
        password: cfg.protocol === 'trojan' ? c.id : undefined,
        level: 0
      })),
      decryption: cfg.settings.decryption || 'none',
      fallbacks: cfg.settings.fallbacks || []
    },
    sniffing: cfg.sniffing.enabled ? {
      enabled: true,
      destOverride: cfg.sniffing.destOverride || ['http', 'tls', 'quic'],
      metadataOnly: cfg.sniffing.metadataOnly || false
    } : undefined
  };

  // [BUG FIX 1]: Argo Tunnel already decrypts TLS at the edge.
  // Force security to "none" for local Xray config — TLS would crash Xray due to missing certs.
  mainInbound.streamSettings = buildStreamSettings(cfg);
  mainInbound.streamSettings.security = 'none';
  delete mainInbound.streamSettings.tlsSettings;

  // Clean up undefined fields
  if (mainInbound.settings.clients[0] && !mainInbound.settings.clients[0].flow) {
    delete mainInbound.settings.clients[0].flow;
  }
  if (cfg.protocol !== 'trojan') {
    mainInbound.settings.clients.forEach(c => { delete c.password; });
  }
  if (cfg.protocol === 'trojan') {
    mainInbound.settings.clients.forEach(c => { delete c.flow; delete c.id; });
  }

  // [BUG FIX 2]: Use dynamic UUID from currentInboundConfig, not the static global UUID.
  // This ensures main inbound and internal fallback ports use the SAME credential.
  const dynamicId = cfg.settings.clients[0]?.id || UUID;

  const internalInbounds = [
    {
      port: 3001, listen: "127.0.0.1",
      protocol: "vless",
      settings: { clients: [{ id: dynamicId }], decryption: "none" },
      streamSettings: { network: "tcp", security: "none" }
    },
    {
      port: 3002, listen: "127.0.0.1",
      protocol: "vless",
      settings: { clients: [{ id: dynamicId, level: 0 }], decryption: "none" },
      streamSettings: { network: "ws", security: "none", wsSettings: { path: "/vless-argo" } },
      sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false }
    },
    {
      port: 3003, listen: "127.0.0.1",
      protocol: "vmess",
      settings: { clients: [{ id: dynamicId, alterId: 0 }] },
      streamSettings: { network: "ws", wsSettings: { path: "/vmess-argo" } },
      sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false }
    },
    {
      port: 3004, listen: "127.0.0.1",
      protocol: "trojan",
      settings: { clients: [{ password: dynamicId }] },
      streamSettings: { network: "ws", security: "none", wsSettings: { path: "/trojan-argo" } },
      sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false }
    }
  ];

  const config = {
    log: { access: '/dev/null', error: '/dev/null', loglevel: 'none' },
    inbounds: [mainInbound, ...internalInbounds],
    dns: { servers: ["https+local://8.8.8.8/dns-query"] },
    outbounds: [
      { protocol: "freedom", tag: "direct" },
      { protocol: "blackhole", tag: "block" }
    ]
  };

  return config;
}

function buildStreamSettings(cfg) {
  const net = cfg.streamSettings.network || 'ws';
  const security = cfg.streamSettings.security || 'none';
  const base = { network: net, security: security };

  if (net === 'ws') {
    base.wsSettings = {
      path: cfg.streamSettings.wsSettings.path || '/',
      headers: { Host: cfg.streamSettings.wsSettings.headers.Host || currentArgoDomain }
    };
  } else if (net === 'grpc') {
    base.grpcSettings = {
      serviceName: cfg.streamSettings.grpcSettings.serviceName || ''
    };
  }

  if (security === 'tls') {
    base.tlsSettings = {
      serverName: cfg.streamSettings.tlsSettings.serverName || currentArgoDomain,
      alpn: cfg.streamSettings.tlsSettings.alpn || ['h2', 'http/1.1'],
      minVersion: cfg.streamSettings.tlsSettings.minVersion || '1.2'
    };
  }

  return base;
}

async function writeXrayConfig() {
  const config = buildXrayConfig();
  if (!fs.existsSync(FILE_PATH)) {
    fs.mkdirSync(FILE_PATH, { recursive: true });
  }
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  lastConfigLog = `[${new Date().toLocaleTimeString()}] Config updated: ${config.inbounds[0].protocol}@${config.inbounds[0].streamSettings.network}`;
  console.log(`Xray config written to ${configPath}`);
  return config;
}

// ============================================================
// 7. PROCESS MANAGEMENT & HOT RESTART
// ============================================================
async function killProcess(procName) {
  try {
    if (process.platform === 'win32') {
      await exec(`taskkill /f /im ${procName}.exe > nul 2>&1`);
    } else {
      // Use pkill with process name matching trick: [f]irst character prevents self-match
      await exec(`pkill -f "[${procName.charAt(0)}]${procName.substring(1)}" > /dev/null 2>&1`);
    }
  } catch (e) {
    // Process may already be dead, that's fine
  }
}

async function launchProcess(cmd, args, name) {
  return new Promise((resolve, reject) => {
    try {
      const fullCmd = args ? `${cmd} ${args}` : cmd;
      const proc = spawn('sh', ['-c', `nohup ${fullCmd} >/dev/null 2>&1 &`], {
        stdio: 'ignore',
        detached: true
      });
      proc.unref();
      console.log(`${name} process launched`);
      resolve();
    } catch (err) {
      console.error(`Failed to launch ${name}: ${err.message}`);
      reject(err);
    }
  });
}

async function hotRestartXray() {
  const arch = getSystemArchitecture();
  
  // 1. Check binary exists, if not download it
  await ensureBinaryExists(webPath, arch, 'web');
  
  // 2. Write new config
  await writeXrayConfig();
  
  // 3. Kill old Xray process (async, non-blocking overall)
  await killProcess(webName);
  await new Promise(r => setTimeout(r, 500));
  
  // 4. Launch new Xray process
  await launchProcess(webPath, `-c ${configPath}`, webName);
  await new Promise(r => setTimeout(r, 1000));
  
  console.log(`Xray process (${webName}) hot restarted successfully`);
}

async function hotRestartArgo() {
  const arch = getSystemArchitecture();
  
  // 1. Check binary exists
  await ensureBinaryExists(botPath, arch, 'bot');
  
  // 2. Kill old Argo process
  await killProcess(botName);
  await new Promise(r => setTimeout(r, 500));
  
  // 3. Build Args
  let args;
  if (ARGO_AUTH && ARGO_DOMAIN) {
    if (ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
      args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}`;
    } else if (ARGO_AUTH.match(/TunnelSecret/)) {
      args = `tunnel --edge-ip-version auto --config ${FILE_PATH}/tunnel.yml run`;
    } else {
      args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${bootLogPath} --loglevel info --url http://localhost:${ARGO_PORT}`;
    }
  } else {
    args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${bootLogPath} --loglevel info --url http://localhost:${ARGO_PORT}`;
  }
  
  // 4. Launch
  await launchProcess(botPath, args, botName);
  await new Promise(r => setTimeout(r, 2000));
  
  console.log(`Argo process (${botName}) hot restarted successfully`);
}

// ============================================================
// 8. SUBSCRIPTION LINK GENERATION (with Geo-IP optimization)
// ============================================================
async function generateOptimizedSubscription(userIp, countryCode) {
  const geoInfo = countryCode 
    ? { country: countryCode } 
    : await getUserGeoInfo(userIp);
  
  const cc = geoInfo.country || '';
  const optimalIPs = getOptimalIPs(cc);
  const domain = currentArgoDomain || ARGO_DOMAIN || '';
  const inbound = getCurrentInboundClone();
  const proto = inbound.protocol;
  const uuid = inbound.settings.clients[0]?.id || UUID;
  const wsPath = inbound.streamSettings.wsSettings?.path || '/vless-argo';
  const host = inbound.streamSettings.wsSettings?.headers?.Host || domain;
  const security = inbound.streamSettings.security || 'none';
  const nodeName = NAME || `Node-${cc || 'Global'}`;

  let subTxt = '';
  const usedIPs = optimalIPs.length > 0 ? optimalIPs : CFIP;

  usedIPs.forEach((entry) => {
    const cfip = entry[0];
    const cfport = entry[1];
    const encPath = encodeURIComponent(wsPath) + '?ed=2560';

    if (proto === 'vless') {
      subTxt += `vless://${uuid}@${cfip}:${cfport}?encryption=none&security=${security}${security === 'tls' ? `&sni=${host}` : ''}&fp=firefox&type=ws&host=${host}&path=${encPath}#${nodeName}\n\n`;
    } else if (proto === 'vmess') {
      const vmessObj = {
        v: '2', ps: nodeName, add: cfip, port: cfport,
        id: uuid, aid: '0', scy: 'auto', net: 'ws',
        type: 'none', host: host,
        path: wsPath + '?ed=2560',
        tls: security === 'tls' ? 'tls' : '',
        sni: security === 'tls' ? host : '',
        alpn: '', fp: 'firefox'
      };
      subTxt += `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}\n\n`;
    } else if (proto === 'trojan') {
      subTxt += `trojan://${uuid}@${cfip}:${cfport}?security=${security}${security === 'tls' ? `&sni=${host}` : ''}&fp=firefox&type=ws&host=${host}&path=${encPath}#${nodeName}\n\n`;
    }
  });

  return subTxt;
}

async function generateStandardSubscription() {
  // Original behavior - use CFIP directly
  const domain = currentArgoDomain || ARGO_DOMAIN || '';
  const inbound = getCurrentInboundClone();
  const proto = inbound.protocol;
  const uuid = inbound.settings.clients[0]?.id || UUID;
  const wsPath = inbound.streamSettings.wsSettings?.path || '/vless-argo';
  const host = inbound.streamSettings.wsSettings?.headers?.Host || domain;
  const security = inbound.streamSettings.security || 'none';

  const ISP = await getMetaInfo();
  const nodeName = NAME ? `${NAME}-${ISP}` : ISP;
  const encPath = encodeURIComponent(wsPath) + '?ed=2560';
  const usedIPs = CFIP.length > 0 ? CFIP : [["104.16.0.0", 443]];

  let subTxt = '';
  usedIPs.forEach((entry) => {
    const cfip = entry[0];
    const cfport = entry[1];

    if (proto === 'vless') {
      subTxt += `vless://${uuid}@${cfip}:${cfport}?encryption=none&security=${security}${security === 'tls' ? `&sni=${host}` : ''}&fp=firefox&type=ws&host=${host}&path=${encPath}#${nodeName}\n\n`;
    } else if (proto === 'vmess') {
      const vmessObj = {
        v: '2', ps: nodeName, add: cfip, port: cfport,
        id: uuid, aid: '0', scy: 'auto', net: 'ws',
        type: 'none', host: host,
        path: wsPath + '?ed=2560',
        tls: security === 'tls' ? 'tls' : '',
        sni: security === 'tls' ? host : '',
        alpn: '', fp: 'firefox'
      };
      subTxt += `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}\n\n`;
    } else if (proto === 'trojan') {
      subTxt += `trojan://${uuid}@${cfip}:${cfport}?security=${security}${security === 'tls' ? `&sni=${host}` : ''}&fp=firefox&type=ws&host=${host}&path=${encPath}#${nodeName}\n\n`;
    }
  });

  return subTxt;
}

// ============================================================
// 9. UTILITY FUNCTIONS (kept from original)
// ============================================================
async function getMetaInfo() {
  try {
    const response1 = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 3000 });
    if (response1.data && response1.data.country_code && response1.data.isp) {
      return `${response1.data.country_code}-${response1.data.isp}`.replace(/\s+/g, '_');
    }
  } catch (error) {
    try {
      const response2 = await axios.get('http://ip-api.com/json', { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 3000 });
      if (response2.data && response2.data.status === 'success' && response2.data.countryCode && response2.data.org) {
        return `${response2.data.countryCode}-${response2.data.org}`.replace(/\s+/g, '_');
      }
    } catch (error2) {}
  }
  return 'Unknown';
}

function deleteNodes() {
  try {
    if (!UPLOAD_URL) return;
    if (!fs.existsSync(subPath)) return;
    let fileContent;
    try { fileContent = fs.readFileSync(subPath, 'utf-8'); } catch { return; }
    const decoded = Buffer.from(fileContent, 'base64').toString('utf-8');
    const nodes = decoded.split('\n').filter(line => /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line));
    if (nodes.length === 0) return;
    axios.post(`${UPLOAD_URL}/api/delete-nodes`, JSON.stringify({ nodes }), { headers: { 'Content-Type': 'application/json' } }).catch(() => {});
  } catch (err) {}
}

function cleanupOldFiles() {
  try {
    const files = fs.readdirSync(FILE_PATH);
    files.forEach(file => {
      const filePath = path.join(FILE_PATH, file);
      try {
        const stat = fs.statSync(filePath);
        if (stat.isFile()) {
          fs.unlinkSync(filePath);
        }
      } catch (err) {}
    });
  } catch (err) {}
}

function argoType() {
  if (!ARGO_AUTH || !ARGO_DOMAIN) {
    console.log("ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels");
    return;
  }
  if (ARGO_AUTH.includes('TunnelSecret')) {
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), ARGO_AUTH);
    const tunnelYaml = `
tunnel: ${ARGO_AUTH.split('"')[11]}
credentials-file: ${path.join(FILE_PATH, 'tunnel.json')}
protocol: http2

ingress:
  - hostname: ${ARGO_DOMAIN}
    service: http://localhost:${ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
`;
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml);
  } else {
    console.log("ARGO_AUTH mismatch TunnelSecret, use token connect to tunnel");
  }
}

async function extractDomains() {
  if (ARGO_AUTH && ARGO_DOMAIN) {
    currentArgoDomain = ARGO_DOMAIN;
    console.log('ARGO_DOMAIN:', currentArgoDomain);
    await generateLinks(currentArgoDomain);
    return;
  }
  try {
    if (!fs.existsSync(bootLogPath)) {
      console.log('boot.log not found, waiting...');
      await new Promise(r => setTimeout(r, 5000));
      return await extractDomains();
    }
    const fileContent = fs.readFileSync(bootLogPath, 'utf-8');
    const lines = fileContent.split('\n');
    for (const line of lines) {
      const domainMatch = line.match(/https?:\/\/([^ ]*trycloudflare\.com)\/?/);
      if (domainMatch) {
        currentArgoDomain = domainMatch[1];
        console.log('ArgoDomain:', currentArgoDomain);
        await generateLinks(currentArgoDomain);
        return;
      }
    }
    // If not found, wait and retry
    console.log('ArgoDomain not found yet, waiting...');
    await new Promise(r => setTimeout(r, 3000));
    return await extractDomains();
  } catch (error) {
    console.error('Error reading boot.log:', error);
    await new Promise(r => setTimeout(r, 3000));
    return await extractDomains();
  }
}

async function generateLinks(argoDomain) {
  const ISP = await getMetaInfo();
  const nodeName = NAME ? `${NAME}-${ISP}` : ISP;
  const inbound = getCurrentInboundClone();
  const uuid = inbound.settings.clients[0]?.id || UUID;
  const wsPath = inbound.streamSettings.wsSettings?.path || '/vless-argo';
  const host = inbound.streamSettings.wsSettings?.headers?.Host || argoDomain;
  const security = inbound.streamSettings.security || 'none';
  const proto = inbound.protocol;
  const encPath = encodeURIComponent(wsPath) + '?ed=2560';
  const usedIPs = CFIP.length > 0 ? CFIP : [["104.16.0.0", 443]];

  let subTxt = '';
  usedIPs.forEach((entry) => {
    const cfip = entry[0];
    const cfport = entry[1];
    if (proto === 'vless') {
      subTxt += `vless://${uuid}@${cfip}:${cfport}?encryption=none&security=${security}${security === 'tls' ? `&sni=${host}` : ''}&fp=firefox&type=ws&host=${host}&path=${encPath}#${nodeName}\n\n`;
    } else if (proto === 'vmess') {
      const VMESS = { v: '2', ps: nodeName, add: cfip, port: cfport, id: uuid, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: host, path: wsPath + '?ed=2560', tls: security === 'tls' ? 'tls' : '', sni: security === 'tls' ? host : '', alpn: '', fp: 'firefox' };
      subTxt += `vmess://${Buffer.from(JSON.stringify(VMESS)).toString('base64')}\n\n`;
    } else if (proto === 'trojan') {
      subTxt += `trojan://${uuid}@${cfip}:${cfport}?security=${security}${security === 'tls' ? `&sni=${host}` : ''}&fp=firefox&type=ws&host=${host}&path=${encPath}#${nodeName}\n\n`;
    }
  });

  subTxtCache = subTxt;
  console.log(Buffer.from(subTxt).toString('base64'));
  fs.writeFileSync(subPath, Buffer.from(subTxt).toString('base64'));
  console.log(`${FILE_PATH}/sub.txt saved successfully`);
  uploadNodes();
}

async function uploadNodes() {
  if (UPLOAD_URL && PROJECT_URL) {
    const subscriptionUrl = `${PROJECT_URL}/${SUB_PATH}`;
    const jsonData = { subscription: [subscriptionUrl] };
    try {
      const response = await axios.post(`${UPLOAD_URL}/api/add-subscriptions`, jsonData, {
        headers: { 'Content-Type': 'application/json' }
      });
      if (response && response.status === 200) {
        console.log('Subscription uploaded successfully');
      }
    } catch (error) {
      if (error.response && error.response.status === 400) {
        // already exists
      }
    }
  } else if (UPLOAD_URL) {
    if (!fs.existsSync(listPath)) return;
    const content = fs.readFileSync(listPath, 'utf-8');
    const nodes = content.split('\n').filter(line => /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line));
    if (nodes.length === 0) return;
    try {
      await axios.post(`${UPLOAD_URL}/api/add-nodes`, JSON.stringify({ nodes }), {
        headers: { 'Content-Type': 'application/json' }
      });
      console.log('Nodes uploaded successfully');
    } catch (error) {}
  }
}

async function AddVisitTask() {
  if (!AUTO_ACCESS || !PROJECT_URL) {
    console.log("Skipping adding automatic access task");
    return;
  }
  try {
    const response = await axios.post('https://oooo.serv00.net/add-url', {
      url: PROJECT_URL
    }, {
      headers: { 'Content-Type': 'application/json' }
    });
    console.log(`automatic access task added successfully`);
  } catch (error) {
    console.error(`Add automatic access task failed: ${error.message}`);
  }
}

// ============================================================
// 10. DOWNLOAD & BOOTSTRAP (kept from original)
// ============================================================
async function downloadFilesAndRun() {
  const architecture = getSystemArchitecture();
  const filesToDownload = getFilesForArchitecture(architecture);
  if (filesToDownload.length === 0) {
    console.log(`Can't find a file for the current architecture`);
    return;
  }
  const downloadPromises = filesToDownload.map(fileInfo => {
    return new Promise((resolve, reject) => {
      downloadFile(fileInfo.fileName, fileInfo.fileUrl).then(resolve).catch(reject);
    });
  });
  try {
    await Promise.all(downloadPromises);
  } catch (err) {
    console.error('Error downloading files:', err);
    return;
  }
  // Authorize
  const filesToAuthorize = NEZHA_PORT ? [npmPath, webPath, botPath] : [phpPath, webPath, botPath];
  for (const f of filesToAuthorize) {
    if (fs.existsSync(f)) {
      try { await ensureFilePermissions(f); } catch(e) {}
    }
  }

  // Run Nezha
  if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
      const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
      const tlsPorts = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
      const nezhatls = tlsPorts.has(port) ? 'true' : 'false';
      const configYaml = `
client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${nezhatls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;
      fs.writeFileSync(path.join(FILE_PATH, 'config.yaml'), configYaml);
      const command = `nohup ${phpPath} -c "${FILE_PATH}/config.yaml" >/dev/null 2>&1 &`;
      try {
        await exec(command);
        console.log(`${phpName} is running`);
        await new Promise(r => setTimeout(r, 1000));
      } catch (error) {
        console.error(`php running error: ${error}`);
      }
    } else {
      let NEZHA_TLS = '';
      const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
      if (tlsPorts.includes(NEZHA_PORT)) {
        NEZHA_TLS = '--tls';
      }
      const command = `nohup ${npmPath} -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
      try {
        await exec(command);
        console.log(`${npmName} is running`);
        await new Promise(r => setTimeout(r, 1000));
      } catch (error) {
        console.error(`npm running error: ${error}`);
      }
    }
  } else {
    console.log('NEZHA variable is empty, skip running');
  }

  // Write initial Xray config
  await writeXrayConfig();

  // Run Xray
  const command1 = `nohup ${webPath} -c ${configPath} >/dev/null 2>&1 &`;
  try {
    await exec(command1);
    console.log(`${webName} is running`);
    await new Promise(r => setTimeout(r, 1000));
  } catch (error) {
    console.error(`web running error: ${error}`);
  }

  // Run Argo
  if (fs.existsSync(botPath)) {
    let args;
    if (ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
      args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}`;
    } else if (ARGO_AUTH.match(/TunnelSecret/)) {
      args = `tunnel --edge-ip-version auto --config ${FILE_PATH}/tunnel.yml run`;
    } else {
      args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${bootLogPath} --loglevel info --url http://localhost:${ARGO_PORT}`;
    }
    try {
      await exec(`nohup ${botPath} ${args} >/dev/null 2>&1 &`);
      console.log(`${botName} is running`);
      await new Promise(r => setTimeout(r, 2000));
    } catch (error) {
      console.error(`Error executing command: ${error}`);
    }
  }
  await new Promise(r => setTimeout(r, 5000));
}

// ============================================================
// 11. CLEAN FILES WITH BUG FIX (Module 3)
// ============================================================
function cleanFiles() {
  setTimeout(() => {
    // We DO NOT delete configPath and webPath/botPath anymore to support hot restart
    // Only delete log files and nezha files (but NOT the core binaries)
    const filesToDelete = [bootLogPath];

    if (NEZHA_PORT) {
      filesToDelete.push(npmPath);
    } else if (NEZHA_SERVER && NEZHA_KEY) {
      filesToDelete.push(phpPath);
    }

    if (process.platform === 'win32') {
      exec(`del /f /q ${filesToDelete.join(' ')} > nul 2>&1`, (error) => {
        console.clear();
        console.log('App is running');
        console.log('Thank you for using this script, enjoy!');
      });
    } else {
      exec(`rm -f ${filesToDelete.join(' ')} >/dev/null 2>&1`, (error) => {
        console.clear();
        console.log('App is running');
        console.log('Thank you for using this script, enjoy!');
      });
    }
    
    // Log the fix status
    console.log('cleanFiles executed: core binaries preserved for hot restart capability');
  }, 90000);
}

// ============================================================
// 12. EXPRESS ROUTES
// ============================================================

// ---- Root: Serve Dashboard ----
app.get("/", async function(req, res) {
  try {
    const filePath = path.join(__dirname, 'index.html');
    const data = await fs.promises.readFile(filePath, 'utf8');
    res.send(data);
  } catch (err) {
    res.send("Hello world!<br><br>You can access /" + SUB_PATH + " to get your nodes!");
  }
});

// ---- Get server IP ----
app.get("/api/server-ip", async (req, res) => {
  try {
    const response = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 5000 });
    if (response.data && response.data.ip) {
      res.json({ ip: response.data.ip, country: response.data.country_code || '', isp: response.data.isp || '' });
    } else {
      res.json({ ip: '', country: '', isp: '' });
    }
  } catch (error) {
    try {
      const response2 = await axios.get('https://ipinfo.io/json', { timeout: 5000 });
      if (response2.data && response2.data.ip) {
        res.json({ ip: response2.data.ip, country: response2.data.country || '', isp: response2.data.org || '' });
      } else {
        res.json({ ip: '', country: '', isp: '' });
      }
    } catch (error2) {
      res.json({ ip: '', country: '', isp: '' });
    }
  }
});

// ---- Get config ----
app.get("/api/config", (req, res) => {
  res.json({
    port: PORT,
    subPath: SUB_PATH,
    uuid: UUID,
    cfip: CFIP,
    argoDomain: currentArgoDomain || ARGO_DOMAIN || '',
    argoPort: ARGO_PORT,
    nezhaServer: NEZHA_SERVER || '',
    nezhaPort: NEZHA_PORT || '',
    autoAccess: AUTO_ACCESS || false,
    uploadUrl: UPLOAD_URL || '',
    projectUrl: PROJECT_URL || '',
    name: NAME || '',
    protocol: currentInboundConfig.protocol,
    network: currentInboundConfig.streamSettings.network,
    security: currentInboundConfig.streamSettings.security,
    wsPath: currentInboundConfig.streamSettings.wsSettings.path || '',
    sniffingEnabled: currentInboundConfig.sniffing.enabled,
    lastConfigLog: lastConfigLog || ''
  });
});

// ---- Get nodes ----
app.get("/api/nodes", (req, res) => {
  try {
    if (subTxtCache) {
      const nodes = subTxtCache.split('\n').filter(line =>
        /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line)
      );
      res.json({ nodes });
    } else if (fs.existsSync(subPath)) {
      const fileContent = fs.readFileSync(subPath, 'utf-8');
      const decoded = Buffer.from(fileContent, 'base64').toString('utf-8');
      const nodes = decoded.split('\n').filter(line =>
        /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line)
      );
      res.json({ nodes });
    } else {
      res.json({ nodes: [] });
    }
  } catch (err) {
    res.json({ nodes: [] });
  }
});

// ---- Get system status (Module 5) ----
app.get("/api/system-status", async (req, res) => {
  try {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const memPercent = ((usedMem / totalMem) * 100).toFixed(1);
    const cpus = os.cpus();
    const cpuCount = cpus.length;
    const cpuModel = cpus.length > 0 ? cpus[0].model : 'unknown';
    
    // Simple CPU load average (not available on Windows but we try)
    let loadAvg = [0, 0, 0];
    try {
      loadAvg = os.loadavg();
    } catch(e) {}

    // Check if xray and argo processes are running
    let webRunning = false;
    let botRunning = false;
    try {
      if (process.platform === 'win32') {
        const { stdout } = await exec(`tasklist /fi "IMAGENAME eq ${webName}.exe" 2>nul`);
        webRunning = stdout.includes(webName);
        const { stdout: botOut } = await exec(`tasklist /fi "IMAGENAME eq ${botName}.exe" 2>nul`);
        botRunning = botOut.includes(botName);
      } else {
        const { stdout } = await exec(`pgrep -f "${webName}" 2>/dev/null || echo ""`);
        webRunning = stdout.trim().length > 0;
        const { stdout: botOut } = await exec(`pgrep -f "${botName}" 2>/dev/null || echo ""`);
        botRunning = botOut.trim().length > 0;
      }
    } catch(e) {}

    res.json({
      memory: {
        total: (totalMem / 1024 / 1024).toFixed(0),
        used: (usedMem / 1024 / 1024).toFixed(0),
        free: (freeMem / 1024 / 1024).toFixed(0),
        percent: memPercent
      },
      cpu: {
        count: cpuCount,
        model: cpuModel,
        loadAvg: loadAvg
      },
      processes: {
        xray: webRunning,
        argo: botRunning,
        xrayName: webName,
        botName: botName
      },
      argoDomain: currentArgoDomain || ARGO_DOMAIN || '',
      uptime: os.uptime(),
      platform: os.platform(),
      arch: os.arch(),
      hostname: os.hostname(),
      lastConfigLog: lastConfigLog || ''
    });
  } catch (err) {
    res.json({ error: err.message });
  }
});

// ---- Get current inbound config (Module 1) ----
app.get("/api/inbound-config", (req, res) => {
  try {
    const cfg = getCurrentInboundClone();
    res.json({
      protocol: cfg.protocol,
      port: cfg.port,
      settings: {
        clients: cfg.settings.clients.map(c => ({
          id: c.id,
          flow: c.flow || ''
        })),
        decryption: cfg.settings.decryption
      },
      streamSettings: {
        network: cfg.streamSettings.network,
        security: cfg.streamSettings.security,
        wsSettings: {
          path: cfg.streamSettings.wsSettings.path,
          headers: {
            Host: cfg.streamSettings.wsSettings.headers.Host
          }
        },
        grpcSettings: {
          serviceName: cfg.streamSettings.grpcSettings.serviceName
        },
        tlsSettings: {
          serverName: cfg.streamSettings.tlsSettings.serverName,
          alpn: cfg.streamSettings.tlsSettings.alpn,
          minVersion: cfg.streamSettings.tlsSettings.minVersion
        }
      },
      sniffing: {
        enabled: cfg.sniffing.enabled,
        destOverride: cfg.sniffing.destOverride,
        metadataOnly: cfg.sniffing.metadataOnly
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- POST: Update inbound config & hot restart (Modules 1 & 2) ----
app.post("/api/update-inbound", async (req, res) => {
  try {
    const body = req.body;
    
    // Validate required fields
    if (!body.protocol || !['vless', 'vmess', 'trojan'].includes(body.protocol)) {
      return res.status(400).json({ error: 'Invalid or missing protocol. Must be vless, vmess, or trojan.' });
    }

    // Update currentInboundConfig
    const newCfg = getCurrentInboundClone();
    newCfg.protocol = body.protocol;
    
    // Update clients
    if (body.settings && body.settings.clients && body.settings.clients.length > 0) {
      const client = body.settings.clients[0];
      newCfg.settings.clients[0].id = client.id || UUID;
      newCfg.settings.clients[0].flow = client.flow || '';
    }

    // Update streamSettings
    if (body.streamSettings) {
      newCfg.streamSettings.network = body.streamSettings.network || 'ws';
      newCfg.streamSettings.security = body.streamSettings.security || 'none';
      
      if (body.streamSettings.wsSettings) {
        newCfg.streamSettings.wsSettings.path = body.streamSettings.wsSettings.path || '/vless-argo';
        if (body.streamSettings.wsSettings.headers) {
          newCfg.streamSettings.wsSettings.headers.Host = body.streamSettings.wsSettings.headers.Host || '';
        }
      }
      
      if (body.streamSettings.grpcSettings) {
        newCfg.streamSettings.grpcSettings.serviceName = body.streamSettings.grpcSettings.serviceName || '';
      }
      
      if (body.streamSettings.tlsSettings) {
        newCfg.streamSettings.tlsSettings.serverName = body.streamSettings.tlsSettings.serverName || '';
        newCfg.streamSettings.tlsSettings.alpn = body.streamSettings.tlsSettings.alpn || ['h2', 'http/1.1'];
        newCfg.streamSettings.tlsSettings.minVersion = body.streamSettings.tlsSettings.minVersion || '1.2';
      }
    }

    // Update sniffing
    if (body.sniffing) {
      newCfg.sniffing.enabled = body.sniffing.enabled === true || body.sniffing.enabled === 'true';
      newCfg.sniffing.destOverride = body.sniffing.destOverride || ['http', 'tls', 'quic'];
      newCfg.sniffing.metadataOnly = body.sniffing.metadataOnly === true || body.sniffing.metadataOnly === 'true';
    }

    // Apply the config to memory
    Object.assign(currentInboundConfig, newCfg);
    
    // Respond immediately that config is accepted
    res.json({ 
      success: true, 
      message: 'Configuration accepted. Hot restart initiated...',
      config: getCurrentInboundClone()
    });

    // --- Async hot restart (non-blocking) ---
    setImmediate(async () => {
      try {
        // Ensure binary exists before restart (Module 3 bug fix)
        const arch = getSystemArchitecture();
        const binaryOk = await ensureBinaryExists(webPath, arch, 'web');
        if (!binaryOk) {
          console.error('CRITICAL: Xray binary could not be ensured after hot restart attempt');
          return;
        }

        // Hot restart Xray
        await hotRestartXray();
        
        // Regenerate subscription links with new config
        if (currentArgoDomain) {
          await generateLinks(currentArgoDomain);
        }
        
        console.log('Hot restart completed successfully with new config');
      } catch (err) {
        console.error('Hot restart failed:', err.message);
      }
    });
    
  } catch (err) {
    console.error('Error in /api/update-inbound:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: err.message });
    }
  }
});

// ---- POST: Restart Argo tunnel (Module 3) ----
app.post("/api/restart-argo", async (req, res) => {
  try {
    res.json({ success: true, message: 'Argo restart initiated...' });
    
    setImmediate(async () => {
      try {
        await hotRestartArgo();
        // Re-extract domain if temporary tunnel
        if (!ARGO_DOMAIN) {
          await extractDomains();
        }
      } catch (err) {
        console.error('Argo restart failed:', err.message);
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Dynamic GeoIP-Optimized Subscription (Module 4) ----
app.get(`/${SUB_PATH}`, async (req, res) => {
  try {
    // Get user's real IP
    const userIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || req.connection.remoteAddress || '';
    
    // [BUG FIX 3]: Check Cloudflare cf-ipcountry header first (highest priority, zero latency).
    // Railway behind proxy often exposes this header directly.
    const cfCountry = (req.headers['cf-ipcountry'] || '').toUpperCase();
    let countryCode = '';
    if (cfCountry && cfCountry.length === 2 && CF_OPTIMAL_IPS[cfCountry]) {
      countryCode = cfCountry;
    } else {
      // Fallback: external geo API lookup
      const geoInfo = await getUserGeoInfo(userIp);
      countryCode = geoInfo.country || '';
    }
    
    // Ultimate fallback: if countryCode is still empty or unrecognized, use 'default'
    if (!countryCode || !CF_OPTIMAL_IPS[countryCode]) {
      countryCode = 'default';
    }
    
    // Generate optimized subscription
    let subTxt;
    if (countryCode && CF_OPTIMAL_IPS[countryCode]) {
      // Geo-optimized for specific country
      subTxt = await generateOptimizedSubscription(userIp, countryCode);
    } else {
      // Fall back to standard subscription
      subTxt = await generateStandardSubscription();
    }
    
    const encodedContent = Buffer.from(subTxt).toString('base64');
    res.set('Content-Type', 'text/plain; charset=utf-8');
    res.set('X-Geo-Country', countryCode || 'unknown');
    res.set('X-Node-Protocol', currentInboundConfig.protocol);
    res.send(encodedContent);
  } catch (err) {
    console.error('Subscription generation error:', err);
    // Fallback to original subscription
    try {
      const sub = await generateStandardSubscription();
      const encodedContent = Buffer.from(sub).toString('base64');
      res.set('Content-Type', 'text/plain; charset=utf-8');
      res.send(encodedContent);
    } catch (err2) {
      res.status(500).send('Subscription generation failed');
    }
  }
});

// ============================================================
// 13. MAIN STARTUP
// ============================================================
async function startserver() {
  try {
    argoType();
    deleteNodes();
    cleanupOldFiles();
    await downloadFilesAndRun();
    await extractDomains();
    await AddVisitTask();
    cleanFiles(); // 90s cleanup (MODIFIED: preserves core binaries)
  } catch (error) {
    console.error('Error in startserver:', error);
  }
}

startserver().catch(error => {
  console.error('Unhandled error in startserver:', error);
});

app.listen(PORT, () => console.log(`HTTP server is running on port:${PORT}!`));
