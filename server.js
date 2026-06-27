'use strict';
require('dotenv').config();

const express = require('express');
const cookieSession = require('cookie-session');
const path = require('path');
const http = require('http');
const https = require('https');
const fs = require('fs');
const { URL } = require('url');

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// ── Configuração ────────────────────────────────────────────
const PORT           = parseInt(process.env.PORT) || 3000;
const EVOLUTION_URL  = (process.env.EVOLUTION_URL || '').replace(/\/$/, '');
const GLOBAL_API_KEY = process.env.GLOBAL_API_KEY || '';
const SESSION_SECRET = process.env.SESSION_SECRET || 'renov-secret-2026';
const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY || '';

if (!EVOLUTION_URL || EVOLUTION_URL === 'https://SEU_IP_OU_DOMINIO') {
  console.error('\n  ❌  EVOLUTION_URL não configurada! Edite o arquivo .env.\n');
  process.exit(1);
}
if (!GLOBAL_API_KEY) {
  console.error('❌ GLOBAL_API_KEY é obrigatória no arquivo .env');
  process.exit(1);
}

// Carrega usuários — USERS_JSON (Vercel env var) ou users.json (local)
function loadUsers() {
  if (process.env.USERS_JSON) {
    try { return JSON.parse(process.env.USERS_JSON); } catch (_) {}
  }
  const usersFile = path.join(__dirname, 'users.json');
  if (fs.existsSync(usersFile)) {
    try { return JSON.parse(fs.readFileSync(usersFile, 'utf8')); } catch (_) {}
  }
  return [];
}
const USERS = loadUsers();

if (!USERS.length) {
  console.error('❌ Nenhum usuário configurado. Crie users.json ou defina USERS_JSON no .env');
  process.exit(1);
}

const app = express();
app.use(express.json({ limit: '60mb' }));
app.use(express.urlencoded({ extended: true, limit: '60mb' }));

// cookie-session funciona em serverless (sem estado no servidor)
app.use(cookieSession({
  name: 'renov_session',
  secret: SESSION_SECRET,
  maxAge: 8 * 60 * 60 * 1000, // 8 horas
  httpOnly: true,
  sameSite: 'lax',
}));

// ── Auth ─────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.loggedIn) return next();
  res.redirect('/login');
}

// ── Proxy fetch ──────────────────────────────────────────────
function proxyFetch(url, options = {}, _redirects = 0) {
  if (_redirects > 5) return Promise.reject(new Error('Muitos redirecionamentos (>5)'));
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;
    const bodyStr = options.body || '';
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(bodyStr),
      ...options.headers,
    };
    const req = lib.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      headers,
      agent: parsed.protocol === 'https:' ? httpsAgent : undefined,
    }, (res) => {
      if ([301,302,303,307,308].includes(res.statusCode) && res.headers.location) {
        const redirectUrl = new URL(res.headers.location, url).href;
        const nextMethod = (res.statusCode === 303 || res.statusCode === 302) ? 'GET' : options.method || 'GET';
        resolve(proxyFetch(redirectUrl, { ...options, method: nextMethod, body: nextMethod === 'GET' ? '' : bodyStr }, _redirects + 1));
        res.resume(); return;
      }
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve({
        status: res.statusCode,
        ok: res.statusCode >= 200 && res.statusCode < 300,
        json: () => { try { return Promise.resolve(JSON.parse(body)); } catch (_) { return Promise.resolve({ error: body }); } },
      }));
    });
    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

function logReq(method, p, extra = '') {
  const ts = new Date().toTimeString().slice(0, 8);
  console.log(`[${ts}] ${method.padEnd(4)} ${p}${extra ? '  →  ' + extra : ''}`);
}

// ── Rotas públicas ───────────────────────────────────────────

app.get('/login', (req, res) => {
  if (req.session && req.session.loggedIn) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = USERS.find(u => u.email === email.trim() && u.password === password);
  if (user) {
    req.session.loggedIn = true;
    req.session.email = email.trim();
    return res.redirect('/');
  }
  res.redirect('/login?erro=1');
});

app.post('/logout', (req, res) => {
  req.session = null;
  res.redirect('/login');
});

// ── Rotas protegidas ─────────────────────────────────────────

app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use(express.static(path.join(__dirname), { index: false }));

// ── Normaliza número: garante DDI (adiciona 55 se parecer BR sem DDI) ──
function normalizeNumber(raw) {
  const n = String(raw).replace(/\D/g, '');
  // Números BR sem DDI: 10 ou 11 dígitos começando com DDD válido (11-99)
  if (n.length >= 10 && n.length <= 11) {
    const ddd = parseInt(n.slice(0, 2));
    if (ddd >= 11 && ddd <= 99) return '55' + n;
  }
  return n;
}

// ── Helpers de MIME / extensão ──────────────────────────────
function guessMime(mediaType, filename) {
  if (filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const map = { jpg:'image/jpeg', jpeg:'image/jpeg', png:'image/png', webp:'image/webp', gif:'image/gif',
                  mp4:'video/mp4', mov:'video/quicktime', avi:'video/avi',
                  mp3:'audio/mpeg', ogg:'audio/ogg', wav:'audio/wav', m4a:'audio/mp4', aac:'audio/aac',
                  pdf:'application/pdf', doc:'application/msword',
                  docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document' };
    if (map[ext]) return map[ext];
  }
  const defaults = { image:'image/jpeg', video:'video/mp4', audio:'audio/mpeg', document:'application/octet-stream' };
  return defaults[mediaType] || 'application/octet-stream';
}

// ── Traduz códigos de erro da Evolution Go ───────────────────
function translateEvolutionError(status, body) {
  if (status === 463) return 'Número sem WhatsApp';
  if (status === 401 || status === 403) return 'Token inválido ou sem permissão';
  if (status === 404) return 'Instância não encontrada';
  if (status === 408 || status === 504) return 'Timeout — instância pode estar desconectada';
  // Para 400 e 500: retorna a mensagem real da Evolution Go para facilitar diagnóstico
  return body.error || body.message || body.response?.message || `Erro ${status}`;
}

// ── API ──────────────────────────────────────────────────────

app.get('/api/instances', requireAuth, async (req, res) => {
  logReq('GET', '/api/instances');
  try {
    const up = await proxyFetch(`${EVOLUTION_URL}/instance/all`, { method: 'GET', headers: { apikey: GLOBAL_API_KEY } });
    res.status(up.status).json(await up.json());
  } catch (err) { res.status(502).json({ error: err.message }); }
});

app.post('/api/instance/connect', requireAuth, async (req, res) => {
  const { instanceToken, webhookUrl, subscribe } = req.body;
  if (!instanceToken) return res.status(400).json({ error: 'instanceToken é obrigatório.' });
  try {
    const up = await proxyFetch(`${EVOLUTION_URL}/instance/connect`, {
      method: 'POST', headers: { apikey: instanceToken },
      body: JSON.stringify({ webhookUrl: webhookUrl || '', subscribe: subscribe || ['MESSAGE'] }),
    });
    res.status(up.status).json(await up.json());
  } catch (err) { res.status(502).json({ error: err.message }); }
});

app.get('/api/instance/qr', requireAuth, async (req, res) => {
  const token = req.headers['x-instance-token'];
  if (!token) return res.status(400).json({ error: 'x-instance-token obrigatório.' });
  try {
    const up = await proxyFetch(`${EVOLUTION_URL}/instance/qr`, { method: 'GET', headers: { apikey: token } });
    res.status(up.status).json(await up.json());
  } catch (err) { res.status(502).json({ error: err.message }); }
});

app.post('/api/instance/pair', requireAuth, async (req, res) => {
  const { instanceToken, phone } = req.body;
  if (!instanceToken) return res.status(400).json({ error: 'instanceToken é obrigatório.' });
  try {
    const up = await proxyFetch(`${EVOLUTION_URL}/instance/pair`, {
      method: 'POST', headers: { apikey: instanceToken },
      body: JSON.stringify({ phone }),
    });
    res.status(up.status).json(await up.json());
  } catch (err) { res.status(502).json({ error: err.message }); }
});

app.get('/api/instance/status', requireAuth, async (req, res) => {
  const token = req.headers['x-instance-token'];
  if (!token) return res.status(400).json({ error: 'x-instance-token obrigatório.' });
  try {
    const up = await proxyFetch(`${EVOLUTION_URL}/instance/status`, { method: 'GET', headers: { apikey: token } });
    res.status(up.status).json(await up.json());
  } catch (err) { res.status(502).json({ error: err.message }); }
});

app.post('/api/send/text', requireAuth, async (req, res) => {
  const { instanceToken, text } = req.body;
  const number = normalizeNumber(req.body.number || '');
  if (!instanceToken) return res.status(400).json({ error: 'instanceToken obrigatório.' });
  if (!number || !/^\d{10,15}$/.test(number)) return res.status(400).json({ error: 'Número inválido.' });
  if (!text || !text.trim()) return res.status(400).json({ error: 'Texto vazio.' });
  logReq('POST', '/api/send/text', number);
  try {
    const up = await proxyFetch(`${EVOLUTION_URL}/send/text`, {
      method: 'POST', headers: { apikey: instanceToken },
      body: JSON.stringify({ number, text: text.trim(), delay: 0 }),
    });
    const body = await up.json();
    if (!up.ok) return res.status(up.status).json({ error: translateEvolutionError(up.status, body) });
    res.status(up.status).json(body);
  } catch (err) { res.status(502).json({ error: err.message }); }
});

app.post('/api/send/media', requireAuth, async (req, res) => {
  const { instanceToken, url, type, caption, filename } = req.body;
  const number = normalizeNumber(req.body.number || '');
  if (!instanceToken || !number || !url || !type) return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
  try {
    const up = await proxyFetch(`${EVOLUTION_URL}/send/media`, {
      method: 'POST', headers: { apikey: instanceToken },
      body: JSON.stringify({ number, url, type, caption, filename }),
    });
    const body = await up.json();
    if (!up.ok) return res.status(up.status).json({ error: translateEvolutionError(up.status, body) });
    res.status(up.status).json(body);
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// ── Envio de mídia via base64 (upload de arquivo) ───────────
app.post('/api/send/media-upload', requireAuth, async (req, res) => {
  const { instanceToken, mediaBase64, mediaType, mimetype, caption, filename, ptt } = req.body;
  const number = normalizeNumber(req.body.number || '');
  if (!instanceToken || !number || !mediaBase64) {
    return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
  }
  logReq('POST', '/api/send/media-upload', number);
  const base64Data = mediaBase64.replace(/^data:[^;]+;base64,/, '');
  const resolvedMime = mimetype || guessMime(mediaType, filename);
  try {
    // Áudio PTT (gravação de voz)
    if (ptt) {
      const up = await proxyFetch(`${EVOLUTION_URL}/send/audio`, {
        method: 'POST', headers: { apikey: instanceToken },
        body: JSON.stringify({ number, audio: base64Data, encoding: true }),
      });
      const body = await up.json().catch(() => ({}));
      if (!up.ok) return res.status(up.status).json({ error: translateEvolutionError(up.status, body) });
      return res.status(up.status).json(body);
    }
    // Outros tipos de mídia
    const up = await proxyFetch(`${EVOLUTION_URL}/send/media`, {
      method: 'POST', headers: { apikey: instanceToken },
      body: JSON.stringify({
        number, type: mediaType,
        media: base64Data,
        mimetype: resolvedMime,
        caption: caption || '',
        filename: filename || `arquivo.${resolvedMime.split('/')[1] || 'bin'}`,
      }),
    });
    const body = await up.json().catch(() => ({}));
    if (!up.ok) return res.status(up.status).json({ error: translateEvolutionError(up.status, body) });
    res.status(up.status).json(body);
  } catch (err) { res.status(502).json({ error: err.message }); }
});

app.post('/api/instance/logout', requireAuth, async (req, res) => {
  const { instanceToken } = req.body;
  if (!instanceToken) return res.status(400).json({ error: 'instanceToken obrigatório.' });
  try {
    const up = await proxyFetch(`${EVOLUTION_URL}/instance/logout`, {
      method: 'DELETE', headers: { apikey: instanceToken },
    });
    res.status(up.status).json(await up.json());
  } catch (err) { res.status(502).json({ error: err.message }); }
});

app.post('/api/instance/restart', requireAuth, async (req, res) => {
  const { instanceToken } = req.body;
  if (!instanceToken) return res.status(400).json({ error: 'instanceToken obrigatório.' });
  try {
    const up = await proxyFetch(`${EVOLUTION_URL}/instance/restart`, {
      method: 'PUT', headers: { apikey: instanceToken },
    });
    res.status(up.status).json(await up.json());
  } catch (err) { res.status(502).json({ error: err.message }); }
});

app.post('/api/user/check', requireAuth, async (req, res) => {
  const { instanceToken, number } = req.body;
  if (!instanceToken || !number) return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
  try {
    const up = await proxyFetch(`${EVOLUTION_URL}/user/check`, {
      method: 'POST', headers: { apikey: instanceToken },
      body: JSON.stringify({ number: Array.isArray(number) ? number : [number] }),
    });
    res.status(up.status).json(await up.json());
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// ── Agente IA ────────────────────────────────────────────────

const AGENT_FILE = path.join(__dirname, 'agent-config.json');

function loadAgentConfig() {
  if (process.env.AGENT_CONFIG_JSON) {
    try { return JSON.parse(process.env.AGENT_CONFIG_JSON); } catch (_) {}
  }
  if (fs.existsSync(AGENT_FILE)) {
    try { return JSON.parse(fs.readFileSync(AGENT_FILE, 'utf8')); } catch (_) {}
  }
  return { active: false, instanceName: '', instanceToken: '', prompt: '', docText: '' };
}

function saveAgentConfig(cfg) {
  try { fs.writeFileSync(AGENT_FILE, JSON.stringify(cfg, null, 2)); } catch (_) {}
}

let agentConfig = loadAgentConfig();

async function callClaude(userMessage) {
  if (!CLAUDE_API_KEY) throw new Error('CLAUDE_API_KEY não configurada');
  const system = [
    agentConfig.prompt,
    agentConfig.docText ? `\n\n# Documento de referência:\n${agentConfig.docText}` : ''
  ].join('').trim();

  const body = JSON.stringify({
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 400,
    system: system || 'Você é um assistente de qualificação comercial. Responda de forma curta, objetiva e sem inventar informações.',
    messages: [{ role: 'user', content: userMessage }],
  });

  const r = await proxyFetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': CLAUDE_API_KEY,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json',
    },
    body,
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data?.error?.message || `Claude API ${r.status}`);
  return data?.content?.[0]?.text || '';
}

function extractMsgText(data) {
  const m = data?.message || {};
  return m.conversation
      || m.extendedTextMessage?.text
      || m.ephemeralMessage?.message?.extendedTextMessage?.text
      || m.ephemeralMessage?.message?.conversation
      || m.buttonsResponseMessage?.selectedDisplayText
      || m.listResponseMessage?.title
      || '';
}

app.get('/api/agent/config', requireAuth, (req, res) => {
  res.json({ ok: true, data: { ...agentConfig, docText: agentConfig.docText ? '(carregado)' : '' } });
});

app.post('/api/agent/config', requireAuth, (req, res) => {
  const { active, instanceName, instanceToken, prompt, docText } = req.body;
  agentConfig = { active: !!active, instanceName: instanceName || '', instanceToken: instanceToken || '', prompt: prompt || '', docText: docText || '' };
  saveAgentConfig(agentConfig);
  logReq('POST', '/api/agent/config', `active=${agentConfig.active} instance=${agentConfig.instanceName}`);
  res.json({ ok: true });
});

app.post('/api/agent/toggle', requireAuth, (req, res) => {
  agentConfig.active = !agentConfig.active;
  saveAgentConfig(agentConfig);
  logReq('POST', '/api/agent/toggle', `active=${agentConfig.active}`);
  res.json({ ok: true, active: agentConfig.active });
});

// Webhook público — Evolution Go posta aqui sem autenticação
app.post('/api/agent/webhook', async (req, res) => {
  res.status(200).json({ ok: true }); // responde imediatamente
  try {
    if (!agentConfig.active || !agentConfig.instanceToken) return;
    const event = req.body?.event || req.body?.type || '';
    if (!event.toLowerCase().includes('message')) return;

    const msgData = req.body?.data || req.body?.messages?.[0] || req.body;
    if (!msgData) return;
    if (msgData?.key?.fromMe) return; // ignora mensagens próprias
    const isGroup = (msgData?.key?.remoteJid || '').includes('@g.us');
    if (isGroup) return;

    const text = extractMsgText(msgData).trim();
    if (!text) return;

    const from = (msgData?.key?.remoteJid || '').replace('@s.whatsapp.net', '');
    if (!from) return;

    const ts = new Date().toTimeString().slice(0, 8);
    console.log(`[${ts}] 🤖 Agente recebeu de ${from}: ${text.slice(0, 60)}`);

    const reply = await callClaude(text);
    if (!reply) return;

    await proxyFetch(`${EVOLUTION_URL}/send/text`, {
      method: 'POST',
      headers: { apikey: agentConfig.instanceToken },
      body: JSON.stringify({ number: from, text: reply, delay: 1500 }),
    });
    console.log(`[${ts}] 🤖 Agente respondeu para ${from}: ${reply.slice(0, 60)}`);
  } catch (err) {
    console.error('Agente IA erro:', err.message);
  }
});

// ── Inicia servidor (apenas localmente — Vercel usa module.exports) ──
if (require.main === module) {
  app.listen(PORT, () => {
    console.log('');
    console.log('  🚀 Renov Disparador em    http://localhost:' + PORT);
    console.log('  📡 Evolution Go em        ' + EVOLUTION_URL);
    console.log('  🔒 Usuários               ' + USERS.map(u => u.email).join(', '));
    console.log('');
  });
}

module.exports = app;
