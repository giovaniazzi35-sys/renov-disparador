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
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

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

// ── Traduz códigos de erro da Evolution Go ───────────────────
function translateEvolutionError(status, body) {
  if (status === 463) return 'Número sem WhatsApp';
  if (status === 400) return body.error || body.message || 'Requisição inválida';
  if (status === 401 || status === 403) return 'Token inválido ou sem permissão';
  if (status === 404) return 'Instância não encontrada';
  if (status === 408 || status === 504) return 'Timeout — instância pode estar desconectada';
  if (status === 500) return 'Erro interno na Evolution Go';
  return body.error || body.message || `Erro ${status}`;
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
  const { instanceToken, number, text } = req.body;
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
  const { instanceToken, number, url, type, caption, filename } = req.body;
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
