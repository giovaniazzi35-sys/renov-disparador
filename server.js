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

// ── Traduz erros baileys/Evolution Go ────────────────────────
function translateEvolutionError(status, body) {
  if (status === 463) return 'Número sem WhatsApp';
  if (status === 401 || status === 403) return 'Token inválido ou sem permissão';
  if (status === 404) return 'Instância não encontrada';
  if (status === 408 || status === 504) return 'Timeout — instância pode estar desconectada';

  const raw = (body.error || body.message || body.response?.message || '').toLowerCase();

  // Erros de sessão baileys (jid / store)
  if (raw.includes('store doesn') || raw.includes('device jid') || raw.includes('jid not found'))
    return 'INSTANCIA_SEM_SESSAO: Sessão não inicializada — reinicie a instância';
  if (raw.includes('connection closed') || raw.includes('connection lost') || raw.includes('stream errored') || raw.includes('bad mac'))
    return 'INSTANCIA_DESCONECTADA: Conexão perdida — reconecte a instância';
  if (raw.includes('not connected') || raw.includes('disconnected'))
    return 'INSTANCIA_DESCONECTADA: Instância desconectada — reconecte o WhatsApp';

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

// ── Agente IA — persistência Supabase ────────────────────────

const AGENT_FILE    = path.join(__dirname, 'agent-config.json');
const SUPABASE_URL  = (process.env.SUPABASE_URL  || '').replace(/\/$/, '');
const SUPABASE_KEY  = process.env.SUPABASE_KEY  || '';
const SB_HEADERS    = { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json' };
const DEFAULT_CFG   = () => ({ active: false, manuallyDeactivated: false, instanceName: '', instanceToken: '', prompt: '', docText: '', openrouterKey: '', model: 'deepseek/deepseek-chat-v3-0324:free', selectedPlaybook: 0, schedulingEnabled: false, calendarId: 'primary', googleClientId: '', googleClientSecret: '', googleRefreshToken: '', googleEmail: '' });

function autoActivate(cfg) {
  // Mantém agente sempre ativo se os campos estiverem preenchidos,
  // a menos que o usuário tenha desativado manualmente via toggle.
  if (cfg.instanceToken && cfg.openrouterKey && !cfg.manuallyDeactivated) {
    cfg.active = true;
  }
  return cfg;
}

async function loadAgentConfig() {
  // 1. Supabase (fonte principal — persiste entre deploys)
  if (SUPABASE_URL && SUPABASE_KEY) {
    try {
      const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_config?id=eq.1&select=data`, { method: 'GET', headers: SB_HEADERS });
      const rows = await r.json();
      if (r.ok && Array.isArray(rows) && rows[0]?.data && Object.keys(rows[0].data).length > 0) {
        console.log('✅ Config carregado do Supabase');
        return autoActivate({ ...DEFAULT_CFG(), ...rows[0].data });
      }
    } catch (err) { console.warn('Supabase load error:', err.message); }
  }
  // 2. Variável de ambiente legada
  if (process.env.AGENT_CONFIG_JSON) {
    try { return autoActivate({ ...DEFAULT_CFG(), ...JSON.parse(process.env.AGENT_CONFIG_JSON) }); } catch (_) {}
  }
  // 3. Arquivo local (desenvolvimento)
  if (fs.existsSync(AGENT_FILE)) {
    try { return autoActivate({ ...DEFAULT_CFG(), ...JSON.parse(fs.readFileSync(AGENT_FILE, 'utf8')) }); } catch (_) {}
  }
  return DEFAULT_CFG();
}

function saveAgentConfig(cfg) {
  // Supabase — fire-and-forget com retry
  if (SUPABASE_URL && SUPABASE_KEY) {
    proxyFetch(`${SUPABASE_URL}/rest/v1/agent_config?id=eq.1`, {
      method: 'PATCH',
      headers: { ...SB_HEADERS, 'Prefer': 'return=minimal' },
      body: JSON.stringify({ data: cfg, updated_at: new Date().toISOString() }),
    }).then(r => { if (!r.ok) console.warn('Supabase save failed:', r.status); })
      .catch(err => console.warn('Supabase save error:', err.message));
  }
  // Arquivo local (backup / desenvolvimento)
  try { fs.writeFileSync(AGENT_FILE, JSON.stringify(cfg, null, 2)); } catch (_) {}
}

// Carrega config assincronamente na inicialização; até lá usa o default
let agentConfig = DEFAULT_CFG();
let _configReady = false;
loadAgentConfig().then(cfg => { agentConfig = cfg; _configReady = true; }).catch(() => { _configReady = true; });

// Garante que agentConfig está carregado antes de qualquer rota sensível.
// Se o load falhou (ex.: Supabase indisponível), tenta de novo na próxima requisição.
async function ensureConfig() {
  if (_configReady && agentConfig.instanceToken) return;
  try {
    agentConfig = await loadAgentConfig();
  } catch (_) {}
  _configReady = true;
}
app.use(async (req, res, next) => { await ensureConfig(); next(); });

// Histórico de conversa por contato — cache em memória + persistência no Supabase
const conversationHistory = new Map(); // phone → [{role,content}]
// Buffer para juntar mensagens seguidas do mesmo contato antes de responder
const msgBuffer = new Map(); // phone → { texts: [], seq: 0 }

// Carrega histórico do Supabase se ainda não está em memória (sobrevive a cold starts)
async function loadConversation(phone) {
  if (conversationHistory.has(phone)) return;
  if (!SUPABASE_URL || !SUPABASE_KEY) { conversationHistory.set(phone, []); return; }
  try {
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_conversations?phone=eq.${phone}&select=messages,disabled`, { method: 'GET', headers: SB_HEADERS });
    const rows = await r.json();
    if (r.ok && Array.isArray(rows) && rows[0]) {
      conversationHistory.set(phone, Array.isArray(rows[0].messages) ? rows[0].messages : []);
      if (rows[0].disabled) disabledNumbers.add(phone); else disabledNumbers.delete(phone);
      return;
    }
  } catch (err) { console.warn('loadConversation error:', err.message); }
  conversationHistory.set(phone, []);
}

// Salva histórico no Supabase (fire-and-forget)
function saveConversation(phone) {
  if (!SUPABASE_URL || !SUPABASE_KEY) return;
  const messages = conversationHistory.get(phone) || [];
  proxyFetch(`${SUPABASE_URL}/rest/v1/agent_conversations`, {
    method: 'POST',
    headers: { ...SB_HEADERS, 'Prefer': 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify({ phone, messages, disabled: disabledNumbers.has(phone), updated_at: new Date().toISOString() }),
  }).then(r => { if (!r.ok) console.warn('saveConversation failed:', r.status); })
    .catch(err => console.warn('saveConversation error:', err.message));
}
const MAX_HISTORY = 30; // mensagens mantidas por contato

// ── Google Calendar helpers ───────────────────────────────────

async function getGoogleAccessToken() {
  const { googleClientId: cid, googleClientSecret: csec, googleRefreshToken: rt } = agentConfig;
  if (!cid || !csec || !rt) return null;
  const body = `client_id=${encodeURIComponent(cid)}&client_secret=${encodeURIComponent(csec)}&refresh_token=${encodeURIComponent(rt)}&grant_type=refresh_token`;
  const r = await proxyFetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d?.error_description || 'Falha ao obter token Google');
  return d.access_token;
}

async function getCalendarBusySlots(accessToken, calendarId) {
  const calId = encodeURIComponent(calendarId || 'primary');
  const now = new Date();
  const maxDate = new Date(now.getTime() + 10 * 24 * 60 * 60 * 1000);
  const url = `https://www.googleapis.com/calendar/v3/calendars/${calId}/events?timeMin=${now.toISOString()}&timeMax=${maxDate.toISOString()}&singleEvents=true&orderBy=startTime&fields=items(start,end,status)`;
  const r = await proxyFetch(url, { method: 'GET', headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' } });
  const d = await r.json();
  if (!r.ok) throw new Error(d?.error?.message || 'Erro ao ler calendário');
  return (d.items || []).filter(e => e.status !== 'cancelled').map(e => ({
    start: new Date(e.start.dateTime || e.start.date + 'T00:00:00Z'),
    end:   new Date(e.end.dateTime   || e.end.date   + 'T23:59:59Z'),
  }));
}

// Retorna próximos slots livres (1h) entre 11-17 BRT, seg-sex
function findAvailableSlots(busySlots, count = 2) {
  const slots = [];
  const now = new Date();
  // BRT = UTC-3. Representação BRT como "UTC falso": brtDate = new Date(utc - 3h)
  const nowBRT = new Date(now.getTime() - 3 * 3600000);

  for (let dayOffset = 0; dayOffset <= 12 && slots.length < count; dayOffset++) {
    // Data BRT do dia
    const dayBRT = new Date(Date.UTC(nowBRT.getUTCFullYear(), nowBRT.getUTCMonth(), nowBRT.getUTCDate() + dayOffset));
    const brtDow = dayBRT.getUTCDay(); // 0=Dom,6=Sab
    if (brtDow === 0 || brtDow === 6) continue;

    for (let brtHour = 11; brtHour <= 16 && slots.length < count; brtHour++) {
      // Converter hora BRT → UTC: brtHour UTC do dayBRT + 3h
      const slotStart = new Date(dayBRT.getTime() + (brtHour + 3) * 3600000);
      const slotEnd   = new Date(slotStart.getTime() + 3600000);
      // Ignora slots no passado (mínimo 2h de antecedência)
      if (slotStart.getTime() < now.getTime() + 2 * 3600000) continue;
      const isBusy = busySlots.some(b => slotStart < b.end && slotEnd > b.start);
      if (!isBusy) slots.push(slotStart);
    }
  }
  return slots;
}

function formatSlotBRT(utcDate) {
  const brt = new Date(utcDate.getTime() - 3 * 3600000);
  const days  = ['domingo','segunda-feira','terça-feira','quarta-feira','quinta-feira','sexta-feira','sábado'];
  const months= ['jan','fev','mar','abr','mai','jun','jul','ago','set','out','nov','dez'];
  return `${days[brt.getUTCDay()]}, ${brt.getUTCDate()} de ${months[brt.getUTCMonth()]} às ${String(brt.getUTCHours()).padStart(2,'0')}:00`;
}

// Detecta [AGENDAR:2025-01-14T14:00] na resposta do AI
function parseScheduleTag(text) {
  const match = text.match(/\[AGENDAR:(\d{4}-\d{2}-\d{2}T\d{2}:\d{2})\]/);
  if (!match) return null;
  // Converte BRT ISO → UTC Date: hora BRT + 3h = UTC
  const [datePart, timePart] = match[1].split('T');
  const [y,mo,d] = datePart.split('-').map(Number);
  const [h,m]    = timePart.split(':').map(Number);
  return new Date(Date.UTC(y, mo-1, d, h+3, m, 0));
}

async function createCalendarEvent(accessToken, calendarId, slotUtc, clientPhone) {
  const calId   = encodeURIComponent(calendarId || 'primary');
  const slotEnd = new Date(slotUtc.getTime() + 3600000);

  function toISOBRT(d) {
    const b = new Date(d.getTime() - 3 * 3600000);
    const pad = n => String(n).padStart(2,'0');
    return `${b.getUTCFullYear()}-${pad(b.getUTCMonth()+1)}-${pad(b.getUTCDate())}T${pad(b.getUTCHours())}:${pad(b.getUTCMinutes())}:00-03:00`;
  }

  const r = await proxyFetch(
    `https://www.googleapis.com/calendar/v3/calendars/${calId}/events?conferenceDataVersion=1`,
    {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        summary: `Reunião Renov Assessoria`,
        description: `Agendado via WhatsApp — ${clientPhone}`,
        start: { dateTime: toISOBRT(slotUtc), timeZone: 'America/Sao_Paulo' },
        end:   { dateTime: toISOBRT(slotEnd),  timeZone: 'America/Sao_Paulo' },
        conferenceData: {
          createRequest: {
            requestId: `renov-${Date.now()}-${clientPhone}`,
            conferenceSolutionKey: { type: 'hangoutsMeet' },
          },
        },
      }),
    }
  );
  const data = await r.json();
  if (!r.ok) throw new Error(data?.error?.message || 'Erro ao criar evento');
  return data?.conferenceData?.entryPoints?.[0]?.uri || data?.hangoutLink || null;
}

// Lista de modelos gratuitos consultada ao vivo (cache 10 min) —
// slugs fixos quebram porque o OpenRouter muda quais modelos são :free
let _freeModelsCache = { ts: 0, list: [] };
async function getLiveFreeModels(apiKey) {
  if (_freeModelsCache.list.length && Date.now() - _freeModelsCache.ts < 10 * 60 * 1000) {
    return _freeModelsCache.list;
  }
  try {
    const r = await proxyFetch('https://openrouter.ai/api/v1/models', {
      method: 'GET', headers: { 'Authorization': `Bearer ${apiKey}` },
    });
    const d = await r.json();
    if (r.ok) {
      const list = (d.data || []).filter(m => m.id && m.id.endsWith(':free')).map(m => m.id);
      if (list.length) _freeModelsCache = { ts: Date.now(), list };
      return list;
    }
  } catch (_) {}
  return _freeModelsCache.list;
}

async function callOpenRouter(apiKey, model, systemPrompt, messages) {
  const liveFree = await getLiveFreeModels(apiKey);
  const primary = model || liveFree[0] || 'deepseek/deepseek-chat-v3-0324:free';
  // Tenta o modelo escolhido + até 6 gratuitos atuais da lista ao vivo
  const chain = [primary, ...liveFree.filter(m => m !== primary).slice(0, 6)];
  const msgPayload = [
    { role: 'system', content: systemPrompt || 'Você é um assistente de qualificação comercial. Responda de forma curta, objetiva e sem inventar informações.' },
    ...messages,
  ];

  let lastErr = null;
  for (const m of chain) {
    try {
      const r = await proxyFetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'https://renov-disparador.vercel.app',
          'X-Title': 'Renov Agente IA',
        },
        body: JSON.stringify({ model: m, temperature: 0.7, max_tokens: 300, messages: msgPayload }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data?.error?.message || `OpenRouter ${r.status}`);
      const reply = data?.choices?.[0]?.message?.content || '';
      if (reply) {
        if (m !== primary) console.log(`[OPENROUTER] fallback usado: ${m} (primário ${primary} falhou)`);
        return reply;
      }
      lastErr = new Error(`Modelo ${m} retornou resposta vazia`);
    } catch (err) {
      console.warn(`[OPENROUTER] ${m} falhou: ${err.message}`);
      lastErr = err;
    }
  }
  throw lastErr || new Error('Nenhum modelo respondeu');
}

// Evolution Go (whatsmeow) envia { Info: {Chat, Sender, IsFromMe, IsGroup, ID, Type}, Message: {...} }
// Evolution JS (Baileys) envia { key: {remoteJid, fromMe, id}, message: {...}, messageType }
// Normaliza ambos para o formato Baileys usado pelo resto do código.
function normalizeMsgData(raw) {
  if (!raw || typeof raw !== 'object') return null;
  if (raw.key && raw.message) return raw; // já é Baileys

  const info = raw.Info || raw.info;
  if (info) {
    const jid = (typeof info.Chat === 'string' ? info.Chat : info.Chat?.User ? `${info.Chat.User}@${info.Chat.Server || 's.whatsapp.net'}` : '') || '';
    return {
      key: { remoteJid: jid, fromMe: !!info.IsFromMe, id: info.ID || '' },
      message: raw.Message || raw.message || {},
      messageType: info.Type || '',
      pushName: info.PushName || '',
      _isGroup: !!info.IsGroup,
    };
  }
  return raw; // formato desconhecido — deixa o fluxo tentar
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

function isAudioMessage(data) {
  const m = data?.message || {};
  return !!(m.audioMessage || m.pttMessage || m.documentMessage?.mimetype?.startsWith('audio'));
}

// Destino das indicações: grupo "Renov Gestão ✅" do WhatsApp.
// Se o envio ao grupo falhar, cai para o número pessoal de reserva.
const CONTACT_FORWARD_GROUP  = '120363427333810759@g.us'; // Renov Gestão ✅
const CONTACT_FORWARD_NUMBER = '5511970799985';           // reserva

// Envia a indicação com até 3 tentativas por destino — a mensagem PRECISA chegar
async function forwardIndication(sendToken, textMsg) {
  for (const dest of [CONTACT_FORWARD_GROUP, CONTACT_FORWARD_NUMBER]) {
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const r = await proxyFetch(`${EVOLUTION_URL}/send/text`, {
          method: 'POST',
          headers: { apikey: sendToken },
          body: JSON.stringify({ number: dest, text: textMsg, delay: 800 }),
        });
        if (r.ok) { console.log(`[INDICACAO] enviada para ${dest} (tentativa ${attempt})`); return true; }
        const errBody = await r.text().catch(() => '');
        console.warn(`[INDICACAO] ${dest} tentativa ${attempt} falhou (${r.status}): ${errBody.slice(0, 200)}`);
      } catch (err) {
        console.warn(`[INDICACAO] ${dest} tentativa ${attempt} erro: ${err.message}`);
      }
      await new Promise(r => setTimeout(r, 1500));
    }
  }
  console.error('[INDICACAO] FALHA DEFINITIVA — grupo e número reserva falharam');
  return false;
}

// Detecta telefones brasileiros digitados no texto (ex.: "o dono é João, 11 98888-7777")
// Encaminha QUALQUER telefone detectado — sem lista de exclusão
function extractPhonesFromText(text) {
  const matches = [...(text || '').matchAll(/(?:\+?55[\s.-]?)?\(?\d{2}\)?[\s.-]?\d{4,5}[\s.-]?\d{4}\b/g)];
  const phones = matches
    .map(m => m[0].replace(/\D/g, ''))
    .filter(d => d.length >= 10 && d.length <= 13)
    .map(d => (d.length === 10 || d.length === 11) ? '55' + d : d);
  return [...new Set(phones)];
}

// Extrai contatos compartilhados (vCard) da mensagem
function extractContacts(data) {
  const m = data?.message || {};
  const list = [];
  const push = (c) => {
    if (!c) return;
    const tel = ((c.vcard || '').match(/TEL[^:]*:([+\d\s().-]+)/i)?.[1] || '').replace(/\D/g, '');
    const name = c.displayName || ((c.vcard || '').match(/FN:(.+)/i)?.[1] || '').trim();
    if (name || tel) list.push({ name: name || 'Sem nome', phone: tel || 'sem telefone' });
  };
  push(m.contactMessage);
  (m.contactsArrayMessage?.contacts || []).forEach(push);
  return list;
}

// Busca o base64 do áudio: primeiro no próprio payload (Evolution Go pode embutir),
// depois via endpoint de mídia da Evolution API
async function getAudioBase64(data, rawPayload, token) {
  // 1. Base64 embutido no webhook (config "webhook base64" da Evolution)
  const inline = rawPayload?.Base64 || rawPayload?.base64 || data?.base64
    || data?.message?.base64 || data?.message?.audioMessage?.base64;
  if (inline && typeof inline === 'string' && inline.length > 100) return inline;

  // 2. Endpoint de download de mídia
  if (!data?.key || !token) return null;
  try {
    const mediaRes = await proxyFetch(`${EVOLUTION_URL}/chat/getBase64FromMediaMessage`, {
      method: 'POST',
      headers: { apikey: token },
      body: JSON.stringify({ key: data.key, message: data.message, convertToMp4: false }),
    });
    if (!mediaRes.ok) {
      console.warn(`[AUDIO] download de mídia falhou (${mediaRes.status})`);
      return null;
    }
    const mediaData = await mediaRes.json();
    return mediaData?.base64 || mediaData?.data || mediaData?.media || null;
  } catch (err) {
    console.warn('[AUDIO] erro no download:', err.message);
    return null;
  }
}

async function transcribeAudio(data, apiKey, instanceToken, rawPayload) {
  try {
    const token = instanceToken || agentConfig.instanceToken;
    const base64 = await getAudioBase64(data, rawPayload, token);
    if (!base64) return null;

    // Modelos com suporte a áudio: Gemini gratuitos da lista ao vivo primeiro
    const liveFree = await getLiveFreeModels(apiKey);
    const audioModels = [
      ...liveFree.filter(m => m.includes('gemini')),
      'google/gemini-2.5-flash-lite', // fallback pago barato caso não haja gemini free
    ];

    const content = [
      { type: 'text', text: 'Transcreva exatamente o que foi dito neste áudio em português brasileiro. Retorne apenas a transcrição, sem comentários.' },
      { type: 'input_audio', input_audio: { data: base64.replace(/^data:[^,]+,/, ''), format: 'ogg' } },
    ];

    for (const model of audioModels) {
      try {
        const r = await proxyFetch('https://openrouter.ai/api/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            'HTTP-Referer': 'https://renov-disparador.vercel.app',
            'X-Title': 'Renov Agente IA',
          },
          body: JSON.stringify({ model, max_tokens: 1000, messages: [{ role: 'user', content }] }),
        });
        const d = await r.json();
        if (!r.ok) { console.warn(`[AUDIO] ${model} falhou: ${d?.error?.message || r.status}`); continue; }
        const out = d?.choices?.[0]?.message?.content?.trim();
        if (out) return out;
      } catch (err) { console.warn(`[AUDIO] ${model} erro: ${err.message}`); }
    }
    return null;
  } catch (err) {
    console.error('Transcribe audio error:', err.message);
    return null;
  }
}

// Números com IA desativada manualmente (em memória)
const disabledNumbers = new Set();

// Endpoint de debug — mostra últimos payloads recebidos no webhook (sem auth para facilitar debug)
const webhookLog = [];
app.get('/api/agent/webhook-log', requireAuth, (req, res) => {
  res.json({ ok: true, log: webhookLog.slice(-20) });
});

app.get('/api/agent/config', requireAuth, (req, res) => {
  res.json({ ok: true, data: { ...agentConfig, docText: agentConfig.docText ? '(carregado)' : '' } });
});

// Lista modelos gratuitos do OpenRouter — sem testar um por um (evita timeout)
app.post('/api/agent/probe-models', requireAuth, async (req, res) => {
  const { apiKey } = req.body;
  if (!apiKey) return res.status(400).json({ error: 'apiKey obrigatória' });
  try {
    // Busca lista de modelos
    const listRes = await proxyFetch('https://openrouter.ai/api/v1/models', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${apiKey}` },
    });
    const listData = await listRes.json();
    if (!listRes.ok) return res.status(400).json({ error: listData?.error?.message || 'Chave inválida' });

    // Filtra gratuitos e ordena por contexto (maior contexto = modelo mais capaz)
    const PREFER = ['deepseek/deepseek-chat-v3-0324:free', 'deepseek/deepseek-r1:free', 'google/gemini-2.0-flash-exp:free', 'meta-llama/llama-3.3-70b-instruct:free'];
    const freeModels = (listData.data || [])
      .filter(m => m.id && m.id.endsWith(':free'))
      .map(m => ({ id: m.id, name: m.name || m.id }));

    if (!freeModels.length) return res.json({ ok: true, models: [], workingModel: null });

    // Prioriza modelos conhecidos, depois lista o restante
    const preferred = freeModels.filter(m => PREFER.includes(m.id));
    const others    = freeModels.filter(m => !PREFER.includes(m.id));
    const sorted    = [...preferred, ...others];

    // Usa o primeiro como workingModel (a lista OpenRouter já confirma disponibilidade)
    res.json({ ok: true, models: sorted, workingModel: sorted[0].id });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.post('/api/agent/chat', requireAuth, async (req, res) => {
  const { apiKey, model, prompt, docText, messages } = req.body;
  if (!apiKey) return res.status(400).json({ error: 'API key obrigatória' });
  try {
    const system = [prompt || '', docText ? `\n\n# Documento de referência:\n${docText}` : ''].join('').trim()
                || 'Você é um assistente útil.';
    const reply = await callOpenRouter(apiKey, model, system, messages || [{ role: 'user', content: 'Olá' }]);
    res.json({ ok: true, reply });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/agent/config', requireAuth, (req, res) => {
  const { active, instanceName, instanceToken, prompt, docText, openrouterKey, model,
          schedulingEnabled, calendarId, googleClientId, googleClientSecret } = req.body;
  // Ao salvar configurações completas, sempre reativa e limpa flag de desativação manual
  const hasRequiredFields = !!(instanceToken && openrouterKey);
  agentConfig = {
    // Preserva token OAuth e email ao salvar — não apaga o login do Google
    googleRefreshToken: agentConfig.googleRefreshToken || '',
    googleEmail:        agentConfig.googleEmail || '',
    active: hasRequiredFields ? true : !!active,
    manuallyDeactivated: false,
    instanceName: instanceName || '', instanceToken: instanceToken || '',
    prompt: prompt || '', docText: docText || '',
    openrouterKey: openrouterKey || '', model: model || 'deepseek/deepseek-chat-v3-0324:free',
    schedulingEnabled: !!schedulingEnabled,
    calendarId: calendarId || 'primary',
    googleClientId: googleClientId || '', googleClientSecret: googleClientSecret || '',
  };
  saveAgentConfig(agentConfig);
  logReq('POST', '/api/agent/config', `active=${agentConfig.active} scheduling=${agentConfig.schedulingEnabled}`);
  res.json({ ok: true });
});

// ── Google OAuth login flow ───────────────────────────────────

app.get('/api/agent/google-auth', requireAuth, (req, res) => {
  const { googleClientId } = agentConfig;
  if (!googleClientId) return res.status(400).send('<h2>Client ID não configurado.</h2><p>Salve as configurações do Agente IA com seu Client ID antes de fazer login.</p>');
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const redirectUri = `${proto}://${req.get('host')}/api/agent/google-callback`;
  const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id: googleClientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/userinfo.email',
    access_type: 'offline',
    prompt: 'consent',
  }).toString();
  res.redirect(authUrl);
});

app.get('/api/agent/google-callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) {
    return res.redirect('/?google_error=' + encodeURIComponent(error || 'sem_codigo'));
  }
  try {
    const proto = req.headers['x-forwarded-proto'] || req.protocol;
    const redirectUri = `${proto}://${req.get('host')}/api/agent/google-callback`;
    const body = new URLSearchParams({
      client_id: agentConfig.googleClientId,
      client_secret: agentConfig.googleClientSecret,
      code, redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }).toString();
    const r = await proxyFetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    const data = await r.json();
    if (!r.ok || !data.refresh_token) {
      return res.redirect('/?google_error=' + encodeURIComponent(data.error_description || 'token_invalido'));
    }
    // Busca email da conta conectada
    let email = '';
    try {
      const ur = await proxyFetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${data.access_token}`, 'Content-Type': 'application/json' },
      });
      const ud = await ur.json();
      email = ud.email || '';
    } catch (_) {}
    agentConfig.googleRefreshToken = data.refresh_token;
    agentConfig.googleEmail = email;
    saveAgentConfig(agentConfig);
    logReq('GET', '/api/agent/google-callback', `email=${email}`);
    res.redirect('/?google_ok=' + encodeURIComponent(email));
  } catch (err) {
    res.redirect('/?google_error=' + encodeURIComponent(err.message));
  }
});

app.get('/api/agent/google-status', requireAuth, (req, res) => {
  res.json({
    ok: true,
    connected: !!(agentConfig.googleRefreshToken && agentConfig.googleEmail),
    email: agentConfig.googleEmail || '',
  });
});

app.post('/api/agent/google-disconnect', requireAuth, (req, res) => {
  agentConfig.googleRefreshToken = '';
  agentConfig.googleEmail = '';
  saveAgentConfig(agentConfig);
  res.json({ ok: true });
});

app.post('/api/agent/test-calendar', requireAuth, async (req, res) => {
  try {
    const token = await getGoogleAccessToken();
    if (!token) return res.status(400).json({ error: 'Credenciais Google não configuradas.' });
    const busy = await getCalendarBusySlots(token, agentConfig.calendarId);
    const slots = findAvailableSlots(busy, 3);
    res.json({ ok: true, slots: slots.map(s => ({ utc: s.toISOString(), brt: formatSlotBRT(s) })) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/agent/toggle', requireAuth, (req, res) => {
  agentConfig.active = !agentConfig.active;
  // Persiste intenção do usuário — só respeita desativação manual
  agentConfig.manuallyDeactivated = !agentConfig.active;
  saveAgentConfig(agentConfig);
  logReq('POST', '/api/agent/toggle', `active=${agentConfig.active}`);
  res.json({ ok: true, active: agentConfig.active });
});

// Webhook público — Evolution Go posta aqui sem autenticação
app.post('/api/agent/webhook', async (req, res) => {
  res.status(200).json({ ok: true }); // responde imediatamente
  try {
    // Salva payload bruto para debug
    const rawEvent = req.body?.event || req.body?.type || '';
    webhookLog.push({ ts: new Date().toISOString(), event: rawEvent, body: JSON.stringify(req.body).slice(0, 500) });
    if (webhookLog.length > 30) webhookLog.shift();
    console.log(`[WEBHOOK] event="${rawEvent}" keys=${Object.keys(req.body || {}).join(',')}`);

    // Token: usa o da config, ou o que a própria Evolution Go manda no webhook
    const sendToken = agentConfig.instanceToken || req.body?.instanceToken || '';
    if (!agentConfig.active || !sendToken) {
      console.log(`[WEBHOOK] ignorado — active=${agentConfig.active} token=${!!sendToken}`);
      return;
    }

    // Evolution Go usa "Message"; Evolution JS usa "messages.upsert" — aceita ambos
    const ev = rawEvent.toUpperCase().replace(/[.\-_]/g, '');
    const isMessageEvent = ev === 'MESSAGE' || ev === 'MESSAGESUPSERT' || ev === 'MESSAGES';
    if (!isMessageEvent) {
      console.log(`[WEBHOOK] evento ignorado: ${rawEvent}`);
      return;
    }

    // Normaliza data — pode ser objeto, array, formato Baileys ou whatsmeow (Evolution Go)
    const rawData = req.body?.data;
    const picked = Array.isArray(rawData) ? rawData[0] : (rawData || req.body?.messages?.[0] || req.body);
    const msgData = normalizeMsgData(picked);
    if (!msgData || typeof msgData !== 'object' || !msgData.key) {
      console.log(`[WEBHOOK] payload não reconhecido: ${JSON.stringify(picked).slice(0, 400)}`);
      return;
    }

    console.log(`[WEBHOOK] fromMe=${msgData.key.fromMe} jid=${msgData.key.remoteJid} type=${msgData.messageType}`);

    // Skip mensagens enviadas por nós
    if (msgData.key.fromMe) return;

    // Skip tipos de mensagem que não são texto/áudio real
    const msgType = msgData?.messageType || '';
    const SKIP_TYPES = ['reactionMessage', 'protocolMessage', 'senderKeyDistributionMessage', 'pollCreationMessage', 'pollUpdateMessage'];
    if (SKIP_TYPES.includes(msgType)) return;

    const remoteJid = msgData.key.remoteJid || '';
    // Skip grupos e broadcasts
    if (msgData._isGroup || !remoteJid || remoteJid.includes('@g.us') || remoteJid.includes('@broadcast') || remoteJid === 'status@broadcast') return;

    // Normaliza número — aceita @s.whatsapp.net e @lid
    const from = remoteJid.replace(/@[\w.]+$/, '');
    if (!from) return;

    // Carrega histórico persistido (Supabase) — mantém memória entre cold starts
    await loadConversation(from);

    // Verifica se IA está desativada para este número
    if (disabledNumbers.has(from)) return;

    const key = agentConfig.openrouterKey;
    if (!key) return;

    const ts = new Date().toTimeString().slice(0, 8);
    let text = extractMsgText(msgData).trim();

    // Transcreve áudio se necessário
    if (!text && isAudioMessage(msgData)) {
      console.log(`[${ts}] 🎙 Áudio recebido de ${from} — transcrevendo...`);
      const transcription = await transcribeAudio(msgData, key, sendToken, picked);
      if (transcription) {
        text = `[Áudio transcrito]: ${transcription}`;
        console.log(`[${ts}] 🎙 Transcrição: ${transcription.slice(0, 80)}`);
      } else {
        // Sem transcrição disponível — avisa o contato
        await proxyFetch(`${EVOLUTION_URL}/send/text`, {
          method: 'POST',
          headers: { apikey: sendToken },
          body: JSON.stringify({ number: from, text: 'Recebi seu áudio! Para agilizar, pode me mandar a mensagem por escrito? 😊', delay: 1500 }),
        });
        return;
      }
    }

    // Contato compartilhado (vCard) — encaminha para o responsável e avisa o modelo
    const sharedContacts = extractContacts(msgData);
    if (sharedContacts.length) {
      const senderName = msgData.pushName || from;
      for (const c of sharedContacts) {
        await forwardIndication(sendToken,
          `📇 *Indicação recebida pelo agente*\n\n👤 Nome: ${c.name}\n📱 Telefone: ${c.phone}\n\n🔁 Indicado por: ${senderName} (${from})`);
      }
      const desc = sharedContacts.map(c => `${c.name} (${c.phone})`).join(', ');
      text = text ? `${text}\n[Enviei o contato de: ${desc}]` : `[Enviei o contato de: ${desc}]`;
    }

    if (!text) {
      console.log(`[WEBHOOK] sem texto extraível — message=${JSON.stringify(msgData.message || {}).slice(0, 300)}`);
      return;
    }

    console.log(`[${ts}] 🤖 Agente recebeu de ${from}: ${text.slice(0, 80)}`);

    // ── Buffer de mensagens: espera 15–30s para juntar mensagens seguidas
    // do mesmo contato e responder tudo de uma vez ──
    let buf = msgBuffer.get(from);
    if (!buf) { buf = { texts: [], seq: 0 }; msgBuffer.set(from, buf); }
    buf.texts.push(text);
    buf.seq++;
    const mySeq = buf.seq;
    const waitMs = 15000 + Math.floor(Math.random() * 15000); // 15–30s
    await new Promise(r => setTimeout(r, waitMs));
    // Se chegou mensagem mais nova durante a espera, essa invocação desiste —
    // a invocação da última mensagem responde tudo junto
    if (buf.seq !== mySeq) {
      console.log(`[WEBHOOK] ${from}: mensagem agregada ao buffer, aguardando a última`);
      return;
    }
    let combined = buf.texts.join('\n');
    buf.texts = [];

    // Telefone digitado no texto (indicação de dono/responsável) — encaminha na hora
    const typedPhones = extractPhonesFromText(combined);
    if (typedPhones.length) {
      const senderName2 = msgData.pushName || from;
      const forwarded = await forwardIndication(sendToken,
        `📇 *Indicação recebida pelo agente*\n\n📱 Telefone(s): ${typedPhones.join(', ')}\n💬 Mensagem original:\n"${combined.slice(0, 400)}"\n\n🔁 Indicado por: ${senderName2} (${from})`);
      if (forwarded) {
        combined += `\n[Enviei o contato de: ${typedPhones.join(', ')}]`;
      }
    }

    // Mantém histórico de conversa por contato
    if (!conversationHistory.has(from)) conversationHistory.set(from, []);
    const history = conversationHistory.get(from);
    history.push({ role: 'user', content: combined });
    if (history.length > MAX_HISTORY) history.splice(0, history.length - MAX_HISTORY);

    // Monta system prompt — injeta slots disponíveis se agendamento ativo
    let sysBase = [agentConfig.prompt || '', agentConfig.docText ? `\n\n# Documento de referência:\n${agentConfig.docText}` : ''].join('').trim();
    const leadName = (msgData.pushName || '').trim();
    sysBase += '\n\nIMPORTANTE:\n'
      + (leadName ? `- O nome do contato no WhatsApp é "${leadName}". Chame-o pelo primeiro nome de forma natural. Se ele se apresentar com outro nome durante a conversa, passe a usar o nome que ele informou.\n` : '- Se o contato informar o nome dele, use-o nas respostas seguintes.\n')
      + '- A mensagem do usuário pode conter várias mensagens juntas (separadas por quebra de linha). Responda tudo em UMA única resposta curta e objetiva — máximo 3 frases.\n'
      + '- NUNCA repita uma saudação ou mensagem que você já enviou nesta conversa. Leia o histórico e continue de onde parou.\n'
      + '- Você é um SDR humano profissional, não uma IA. O material do playbook é APENAS apoio e referência de argumentos — nunca copie frases prontas dele. Reformule tudo com suas palavras, adaptando ao contexto do que a pessoa disse.\n'
      + '- Responda diretamente ao que a pessoa disse, em tom natural de WhatsApp: frases curtas, linguagem do dia a dia, sem formalidade excessiva, sem listas, sem emojis em excesso (no máximo 1 por mensagem, e nem sempre).\n'
      + '- Varie a forma de escrever. Nunca dê duas respostas com a mesma estrutura ou abertura.\n'
      + '- Se a pessoa já se apresentou ou já respondeu algo, não pergunte de novo.\n'
      + '- Se a pessoa não for a decisora, peça com naturalidade o contato (nome e telefone) do dono ou responsável — diga que pode chamar a pessoa diretamente.\n'
      + '- Se receber uma mensagem tipo "[Enviei o contato de: ...]", significa que a pessoa compartilhou um contato e ele JÁ FOI encaminhado ao nosso time. Agradeça de forma natural e diga que vamos falar com a pessoa indicada.';

    if (agentConfig.schedulingEnabled) {
      let slotsText = '';
      try {
        const gToken = await getGoogleAccessToken();
        if (gToken) {
          const busy  = await getCalendarBusySlots(gToken, agentConfig.calendarId);
          const slots = findAvailableSlots(busy, 2);
          if (slots.length > 0) {
            slotsText = '\n\n# Horários disponíveis para reunião (horário de Brasília):\n'
              + slots.map((s, i) => `- Opção ${i + 1}: ${formatSlotBRT(s)}`).join('\n');
            slotsText += '\n\nRegras de agendamento:\n'
              + '- Ofereça no máximo 2 opções ao cliente quando ele demonstrar interesse em reunião.\n'
              + '- Quando o cliente CONFIRMAR um horário específico, inclua na sua resposta o marcador: [AGENDAR:' + slots[0].toISOString().slice(0,16).replace('T', 'T') + '] (substituindo pelo ISO do horário confirmado, sempre em UTC+0).\n'
              + '- Não tente vender ou convencer — apenas facilite o agendamento.\n'
              + '- Nunca invente horários fora dessa lista.';
            // Reformula com ISOstring correto por slot
            const slotMarkers = slots.map(s => s.toISOString().slice(0,16));
            slotsText = '\n\n# Horários disponíveis para reunião (horário de Brasília):\n'
              + slots.map((s, i) => `- Opção ${i + 1}: ${formatSlotBRT(s)} [ISO:${slotMarkers[i]}]`).join('\n');
            slotsText += '\n\nRegras de agendamento:\n'
              + '- Ofereça no máximo 2 opções quando o cliente demonstrar interesse.\n'
              + '- Quando o cliente CONFIRMAR um horário, inclua na sua resposta EXATAMENTE: [AGENDAR:ISO_DO_HORARIO] usando o ISO da opção confirmada.\n'
              + '- Exemplo: [AGENDAR:' + slotMarkers[0] + ']\n'
              + '- Não invente horários além dessa lista. Não tente vender fora da reunião.';
          } else {
            slotsText = '\n\n# Agendamento: Não há horários disponíveis nos próximos dias. Informe ao cliente e peça que tente novamente mais tarde.';
          }
        }
      } catch (calErr) {
        console.error('Calendar slot error:', calErr.message);
      }
      sysBase += slotsText;
    }

    const reply = await callOpenRouter(key, agentConfig.model, sysBase, history);
    if (!reply) return;

    // Adiciona resposta ao histórico e persiste no Supabase
    history.push({ role: 'assistant', content: reply });
    if (history.length > MAX_HISTORY) history.splice(0, history.length - MAX_HISTORY);
    saveConversation(from);

    // Detecta marcador de agendamento
    const scheduleTag = parseScheduleTag(reply);
    let cleanReply = reply.replace(/\[AGENDAR:[^\]]+\]/g, '').trim();
    let meetLink = null;

    if (scheduleTag && agentConfig.schedulingEnabled) {
      try {
        const gToken = await getGoogleAccessToken();
        if (gToken) {
          meetLink = await createCalendarEvent(gToken, agentConfig.calendarId, scheduleTag, from);
          console.log(`[${ts}] 📅 Reunião criada para ${from}: ${meetLink}`);
        }
      } catch (calErr) {
        console.error('Calendar create error:', calErr.message);
      }
    }

    // Envia resposta principal — delay de "digitando" proporcional ao tamanho (mais humano)
    const typingMs = Math.min(9000, 2500 + cleanReply.length * 35);
    const sendRes = await proxyFetch(`${EVOLUTION_URL}/send/text`, {
      method: 'POST',
      headers: { apikey: sendToken },
      body: JSON.stringify({ number: from, text: cleanReply, delay: typingMs }),
    });
    if (!sendRes.ok) {
      const errBody = await sendRes.text().catch(() => '');
      console.error(`[WEBHOOK] falha ao enviar resposta (${sendRes.status}): ${errBody.slice(0, 300)}`);
    }

    // Envia link do Meet separado
    if (meetLink) {
      const slotBRT = formatSlotBRT(scheduleTag);
      const linkMsg = `📅 *Reunião confirmada!*\n\n🗓 ${slotBRT}\n🔗 Link para entrar:\n${meetLink}\n\nEsperamos você! 🚀`;
      await proxyFetch(`${EVOLUTION_URL}/send/text`, {
        method: 'POST',
        headers: { apikey: sendToken },
        body: JSON.stringify({ number: from, text: linkMsg, delay: 3000 }),
      });
    }

    console.log(`[${ts}] 🤖 Agente respondeu para ${from}: ${cleanReply.slice(0, 60)}`);
  } catch (err) {
    console.error('Agente IA erro:', err.message);
  }
});

// Lista conversas ativas — lê do Supabase para sobreviver a cold starts
app.get('/api/agent/conversations', requireAuth, async (req, res) => {
  try {
    if (SUPABASE_URL && SUPABASE_KEY) {
      const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_conversations?select=phone,messages,disabled&order=updated_at.desc&limit=50`, { method: 'GET', headers: SB_HEADERS });
      const rows = await r.json();
      if (r.ok && Array.isArray(rows)) {
        const list = rows.map(row => {
          const msgs = Array.isArray(row.messages) ? row.messages : [];
          return {
            phone: row.phone,
            msgCount: msgs.length,
            lastMsg: msgs.filter(m => m.role === 'user').slice(-1)[0]?.content?.slice(0, 60) || '',
            disabled: !!row.disabled,
          };
        });
        return res.json({ ok: true, conversations: list });
      }
    }
  } catch (err) { console.warn('conversations list error:', err.message); }
  // Fallback: memória local
  const list = [];
  conversationHistory.forEach((msgs, phone) => {
    list.push({
      phone,
      msgCount: msgs.length,
      lastMsg: msgs.filter(m => m.role === 'user').slice(-1)[0]?.content?.slice(0, 60) || '',
      disabled: disabledNumbers.has(phone),
    });
  });
  list.sort((a, b) => b.msgCount - a.msgCount);
  res.json({ ok: true, conversations: list });
});

// Ativa/desativa IA para um número específico — persiste no Supabase
app.post('/api/agent/conversation-toggle', requireAuth, async (req, res) => {
  const { phone, disabled } = req.body;
  if (!phone) return res.status(400).json({ error: 'phone obrigatório' });
  if (disabled) disabledNumbers.add(phone); else disabledNumbers.delete(phone);
  if (SUPABASE_URL && SUPABASE_KEY) {
    try {
      await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_conversations`, {
        method: 'POST',
        headers: { ...SB_HEADERS, 'Prefer': 'resolution=merge-duplicates,return=minimal' },
        body: JSON.stringify({ phone, disabled: !!disabled, updated_at: new Date().toISOString() }),
      });
    } catch (err) { console.warn('toggle persist error:', err.message); }
  }
  res.json({ ok: true, phone, disabled: disabledNumbers.has(phone) });
});

// Apaga histórico de conversa de um número — também no Supabase
app.delete('/api/agent/conversation/:phone', requireAuth, async (req, res) => {
  const phone = req.params.phone;
  conversationHistory.delete(phone);
  disabledNumbers.delete(phone);
  if (SUPABASE_URL && SUPABASE_KEY) {
    try {
      await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_conversations?phone=eq.${phone}`, { method: 'DELETE', headers: SB_HEADERS });
    } catch (err) { console.warn('conversation delete error:', err.message); }
  }
  res.json({ ok: true });
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
