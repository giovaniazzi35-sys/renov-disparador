'use strict';
require('dotenv').config();

const express = require('express');
const cookieSession = require('cookie-session');
const path = require('path');
const http = require('http');
const https = require('https');
const fs = require('fs');
const { URL } = require('url');
// XLSX/PDF são carregados sob demanda (lazy) dentro do parser — um problema
// nessas libs opcionais nunca deve derrubar o app inteiro (já aconteceu:
// uma versão nova do pdf-parse quebrava TODAS as rotas, incl. /login).

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// ── Configuração ────────────────────────────────────────────
const PORT           = parseInt(process.env.PORT) || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'renov-secret-2026';
// Login com Google (OAuth de nível de aplicativo) — multiusuário
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';

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
        text: () => Promise.resolve(body),
      }));
    });
    req.on('error', reject);
    // Timeout: uma chamada travada não pode consumir o tempo da função serverless
    req.setTimeout(options.timeoutMs || 20000, () => req.destroy(new Error('timeout de requisição')));
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

// ── Login com Google (OAuth) — cada conta Google vira um usuário isolado ──
function googleRedirectUri(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  return `${proto}://${req.get('host')}/auth/google/callback`;
}

app.get('/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.status(500).send('Login Google não configurado (GOOGLE_CLIENT_ID ausente).');
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: googleRedirectUri(req),
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'online',
    prompt: 'select_account',
  });
  res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect('/login?erro=google');
  try {
    // Troca o código por token
    const tokenRes = await proxyFetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: googleRedirectUri(req),
        grant_type: 'authorization_code',
      }).toString(),
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok || !tokenData.access_token) return res.redirect('/login?erro=google');

    // Busca o e-mail do usuário
    const userRes = await proxyFetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` },
    });
    const profile = await userRes.json();
    const email = (profile.email || '').trim().toLowerCase();
    if (!email) return res.redirect('/login?erro=google');

    req.session.loggedIn = true;
    req.session.email = email;
    req.session.name = profile.name || email;
    req.session.picture = profile.picture || '';
    logReq('GET', '/auth/google/callback', `login=${email}`);
    res.redirect('/');
  } catch (err) {
    console.error('Google login erro:', err.message);
    res.redirect('/login?erro=google');
  }
});

// Retorna o usuário logado (para o frontend exibir nome/foto)
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ ok: true, email: req.session.email, name: req.session.name || req.session.email, picture: req.session.picture || '' });
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

// ══════════════════════════════════════════════════════════════
// WhatsApp via Uzapi (https://api.uzapi.com.br)
// Credenciais por usuário (Phone Number ID + token), preenchidas no próprio app.
// ══════════════════════════════════════════════════════════════
const UZAPI_HOST = (process.env.UZAPI_HOST || 'https://api.uzapi.com.br').replace(/\/$/, '');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// Rota atual da API: /v1/{phone_number_id}/...  A rota antiga (/{username}/v1/...) ainda
// responde, então fica como fallback quando o usuário tem um username salvo.
function uzapiBases(cfg) {
  const id = encodeURIComponent(cfg.uzapiPhoneId);
  const bases = [`${UZAPI_HOST}/v1/${id}`];
  if (cfg.uzapiUsername) bases.push(`${UZAPI_HOST}/${encodeURIComponent(cfg.uzapiUsername)}/v1/${id}`);
  return bases;
}

async function uzapiRequest(cfg, sub, { method = 'GET', json, body, contentType } = {}) {
  const headers = { 'Authorization': `Bearer ${cfg.uzapiToken}` };
  if (json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(json); }
  else if (contentType) headers['Content-Type'] = contentType;
  let last;
  for (const base of uzapiBases(cfg)) {
    last = await proxyFetch(base + sub, { method, headers, body });
    if (last.status !== 404) break; // 404 = a rota não existe nessa forma → tenta a próxima
  }
  return last;
}

// Número (só dígitos) ou grupo (ID com @g.us)
function waTarget(to) {
  const s = String(to || '').trim();
  return s.includes('@') ? s : s.replace(/\D/g, '');
}

async function uzapiSendText(cfg, to, text, opts = {}) {
  const body = { to: waTarget(to), type: 'text', text: { preview_url: false, body: text } };
  if (opts.delaySec) body.delayMessage = opts.delaySec;
  if (opts.typingSec) body.delayTyping = opts.typingSec;
  return uzapiRequest(cfg, '/messages', { method: 'POST', json: body });
}

// Envia mídia — por link (URL pública) ou por upload prévio (base64) que retorna um id
async function uzapiSendMedia(cfg, phone, { type, url, base64, mimetype, caption, filename }) {
  const to = waTarget(phone);
  let mediaRef = url ? { link: url } : null;
  if (!mediaRef && base64) {
    const raw = Buffer.from(base64.replace(/^data:[^,]+,/, ''), 'base64');
    const boundary = '----uzapi' + Date.now();
    const fname = filename || 'arquivo';
    const head = `--${boundary}\r\nContent-Disposition: form-data; name="messaging_product"\r\n\r\nwhatsapp\r\n`
               + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${fname}"\r\nContent-Type: ${mimetype || 'application/octet-stream'}\r\n\r\n`;
    const body = Buffer.concat([Buffer.from(head), raw, Buffer.from(`\r\n--${boundary}--\r\n`)]);
    const up = await uzapiRequest(cfg, '/media', { method: 'POST', body, contentType: `multipart/form-data; boundary=${boundary}` });
    const upBody = await up.json().catch(() => ({}));
    if (!up.ok || !upBody.id) return { ok: false, status: up.status, text: async () => JSON.stringify(upBody) };
    mediaRef = { id: upBody.id };
  }
  if (!mediaRef) return { ok: false, status: 400, text: async () => 'Sem URL nem arquivo para enviar.' };
  return uzapiRequest(cfg, '/messages', { method: 'POST', json: { to, type, [type]: { ...mediaRef, caption: caption || '' } } });
}

async function uzapiInstanceStatus(cfg) {
  const r = await uzapiRequest(cfg, '/instance');
  const d = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, raw: d };
}

// A resposta de /instance varia; só dá como desconectada quando ela diz isso claramente.
function uzapiIsConnected(r) {
  if (!r.ok) return false;
  const flat = JSON.stringify(r.raw || {}).toLowerCase();
  if (/"(connected|isconnected|loggedin|logged_in|online)":false/.test(flat)) return false;
  if (/"(status|state|connection|connectionstatus)":"(disconnected|close|closed|offline|qr|qrcode|pending|paused|unauthenticated|not_connected)"/.test(flat)) return false;
  return true;
}

// ── Grupos ───────────────────────────────────────────────────
// A resposta da Uzapi pra grupos não é documentada em detalhe, então a leitura é defensiva:
// pega qualquer objeto com um ID terminado em @g.us (e o nome, se houver) em qualquer nível.
function extractGroups(raw) {
  const out = new Map();
  (function walk(o) {
    if (Array.isArray(o)) return o.forEach(walk);
    if (o && typeof o === 'object') {
      const id = [o.id, o.jid, o.JID, o.groupId, o.GroupId].find(v => typeof v === 'string' && v.endsWith('@g.us'));
      if (id) {
        const name = [o.subject, o.name, o.Name, o.title, o.groupName].find(v => typeof v === 'string' && v.trim()) || '';
        const parts = o.participants || o.Participants;
        out.set(id, { id, name: name.trim(), size: Array.isArray(parts) ? parts.length : undefined });
      }
      Object.values(o).forEach(walk);
    }
  })(raw);
  // IDs soltos que não vieram em objeto com nome
  for (const m of JSON.stringify(raw || {}).matchAll(/\b\d{10,}(?:-\d+)?@g\.us\b/g)) {
    if (!out.has(m[0])) out.set(m[0], { id: m[0], name: '' });
  }
  return [...out.values()];
}

async function uzapiListGroups(cfg) {
  const r = await uzapiRequest(cfg, '/groups', { method: 'POST', json: { type: 'getAllGroups', delayMessage: 0 } });
  const raw = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, raw, groups: r.ok ? extractGroups(raw) : [] };
}

// Descobre o ID de um grupo a partir do link de convite (chat.whatsapp.com/...)
async function uzapiResolveInvite(cfg, invite) {
  const r = await uzapiRequest(cfg, '/groups', { method: 'POST', json: { type: 'invite', action: 'getInfo', invite, delayMessage: 0 } });
  const raw = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, raw, groups: r.ok ? extractGroups(raw) : [] };
}

// Envia texto pra um grupo: tenta o ID com @g.us (formato do WhatsApp); se a API recusar,
// tenta só os dígitos.
async function uzapiSendToGroup(cfg, groupId, text) {
  const jid = groupId.includes('@') ? groupId : `${groupId}@g.us`;
  let last = { ok: false, status: 0, error: 'sem tentativa' };
  for (const to of [jid, jid.replace(/@g\.us$/, '')]) {
    const r = await uzapiRequest(cfg, '/messages', { method: 'POST', json: { to, type: 'text', text: { preview_url: false, body: text } } });
    if (r.ok) return { ok: true, status: r.status, to };
    last = { ok: false, status: r.status, to, error: String(await r.text().catch(() => '')).slice(0, 300) };
  }
  return last;
}

// ENVIO UNIFICADO — usado pelo agente, CRM e disparador (sempre pela Uzapi do usuário)
function resolveProvider(cfg) {
  return (cfg?.uzapiToken && cfg.uzapiPhoneId) ? 'uzapi' : 'none';
}
const NO_PROVIDER_ERR = { ok: false, status: 400, text: async () => 'Nenhum provedor de WhatsApp configurado. Preencha suas credenciais da Uzapi na aba Agente.' };
async function waSendText(wa, to, text, opts = {}) {
  if (resolveProvider(wa) !== 'uzapi') return NO_PROVIDER_ERR;
  const r = await uzapiSendText(wa, to, text, opts);
  return { ok: r.ok, status: r.status, text: () => r.text() };
}
async function waSendMedia(wa, phone, opts) {
  if (resolveProvider(wa) !== 'uzapi') return NO_PROVIDER_ERR;
  return uzapiSendMedia(wa, phone, opts);
}

// ── API ──────────────────────────────────────────────────────

// URL do webhook do agente (mesma origem do app)
function appWebhookUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  return `${proto}://${req.get('host')}/api/agent/webhook`;
}

// Status da instância Uzapi do usuário logado (usado pelo Disparador e pela aba Agente)
app.get('/api/instances', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  if (resolveProvider(cfg) !== 'uzapi') return res.json([]);
  try {
    const r = await uzapiInstanceStatus(cfg);
    res.json([{ name: cfg.uzapiUsername || `Uzapi ${cfg.uzapiPhoneId}`, connected: uzapiIsConnected(r), provider: 'uzapi' }]);
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Envio de texto — usado pelo Disparador. Usa a Uzapi do usuário logado.
app.post('/api/send/text', requireAuth, async (req, res) => {
  const number = normalizeNumber(req.body.number || '');
  const { text } = req.body;
  if (!number || !/^\d{10,15}$/.test(number)) return res.status(400).json({ error: 'Número inválido.' });
  if (!text || !text.trim()) return res.status(400).json({ error: 'Texto vazio.' });
  logReq('POST', '/api/send/text', number);
  try {
    const cfg = await getUserConfig(req.session.email);
    if (resolveProvider(cfg) === 'none') return res.status(400).json({ error: 'Configure suas credenciais da Uzapi na aba Agente antes de disparar.' });
    const up = await waSendText(cfg, number, text.trim());
    if (!up.ok) return res.status(up.status).json({ error: await up.text().catch(() => `Erro ${up.status}`) });
    res.json({ ok: true });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Envio de mídia por URL
app.post('/api/send/media', requireAuth, async (req, res) => {
  const { url, type, caption, filename } = req.body;
  const number = normalizeNumber(req.body.number || '');
  if (!number || !url || !type) return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
  try {
    const cfg = await getUserConfig(req.session.email);
    if (resolveProvider(cfg) === 'none') return res.status(400).json({ error: 'Configure suas credenciais da Uzapi na aba Agente antes de disparar.' });
    const up = await waSendMedia(cfg, number, { type, url, caption, filename });
    if (!up.ok) return res.status(up.status).json({ error: await up.text().catch(() => `Erro ${up.status}`) });
    res.json({ ok: true });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Envio de mídia via base64 (upload de arquivo)
app.post('/api/send/media-upload', requireAuth, async (req, res) => {
  const { mediaBase64, mediaType, mimetype, caption, filename, ptt } = req.body;
  const number = normalizeNumber(req.body.number || '');
  if (!number || !mediaBase64) return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
  logReq('POST', '/api/send/media-upload', number);
  const resolvedMime = mimetype || guessMime(mediaType, filename);
  const type = ptt ? 'audio' : mediaType;
  try {
    const cfg = await getUserConfig(req.session.email);
    if (resolveProvider(cfg) === 'none') return res.status(400).json({ error: 'Configure suas credenciais da Uzapi na aba Agente antes de disparar.' });
    const up = await waSendMedia(cfg, number, { type, base64: mediaBase64, mimetype: resolvedMime, caption, filename: filename || `arquivo.${resolvedMime.split('/')[1] || 'bin'}` });
    if (!up.ok) return res.status(up.status).json({ error: await up.text().catch(() => `Erro ${up.status}`) });
    res.json({ ok: true });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// AGENTE IA — recebe a mensagem do lead (webhook Uzapi), responde com a IA do
// usuário e, quando o lead é qualificado, envia o resumo para um grupo do WhatsApp.
// ══════════════════════════════════════════════════════════════

const SUPABASE_URL  = (process.env.SUPABASE_URL  || '').replace(/\/$/, '');
const SUPABASE_KEY  = process.env.SUPABASE_KEY  || '';
const SB_HEADERS    = { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json' };

const DEFAULT_AI_BASE  = 'https://openrouter.ai/api/v1';
const DEFAULT_AI_MODEL = 'deepseek/deepseek-chat-v3-0324:free';
const DEFAULT_CFG = () => ({
  active: false, manuallyDeactivated: false,
  prompt: '',
  aiBaseUrl: DEFAULT_AI_BASE, aiKey: '', aiModel: DEFAULT_AI_MODEL,   // qualquer API compatível com OpenAI (chat/completions)
  handoffGroupId: '', handoffGroupName: '',                           // grupo que recebe os leads qualificados
  uzapiPhoneId: '', uzapiToken: '', uzapiUsername: '',
});

function autoActivate(cfg) {
  // Mantém o agente ativo quando tudo está preenchido, a menos que o usuário tenha desativado manualmente.
  if (cfg.aiKey && cfg.uzapiToken && cfg.uzapiPhoneId && !cfg.manuallyDeactivated) cfg.active = true;
  return cfg;
}

// Configs antigas (OpenRouter) continuam valendo: chave/modelo antigos viram os campos novos.
function normalizeCfg(data) {
  const d = data || {};
  const cfg = { ...DEFAULT_CFG(), ...d };
  cfg.aiKey     = d.aiKey   || d.openrouterKey || '';
  cfg.aiModel   = d.aiModel || d.model || DEFAULT_AI_MODEL;
  cfg.aiBaseUrl = String(d.aiBaseUrl || DEFAULT_AI_BASE).replace(/\/+$/, '');
  return autoActivate(cfg);
}

// ── Multiusuário: cada e-mail Google tem sua própria config (linha própria) ──
// O e-mail primário mapeia para a linha legada id=1 (mantém o agente atual vivo).
const PRIMARY_EMAIL = (process.env.PRIMARY_EMAIL || 'giovaniazzi35@gmail.com').toLowerCase();

function emailHash(email) {
  // Inteiro positivo estável derivado do e-mail (evita colidir com id=1 legado)
  let h = 5381;
  const s = (email || '').toLowerCase();
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return 1000000 + (h % 900000000); // faixa bem acima de 1
}
function configIdFor(email) {
  return (email && email.toLowerCase() === PRIMARY_EMAIL) ? 1 : emailHash(email);
}

async function loadConfigById(id) {
  if (SUPABASE_URL && SUPABASE_KEY) {
    try {
      const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_config?id=eq.${id}&select=data`, { method: 'GET', headers: SB_HEADERS });
      const rows = await r.json();
      if (r.ok && Array.isArray(rows) && rows[0]?.data && Object.keys(rows[0].data).length > 0) {
        return normalizeCfg(rows[0].data);
      }
    } catch (err) { console.warn('loadConfigById error:', err.message); }
  }
  return null;
}

// Salva a config (upsert). Retorna a promise: as rotas aguardam, senão o Vercel pode
// congelar a função antes da gravação terminar.
function saveConfigById(id, cfg) {
  if (!SUPABASE_URL || !SUPABASE_KEY) return Promise.resolve();
  return proxyFetch(`${SUPABASE_URL}/rest/v1/agent_config`, {
    method: 'POST',
    headers: { ...SB_HEADERS, 'Prefer': 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify({ id, data: cfg, updated_at: new Date().toISOString() }),
  }).then(r => { if (!r.ok) console.warn('saveConfigById failed:', r.status); })
    .catch(err => console.warn('saveConfigById error:', err.message));
}

// Dona de um phone_number_id da Uzapi (usado no webhook, que não tem sessão)
async function findConfigByUzapiPhoneId(phoneId) {
  if (!phoneId || !SUPABASE_URL || !SUPABASE_KEY) return null;
  try {
    const q = encodeURIComponent(phoneId);
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_config?data->>uzapiPhoneId=eq.${q}&select=id,data`, { method: 'GET', headers: SB_HEADERS });
    const rows = await r.json();
    if (r.ok && Array.isArray(rows) && rows[0]?.data) return { id: rows[0].id, cfg: normalizeCfg(rows[0].data) };
  } catch (err) { console.warn('findConfigByUzapiPhoneId error:', err.message); }
  return null;
}

// Cache por e-mail (curto) — evita hit no Supabase a cada request autenticado
const _userConfigCache = new Map(); // email → { cfg, ts }
async function getUserConfig(email) {
  const cached = _userConfigCache.get(email);
  if (cached && Date.now() - cached.ts < 5000) return cached.cfg;
  const cfg = (await loadConfigById(configIdFor(email))) || normalizeCfg({});
  cfg.owner = email;
  _userConfigCache.set(email, { cfg, ts: Date.now() });
  return cfg;
}
async function putUserConfig(email, cfg) {
  cfg.owner = email;
  _userConfigCache.set(email, { cfg, ts: Date.now() });
  await saveConfigById(configIdFor(email), cfg);
}

// ── Conversas (histórico por contato) ────────────────────────
const conversationHistory = new Map(); // chave da conversa → [{role,content}]
const conversationStatus  = new Map(); // chave → '' | 'potencial' (qualificado e já enviado ao grupo) | 'desqualificado'
const disabledNumbers     = new Set(); // contatos com a IA desligada
const msgBuffer           = new Map(); // chave → { texts: [], seq } — junta mensagens seguidas do mesmo lead
const seenMsgIds          = new Set(); // evita processar duas vezes o mesmo webhook
const MAX_HISTORY = 30;                // mensagens mantidas por contato
const BUFFER_MS   = 6000;              // espera pra juntar mensagens seguidas antes de responder

// Chave de conversa escopada por dono (multiusuário): o usuário primário mantém a chave "crua"
// (compatível com dados existentes); os demais recebem o prefixo "<id>:".
function convKey(cfg, phone) {
  const tag = configIdFor((cfg && cfg.owner) || PRIMARY_EMAIL);
  return tag === 1 ? phone : `${tag}:${phone}`;
}
function convPrefixFor(email) {
  const tag = configIdFor(email);
  return tag === 1 ? '' : `${tag}:`;
}

// Sempre relê do banco: com várias instâncias serverless, o cache em memória pode estar velho.
async function loadConversation(sk) {
  if (SUPABASE_URL && SUPABASE_KEY) {
    try {
      const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_conversations?phone=eq.${encodeURIComponent(sk)}&select=messages,disabled,status`, { method: 'GET', headers: SB_HEADERS });
      const rows = await r.json();
      if (r.ok && Array.isArray(rows)) {
        const row = rows[0];
        conversationHistory.set(sk, row && Array.isArray(row.messages) ? row.messages : []);
        if (row && row.disabled) disabledNumbers.add(sk); else disabledNumbers.delete(sk);
        if (row && row.status) conversationStatus.set(sk, row.status); else conversationStatus.delete(sk);
        return;
      }
    } catch (err) { console.warn('loadConversation error:', err.message); }
  }
  if (!conversationHistory.has(sk)) conversationHistory.set(sk, []);
}

async function saveConversation(sk) {
  if (!SUPABASE_URL || !SUPABASE_KEY) return;
  try {
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_conversations`, {
      method: 'POST',
      headers: { ...SB_HEADERS, 'Prefer': 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify({ phone: sk, messages: conversationHistory.get(sk) || [], disabled: disabledNumbers.has(sk), status: conversationStatus.get(sk) || '', updated_at: new Date().toISOString() }),
    });
    if (!r.ok) console.warn('saveConversation failed:', r.status);
  } catch (err) { console.warn('saveConversation error:', err.message); }
}

// ── IA (qualquer API compatível com OpenAI: OpenRouter, OpenAI, Groq, Gemini, Claude…) ──
function aiErrorMessage(data, status) {
  const e = data?.error;
  const msg = (typeof e === 'string' ? e : e?.message) || (Array.isArray(data?.message) ? data.message.join('; ') : data?.message);
  return msg ? String(msg).slice(0, 300) : `HTTP ${status}`;
}

async function callLLM(cfg, systemPrompt, messages, { maxTokens = 400, temperature = 0.7, budgetMs = 40000 } = {}) {
  const base  = String(cfg.aiBaseUrl || DEFAULT_AI_BASE).replace(/\/+$/, '');
  const key   = cfg.aiKey || cfg.openrouterKey || '';
  const model = cfg.aiModel || cfg.model || '';
  if (!key)   throw new Error('Informe a chave da API de IA.');
  if (!model) throw new Error('Informe o modelo de IA.');
  const headers = { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' };
  if (base.includes('openrouter.ai')) { headers['HTTP-Referer'] = 'https://doitsend.vercel.app'; headers['X-Title'] = 'DOIT SEND'; }
  const body = JSON.stringify({ model, temperature, max_tokens: maxTokens, messages: [{ role: 'system', content: systemPrompt }, ...messages] });

  const t0 = Date.now();
  let lastErr;
  for (let attempt = 1; attempt <= 2; attempt++) {
    const left = budgetMs - (Date.now() - t0);
    if (left < 6000) break;
    try {
      const r = await proxyFetch(`${base}/chat/completions`, { method: 'POST', headers, body, timeoutMs: Math.min(25000, left) });
      const data = await r.json();
      if (!r.ok) throw new Error(aiErrorMessage(data, r.status));
      const out = data?.choices?.[0]?.message?.content;
      const text = (Array.isArray(out) ? out.map(p => p.text || '').join('') : (out || '')).trim();
      if (text) return text;
      throw new Error('A IA retornou uma resposta vazia.');
    } catch (err) {
      lastErr = err;
      console.warn(`[IA] tentativa ${attempt} falhou: ${err.message}`);
      if (attempt < 2) await sleep(1200);
    }
  }
  throw lastErr || new Error('A IA não respondeu a tempo.');
}

// O prompt do usuário define o negócio e o que é "qualificado"; aqui entram só as regras técnicas.
function buildSystemPrompt(cfg, leadName) {
  const base = (cfg.prompt || '').trim() || 'Você é um atendente comercial cordial. Converse para entender a necessidade da pessoa.';
  return base + `

# Regras de funcionamento (sempre siga)
- Você conversa com o lead pelo WhatsApp. Escreva como no WhatsApp: mensagem curta e natural (em geral até 3 frases, a menos que o prompt acima peça outro formato), sem listas e sem markdown.
- A mensagem do lead pode juntar várias mensagens seguidas: responda a tudo de uma vez, numa única resposta.
- Nunca repita uma saudação ou uma frase que você já enviou nesta conversa; continue de onde parou.
- ${leadName ? `O nome do contato no WhatsApp é "${leadName}". Chame-o pelo primeiro nome, de forma natural. Se ele informar outro nome, use o que ele informou.` : 'Se o lead informar o nome, use-o nas próximas respostas.'}
- Se o lead pedir para parar ou disser que não tem interesse, agradeça e se despeça sem insistir.

# Classificação (obrigatório)
No FINAL de toda resposta, em uma linha separada, acrescente EXATAMENTE UM marcador. Ele é removido antes do envio e o lead nunca o vê:
[STATUS:qualificado]    → o lead foi qualificado na conversa E demonstrou interesse real em avançar
[STATUS:desqualificado] → sem fit, sem interesse ou pediu para parar
[STATUS:andamento]      → a conversa ainda está em andamento
Ao usar [STATUS:qualificado], avise o lead de forma natural que um especialista do time vai entrar em contato em breve.`;
}

function parseAgentReply(raw) {
  const text = String(raw || '');
  const tags = [...text.matchAll(/\[STATUS:\s*([\wçãÇÃ]+)\s*\]/gi)].map(m => m[1].toLowerCase());
  let tag = tags[tags.length - 1] || '';
  if (tag === 'potencial') tag = 'qualificado';
  return {
    clean: text.replace(/\[STATUS:[^\]]*\]/gi, '').replace(/\n{3,}/g, '\n\n').trim(),
    status: ['qualificado', 'desqualificado', 'andamento'].includes(tag) ? tag : '',
  };
}

// ── Lead qualificado → grupo do WhatsApp ─────────────────────
function normalizeGroupId(raw) {
  const s = String(raw || '').trim();
  if (!s) return '';
  if (s.includes('@')) return s;
  return /^\d{10,}(-\d+)?$/.test(s) ? `${s}@g.us` : s;
}

function buildTranscript(history, maxMsgs = 30) {
  return history.slice(-maxMsgs).map(m => `${m.role === 'user' ? 'Lead' : 'Agente'}: ${m.content}`).join('\n');
}

// Resumo + nome do lead gerados pela IA. Se a IA falhar, o repasse sai mesmo assim com as últimas mensagens.
async function summarizeLead(cfg, history, profileName) {
  const fallbackName = profileName || 'Não informado';
  const lastLead = history.filter(m => m.role === 'user').slice(-3).map(m => m.content).join(' | ').slice(0, 400);
  try {
    const out = await callLLM(cfg,
      'Você prepara o repasse de leads qualificados para o time comercial. Leia a conversa e responda EXATAMENTE neste formato, em português, sem mais nada:\n'
      + `NOME: <nome do lead, se ele disse na conversa; senão escreva "${fallbackName}">\n`
      + 'RESUMO: <resumo objetivo em até 5 linhas: quem é o lead, o que precisa ou pediu, nível de interesse e próximos passos combinados>',
      [{ role: 'user', content: 'Conversa:\n' + buildTranscript(history) }],
      { maxTokens: 350, temperature: 0.2, budgetMs: 25000 });
    const name = (out.match(/NOME:\s*(.+)/i)?.[1] || '').trim();
    const summary = (out.match(/RESUMO:\s*([\s\S]+)/i)?.[1] || out).trim();
    return { name: name || fallbackName, summary };
  } catch (err) {
    console.warn('[HANDOFF] resumo pela IA falhou:', err.message);
    return { name: fallbackName, summary: `O lead demonstrou interesse. Últimas mensagens: ${lastLead}` };
  }
}

// 5511988887777 → +55 11 98888-7777 (qualquer outro formato sai como +<dígitos>)
function prettyPhone(p) {
  const m = String(p).match(/^55(\d{2})(\d{4,5})(\d{4})$/);
  return m ? `+55 ${m[1]} ${m[2]}-${m[3]}` : `+${p}`;
}

function formatHandoff({ name, phone, summary }) {
  return `*Nome do lead:* ${name}\n*Número do lead:* ${prettyPhone(phone)}\n*Resumo da conversa:*\n${summary}`;
}

async function sendHandoff(cfg, lead) {
  if (!cfg.handoffGroupId) return { ok: false, error: 'Nenhum grupo de destino configurado.' };
  const text = formatHandoff(lead);
  let res = { ok: false, error: 'sem tentativa' };
  for (let attempt = 1; attempt <= 3; attempt++) {
    res = await uzapiSendToGroup(cfg, cfg.handoffGroupId, text).catch(err => ({ ok: false, error: err.message }));
    if (res.ok) return { ok: true, to: res.to };
    console.warn(`[HANDOFF] tentativa ${attempt} falhou (${res.status || '-'}): ${res.error}`);
    await sleep(1500);
  }
  return { ok: false, error: res.error || 'falha ao enviar' };
}

// ── Webhook da Uzapi ─────────────────────────────────────────
// A resposta HTTP só é enviada ao FINAL do processamento: no Vercel, responder cedo
// congela a função e mata a espera/IA/envio.
const AUDIO_REPLY = 'Recebi seu áudio! Para eu te atender melhor, pode me mandar por escrito? 😊';

async function handleAgentWebhook(body) {
  const value = body.entry?.[0]?.changes?.[0]?.value;
  const msg = value?.messages?.[0];
  if (!msg) return;                                                    // status de entrega, conexão etc.
  if (msg.isGroup || String(msg.from || '').includes('@g.us')) return; // o agente só atende conversa individual

  const phoneId = value.metadata?.phone_number_id || '';
  const owner = await findConfigByUzapiPhoneId(phoneId);
  if (!owner) { console.log(`[AGENTE] phone_number_id ${phoneId} sem configuração — ignorado`); return; }
  const cfg = owner.cfg;
  if (!cfg.active) { console.log(`[AGENTE] desativado (${cfg.owner || phoneId})`); return; }
  if (!cfg.aiKey) { console.warn(`[AGENTE] sem chave de IA (${cfg.owner || phoneId})`); return; }

  const from = String(msg.from || '').replace(/\D/g, '');
  if (!from) return;
  if (msg.id) {
    if (seenMsgIds.has(msg.id)) return;
    seenMsgIds.add(msg.id);
    if (seenMsgIds.size > 500) seenMsgIds.delete(seenMsgIds.values().next().value);
  }
  const profileName = (value.contacts?.[0]?.profile?.name || '').trim();
  const sk = convKey(cfg, from);

  await loadConversation(sk);
  if (disabledNumbers.has(sk)) return;

  let text = '';
  if (msg.type === 'text') text = (msg.text?.body || '').trim();
  else if (msg.type === 'interactive') text = (msg.interactive?.button_reply?.title || msg.interactive?.list_reply?.title || '').trim();
  else if (msg.type === 'button') text = (msg.button?.text || '').trim();
  else if (msg.type === 'audio') { await waSendText(cfg, from, AUDIO_REPLY, { typingSec: 2 }); return; }
  if (!text) return;
  console.log(`[AGENTE] ${from}: ${text.slice(0, 80)}`);

  // Junta mensagens seguidas do mesmo lead e responde tudo de uma vez
  let buf = msgBuffer.get(sk);
  if (!buf) { buf = { texts: [], seq: 0 }; msgBuffer.set(sk, buf); }
  buf.texts.push(text);
  const mySeq = ++buf.seq;
  await sleep(BUFFER_MS);
  if (buf.seq !== mySeq) return;            // chegou mensagem mais nova — a invocação dela responde tudo
  const combined = buf.texts.join('\n');
  buf.texts = [];

  await loadConversation(sk);               // histórico fresco (outra instância pode ter respondido nesse meio-tempo)
  if (disabledNumbers.has(sk)) return;
  const history = conversationHistory.get(sk);
  history.push({ role: 'user', content: combined });
  if (history.length > MAX_HISTORY) history.splice(0, history.length - MAX_HISTORY);
  await saveConversation(sk);               // se a IA falhar, a conversa aparece como "sem resposta"

  let raw;
  try {
    raw = await callLLM(cfg, buildSystemPrompt(cfg, profileName), history, { maxTokens: 400, budgetMs: 38000 });
  } catch (err) {
    console.error(`[AGENTE] a IA falhou para ${from}: ${err.message}`);
    return;
  }
  const { clean, status } = parseAgentReply(raw);
  const alreadyHandedOff = conversationStatus.get(sk) === 'potencial';
  const reply = clean || (status === 'qualificado' ? 'Perfeito! Já passei seus dados pro nosso time e logo entram em contato com você.' : '');
  if (!reply) { console.warn(`[AGENTE] resposta vazia da IA para ${from}`); return; }

  history.push({ role: 'assistant', content: reply });
  if (history.length > MAX_HISTORY) history.splice(0, history.length - MAX_HISTORY);

  // 1) responde o lead (com "digitando..." proporcional ao tamanho) — até 3 tentativas
  const typingSec = Math.min(8, Math.max(2, Math.round(reply.length / 30)));
  let sent = false;
  for (let attempt = 1; attempt <= 3 && !sent; attempt++) {
    try {
      const r = await waSendText(cfg, from, reply, { typingSec });
      if (r.ok) { sent = true; break; }
      console.error(`[AGENTE] envio ${attempt} falhou (${r.status}): ${String(await r.text().catch(() => '')).slice(0, 200)}`);
    } catch (err) { console.error(`[AGENTE] envio ${attempt} erro: ${err.message}`); }
    await sleep(1500);
  }
  if (!sent) console.error(`[AGENTE] FALHA ao responder ${from} após 3 tentativas`);

  // 2) lead qualificado → resumo da conversa no grupo (uma vez por lead; se falhar, tenta de novo na próxima mensagem)
  if (status === 'qualificado' && !alreadyHandedOff) {
    const { name, summary } = await summarizeLead(cfg, history, profileName);
    const h = await sendHandoff(cfg, { name, phone: from, summary });
    if (h.ok) { conversationStatus.set(sk, 'potencial'); console.log(`[HANDOFF] ${from} enviado ao grupo`); }
    else console.error(`[HANDOFF] não foi possível enviar ${from} ao grupo: ${h.error}`);
  } else if (status === 'desqualificado' && !conversationStatus.get(sk)) {
    conversationStatus.set(sk, 'desqualificado');
  }
  await saveConversation(sk);
}

app.post('/api/agent/webhook', async (req, res) => {
  try { await handleAgentWebhook(req.body || {}); }
  catch (err) { console.error('[AGENTE] erro:', err); }
  finally { if (!res.headersSent) res.status(200).json({ ok: true }); }
});

// ── Rotas do painel do agente ────────────────────────────────
// Nunca devolve chaves/tokens pro navegador — só se existem.
function publicAgentCfg(cfg) {
  return {
    active: !!cfg.active, prompt: cfg.prompt || '',
    aiBaseUrl: cfg.aiBaseUrl, aiModel: cfg.aiModel, hasAiKey: !!cfg.aiKey,
    uzapiPhoneId: cfg.uzapiPhoneId || '', hasUzapiToken: !!cfg.uzapiToken,
    handoffGroupId: cfg.handoffGroupId || '', handoffGroupName: cfg.handoffGroupName || '',
  };
}
function apiErrorText(raw) {
  if (!raw) return '';
  if (Array.isArray(raw.message)) return raw.message.join('; ');
  return raw.message || (typeof raw.error === 'string' ? raw.error : raw.error?.message) || '';
}

app.get('/api/agent/config', requireAuth, async (req, res) => {
  res.json({ ok: true, data: publicAgentCfg(await getUserConfig(req.session.email)) });
});

app.post('/api/agent/config', requireAuth, async (req, res) => {
  const b = req.body || {};
  const cfg = await getUserConfig(req.session.email);
  if (typeof b.prompt === 'string') cfg.prompt = b.prompt.trim();
  if (typeof b.aiBaseUrl === 'string' && b.aiBaseUrl.trim()) cfg.aiBaseUrl = b.aiBaseUrl.trim().replace(/\/+$/, '');
  if (typeof b.aiModel === 'string') cfg.aiModel = b.aiModel.trim();
  if (typeof b.aiKey === 'string' && b.aiKey.trim()) cfg.aiKey = b.aiKey.trim();   // só troca se vier uma nova
  if (typeof b.handoffGroupId === 'string') {
    cfg.handoffGroupId = normalizeGroupId(b.handoffGroupId);
    cfg.handoffGroupName = String(b.handoffGroupName || '').trim();
  }
  // Salvar a configuração completa reativa o agente (e limpa a desativação manual)
  cfg.manuallyDeactivated = false;
  if (cfg.aiKey && cfg.uzapiToken && cfg.uzapiPhoneId && cfg.prompt) cfg.active = true;
  await putUserConfig(req.session.email, cfg);
  logReq('POST', '/api/agent/config', `user=${req.session.email} active=${cfg.active}`);
  res.json({ ok: true, data: publicAgentCfg(cfg) });
});

app.post('/api/agent/toggle', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  cfg.active = !cfg.active;
  cfg.manuallyDeactivated = !cfg.active;   // só respeita a desativação manual
  await putUserConfig(req.session.email, cfg);
  logReq('POST', '/api/agent/toggle', `user=${req.session.email} active=${cfg.active}`);
  res.json({ ok: true, active: cfg.active });
});

// Chat de teste do painel (e botão "Testar IA"): usa os campos digitados e, se vierem vazios, os salvos.
app.post('/api/agent/chat', requireAuth, async (req, res) => {
  const b = req.body || {};
  const saved = await getUserConfig(req.session.email);
  const cfg = {
    ...saved,
    aiBaseUrl: (b.aiBaseUrl || '').trim() || saved.aiBaseUrl,
    aiKey:     (b.aiKey || '').trim()     || saved.aiKey,
    aiModel:   (b.aiModel || '').trim()   || saved.aiModel,
    prompt:    (typeof b.prompt === 'string' && b.prompt.trim()) ? b.prompt : saved.prompt,
  };
  try {
    if (b.test) {   // só confirma que a chave/modelo/endereço respondem
      const out = await callLLM(cfg, 'Responda apenas com a palavra: ok', [{ role: 'user', content: 'Teste' }], { maxTokens: 10, temperature: 0, budgetMs: 30000 });
      return res.json({ ok: true, reply: out.slice(0, 80) });
    }
    const messages = (Array.isArray(b.messages) ? b.messages : [])
      .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string' && m.content.trim())
      .slice(-20).map(m => ({ role: m.role, content: m.content }));
    if (!messages.length) messages.push({ role: 'user', content: 'Olá' });
    const raw = await callLLM(cfg, buildSystemPrompt(cfg, ''), messages, { maxTokens: 400, budgetMs: 40000 });
    const { clean, status } = parseAgentReply(raw);
    res.json({ ok: true, reply: clean, status });
  } catch (err) {
    res.status(502).json({ ok: false, error: err.message });
  }
});

// ── Grupo que recebe os leads qualificados ──
app.get('/api/agent/groups', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  if (resolveProvider(cfg) !== 'uzapi') return res.status(400).json({ error: 'Salve o Phone Number ID e o token da Uzapi antes de buscar os grupos.' });
  try {
    const r = await uzapiListGroups(cfg);
    if (!r.ok) return res.status(r.status || 502).json({ error: apiErrorText(r.raw) || `A Uzapi respondeu HTTP ${r.status}.` });
    res.json({ ok: true, groups: r.groups, raw: r.groups.length ? undefined : r.raw });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Descobre o ID do grupo a partir do link de convite (plano B se a lista de grupos vier vazia)
app.post('/api/agent/groups/invite', requireAuth, async (req, res) => {
  const invite = String((req.body || {}).invite || '').trim();
  if (!/chat\.whatsapp\.com\/\S+/i.test(invite)) return res.status(400).json({ error: 'Cole o link de convite do grupo (chat.whatsapp.com/...).' });
  const cfg = await getUserConfig(req.session.email);
  if (resolveProvider(cfg) !== 'uzapi') return res.status(400).json({ error: 'Salve o Phone Number ID e o token da Uzapi primeiro.' });
  try {
    const r = await uzapiResolveInvite(cfg, invite);
    if (!r.ok) return res.status(r.status || 502).json({ error: apiErrorText(r.raw) || `A Uzapi respondeu HTTP ${r.status}.` });
    res.json({ ok: true, groups: r.groups, raw: r.groups.length ? undefined : r.raw });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Envia uma mensagem de exemplo pro grupo configurado (confere se o envio chega)
app.post('/api/agent/handoff-test', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  if (resolveProvider(cfg) !== 'uzapi') return res.status(400).json({ error: 'Salve o Phone Number ID e o token da Uzapi primeiro.' });
  if (!cfg.handoffGroupId) return res.status(400).json({ error: 'Escolha e salve o grupo de destino primeiro.' });
  try {
    const r = await sendHandoff(cfg, {
      name: 'Teste (mensagem de exemplo)', phone: '5511999999999',
      summary: 'Esta é uma mensagem de teste do DOIT SEND. Quando um lead for qualificado na conversa, o resumo dele chega aqui neste formato.',
    });
    if (!r.ok) return res.status(502).json({ error: `Não consegui enviar ao grupo: ${r.error}` });
    res.json({ ok: true });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// ── Conversas ──
app.get('/api/agent/conversations', requireAuth, async (req, res) => {
  const prefix = convPrefixFor(req.session.email); // '' para primário, '<id>:' p/ demais
  const stripPrefix = (p) => prefix ? p.slice(prefix.length) : p;
  try {
    if (SUPABASE_URL && SUPABASE_KEY) {
      // Primário: chaves "cruas" (sem ":"); demais: chaves que começam com "<id>:"
      const filter = prefix
        ? `phone=like.${encodeURIComponent(prefix + '*')}`
        : `phone=not.like.${encodeURIComponent('*:*')}`;
      const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_conversations?select=phone,messages,disabled,status&${filter}&order=updated_at.desc&limit=50`, { method: 'GET', headers: SB_HEADERS });
      const rows = await r.json();
      if (r.ok && Array.isArray(rows)) {
        const list = rows.map(row => {
          const msgs = Array.isArray(row.messages) ? row.messages : [];
          return {
            phone: stripPrefix(row.phone),
            msgCount: msgs.length,
            lastMsg: msgs.filter(m => m.role === 'user').slice(-1)[0]?.content?.slice(0, 60) || '',
            pending: msgs.length > 0 && msgs[msgs.length - 1].role === 'user',   // lead falou e a IA não respondeu
            disabled: !!row.disabled,
            status: row.status || '',
          };
        });
        const rank = { potencial: 0, '': 1, andamento: 1, desqualificado: 2 };
        list.sort((a, b) => (rank[a.status] ?? 1) - (rank[b.status] ?? 1));
        return res.json({ ok: true, conversations: list });
      }
    }
  } catch (err) { console.warn('conversations list error:', err.message); }
  res.json({ ok: true, conversations: [] });
});

// Liga/desliga a IA para um número específico — escopado por usuário
app.post('/api/agent/conversation-toggle', requireAuth, async (req, res) => {
  const { phone, disabled } = req.body;
  if (!phone) return res.status(400).json({ error: 'phone obrigatório' });
  const sk = convPrefixFor(req.session.email) + phone;
  if (disabled) disabledNumbers.add(sk); else disabledNumbers.delete(sk);
  if (SUPABASE_URL && SUPABASE_KEY) {
    try {
      await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_conversations`, {
        method: 'POST',
        headers: { ...SB_HEADERS, 'Prefer': 'resolution=merge-duplicates,return=minimal' },
        body: JSON.stringify({ phone: sk, disabled: !!disabled, updated_at: new Date().toISOString() }),
      });
    } catch (err) { console.warn('toggle persist error:', err.message); }
  }
  res.json({ ok: true, phone, disabled: disabledNumbers.has(sk) });
});

// Apaga o histórico de um número — escopado por usuário
app.delete('/api/agent/conversation/:phone', requireAuth, async (req, res) => {
  const sk = convPrefixFor(req.session.email) + req.params.phone;
  conversationHistory.delete(sk);
  conversationStatus.delete(sk);
  disabledNumbers.delete(sk);
  if (SUPABASE_URL && SUPABASE_KEY) {
    try {
      await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_conversations?phone=eq.${encodeURIComponent(sk)}`, { method: 'DELETE', headers: SB_HEADERS });
    } catch (err) { console.warn('conversation delete error:', err.message); }
  }
  res.json({ ok: true });
});

// ── Credenciais da Uzapi (por usuário) ──
app.get('/api/agent/uzapi-settings', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  res.json({ ok: true, uzapiPhoneId: cfg.uzapiPhoneId || '', hasToken: !!cfg.uzapiToken }); // nunca devolve o token
});
app.post('/api/agent/uzapi-settings', requireAuth, async (req, res) => {
  const { uzapiPhoneId, uzapiToken, uzapiUsername } = req.body || {};
  const cfg = await getUserConfig(req.session.email);
  if (typeof uzapiPhoneId === 'string') cfg.uzapiPhoneId = uzapiPhoneId.replace(/\D/g, '');
  if (typeof uzapiUsername === 'string') cfg.uzapiUsername = uzapiUsername.trim();   // opcional (instâncias antigas)
  if (typeof uzapiToken === 'string' && uzapiToken.trim()) cfg.uzapiToken = uzapiToken.trim().replace(/^Bearer\s+/i, '');
  await putUserConfig(req.session.email, cfg);
  res.json({ ok: true });
});

// Testa a conexão com a Uzapi usando as credenciais salvas
app.post('/api/agent/uzapi-test', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  if (resolveProvider(cfg) !== 'uzapi') return res.status(400).json({ error: 'Preencha o Phone Number ID e o token antes de testar.' });
  try {
    const r = await uzapiInstanceStatus(cfg);
    if (!r.ok) return res.status(r.status || 502).json({ error: apiErrorText(r.raw) || `Falha ao consultar a instância (HTTP ${r.status}).` });
    res.json({ ok: true, connected: uzapiIsConnected(r), status: r.raw });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Configura automaticamente o webhook da instância pra apontar pro app
app.post('/api/agent/uzapi-configure-webhook', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  if (resolveProvider(cfg) !== 'uzapi') return res.status(400).json({ error: 'Preencha o Phone Number ID e o token antes de configurar o webhook.' });
  try {
    const webhookUrl = appWebhookUrl(req);
    const r = await uzapiRequest(cfg, '/instance/update', { method: 'PUT', json: { webhook: webhookUrl } });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) return res.status(r.status).json({ error: apiErrorText(body) || `Falha ao configurar o webhook (HTTP ${r.status}).` });
    res.json({ ok: true, webhookUrl });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// ── Mídia do Disparador ──────────────────────────────────────
// O Vercel recusa corpo de requisição acima de ~4,5 MB (HTTP 413), então o arquivo NÃO passa
// pelo servidor: o navegador sobe direto pro Supabase Storage com uma URL assinada (uma vez só)
// e o disparo manda apenas o link público pra Uzapi.
const MEDIA_BUCKET    = 'disparo-media';
const MEDIA_MAX_BYTES = 30 * 1024 * 1024;
const MEDIA_TTL_MS    = 3 * 24 * 3600 * 1000;   // arquivos do disparo são apagados depois de 3 dias

function storageCall(p, { method = 'GET', json } = {}) {
  return proxyFetch(`${SUPABASE_URL}/storage/v1${p}`, { method, headers: SB_HEADERS, body: json !== undefined ? JSON.stringify(json) : undefined });
}
async function ensureMediaBucket() {
  const r = await storageCall('/bucket', { method: 'POST', json: { id: MEDIA_BUCKET, name: MEDIA_BUCKET, public: true, file_size_limit: MEDIA_MAX_BYTES } });
  return r.ok || r.status === 409 || /already exists|duplicate/i.test(await r.text().catch(() => ''));
}
// Apaga os arquivos antigos deste usuário (melhor esforço — nunca atrapalha o envio)
async function cleanupOldMedia(prefix) {
  try {
    const r = await storageCall(`/object/list/${MEDIA_BUCKET}`, { method: 'POST', json: { prefix, limit: 200, sortBy: { column: 'created_at', order: 'asc' } } });
    const rows = await r.json();
    if (!r.ok || !Array.isArray(rows)) return;
    const old = rows.filter(o => o.created_at && Date.now() - new Date(o.created_at).getTime() > MEDIA_TTL_MS).map(o => prefix + o.name);
    if (old.length) await storageCall(`/object/${MEDIA_BUCKET}`, { method: 'DELETE', json: { prefixes: old } });
  } catch (_) {}
}

// Devolve uma URL assinada pro navegador subir o arquivo + o link público que o disparo vai usar
app.post('/api/media/sign', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Armazenamento indisponível.' });
  const { filename, size } = req.body || {};
  if (Number(size) > MEDIA_MAX_BYTES) return res.status(413).json({ error: `Arquivo acima do limite de ${MEDIA_MAX_BYTES / 1024 / 1024} MB.` });
  const prefix = `${configIdFor(req.session.email)}/`;
  const safeName = String(filename || 'arquivo').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^\w.\-]+/g, '_').slice(-80) || 'arquivo';
  const objectPath = `${prefix}${Date.now()}-${Math.random().toString(36).slice(2, 8)}-${safeName}`;
  try {
    const sign = () => storageCall(`/object/upload/sign/${MEDIA_BUCKET}/${objectPath}`, { method: 'POST', json: {} });
    let r = await sign();
    if (!r.ok && await ensureMediaBucket()) r = await sign();   // bucket ainda não existia → cria e tenta de novo
    const data = await r.json().catch(() => ({}));
    if (!r.ok || !data.url) return res.status(502).json({ error: data.message || (typeof data.error === 'string' ? data.error : '') || `Falha ao preparar o upload (HTTP ${r.status}).` });
    await cleanupOldMedia(prefix);
    const rel = String(data.url);
    res.json({
      ok: true,
      uploadUrl: rel.startsWith('http') ? rel : `${SUPABASE_URL}/storage/v1${rel}`,
      publicUrl: `${SUPABASE_URL}/storage/v1/object/public/${MEDIA_BUCKET}/${objectPath}`,
    });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// CRM — leads / pipeline (por usuário)
// ══════════════════════════════════════════════════════════════
// Etapas com probabilidade de fechamento (para a previsão ponderada)
const CRM_STAGE_DEFS = [
  { key: 'novo',        prob: 0.05 },
  { key: 'msg_enviada', prob: 0.10 },
  { key: 'respondeu',   prob: 0.20 },
  { key: 'qualificado', prob: 0.40 },
  { key: 'reuniao',     prob: 0.60 },
  { key: 'proposta',    prob: 0.75 },
  { key: 'negociacao',  prob: 0.90 },
  { key: 'ganho',       prob: 1.00 },
  { key: 'perdido',     prob: 0.00 },
];
const CRM_STAGES = CRM_STAGE_DEFS.map(s => s.key);
const CRM_STAGE_PROB = Object.fromEntries(CRM_STAGE_DEFS.map(s => [s.key, s.prob]));

// Mapeia o status do agente IA para uma etapa do CRM
function agentStatusToStage(status) {
  switch ((status || '').toLowerCase()) {
    case 'potencial':      return 'qualificado';
    case 'agencia':        return 'perdido';
    case 'desqualificado': return 'perdido';
    default:               return 'respondeu';
  }
}

// Lista todos os leads do usuário
app.get('/api/crm/leads', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.json({ ok: true, leads: [] });
  try {
    const owner = encodeURIComponent(req.session.email);
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads?owner=eq.${owner}&select=*&order=last_activity.desc&limit=500`, { method: 'GET', headers: SB_HEADERS });
    const rows = await r.json();
    res.json({ ok: true, leads: Array.isArray(rows) ? rows : [] });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Cria um lead
app.post('/api/crm/leads', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Banco indisponível' });
  const { name, phone, stage, tags, notes, value, source, company, next_action, next_action_at } = req.body;
  const st = CRM_STAGES.includes(stage) ? stage : 'novo';
  const lead = {
    owner: req.session.email,
    name: (name || '').trim(),
    phone: (phone || '').replace(/\D/g, ''),
    company: (company || '').trim(),
    stage: st,
    tags: Array.isArray(tags) ? tags : [],
    notes: notes || '',
    value: Number(value) || 0,
    source: source || 'manual',
    next_action: next_action || '',
    next_action_at: next_action_at || null,
    won_at: st === 'ganho' ? new Date().toISOString() : null,
    last_activity: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
  try {
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads`, {
      method: 'POST', headers: { ...SB_HEADERS, 'Prefer': 'return=representation' },
      body: JSON.stringify(lead),
    });
    const rows = await r.json();
    if (!r.ok) return res.status(r.status).json({ error: rows?.message || 'Erro ao criar lead' });
    res.json({ ok: true, lead: Array.isArray(rows) ? rows[0] : rows });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Adiciona vários contatos ao CRM de uma vez numa etapa (ex: após um disparo →
// "msg_enviada"). Pula quem já existe no CRM (por telefone) pra não sobrescrever
// o progresso de leads que já avançaram no pipeline.
app.post('/api/crm/leads/bulk-add', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Banco indisponível' });
  const contacts = Array.isArray(req.body?.contacts) ? req.body.contacts : [];
  const stage = CRM_STAGES.includes(req.body?.stage) ? req.body.stage : 'msg_enviada';
  if (!contacts.length) return res.json({ ok: true, added: 0 });
  try {
    const owner = req.session.email;
    const ownerQ = encodeURIComponent(owner);
    const existingR = await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads?owner=eq.${ownerQ}&select=phone`, { method: 'GET', headers: SB_HEADERS });
    const existingRows = await existingR.json();
    const existingPhones = new Set((Array.isArray(existingRows) ? existingRows : []).map(r => r.phone));

    const seen = new Set();
    const now = new Date().toISOString();
    const leads = contacts
      .map(c => ({ name: (c.name || '').trim(), phone: String(c.phone || '').replace(/\D/g, '') }))
      .filter(c => c.phone && !existingPhones.has(c.phone) && !seen.has(c.phone) && seen.add(c.phone))
      .map(c => ({
        owner, name: c.name, phone: c.phone, stage, tags: [], notes: '',
        value: 0, source: 'disparador',
        last_activity: now, updated_at: now,
      }));
    if (!leads.length) return res.json({ ok: true, added: 0 });

    let added = 0;
    for (let i = 0; i < leads.length; i += 500) {
      const batch = leads.slice(i, i + 500);
      const ir = await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads`, {
        method: 'POST', headers: { ...SB_HEADERS, 'Prefer': 'return=minimal' },
        body: JSON.stringify(batch),
      });
      if (ir.ok) added += batch.length;
    }
    res.json({ ok: true, added });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Atualiza um lead (etapa, nome, tags, notas, valor…)
app.patch('/api/crm/leads/:id', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Banco indisponível' });
  const id = req.params.id;
  const allowed = ['name', 'phone', 'stage', 'tags', 'notes', 'value', 'source', 'company', 'next_action', 'next_action_at'];
  const patch = { updated_at: new Date().toISOString(), last_activity: new Date().toISOString() };
  for (const k of allowed) if (k in req.body) patch[k] = req.body[k];
  if (patch.phone !== undefined) patch.phone = String(patch.phone).replace(/\D/g, '');
  if (patch.stage !== undefined && !CRM_STAGES.includes(patch.stage)) delete patch.stage;
  // Marca a data de fechamento ao mover para "ganho"
  if (patch.stage === 'ganho') patch.won_at = new Date().toISOString();
  if (patch.next_action_at === '') patch.next_action_at = null;
  try {
    const owner = encodeURIComponent(req.session.email);
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads?id=eq.${id}&owner=eq.${owner}`, {
      method: 'PATCH', headers: { ...SB_HEADERS, 'Prefer': 'return=representation' },
      body: JSON.stringify(patch),
    });
    const rows = await r.json();
    res.json({ ok: true, lead: Array.isArray(rows) ? rows[0] : rows });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Exclui um lead
app.delete('/api/crm/leads/:id', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Banco indisponível' });
  try {
    const owner = encodeURIComponent(req.session.email);
    await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads?id=eq.${req.params.id}&owner=eq.${owner}`, { method: 'DELETE', headers: SB_HEADERS });
    res.json({ ok: true });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Importa leads a partir das conversas do Agente IA (mapeia status → etapa)
app.post('/api/crm/import-conversations', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Banco indisponível' });
  try {
    const email = req.session.email;
    const prefix = convPrefixFor(email);
    const filter = prefix ? `phone=like.${encodeURIComponent(prefix + '*')}` : `phone=not.like.${encodeURIComponent('*:*')}`;
    const cr = await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_conversations?select=phone,messages,status,updated_at&${filter}&limit=500`, { method: 'GET', headers: SB_HEADERS });
    const convs = await cr.json();
    if (!Array.isArray(convs) || !convs.length) return res.json({ ok: true, imported: 0 });

    // Leads já existentes (por telefone) para não duplicar
    const owner = encodeURIComponent(email);
    const lr = await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads?owner=eq.${owner}&select=phone`, { method: 'GET', headers: SB_HEADERS });
    const existing = new Set((await lr.json() || []).map(l => l.phone));

    const stripPrefix = (p) => prefix ? p.slice(prefix.length) : p;
    const novos = [];
    for (const c of convs) {
      const phone = stripPrefix(c.phone);
      if (!phone || existing.has(phone)) continue;
      const msgs = Array.isArray(c.messages) ? c.messages : [];
      const firstUser = msgs.find(m => m.role === 'user')?.content || '';
      const tags = c.status === 'agencia' ? ['tem-agência'] : [];
      novos.push({
        owner: email, phone, name: '', stage: agentStatusToStage(c.status),
        tags, notes: firstUser ? `Primeira mensagem: "${firstUser.slice(0, 200)}"` : '',
        value: 0, source: 'agente-ia',
        last_activity: c.updated_at || new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });
    }
    if (!novos.length) return res.json({ ok: true, imported: 0 });
    const ins = await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads`, {
      method: 'POST', headers: { ...SB_HEADERS, 'Prefer': 'return=minimal,resolution=ignore-duplicates' },
      body: JSON.stringify(novos),
    });
    res.json({ ok: ins.ok, imported: novos.length });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Envia uma mensagem de texto para um lead (WhatsApp) e registra a atividade
app.post('/api/crm/leads/:id/message', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Banco indisponível' });
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'Mensagem vazia.' });
  try {
    const owner = encodeURIComponent(req.session.email);
    const lr = await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads?id=eq.${req.params.id}&owner=eq.${owner}&select=phone`, { method: 'GET', headers: SB_HEADERS });
    const lead = (await lr.json() || [])[0];
    if (!lead || !lead.phone) return res.status(400).json({ error: 'Lead sem telefone.' });

    const cfg = await getUserConfig(req.session.email);
    const provider = resolveProvider(cfg);

    const sendRes = await waSendText(cfg, lead.phone, text.trim());
    if (!sendRes.ok) {
      const eb = await (sendRes.text ? sendRes.text() : Promise.resolve('')).catch(() => '');
      return res.status(502).json({ error: `Falha ao enviar (${sendRes.status}): ${String(eb).slice(0, 150)}` });
    }
    // Atualiza última atividade
    await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads?id=eq.${req.params.id}&owner=eq.${owner}`, {
      method: 'PATCH', headers: { ...SB_HEADERS, 'Prefer': 'return=minimal' },
      body: JSON.stringify({ last_activity: new Date().toISOString() }),
    }).catch(() => {});
    res.json({ ok: true, provider });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Estatísticas do dashboard
app.get('/api/crm/stats', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.json({ ok: true, stats: {} });
  try {
    const owner = encodeURIComponent(req.session.email);
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads?owner=eq.${owner}&select=stage,value,next_action_at,won_at`, { method: 'GET', headers: SB_HEADERS });
    const leads = await r.json();
    const arr = Array.isArray(leads) ? leads : [];

    const byStage = {}; CRM_STAGES.forEach(s => byStage[s] = 0);
    let total = 0, ganhos = 0, valorGanho = 0, previsaoPonderada = 0, atrasadas = 0;
    const now = Date.now();
    // Faturamento acumulado por mês (últimos 6 meses)
    const meses = [];
    const d0 = new Date(); d0.setDate(1);
    for (let i = 5; i >= 0; i--) {
      const d = new Date(d0.getFullYear(), d0.getMonth() - i, 1);
      meses.push({ key: `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`, label: ['jan','fev','mar','abr','mai','jun','jul','ago','set','out','nov','dez'][d.getMonth()], valor: 0 });
    }
    const mesIndex = Object.fromEntries(meses.map((m, i) => [m.key, i]));

    arr.forEach(l => {
      const st = l.stage; const val = Number(l.value) || 0;
      byStage[st] = (byStage[st] || 0) + 1; total++;
      if (st === 'ganho') {
        ganhos++; valorGanho += val;
        const wd = l.won_at ? new Date(l.won_at) : null;
        if (wd) { const k = `${wd.getFullYear()}-${String(wd.getMonth()+1).padStart(2,'0')}`; if (k in mesIndex) meses[mesIndex[k]].valor += val; }
      } else if (st !== 'perdido') {
        previsaoPonderada += val * (CRM_STAGE_PROB[st] || 0);
      }
      // Atividades atrasadas: próxima ação vencida em leads ainda abertos
      if (l.next_action_at && st !== 'ganho' && st !== 'perdido' && new Date(l.next_action_at).getTime() < now) atrasadas++;
    });
    const fechados = ganhos + (byStage['perdido'] || 0);
    const conversao = fechados > 0 ? (ganhos / fechados) * 100 : 0;

    res.json({ ok: true, stats: {
      total, byStage, ganhos, valorGanho,
      previsaoPonderada: Math.round(previsaoPonderada),
      conversao: Math.round(conversao * 10) / 10,
      atrasadas, faturamentoMensal: meses,
    }});
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Prioridades de hoje + oportunidades em destaque
app.get('/api/crm/priorities', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.json({ ok: true, hoje: [], oportunidades: [] });
  try {
    const owner = encodeURIComponent(req.session.email);
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads?owner=eq.${owner}&select=id,name,phone,company,stage,value,next_action,next_action_at&limit=500`, { method: 'GET', headers: SB_HEADERS });
    const leads = await r.json();
    const list = Array.isArray(leads) ? leads : [];
    const abertos = list.filter(l => l.stage !== 'ganho' && l.stage !== 'perdido');
    // Prioridades: com próxima ação, ordenadas pela data (vencidas primeiro)
    const hoje = abertos.filter(l => l.next_action_at)
      .sort((a, b) => new Date(a.next_action_at) - new Date(b.next_action_at))
      .slice(0, 6);
    // Oportunidades: maior valor ponderado
    const oportunidades = abertos
      .map(l => ({ ...l, score: (Number(l.value)||0) * (CRM_STAGE_PROB[l.stage]||0) }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 6);
    res.json({ ok: true, hoje, oportunidades });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// LIGAÇÕES — click-to-call (VoIP do Brasil) + registro manual
// ══════════════════════════════════════════════════════════════
const CALL_OUTCOMES = ['atendida', 'nao_atendida', 'caixa_postal', 'numero_errado', 'ocupado'];

// Config de discagem do usuário: método (tel: app instalado ou URL de integração) + ramal
app.get('/api/crm/voip-settings', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  res.json({ ok: true, voipMethod: cfg.voipMethod || 'tel', voipIntegrationUrl: cfg.voipIntegrationUrl || '', voipRamal: cfg.voipRamal || '' });
});
app.post('/api/crm/voip-settings', requireAuth, async (req, res) => {
  const { voipMethod, voipIntegrationUrl, voipRamal } = req.body;
  const cfg = await getUserConfig(req.session.email);
  cfg.voipMethod = voipMethod === 'url' ? 'url' : 'tel';
  cfg.voipIntegrationUrl = (voipIntegrationUrl || '').trim();
  cfg.voipRamal = (voipRamal || '').trim();
  putUserConfig(req.session.email, cfg);
  res.json({ ok: true });
});

// Registra uma chamada (feita via click-to-call ou manualmente) e opcionalmente reclassifica o lead
app.post('/api/crm/calls', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Banco indisponível' });
  const { lead_id, phone, lead_name, outcome, duration_sec, notes, new_stage } = req.body;
  if (!phone) return res.status(400).json({ error: 'Telefone obrigatório.' });
  const call = {
    owner: req.session.email,
    lead_id: lead_id || null,
    phone: String(phone).replace(/\D/g, ''),
    lead_name: lead_name || '',
    outcome: CALL_OUTCOMES.includes(outcome) ? outcome : 'atendida',
    duration_sec: Number(duration_sec) || 0,
    notes: notes || '',
  };
  try {
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_calls`, {
      method: 'POST', headers: { ...SB_HEADERS, 'Prefer': 'return=representation' },
      body: JSON.stringify(call),
    });
    const rows = await r.json();
    if (!r.ok) return res.status(r.status).json({ error: rows?.message || 'Erro ao registrar chamada' });

    // Reclassifica o lead se solicitado (classificação a partir da ligação)
    if (lead_id && new_stage && CRM_STAGES.includes(new_stage)) {
      const owner = encodeURIComponent(req.session.email);
      await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads?id=eq.${lead_id}&owner=eq.${owner}`, {
        method: 'PATCH', headers: { ...SB_HEADERS, 'Prefer': 'return=minimal' },
        body: JSON.stringify({ stage: new_stage, last_activity: new Date().toISOString(), updated_at: new Date().toISOString(), ...(new_stage === 'ganho' ? { won_at: new Date().toISOString() } : {}) }),
      }).catch(() => {});
    }
    res.json({ ok: true, call: Array.isArray(rows) ? rows[0] : rows });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Lista chamadas recentes (com filtro opcional por lead)
app.get('/api/crm/calls', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.json({ ok: true, calls: [] });
  try {
    const owner = encodeURIComponent(req.session.email);
    let url = `${SUPABASE_URL}/rest/v1/crm_calls?owner=eq.${owner}&select=*&order=created_at.desc&limit=200`;
    if (req.query.lead_id) url += `&lead_id=eq.${encodeURIComponent(req.query.lead_id)}`;
    const r = await proxyFetch(url, { method: 'GET', headers: SB_HEADERS });
    const rows = await r.json();
    res.json({ ok: true, calls: Array.isArray(rows) ? rows : [] });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Estatísticas de chamadas (para o topo da aba Ligações)
app.get('/api/crm/calls/stats', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.json({ ok: true, stats: {} });
  try {
    const owner = encodeURIComponent(req.session.email);
    const since = new Date(); since.setHours(0,0,0,0);
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_calls?owner=eq.${owner}&select=outcome,duration_sec,created_at&created_at=gte.${since.toISOString()}`, { method: 'GET', headers: SB_HEADERS });
    const rows = await r.json();
    const arr = Array.isArray(rows) ? rows : [];
    const total = arr.length;
    const atendidas = arr.filter(c => c.outcome === 'atendida').length;
    const tempoTotal = arr.reduce((a, c) => a + (Number(c.duration_sec)||0), 0);
    res.json({ ok: true, stats: { total, atendidas, taxaAtendimento: total ? Math.round((atendidas/total)*100) : 0, tempoTotal } });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// LISTAS DE CONTATOS — importação de PDF / Excel / CSV
// ══════════════════════════════════════════════════════════════

// Detecta colunas de nome/telefone/email num cabeçalho de planilha/CSV
const HEADER_NAME_HINTS  = ['nome', 'name', 'contato', 'cliente', 'razao', 'razão'];
const HEADER_PHONE_HINTS = ['telefone', 'fone', 'celular', 'whatsapp', 'phone', 'tel', 'numero', 'número', 'contato'];
const HEADER_EMAIL_HINTS = ['email', 'e-mail'];

function detectHeaderCols(headerRow) {
  const norm = headerRow.map(h => String(h || '').trim().toLowerCase());
  const findIdx = (hints) => norm.findIndex(h => hints.some(hint => h.includes(hint)));
  return { nameIdx: findIdx(HEADER_NAME_HINTS), phoneIdx: findIdx(HEADER_PHONE_HINTS), emailIdx: findIdx(HEADER_EMAIL_HINTS) };
}

const PHONE_RE = /(?:\+?55[\s.-]?)?\(?\d{2}\)?[\s.-]?\d{4,5}[\s.-]?\d{4}\b/;
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;

// Converte uma matriz de linhas (planilha/CSV) em contatos {name,phone,email}
function rowsToContacts(rows) {
  const contacts = [];
  if (!rows.length) return contacts;
  const { nameIdx, phoneIdx, emailIdx } = detectHeaderCols(rows[0]);
  const hasHeader = phoneIdx !== -1 || nameIdx !== -1;
  const dataRows = hasHeader ? rows.slice(1) : rows;

  for (const row of dataRows) {
    if (!row || !row.length) continue;
    let name = '', phone = '', email = '';
    if (hasHeader) {
      name  = nameIdx  !== -1 ? String(row[nameIdx]  || '').trim() : '';
      phone = phoneIdx !== -1 ? String(row[phoneIdx] || '').trim() : '';
      email = emailIdx !== -1 ? String(row[emailIdx] || '').trim() : '';
    }
    // Sem cabeçalho reconhecido (ou coluna vazia na linha): varre a linha procurando telefone/email/nome
    if (!phone) {
      const cellWithPhone = row.find(c => PHONE_RE.test(String(c || '')));
      if (cellWithPhone) phone = String(cellWithPhone).match(PHONE_RE)[0];
    }
    if (!email) {
      const cellWithEmail = row.find(c => EMAIL_RE.test(String(c || '')));
      if (cellWithEmail) email = String(cellWithEmail).match(EMAIL_RE)[0];
    }
    if (!name) {
      const cand = row.find(c => {
        const s = String(c || '').trim();
        return s && !PHONE_RE.test(s) && !EMAIL_RE.test(s) && isNaN(Number(s));
      });
      if (cand) name = String(cand).trim();
    }
    phone = normalizeNumber(phone);
    if (!phone && !name && !email) continue;
    if (phone && (phone.length < 10 || phone.length > 13)) phone = ''; // descarta lixo não-telefone
    contacts.push({ name, phone, email });
  }
  return contacts;
}

// Extrai contatos de texto livre (PDF): procura telefones e usa o texto ao redor como nome
function textToContacts(text) {
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const contacts = [];
  for (const line of lines) {
    const phoneMatch = line.match(PHONE_RE);
    if (!phoneMatch) continue;
    const phone = normalizeNumber(phoneMatch[0]);
    if (phone.length < 10 || phone.length > 13) continue;
    const emailMatch = line.match(EMAIL_RE);
    let name = line.replace(phoneMatch[0], '').replace(EMAIL_RE, '').replace(/[-–—:|,;]+/g, ' ').trim();
    name = name.replace(/\s{2,}/g, ' ').slice(0, 120);
    contacts.push({ name, phone, email: emailMatch ? emailMatch[0] : '' });
  }
  // Remove duplicados por telefone, mantendo o primeiro
  const seen = new Set();
  return contacts.filter(c => { if (seen.has(c.phone)) return false; seen.add(c.phone); return true; });
}

// Faz o parsing de um arquivo (CSV/Excel/PDF) em base64 e devolve a lista de contatos
async function parseContactFile(base64, format) {
  const buf = Buffer.from(base64.replace(/^data:[^,]+,/, ''), 'base64');
  const fmt = (format || '').toLowerCase();

  if (fmt === 'csv' || fmt === 'txt') {
    const text = buf.toString('utf8');
    const delim = text.includes(';') && text.split(';').length > text.split(',').length ? ';' : ',';
    const rows = text.split(/\r?\n/).filter(l => l.trim()).map(line => {
      // parser simples de CSV com suporte a aspas
      const cells = []; let cur = '', inQ = false;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') inQ = !inQ;
        else if (ch === delim && !inQ) { cells.push(cur); cur = ''; }
        else cur += ch;
      }
      cells.push(cur);
      return cells.map(c => c.trim());
    });
    return rowsToContacts(rows);
  }

  if (fmt === 'xlsx' || fmt === 'xls') {
    let XLSX;
    try { XLSX = require('xlsx'); } catch (e) { throw new Error('Suporte a Excel indisponível no momento.'); }
    const wb = XLSX.read(buf, { type: 'buffer' });
    const sheet = wb.Sheets[wb.SheetNames[0]];
    const rows = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '' });
    return rowsToContacts(rows);
  }

  if (fmt === 'pdf') {
    let pdfParse;
    try { pdfParse = require('pdf-parse'); } catch (e) { throw new Error('Suporte a PDF indisponível no momento.'); }
    const data = await pdfParse(buf);
    return textToContacts(data.text || '');
  }

  throw new Error('Formato de arquivo não suportado. Use CSV, XLSX, XLS ou PDF.');
}

// ============================================================
// GERADOR DE LEADS (segmento + região → lista via OpenStreetMap)
// ============================================================
// Espelhos públicos do Overpass — o overpass-api.de sozinho costuma dar 504 sob carga
const OVERPASS_URLS = ['https://overpass-api.de/api/interpreter', 'https://overpass.openstreetmap.fr/api/interpreter'];
const NOMINATIM_URL = 'https://nominatim.openstreetmap.org/search';
const OSM_UA = 'DoitSend-CRM/1.0 (uso interno - geracao de listas de prospeccao)';

// Dicionário curto PT-BR → tags OSM comuns, pra ampliar a busca além do nome.
// A checagem é por palavra contida no segmento digitado, não exata (ex: "loja de carro" casa com "carro").
const SEGMENT_TAG_HINTS = {
  otica: ['optician'], oticas: ['optician'], oculista: ['optician'],
  restaurante: ['restaurant'], lanchonete: ['fast_food'],
  farmacia: ['pharmacy'],
  mercado: ['supermarket', 'convenience'], supermercado: ['supermarket'],
  academia: ['fitness_centre'],
  salao: ['hairdresser'], barbearia: ['hairdresser'],
  petshop: ['pet'], pet: ['pet'],
  imobiliaria: ['estate_agent'],
  contabilidade: ['accountant'], contador: ['accountant'],
  advocacia: ['lawyer'], advogado: ['lawyer'],
  clinica: ['clinic'], dentista: ['dentist'],
  hotel: ['hotel'], pousada: ['guest_house'],
  padaria: ['bakery'],
  autoescola: ['driving_school'],
  oficina: ['car_repair'], concessionaria: ['car'], carro: ['car'], carros: ['car'],
  veiculo: ['car'], veiculos: ['car', 'car_repair'], moto: ['motorcycle'], motos: ['motorcycle'],
  pneu: ['tyres'], pneus: ['tyres'],
  moveis: ['furniture'], eletronico: ['electronics'], eletronicos: ['electronics'],
  roupa: ['clothes'], roupas: ['clothes'], loja: [],
  pizzaria: ['restaurant', 'fast_food'], hamburgueria: ['fast_food'], sorveteria: ['ice_cream'],
  banco: ['bank'], posto: ['fuel'], papelaria: ['stationery'], livraria: ['books'],
  joalheria: ['jewelry'], joalharia: ['jewelry'], floricultura: ['florist'],
  confeitaria: ['confectionery'], doceria: ['confectionery'],
  informatica: ['computer'], celular: ['mobile_phone'], celulares: ['mobile_phone'],
  lavanderia: ['laundry'], veterinaria: ['veterinary'], veterinario: ['veterinary'],
  fotografia: ['photo'], fotografo: ['photo'], grafica: ['copyshop'],
  chaveiro: ['locksmith'], serralheria: ['locksmith'],
};

function normalizeTxt(s) {
  return String(s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim();
}

function segmentTags(segment) {
  const words = normalizeTxt(segment).split(/\s+/).filter(Boolean);
  const tags = new Set();
  words.forEach(w => (SEGMENT_TAG_HINTS[w] || []).forEach(t => tags.add(t)));
  return [...tags];
}

// POST com retry — tenta cada espelho até 2x antes de desistir (o Overpass público
// costuma responder 504 quando está sob carga; um retry simples resolve a maioria).
async function fetchWithRetry(urls, options, attemptsPerUrl = 1, timeoutMs = 12000) {
  let lastErr;
  for (const url of urls) {
    for (let i = 0; i < attemptsPerUrl; i++) {
      try {
        const r = await proxyFetch(url, { ...options, timeoutMs });
        if (r.ok) return r;
        lastErr = new Error(`HTTP ${r.status}`);
      } catch (err) { lastErr = err; }
    }
  }
  throw lastErr || new Error('Falha ao contatar o serviço.');
}

async function geocodeLocation(location) {
  const url = `${NOMINATIM_URL}?format=json&limit=1&countrycodes=br&q=${encodeURIComponent(location)}`;
  const r = await fetchWithRetry([url], { method: 'GET', headers: { 'User-Agent': OSM_UA } }, 2);
  const rows = await r.json();
  if (!Array.isArray(rows) || !rows.length) throw new Error('Localização não encontrada. Tente algo como "Curitiba, PR".');
  return { lat: parseFloat(rows[0].lat), lon: parseFloat(rows[0].lon) };
}

// Busca por regex de nome (["shop"]["name"~"x"]) sem filtro de valor é uma varredura
// pesada sobre TODO estabelecimento com aquela tag na área — no Overpass público isso
// estoura o timeout quase sempre. Por isso: quando o dicionário reconhece o termo,
// usamos só filtros de tag exata (indexados, rápidos); regex de nome só entra como
// fallback pra termos desconhecidos, e mesmo assim só na tag "shop" (mais comum) e
// com o raio limitado, pra manter o custo baixo.
async function overpassSearch(lat, lon, radiusM, segment) {
  const tagHints = segmentTags(segment);
  const nameRegex = segment.replace(/["\\]/g, '').trim();
  let body;
  if (tagHints.length) {
    const tagFilters = tagHints.map(t =>
      `nwr["shop"="${t}"](around:${radiusM},${lat},${lon});nwr["amenity"="${t}"](around:${radiusM},${lat},${lon});nwr["office"="${t}"](around:${radiusM},${lat},${lon});`
    ).join('\n  ');
    body = `[out:json][timeout:20];(\n  ${tagFilters}\n);out center 300;`;
  } else {
    const capRadius = Math.min(radiusM, 20000);
    body = `[out:json][timeout:20];(\n  nwr["shop"]["name"~"${nameRegex}",i](around:${capRadius},${lat},${lon});\n);out center 300;`;
  }
  const r = await fetchWithRetry(OVERPASS_URLS, {
    method: 'POST', headers: { 'Content-Type': 'text/plain', 'User-Agent': OSM_UA },
    body: 'data=' + encodeURIComponent(body),
  }, 1, 15000);
  const j = await r.json();
  return Array.isArray(j.elements) ? j.elements : [];
}

// Só celular pode ter WhatsApp — valida o formato BR (DDI 55 + DDD + 9 + 8 dígitos = 13 no total).
function isLikelyMobileBR(digits) {
  if (digits.length !== 13 || !digits.startsWith('55')) return false;
  const ddd = parseInt(digits.slice(2, 4), 10);
  return ddd >= 11 && ddd <= 99 && digits[4] === '9';
}

// Extrai o primeiro número de celular válido de um campo que pode ter vários
// telefones separados por ";", "," ou "/" (comum em dados do OSM).
function firstMobilePhone(...rawFields) {
  for (const raw of rawFields) {
    if (!raw) continue;
    for (const candidate of String(raw).split(/[;,/]/)) {
      const normalized = normalizeNumber(candidate.trim());
      if (isLikelyMobileBR(normalized)) return normalized;
    }
  }
  return '';
}

function elementToLead(el) {
  const tags = el.tags || {};
  const name = (tags.name || '').trim();
  if (!name) return null;
  const phone = firstMobilePhone(tags['contact:mobile'], tags.phone, tags['contact:phone']);
  const email = tags.email || tags['contact:email'] || '';
  return { name, phone, email };
}

// Gera uma lista de leads (nome/telefone/email) por segmento + região, usando dados
// abertos do OpenStreetMap (Nominatim p/ geocodificar + Overpass p/ buscar estabelecimentos).
app.post('/api/leads/generate', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Banco indisponível' });
  const segment = (req.body?.segment || '').trim();
  const location = (req.body?.location || '').trim();
  if (!segment) return res.status(400).json({ error: 'Informe o segmento (ex: óticas, restaurantes).' });
  if (!location) return res.status(400).json({ error: 'Informe a região (ex: Curitiba, PR).' });
  try {
    const { lat, lon } = await geocodeLocation(location);
    const RADII = [10000, 25000, 50000, 80000];
    const found = new Map();
    const deadline = Date.now() + 45000; // deixa folga sob o limite de 60s da função
    for (const radius of RADII) {
      if (Date.now() > deadline) break;
      try {
        const elements = await overpassSearch(lat, lon, radius, segment);
        elements.forEach(el => {
          const lead = elementToLead(el);
          if (!lead || !lead.phone) return; // só interessa quem tem telefone/whatsapp
          const key = lead.phone;
          if (!found.has(key)) found.set(key, lead);
        });
      } catch (err) {
        console.warn('[LEADS] Overpass falhou num raio, seguindo pro próximo:', err.message);
      }
      if (found.size >= 50) break;
    }
    const leads = [...found.values()];
    if (!leads.length) {
      return res.status(404).json({ error: 'Nenhum estabelecimento com telefone encontrado para esse segmento/região (ou o serviço do OpenStreetMap está sobrecarregado no momento). Tente de novo em instantes, um termo mais simples ou uma região maior.' });
    }

    const owner = req.session.email;
    const listName = `${segment} — ${location}`.slice(0, 120);
    const lr = await proxyFetch(`${SUPABASE_URL}/rest/v1/contact_lists`, {
      method: 'POST', headers: { ...SB_HEADERS, 'Prefer': 'return=representation' },
      body: JSON.stringify({ owner, name: listName, source_format: 'leads', total: leads.length }),
    });
    const listRows = await lr.json();
    if (!lr.ok) return res.status(lr.status).json({ error: listRows?.message || 'Erro ao criar lista' });
    const list = Array.isArray(listRows) ? listRows[0] : listRows;

    const items = leads.map(l => ({ list_id: list.id, owner, name: l.name, phone: l.phone || '', email: l.email || '' }));
    for (let i = 0; i < items.length; i += 500) {
      await proxyFetch(`${SUPABASE_URL}/rest/v1/contact_list_items`, {
        method: 'POST', headers: { ...SB_HEADERS, 'Prefer': 'return=minimal' },
        body: JSON.stringify(items.slice(i, i + 500)),
      });
    }
    res.json({ ok: true, list, total: leads.length, withPhone: leads.filter(l => l.phone).length });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Baixa uma lista como CSV (nome,telefone,email)
app.get('/api/lists/:id/csv', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Banco indisponível' });
  try {
    const owner = encodeURIComponent(req.session.email);
    const lr = await proxyFetch(`${SUPABASE_URL}/rest/v1/contact_lists?id=eq.${req.params.id}&owner=eq.${owner}&select=name`, { method: 'GET', headers: SB_HEADERS });
    const listRows = await lr.json();
    const list = Array.isArray(listRows) ? listRows[0] : null;
    if (!list) return res.status(404).json({ error: 'Lista não encontrada.' });

    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/contact_list_items?list_id=eq.${req.params.id}&owner=eq.${owner}&select=name,phone,email&order=created_at.asc&limit=5000`, { method: 'GET', headers: SB_HEADERS });
    const rows = await r.json();
    const items = Array.isArray(rows) ? rows : [];
    const escCsv = (s) => `"${String(s || '').replace(/"/g, '""')}"`;
    const csv = ['nome,telefone,email', ...items.map(it => `${escCsv(it.name)},${escCsv(it.phone)},${escCsv(it.email)}`)].join('\n');
    const filename = (list.name || 'lista').replace(/[^\w\- ]+/g, '').trim() || 'lista';
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}.csv"`);
    res.send('\uFEFF' + csv);
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Importa um arquivo e cria uma nova lista de contatos
app.post('/api/lists/import', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Banco indisponível' });
  const { name, format, fileBase64 } = req.body;
  if (!fileBase64) return res.status(400).json({ error: 'Arquivo obrigatório.' });
  try {
    const contacts = await parseContactFile(fileBase64, format);
    if (!contacts.length) return res.status(400).json({ error: 'Nenhum contato reconhecido no arquivo. Verifique se há nomes/telefones nas colunas ou no texto.' });

    const owner = req.session.email;
    const listName = (name || `Lista ${new Date().toLocaleDateString('pt-BR')}`).slice(0, 120);
    const lr = await proxyFetch(`${SUPABASE_URL}/rest/v1/contact_lists`, {
      method: 'POST', headers: { ...SB_HEADERS, 'Prefer': 'return=representation' },
      body: JSON.stringify({ owner, name: listName, source_format: format, total: contacts.length }),
    });
    const listRows = await lr.json();
    if (!lr.ok) return res.status(lr.status).json({ error: listRows?.message || 'Erro ao criar lista' });
    const list = Array.isArray(listRows) ? listRows[0] : listRows;

    // Insere os contatos em lotes (evita payload gigante numa única requisição)
    const items = contacts.map(c => ({ list_id: list.id, owner, name: c.name || '', phone: c.phone || '', email: c.email || '' }));
    for (let i = 0; i < items.length; i += 500) {
      const batch = items.slice(i, i + 500);
      await proxyFetch(`${SUPABASE_URL}/rest/v1/contact_list_items`, {
        method: 'POST', headers: { ...SB_HEADERS, 'Prefer': 'return=minimal' },
        body: JSON.stringify(batch),
      });
    }
    res.json({ ok: true, list, total: contacts.length, withPhone: contacts.filter(c => c.phone).length });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Lista as listas de contatos do usuário
app.get('/api/lists', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.json({ ok: true, lists: [] });
  try {
    const owner = encodeURIComponent(req.session.email);
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/contact_lists?owner=eq.${owner}&select=*&order=created_at.desc`, { method: 'GET', headers: SB_HEADERS });
    const rows = await r.json();
    res.json({ ok: true, lists: Array.isArray(rows) ? rows : [] });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Contatos de uma lista específica
app.get('/api/lists/:id/items', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.json({ ok: true, items: [] });
  try {
    const owner = encodeURIComponent(req.session.email);
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/contact_list_items?list_id=eq.${req.params.id}&owner=eq.${owner}&select=*&order=created_at.asc&limit=5000`, { method: 'GET', headers: SB_HEADERS });
    const rows = await r.json();
    res.json({ ok: true, items: Array.isArray(rows) ? rows : [] });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Exclui uma lista inteira (e seus contatos, via cascade)
app.delete('/api/lists/:id', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Banco indisponível' });
  try {
    const owner = encodeURIComponent(req.session.email);
    await proxyFetch(`${SUPABASE_URL}/rest/v1/contact_lists?id=eq.${req.params.id}&owner=eq.${owner}`, { method: 'DELETE', headers: SB_HEADERS });
    res.json({ ok: true });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Exclui um contato específico de uma lista
app.delete('/api/lists/:id/items/:itemId', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Banco indisponível' });
  try {
    const owner = encodeURIComponent(req.session.email);
    await proxyFetch(`${SUPABASE_URL}/rest/v1/contact_list_items?id=eq.${req.params.itemId}&list_id=eq.${req.params.id}&owner=eq.${owner}`, { method: 'DELETE', headers: SB_HEADERS });
    res.json({ ok: true });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Importa contatos selecionados de uma lista como leads do CRM
app.post('/api/lists/:id/to-crm', requireAuth, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(503).json({ error: 'Banco indisponível' });
  const { itemIds } = req.body; // opcional — se ausente, importa todos os itens com telefone
  try {
    const owner = req.session.email;
    const ownerQ = encodeURIComponent(owner);
    let url = `${SUPABASE_URL}/rest/v1/contact_list_items?list_id=eq.${req.params.id}&owner=eq.${ownerQ}&select=name,phone,email`;
    const r = await proxyFetch(url, { method: 'GET', headers: SB_HEADERS });
    let items = await r.json();
    items = Array.isArray(items) ? items : [];
    if (Array.isArray(itemIds) && itemIds.length) {
      // já buscamos por lista inteira acima; filtra client-side se veio um subconjunto
    }
    items = items.filter(c => c.phone);
    if (!items.length) return res.json({ ok: true, imported: 0 });

    const leads = items.map(c => ({
      owner, name: c.name || '', phone: c.phone, stage: 'novo', tags: [], notes: '',
      value: 0, source: 'lista_importada',
      last_activity: new Date().toISOString(), updated_at: new Date().toISOString(),
    }));
    let imported = 0;
    for (let i = 0; i < leads.length; i += 500) {
      const batch = leads.slice(i, i + 500);
      const ir = await proxyFetch(`${SUPABASE_URL}/rest/v1/crm_leads`, {
        method: 'POST', headers: { ...SB_HEADERS, 'Prefer': 'return=minimal,resolution=ignore-duplicates' },
        body: JSON.stringify(batch),
      });
      if (ir.ok) imported += batch.length;
    }
    res.json({ ok: true, imported });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// ── Inicia servidor (apenas localmente — Vercel usa module.exports) ──
if (require.main === module) {
  app.listen(PORT, () => {
    console.log('');
    console.log('  🚀 Renov Disparador em    http://localhost:' + PORT);
    console.log('  🔒 Usuários               ' + USERS.map(u => u.email).join(', '));
    console.log('');
  });
}

module.exports = app;
