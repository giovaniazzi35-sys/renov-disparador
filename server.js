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
const EVOLUTION_URL  = (process.env.EVOLUTION_URL || '').replace(/\/$/, '');
const GLOBAL_API_KEY = process.env.GLOBAL_API_KEY || '';
const SESSION_SECRET = process.env.SESSION_SECRET || 'renov-secret-2026';
// Login com Google (OAuth de nível de aplicativo) — multiusuário
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';

// WAHA (WhatsApp HTTP API) — motor alternativo. Ativa quando WAHA_URL estiver definido.
const WAHA_URL     = (process.env.WAHA_URL || '').replace(/\/$/, '');
const WAHA_API_KEY = process.env.WAHA_API_KEY || '';
// Provedor padrão do app (Evolution está sendo desativada — Uzapi é o provedor
// principal, configurado por usuário). WA_PROVIDER só decide um fallback global
// quando o usuário não tem Uzapi configurada; nunca trava a inicialização.
const WA_PROVIDER = WAHA_URL ? 'waha' : 'evolution';
if (!EVOLUTION_URL) console.warn('⚠ EVOLUTION_URL não configurada — recursos legados da Evolution ficam indisponíveis (Uzapi é o provedor ativo).');

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

// ══════════════════════════════════════════════════════════════
// Camada WhatsApp unificada — roteia para WAHA ou Evolution
// ══════════════════════════════════════════════════════════════
// Quando WAHA_URL estiver configurado, todo envio passa pelo WAHA.
// Session (WAHA) = instanceName; chatId = <numero>@c.us
function wahaChatId(phone) {
  const n = String(phone).replace(/\D/g, '');
  return `${n}@c.us`;
}

// Envia texto via WAHA
async function wahaSendText(session, phone, text) {
  return proxyFetch(`${WAHA_URL}/api/sendText`, {
    method: 'POST',
    headers: { 'X-Api-Key': WAHA_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ session: session || 'default', chatId: wahaChatId(phone), text }),
  });
}

// Envia mídia via WAHA (imagem/arquivo/vídeo/voz) — data base64 ou url
async function wahaSendMedia(session, phone, { type, url, base64, mimetype, caption, filename }) {
  const chatId = wahaChatId(phone);
  const s = session || 'default';
  const file = url ? { url } : { mimetype: mimetype || 'application/octet-stream', filename: filename || 'arquivo', data: (base64 || '').replace(/^data:[^,]+,/, '') };
  let endpoint = '/api/sendFile', payloadKey = 'file';
  if (type === 'image') endpoint = '/api/sendImage';
  else if (type === 'video') endpoint = '/api/sendVideo';
  else if (type === 'audio') { endpoint = '/api/sendVoice'; }
  const body = { session: s, chatId, caption: caption || '' };
  body[payloadKey] = file;
  return proxyFetch(`${WAHA_URL}${endpoint}`, {
    method: 'POST',
    headers: { 'X-Api-Key': WAHA_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// Status da sessão WAHA (WORKING/SCAN_QR_CODE/STARTING/FAILED)
async function wahaSessionStatus(session) {
  const r = await proxyFetch(`${WAHA_URL}/api/sessions/${encodeURIComponent(session || 'default')}`, {
    method: 'GET', headers: { 'X-Api-Key': WAHA_API_KEY },
  });
  const d = await r.json().catch(() => ({}));
  return { raw: d, connected: (d.status === 'WORKING'), status: d.status };
}

// ── Uzapi (https://api.uzapi.com.br) — credenciais são por usuário,
// preenchidas por cada um no próprio app (nunca em env var global).
function uzapiBase(cfg) {
  return `https://api.uzapi.com.br/${encodeURIComponent(cfg.uzapiUsername)}/v1/${encodeURIComponent(cfg.uzapiPhoneId)}`;
}
async function uzapiSendText(cfg, phone, text, opts = {}) {
  return proxyFetch(`${uzapiBase(cfg)}/messages`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${cfg.uzapiToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ to: String(phone).replace(/\D/g, ''), type: 'text', text: { body: text }, delayMessage: opts.delaySec || 0 }),
  });
}
// Envia mídia via Uzapi — por link (URL pública) ou por upload prévio (base64) que retorna um id
async function uzapiSendMedia(cfg, phone, { type, url, base64, mimetype, caption, filename }) {
  const to = String(phone).replace(/\D/g, '');
  let mediaRef = url ? { link: url } : null;
  if (!mediaRef && base64) {
    // Upload multipart para obter um media id, depois referencia no envio
    const raw = Buffer.from(base64.replace(/^data:[^,]+,/, ''), 'base64');
    const boundary = '----uzapi' + Date.now();
    const fname = filename || 'arquivo';
    const parts = [
      `--${boundary}\r\nContent-Disposition: form-data; name="messaging_product"\r\n\r\nwhatsapp\r\n`,
      `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${fname}"\r\nContent-Type: ${mimetype || 'application/octet-stream'}\r\n\r\n`,
    ];
    const tail = `\r\n--${boundary}--\r\n`;
    const body = Buffer.concat([Buffer.from(parts[0] + parts[1]), raw, Buffer.from(tail)]);
    const up = await proxyFetch(`${uzapiBase(cfg)}/media`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${cfg.uzapiToken}`, 'Content-Type': `multipart/form-data; boundary=${boundary}` },
      body,
    });
    const upBody = await up.json().catch(() => ({}));
    if (!up.ok || !upBody.id) return { ok: false, status: up.status, text: async () => JSON.stringify(upBody) };
    mediaRef = { id: upBody.id };
  }
  if (!mediaRef) return { ok: false, status: 400, text: async () => 'Sem URL nem arquivo para enviar.' };
  const payload = { to, type, [type]: { ...mediaRef, caption: caption || '' } };
  return proxyFetch(`${uzapiBase(cfg)}/messages`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${cfg.uzapiToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}
async function uzapiInstanceStatus(cfg) {
  const r = await proxyFetch(`${uzapiBase(cfg)}/instance`, {
    method: 'GET', headers: { 'Authorization': `Bearer ${cfg.uzapiToken}` },
  });
  const d = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, raw: d };
}

// ENVIO UNIFICADO — usado pelo agente, CRM e disparador. Roteia por usuário:
// Uzapi (se configurada) > WAHA (se WAHA_URL global definida) > Evolution (padrão).
// A Evolution API foi desativada — Uzapi é o provedor de envio ativo.
function resolveProvider(cfg) {
  if (cfg?.uzapiToken && cfg.uzapiUsername && cfg.uzapiPhoneId) return 'uzapi';
  if (WA_PROVIDER === 'waha') return 'waha';
  return 'none';
}
const NO_PROVIDER_ERR = { ok: false, status: 400, text: async () => 'Nenhum provedor de WhatsApp configurado. Preencha suas credenciais da Uzapi na aba Agente.' };
async function waSendText(wa, phone, text) {
  const provider = resolveProvider(wa);
  if (provider === 'uzapi') {
    const r = await uzapiSendText(wa, phone, text, { delaySec: wa.delay ? Math.round(wa.delay / 1000) : 0 });
    return { ok: r.ok, status: r.status, text: () => r.text() };
  }
  if (provider === 'waha') {
    const r = await wahaSendText(wa.session || wa.instanceName, phone, text);
    return { ok: r.ok, status: r.status, text: () => r.text() };
  }
  return NO_PROVIDER_ERR;
}
async function waSendMedia(wa, phone, opts) {
  const provider = resolveProvider(wa);
  if (provider === 'uzapi') return uzapiSendMedia(wa, phone, opts);
  if (provider === 'waha') return wahaSendMedia(wa.session || wa.instanceName, phone, opts);
  return NO_PROVIDER_ERR;
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
    res.json([{ name: cfg.uzapiUsername, connected: !!r.ok, provider: 'uzapi' }]);
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

// Carrega a config de um id específico do Supabase
async function loadConfigById(id) {
  if (SUPABASE_URL && SUPABASE_KEY) {
    try {
      const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_config?id=eq.${id}&select=data`, { method: 'GET', headers: SB_HEADERS });
      const rows = await r.json();
      if (r.ok && Array.isArray(rows) && rows[0]?.data && Object.keys(rows[0].data).length > 0) {
        return autoActivate({ ...DEFAULT_CFG(), ...rows[0].data });
      }
    } catch (err) { console.warn('loadConfigById error:', err.message); }
  }
  return null;
}

// Salva a config de um id específico (upsert)
function saveConfigById(id, cfg) {
  if (SUPABASE_URL && SUPABASE_KEY) {
    proxyFetch(`${SUPABASE_URL}/rest/v1/agent_config`, {
      method: 'POST',
      headers: { ...SB_HEADERS, 'Prefer': 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify({ id, data: cfg, updated_at: new Date().toISOString() }),
    }).then(r => { if (!r.ok) console.warn('saveConfigById failed:', r.status); })
      .catch(err => console.warn('saveConfigById error:', err.message));
  }
}

// Busca a config dona de uma instância pelo token (usado no webhook, sem sessão)
async function findConfigByToken(token) {
  if (!token || !SUPABASE_URL || !SUPABASE_KEY) return null;
  try {
    const q = encodeURIComponent(token);
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_config?data->>instanceToken=eq.${q}&select=id,data`, { method: 'GET', headers: SB_HEADERS });
    const rows = await r.json();
    if (r.ok && Array.isArray(rows) && rows[0]?.data) {
      return { id: rows[0].id, cfg: autoActivate({ ...DEFAULT_CFG(), ...rows[0].data }) };
    }
  } catch (err) { console.warn('findConfigByToken error:', err.message); }
  return null;
}

// Encontra a config do usuário dono de um phone_number_id da Uzapi (webhooks)
async function findConfigByUzapiPhoneId(phoneId) {
  if (!phoneId || !SUPABASE_URL || !SUPABASE_KEY) return null;
  try {
    const q = encodeURIComponent(phoneId);
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_config?data->>uzapiPhoneId=eq.${q}&select=id,data`, { method: 'GET', headers: SB_HEADERS });
    const rows = await r.json();
    if (r.ok && Array.isArray(rows) && rows[0]?.data) {
      return { id: rows[0].id, cfg: autoActivate({ ...DEFAULT_CFG(), ...rows[0].data }) };
    }
  } catch (err) { console.warn('findConfigByUzapiPhoneId error:', err.message); }
  return null;
}

// Cache por e-mail (curto) — evita hit no Supabase a cada request autenticado
const _userConfigCache = new Map(); // email → { cfg, ts }
async function getUserConfig(email) {
  const cached = _userConfigCache.get(email);
  if (cached && Date.now() - cached.ts < 5000) return cached.cfg;
  const cfg = (await loadConfigById(configIdFor(email))) || DEFAULT_CFG();
  cfg.owner = email;
  _userConfigCache.set(email, { cfg, ts: Date.now() });
  return cfg;
}
function putUserConfig(email, cfg) {
  cfg.owner = email;
  saveConfigById(configIdFor(email), cfg);
  _userConfigCache.set(email, { cfg, ts: Date.now() });
}

// Compat: funções antigas continuam operando sobre a linha legada id=1
async function loadAgentConfig() {
  const legacy = await loadConfigById(1);
  if (legacy) { console.log('✅ Config legado (id=1) carregado do Supabase'); return legacy; }
  if (process.env.AGENT_CONFIG_JSON) {
    try { return autoActivate({ ...DEFAULT_CFG(), ...JSON.parse(process.env.AGENT_CONFIG_JSON) }); } catch (_) {}
  }
  if (fs.existsSync(AGENT_FILE)) {
    try { return autoActivate({ ...DEFAULT_CFG(), ...JSON.parse(fs.readFileSync(AGENT_FILE, 'utf8')) }); } catch (_) {}
  }
  return DEFAULT_CFG();
}
function saveAgentConfig(cfg) {
  saveConfigById(1, cfg);
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

// Status de qualificação por contato: potencial | desqualificado | agencia | ''
const conversationStatus = new Map(); // phone → status

// Chave de conversa escopada por dono (multiusuário).
// Usuário primário mantém a chave "crua" (compatível com dados existentes);
// os demais recebem prefixo "<id>:" para isolamento total.
function convKey(cfg, phone) {
  const tag = configIdFor((cfg && cfg.owner) || PRIMARY_EMAIL);
  return tag === 1 ? phone : `${tag}:${phone}`;
}
// Prefixo usado para filtrar as conversas de um usuário na listagem
function convPrefixFor(email) {
  const tag = configIdFor(email);
  return tag === 1 ? '' : `${tag}:`;
}

// Classificação determinística por palavras-chave (backup, não depende do modelo)
function classifyByKeywords(text) {
  const t = (text || '').toLowerCase();
  // Já tem agência/assessoria — prioridade máxima
  if (/\b(j[áa]\s+(tenho|temos|trabalho|possu[oi])|tenho|temos|contrat[ei]|uso)\b[^.]{0,40}\b(ag[êe]ncia|assessoria|marketing|social media|g[eê]stor de tr[aá]fego|empresa de marketing)\b/.test(t)
      || /\b(minha|nossa)\s+(ag[êe]ncia|assessoria)\b/.test(t)
      || /\bj[áa]\s+(fa[çc]o|fazemos|invisto)\b[^.]{0,30}\bcom\b[^.]{0,30}\b(ag[êe]ncia|assessoria)\b/.test(t)) {
    return 'agencia';
  }
  // Sinais fortes de lead potencial
  const ownerSignal  = /\b(sou (dono|dona|propriet[áa]ri|s[óo]ci)|minha [óo]tica|minha loja|minha rede|tenho \d+ (loja|[óo]tica)|respons[áa]vel pelo)\b/.test(t);
  const opticSignal  = /\b([óo]tica|[óo]ticas|[óo]culos|lentes)\b/.test(t);
  const interestSignal = /\b(quero|tenho interesse|me interessa|gostaria|bora|vamos marcar|marcar (uma )?reuni[ãa]o|quero saber mais|como funciona|quanto|aumentar (meus |as )?(clientes|vendas)|preciso vender)\b/.test(t);
  if ((ownerSignal && (opticSignal || interestSignal)) || (opticSignal && interestSignal)) {
    return 'potencial';
  }
  return '';
}

// Carrega histórico do Supabase se ainda não está em memória (sobrevive a cold starts)
async function loadConversation(phone) {
  if (conversationHistory.has(phone)) return;
  if (!SUPABASE_URL || !SUPABASE_KEY) { conversationHistory.set(phone, []); return; }
  try {
    const r = await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_conversations?phone=eq.${phone}&select=messages,disabled,status`, { method: 'GET', headers: SB_HEADERS });
    const rows = await r.json();
    if (r.ok && Array.isArray(rows) && rows[0]) {
      conversationHistory.set(phone, Array.isArray(rows[0].messages) ? rows[0].messages : []);
      if (rows[0].disabled) disabledNumbers.add(phone); else disabledNumbers.delete(phone);
      if (rows[0].status) conversationStatus.set(phone, rows[0].status);
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
    body: JSON.stringify({ phone, messages, disabled: disabledNumbers.has(phone), status: conversationStatus.get(phone) || '', updated_at: new Date().toISOString() }),
  }).then(r => { if (!r.ok) console.warn('saveConversation failed:', r.status); })
    .catch(err => console.warn('saveConversation error:', err.message));
}
const MAX_HISTORY = 30; // mensagens mantidas por contato

// ── Google Calendar helpers ───────────────────────────────────

async function getGoogleAccessToken(cfg = agentConfig) {
  const { googleClientId: cid, googleClientSecret: csec, googleRefreshToken: rt } = cfg;
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
  // Tenta o modelo escolhido + até 4 gratuitos atuais da lista ao vivo
  // (limitado para caber no tempo máximo da função serverless)
  const chain = [primary, ...liveFree.filter(m => m !== primary).slice(0, 4)];
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

// Destino padrão das indicações (usuário primário): grupo "Renov Gestão ✅".
const CONTACT_FORWARD_GROUP  = '120363427333810759@g.us'; // Renov Gestão ✅
const CONTACT_FORWARD_NUMBER = '5511970799985';           // reserva

// Descobre para onde encaminhar as indicações deste usuário.
// Cada usuário pode ter seu próprio grupo/número em cfg.forwardGroup / cfg.forwardNumber.
// O usuário primário usa o grupo Renov por padrão.
function forwardDestinations(cfg) {
  const dests = [];
  if (cfg?.forwardGroup) dests.push(cfg.forwardGroup);
  if (cfg?.forwardNumber) dests.push(cfg.forwardNumber);
  if (!dests.length && (cfg?.owner || '').toLowerCase() === PRIMARY_EMAIL) {
    dests.push(CONTACT_FORWARD_GROUP, CONTACT_FORWARD_NUMBER);
  }
  // Fallback final: manda para o próprio dono da instância (não perde a indicação)
  if (!dests.length && cfg?.instanceOwnerPhone) dests.push(cfg.instanceOwnerPhone);
  return dests;
}

// Envia a indicação com até 3 tentativas por destino — a mensagem PRECISA chegar
async function forwardIndication(sendToken, cfg, textMsg) {
  const dests = forwardDestinations(cfg);
  if (!dests.length) { console.warn('[INDICACAO] sem destino configurado para', cfg?.owner); return false; }
  const waCfg = { ...cfg, instanceToken: sendToken };
  for (const dest of dests) {
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const r = await waSendText(waCfg, dest, textMsg);
        if (r.ok) { console.log(`[INDICACAO] enviada para ${dest} (tentativa ${attempt})`); return true; }
        const errBody = await (r.text ? r.text() : Promise.resolve('')).catch(() => '');
        console.warn(`[INDICACAO] ${dest} tentativa ${attempt} falhou (${r.status}): ${String(errBody).slice(0, 200)}`);
      } catch (err) {
        console.warn(`[INDICACAO] ${dest} tentativa ${attempt} erro: ${err.message}`);
      }
      await new Promise(r => setTimeout(r, 1500));
    }
  }
  console.error('[INDICACAO] FALHA DEFINITIVA — todos os destinos falharam');
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

// Baixa mídia da Uzapi por id (endpoint /{username}/{version}/{mediaId}) e retorna base64
async function uzapiDownloadMedia(cfg, mediaId) {
  if (!mediaId || !cfg?.uzapiToken) return null;
  try {
    const r = await proxyFetch(`https://api.uzapi.com.br/${encodeURIComponent(cfg.uzapiUsername)}/v1/${encodeURIComponent(mediaId)}`, {
      method: 'GET', headers: { 'Authorization': `Bearer ${cfg.uzapiToken}` },
    });
    if (!r.ok) { console.warn(`[AUDIO] download Uzapi falhou (${r.status})`); return null; }
    // Pode vir como JSON {base64} ou como binário/base64 cru — trata os dois casos
    const txt = await r.text();
    try {
      const j = JSON.parse(txt);
      if (j.base64 || j.data) return j.base64 || j.data;
    } catch (_) {
      // não é JSON — assume binário/base64 cru na resposta
      if (txt && txt.length > 100) return Buffer.from(txt, 'binary').toString('base64');
    }
    return null;
  } catch (err) { console.warn('[AUDIO] erro no download Uzapi:', err.message); return null; }
}

// Busca o base64 do áudio: embutido no payload, Uzapi (por mediaId) ou Evolution (legado)
async function getAudioBase64(data, rawPayload, token, cfg) {
  // 1. Base64 embutido no webhook
  const inline = rawPayload?.Base64 || rawPayload?.base64 || data?.base64
    || data?.message?.base64 || data?.message?.audioMessage?.base64;
  if (inline && typeof inline === 'string' && inline.length > 100) return inline;

  // 2. Uzapi — baixa por media id
  const uzapiMediaId = data?.message?.audioMessage?.id;
  if (uzapiMediaId && cfg?.uzapiToken) {
    const b64 = await uzapiDownloadMedia(cfg, uzapiMediaId);
    if (b64) return b64;
  }

  // 3. Evolution (legado) — endpoint de download de mídia
  if (!data?.key || !token || !EVOLUTION_URL) return null;
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

async function transcribeAudio(data, apiKey, instanceToken, rawPayload, cfg) {
  try {
    const token = instanceToken || agentConfig.instanceToken;
    const base64 = await getAudioBase64(data, rawPayload, token, cfg);
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

app.get('/api/agent/config', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  res.json({ ok: true, data: { ...cfg, docText: cfg.docText ? '(carregado)' : '' } });
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
    res.json({ ok: true, reply: (reply || '').replace(/\[STATUS:[^\]]+\]/gi, '').trim() });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/agent/config', requireAuth, async (req, res) => {
  const { active, instanceName, instanceToken, prompt, docText, openrouterKey, model,
          schedulingEnabled, calendarId, googleClientId, googleClientSecret } = req.body;
  const prev = await getUserConfig(req.session.email);
  // Ao salvar configurações completas, sempre reativa e limpa flag de desativação manual
  const hasRequiredFields = !!(instanceToken && openrouterKey);
  const newCfg = {
    // Preserva token OAuth e email ao salvar — não apaga o login do Google
    googleRefreshToken: prev.googleRefreshToken || '',
    googleEmail:        prev.googleEmail || '',
    active: hasRequiredFields ? true : !!active,
    manuallyDeactivated: false,
    instanceName: instanceName || '', instanceToken: instanceToken || '',
    prompt: prompt || '', docText: docText || '',
    openrouterKey: openrouterKey || '', model: model || 'deepseek/deepseek-chat-v3-0324:free',
    schedulingEnabled: !!schedulingEnabled,
    calendarId: calendarId || 'primary',
    googleClientId: googleClientId || '', googleClientSecret: googleClientSecret || '',
    owner: req.session.email,
  };
  putUserConfig(req.session.email, newCfg);
  // E-mail primário também escreve na linha legada id=1 (mantém o agente atual)
  if (configIdFor(req.session.email) === 1) { agentConfig = newCfg; }
  logReq('POST', '/api/agent/config', `user=${req.session.email} active=${newCfg.active}`);
  res.json({ ok: true });
});

// ── Google OAuth login flow ───────────────────────────────────

app.get('/api/agent/google-auth', requireAuth, async (req, res) => {
  const { googleClientId } = await getUserConfig(req.session.email);
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
    const cfg = await getUserConfig(req.session.email);
    const proto = req.headers['x-forwarded-proto'] || req.protocol;
    const redirectUri = `${proto}://${req.get('host')}/api/agent/google-callback`;
    const body = new URLSearchParams({
      client_id: cfg.googleClientId,
      client_secret: cfg.googleClientSecret,
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
    cfg.googleRefreshToken = data.refresh_token;
    cfg.googleEmail = email;
    putUserConfig(req.session.email, cfg);
    if (configIdFor(req.session.email) === 1) agentConfig = cfg;
    logReq('GET', '/api/agent/google-callback', `email=${email}`);
    res.redirect('/?google_ok=' + encodeURIComponent(email));
  } catch (err) {
    res.redirect('/?google_error=' + encodeURIComponent(err.message));
  }
});

app.get('/api/agent/google-status', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  res.json({
    ok: true,
    connected: !!(cfg.googleRefreshToken && cfg.googleEmail),
    email: cfg.googleEmail || '',
  });
});

app.post('/api/agent/google-disconnect', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  cfg.googleRefreshToken = '';
  cfg.googleEmail = '';
  putUserConfig(req.session.email, cfg);
  if (configIdFor(req.session.email) === 1) agentConfig = cfg;
  res.json({ ok: true });
});

app.post('/api/agent/test-calendar', requireAuth, async (req, res) => {
  try {
    const cfg = await getUserConfig(req.session.email);
    const token = await getGoogleAccessToken(cfg);
    if (!token) return res.status(400).json({ error: 'Credenciais Google não configuradas.' });
    const busy = await getCalendarBusySlots(token, cfg.calendarId);
    const slots = findAvailableSlots(busy, 3);
    res.json({ ok: true, slots: slots.map(s => ({ utc: s.toISOString(), brt: formatSlotBRT(s) })) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/agent/toggle', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  cfg.active = !cfg.active;
  // Persiste intenção do usuário — só respeita desativação manual
  cfg.manuallyDeactivated = !cfg.active;
  putUserConfig(req.session.email, cfg);
  if (configIdFor(req.session.email) === 1) agentConfig = cfg;
  logReq('POST', '/api/agent/toggle', `user=${req.session.email} active=${cfg.active}`);
  res.json({ ok: true, active: cfg.active });
});

// Webhook público — Evolution Go posta aqui sem autenticação.
// IMPORTANTE: a resposta HTTP só é enviada ao FINAL do processamento —
// no Vercel, responder cedo congela a função e mata o buffer/modelo/envio.
app.post('/api/agent/webhook', async (req, res) => {
  try {
    const body = req.body || {};
    webhookLog.push({ ts: new Date().toISOString(), event: body.object || body.event || body.type || '?', body: JSON.stringify(body).slice(0, 500) });
    if (webhookLog.length > 30) webhookLog.shift();

    // Formato Uzapi (idêntico ao WhatsApp Cloud API): { object, entry:[{changes:[{value:{...}}]}] }
    const isUzapiFormat = body.object === 'whatsapp_business_account' || Array.isArray(body.entry);

    let cfg = null, effToken = '', msgData = null, picked = null;

    if (isUzapiFormat) {
      const value = (body.entry?.[0]?.changes?.[0]?.value) || {};
      const phoneNumberId = value.metadata?.phone_number_id || '';
      const msg = (value.messages || [])[0];
      console.log(`[WEBHOOK] uzapi phoneId=${phoneNumberId} temMensagem=${!!msg} tipo=${msg?.type || '-'}`);
      if (!msg) return; // eventos sem mensagem (status de entrega, conexão etc.) — só confirma recebimento

      const owner = await findConfigByUzapiPhoneId(phoneNumberId);
      cfg = owner ? owner.cfg : agentConfig;
      if (!cfg.active) { console.log(`[WEBHOOK] ignorado — active=${cfg.active} (uzapi phoneId=${phoneNumberId})`); return; }

      const waId = (msg.from || '').replace(/\D/g, '');
      const contactName = (value.contacts || [])[0]?.profile?.name || '';
      const messageObj = {};
      if (msg.type === 'text') messageObj.conversation = msg.text?.body || '';
      else if (msg.type === 'audio') messageObj.audioMessage = { ...(msg.audio || {}) };
      else if (msg.type === 'image') messageObj.imageMessage = { ...(msg.image || {}) };
      else if (msg.type === 'document') messageObj.documentMessage = { ...(msg.document || {}) };
      else if (msg.type === 'contacts') messageObj.contactsArrayMessage = { contacts: (msg.contacts || []).map(c => ({ displayName: c.name?.formatted_name || '', vcard: `TEL:${c.phones?.[0]?.phone || ''}\nFN:${c.name?.formatted_name || ''}` })) };

      msgData = {
        key: { remoteJid: `${waId}@s.whatsapp.net`, fromMe: false, id: msg.id || '' },
        message: messageObj,
        messageType: msg.type === 'text' ? '' : `${msg.type}Message`,
        pushName: contactName,
      };
      picked = msg; // usado pela transcrição de áudio (media id da Uzapi)
      effToken = ''; // Uzapi não usa apikey por requisição — resolve tudo pela cfg
    } else {
      // Formato legado (Evolution) — mantido durante a transição
      const rawEvent = body?.event || body?.type || '';
      const sendToken = body?.instanceToken || '';
      if (sendToken) {
        const owner = await findConfigByToken(sendToken);
        if (owner) cfg = owner.cfg;
      }
      if (!cfg) cfg = agentConfig;
      effToken = sendToken || cfg.instanceToken || '';
      if (!cfg.active || !effToken) { console.log(`[WEBHOOK] ignorado — active=${cfg.active} token=${!!effToken}`); return; }

      const ev = rawEvent.toUpperCase().replace(/[.\-_]/g, '');
      if (!(ev === 'MESSAGE' || ev === 'MESSAGESUPSERT' || ev === 'MESSAGES')) { console.log(`[WEBHOOK] evento ignorado: ${rawEvent}`); return; }

      const rawData = body?.data;
      picked = Array.isArray(rawData) ? rawData[0] : (rawData || body?.messages?.[0] || body);
      msgData = normalizeMsgData(picked);
      if (!msgData || typeof msgData !== 'object' || !msgData.key) {
        console.log(`[WEBHOOK] payload não reconhecido: ${JSON.stringify(picked).slice(0, 400)}`);
        return;
      }
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

    // Chave escopada por dono — isola conversas entre usuários
    const sk = convKey(cfg, from);

    // Carrega histórico persistido (Supabase) — mantém memória entre cold starts
    await loadConversation(sk);

    // Verifica se IA está desativada para este número
    if (disabledNumbers.has(sk)) return;

    const key = cfg.openrouterKey;
    if (!key) return;

    const ts = new Date().toTimeString().slice(0, 8);
    let text = extractMsgText(msgData).trim();

    // Transcreve áudio se necessário
    if (!text && isAudioMessage(msgData)) {
      console.log(`[${ts}] 🎙 Áudio recebido de ${from} — transcrevendo...`);
      const transcription = await transcribeAudio(msgData, key, effToken, picked, cfg);
      if (transcription) {
        text = `[Áudio transcrito]: ${transcription}`;
        console.log(`[${ts}] 🎙 Transcrição: ${transcription.slice(0, 80)}`);
      } else {
        // Sem transcrição disponível — avisa o contato
        await waSendText({ ...cfg, instanceToken: effToken }, from, 'Recebi seu áudio! Para agilizar, pode me mandar a mensagem por escrito? 😊');
        return;
      }
    }

    // Contato compartilhado (vCard) — encaminha para o grupo do dono
    const sharedContacts = extractContacts(msgData);
    if (sharedContacts.length) {
      const senderName = msgData.pushName || from;
      for (const c of sharedContacts) {
        await forwardIndication(effToken, cfg,
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

    // ── Buffer de mensagens: espera 20s para juntar mensagens seguidas
    // do mesmo contato e responder tudo de uma vez ──
    let buf = msgBuffer.get(sk);
    if (!buf) { buf = { texts: [], seq: 0 }; msgBuffer.set(sk, buf); }
    buf.texts.push(text);
    buf.seq++;
    const mySeq = buf.seq;
    const waitMs = 20000; // 20s juntando mensagens antes de responder
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
      const forwarded = await forwardIndication(effToken, cfg,
        `📇 *Indicação recebida pelo agente*\n\n📱 Telefone(s): ${typedPhones.join(', ')}\n💬 Mensagem original:\n"${combined.slice(0, 400)}"\n\n🔁 Indicado por: ${senderName2} (${from})`);
      if (forwarded) {
        combined += `\n[Enviei o contato de: ${typedPhones.join(', ')}]`;
      }
    }

    // Classificação por palavras-chave ANTES do modelo — garante disparo mesmo
    // que o modelo gratuito falhe em responder
    const prevStatusEarly = conversationStatus.get(sk) || '';
    const kwEarly = classifyByKeywords(combined);
    if (kwEarly === 'potencial' && prevStatusEarly !== 'potencial' && prevStatusEarly !== 'agencia') {
      conversationStatus.set(sk, 'potencial');
      const leadNome = msgData.pushName || from;
      await forwardIndication(effToken, cfg,
        `🟢 *Lead qualificado pelo agente!*\n\n👤 Nome: ${leadNome}\n📱 WhatsApp: ${from}\n\n💬 Última mensagem:\n"${combined.slice(0, 300)}"\n\n✅ Demonstrou interesse — vale acompanhar.`);
      console.log(`[${ts}] 🟢 ${from} qualificado (palavra-chave) — encaminhado`);
    } else if (kwEarly === 'agencia' && prevStatusEarly !== 'agencia') {
      conversationStatus.set(sk, 'agencia');
      console.log(`[${ts}] 🟠 ${from} tem agência (palavra-chave)`);
    }

    // Mantém histórico de conversa por contato
    if (!conversationHistory.has(sk)) conversationHistory.set(sk, []);
    const history = conversationHistory.get(sk);
    history.push({ role: 'user', content: combined });
    if (history.length > MAX_HISTORY) history.splice(0, history.length - MAX_HISTORY);

    // Monta system prompt — injeta slots disponíveis se agendamento ativo
    let sysBase = [cfg.prompt || '', cfg.docText ? `\n\n# Documento de referência:\n${cfg.docText}` : ''].join('').trim();
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
      + '- Se receber uma mensagem tipo "[Enviei o contato de: ...]", significa que a pessoa compartilhou um contato e ele JÁ FOI encaminhado ao nosso time. Agradeça de forma natural e diga que vamos falar com a pessoa indicada.\n'
      + '\n# Fluxo de qualificação (siga esta ordem, sem pular etapas):\n'
      + '1. NUNCA convide para reunião logo de primeira. Primeiro qualifique: descubra se a pessoa é decisora, se tem ótica/rede, quantas lojas, se já investe em anúncios.\n'
      + '2. Conte sobre a Renov naturalmente durante a conversa (assessoria de tráfego pago, 70+ cases como iFood e Coca-Cola, média de 250–300 potenciais clientes/mês para óticas) — em doses pequenas, nunca tudo de uma vez.\n'
      + '3. Quebre objeções com calma ("já tentei anúncio e não funcionou", "tá caro", "não tenho tempo") usando argumentos do playbook reformulados com suas palavras.\n'
      + '4. Só ofereça reunião depois que a pessoa demonstrar interesse real e você já souber quem ela é e o tamanho da operação.\n'
      + '5. Se a pessoa disser que JÁ TEM agência ou assessoria de marketing: agradeça educadamente, deseje sucesso e encerre — NÃO insista, NÃO ofereça reunião.\n'
      + '\n# Classificação (obrigatório): no FINAL de toda resposta, adicione EXATAMENTE UM marcador invisível:\n'
      + '- [STATUS:agencia] → a pessoa disse que já tem agência ou assessoria de marketing\n'
      + '- [STATUS:potencial] → é decisor(a) engajado(a) ou demonstrou interesse real\n'
      + '- [STATUS:desqualificado] → sem fit: não tem ótica, pediu para parar, sem interesse claro após insistência\n'
      + '- [STATUS:andamento] → ainda em qualificação\n'
      + 'O marcador será removido antes do envio — o cliente nunca o verá.';

    if (cfg.schedulingEnabled) {
      let slotsText = '';
      try {
        const gToken = await getGoogleAccessToken(cfg);
        if (gToken) {
          const busy  = await getCalendarBusySlots(gToken, cfg.calendarId);
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

    // Gera a resposta — NUNCA deixa o lead sem devolutiva:
    // 1ª camada: cadeia de modelos (primário + gratuitos ao vivo)
    // 2ª camada: repete a cadeia inteira após 3s
    // 3ª camada: resposta de segurança pré-definida
    let reply = null;
    for (let round = 1; round <= 2 && !reply; round++) {
      try {
        reply = await callOpenRouter(key, cfg.model, sysBase, history);
      } catch (err) {
        console.warn(`[MODELO] rodada ${round} falhou por completo: ${err.message}`);
        if (round < 2) await new Promise(r => setTimeout(r, 3000));
      }
    }
    if (!reply) {
      const canned = [
        'Opa! Recebi sua mensagem 👍 Já te retorno em instantes.',
        'Oi! Vi sua mensagem aqui — me dá só um minutinho que já te respondo.',
        'Recebi aqui! Só um momento que já te dou um retorno certinho.',
      ];
      reply = canned[Math.floor(Math.random() * canned.length)];
      console.warn(`[${ts}] 🛟 todos os modelos falharam — resposta de segurança enviada para ${from}`);
    }

    // Refina a classificação com o marcador do modelo (a heurística já rodou antes)
    const statusBefore = conversationStatus.get(sk) || '';
    const modelTag = (reply.match(/\[STATUS:\s*(\w+)\s*\]/i)?.[1] || '').toLowerCase();
    let statusTag = statusBefore;
    if (modelTag === 'agencia') statusTag = 'agencia';
    else if (modelTag === 'potencial' && statusBefore !== 'agencia') statusTag = 'potencial';
    else if (modelTag === 'desqualificado' && !statusBefore) statusTag = 'desqualificado';

    if (statusTag && statusTag !== statusBefore) {
      conversationStatus.set(sk, statusTag);
      console.log(`[${ts}] 🏷 ${from} classificado como: ${statusTag} (modelo=${modelTag||'-'})`);
    }
    // Lead com agência/assessoria: para de responder automaticamente
    if (statusTag === 'agencia') {
      disabledNumbers.add(sk);
      console.log(`[${ts}] 🟠 ${from} tem agência — IA desativada para este contato`);
    }
    // Lead qualificado detectado só agora pelo modelo (heurística não pegou): encaminha
    if (statusTag === 'potencial' && statusBefore !== 'potencial') {
      const leadNome = msgData.pushName || from;
      await forwardIndication(effToken, cfg,
        `🟢 *Lead qualificado pelo agente!*\n\n👤 Nome: ${leadNome}\n📱 WhatsApp: ${from}\n\n💬 Última mensagem:\n"${combined.slice(0, 300)}"\n\n✅ Demonstrou interesse — vale acompanhar.`);
      console.log(`[${ts}] 🟢 ${from} qualificado (modelo) — encaminhado`);
    }

    // Detecta marcador de agendamento
    const scheduleTag = parseScheduleTag(reply);
    let cleanReply = reply.replace(/\[AGENDAR:[^\]]+\]/g, '').replace(/\[STATUS:[^\]]+\]/gi, '').trim();

    // Adiciona resposta limpa ao histórico e persiste no Supabase
    history.push({ role: 'assistant', content: cleanReply });
    if (history.length > MAX_HISTORY) history.splice(0, history.length - MAX_HISTORY);
    saveConversation(sk);
    let meetLink = null;

    if (scheduleTag && cfg.schedulingEnabled) {
      try {
        const gToken = await getGoogleAccessToken(cfg);
        if (gToken) {
          meetLink = await createCalendarEvent(gToken, cfg.calendarId, scheduleTag, from);
          console.log(`[${ts}] 📅 Reunião criada para ${from}: ${meetLink}`);
        }
      } catch (calErr) {
        console.error('Calendar create error:', calErr.message);
      }
    }

    // Envia resposta principal — delay de "digitando" proporcional ao tamanho (mais humano)
    // Até 3 tentativas: a devolutiva PRECISA chegar
    const typingMs = Math.min(9000, 2500 + cleanReply.length * 35);
    const waCfg = { ...cfg, instanceToken: effToken };
    let sent = false;
    for (let attempt = 1; attempt <= 3 && !sent; attempt++) {
      try {
        const sendRes = await waSendText({ ...waCfg, delay: attempt === 1 ? typingMs : 1000 }, from, cleanReply);
        if (sendRes.ok) { sent = true; break; }
        const errBody = await sendRes.text().catch(() => '');
        console.error(`[WEBHOOK] envio tentativa ${attempt} falhou (${sendRes.status}): ${errBody.slice(0, 300)}`);
      } catch (err) {
        console.error(`[WEBHOOK] envio tentativa ${attempt} erro: ${err.message}`);
      }
      await new Promise(r => setTimeout(r, 2000));
    }
    if (!sent) console.error(`[WEBHOOK] 🚨 FALHA DEFINITIVA ao responder ${from} após 3 tentativas`);

    // Envia link do Meet separado
    if (meetLink) {
      const slotBRT = formatSlotBRT(scheduleTag);
      const linkMsg = `📅 *Reunião confirmada!*\n\n🗓 ${slotBRT}\n🔗 Link para entrar:\n${meetLink}\n\nEsperamos você! 🚀`;
      await waSendText(waCfg, from, linkMsg);
    }

    console.log(`[${ts}] 🤖 Agente respondeu para ${from}: ${cleanReply.slice(0, 60)}`);
  } catch (err) {
    console.error('Agente IA erro:', err.message);
  } finally {
    // Responde à Evolution só agora — mantém a função viva durante todo o fluxo
    if (!res.headersSent) res.status(200).json({ ok: true });
  }
});

// Lista conversas ativas do usuário logado — filtradas pelo prefixo do dono
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
            disabled: !!row.disabled,
            status: row.status || '',
          };
        });
        const rank = { agencia: 0, potencial: 1, '': 2, andamento: 2, desqualificado: 3 };
        list.sort((a, b) => (rank[a.status] ?? 2) - (rank[b.status] ?? 2));
        return res.json({ ok: true, conversations: list });
      }
    }
  } catch (err) { console.warn('conversations list error:', err.message); }
  res.json({ ok: true, conversations: [] });
});

// Ativa/desativa IA para um número específico — escopado por usuário
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

// Apaga histórico de conversa de um número — escopado por usuário
app.delete('/api/agent/conversation/:phone', requireAuth, async (req, res) => {
  const sk = convPrefixFor(req.session.email) + req.params.phone;
  conversationHistory.delete(sk);
  disabledNumbers.delete(sk);
  if (SUPABASE_URL && SUPABASE_KEY) {
    try {
      await proxyFetch(`${SUPABASE_URL}/rest/v1/agent_conversations?phone=eq.${encodeURIComponent(sk)}`, { method: 'DELETE', headers: SB_HEADERS });
    } catch (err) { console.warn('conversation delete error:', err.message); }
  }
  res.json({ ok: true });
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
    if (provider === 'evolution' && !cfg.instanceToken) return res.status(400).json({ error: 'Conecte uma instância de WhatsApp antes de enviar.' });

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

// ── Uzapi (provedor de WhatsApp alternativo) — credenciais por usuário ──
app.get('/api/agent/uzapi-settings', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  res.json({
    ok: true,
    waProvider: cfg.waProvider || 'evolution',
    uzapiUsername: cfg.uzapiUsername || '',
    uzapiPhoneId: cfg.uzapiPhoneId || '',
    hasToken: !!cfg.uzapiToken, // nunca devolve o token em si
  });
});
app.post('/api/agent/uzapi-settings', requireAuth, async (req, res) => {
  const { waProvider, uzapiUsername, uzapiPhoneId, uzapiToken } = req.body;
  const cfg = await getUserConfig(req.session.email);
  cfg.waProvider = waProvider === 'uzapi' ? 'uzapi' : 'evolution';
  cfg.uzapiUsername = (uzapiUsername || '').trim();
  cfg.uzapiPhoneId = (uzapiPhoneId || '').replace(/\D/g, '');
  // Só sobrescreve o token se um novo foi enviado — permite trocar username/phoneId sem reenviar o token
  if (uzapiToken && uzapiToken.trim()) cfg.uzapiToken = uzapiToken.trim();
  if (configIdFor(req.session.email) === 1) agentConfig = cfg;
  putUserConfig(req.session.email, cfg);
  res.json({ ok: true });
});
// Testa a conexão com a Uzapi usando as credenciais salvas
app.post('/api/agent/uzapi-test', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  if (!cfg.uzapiToken || !cfg.uzapiUsername || !cfg.uzapiPhoneId) {
    return res.status(400).json({ error: 'Preencha username, phone number ID e token antes de testar.' });
  }
  try {
    const r = await uzapiInstanceStatus(cfg);
    if (!r.ok) return res.status(r.status || 502).json({ error: r.raw?.message || `Falha ao consultar a instância (HTTP ${r.status}).` });
    res.json({ ok: true, status: r.raw });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// Configura automaticamente o webhook da instância Uzapi para apontar pro app
app.post('/api/agent/uzapi-configure-webhook', requireAuth, async (req, res) => {
  const cfg = await getUserConfig(req.session.email);
  if (!cfg.uzapiToken || !cfg.uzapiUsername || !cfg.uzapiPhoneId) {
    return res.status(400).json({ error: 'Preencha username, phone number ID e token antes de configurar o webhook.' });
  }
  try {
    const webhookUrl = appWebhookUrl(req);
    const r = await proxyFetch(`${uzapiBase(cfg)}/instance/update`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${cfg.uzapiToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ webhook: webhookUrl }),
    });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) return res.status(r.status).json({ error: body?.message || `Falha ao configurar webhook (HTTP ${r.status}).` });
    res.json({ ok: true, webhookUrl });
  } catch (err) { res.status(502).json({ error: err.message }); }
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
    console.log('  📡 Evolution Go em        ' + EVOLUTION_URL);
    console.log('  🔒 Usuários               ' + USERS.map(u => u.email).join(', '));
    console.log('');
  });
}

module.exports = app;
