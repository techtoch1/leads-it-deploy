// IT Leads system — Express server for leads-it.aligned-tech.com
import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns';
import nodemailer from 'nodemailer';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const resolveMx = dns.promises.resolveMx;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const PORT = Number(process.env.PORT || 3011);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = process.env.STATE_DIRECTORY || process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-insecure-secret';
const SEED_USER = process.env.ADMIN_USER || 'admin';
const SEED_HASH = process.env.ADMIN_PASS_HASH || '';
const VERSION = '2026-10-09.3-deployhook';

fs.mkdirSync(DATA_DIR, { recursive: true });
const LEADS_FILE = path.join(DATA_DIR, 'leads.json');
const CREDS_FILE = path.join(DATA_DIR, 'credentials.json');
const MAIL_FILE = path.join(DATA_DIR, 'mail.json');
const TENDERS_FILE = path.join(DATA_DIR, 'tenders.json');
const SOURCES_FILE = path.join(DATA_DIR, 'tender-sources.json');
const AI_FILE = path.join(DATA_DIR, 'ai.json');

const SERVICES = ['Cloud Services', 'IT Support', 'Networking', 'Cybersecurity', 'AI Chatbots', 'Hardware', 'Software', 'Other'];
const PRIORITIES = ['Low', 'Medium', 'High', 'Urgent'];
const STATUSES = ['new', 'contacted', 'qualified', 'proposal', 'won', 'lost'];
const AI_MODELS = ['claude-haiku-5-5', 'claude-sonnet-5-5', 'claude-opus-5-5'];

// ---- credentials (writable, seeded from env on first run) ----
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function readCreds() {
  try { return JSON.parse(fs.readFileSync(CREDS_FILE, 'utf8')); }
  catch { return { user: SEED_USER, passHash: SEED_HASH }; }
}
function writeCreds(c) { fs.writeFileSync(CREDS_FILE, JSON.stringify(c, null, 2), { mode: 0o600 }); }

// ---- leads store ----
function readLeads() { try { return JSON.parse(fs.readFileSync(LEADS_FILE, 'utf8')); } catch { return []; } }
function writeLeads(leads) { fs.writeFileSync(LEADS_FILE, JSON.stringify(leads, null, 2)); }

// ---- signed-cookie session ----
function sign(v) { return `${v}.${crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('hex')}`; }
function verify(signed) {
  if (!signed || !signed.includes('.')) return null;
  const i = signed.lastIndexOf('.');
  const v = signed.slice(0, i), mac = signed.slice(i + 1);
  const exp = crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('hex');
  const a = Buffer.from(mac), b = Buffer.from(exp);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return v;
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i < 0) return; out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return out;
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));

app.get('/health', (req, res) => res.json({ ok: true, service: 'leads-it', version: VERSION, time: new Date().toISOString() }));

function requireAuth(req, res, next) {
  const user = verify(parseCookies(req).sid);
  if (user) { req.user = user; return next(); }
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'unauthorized' });
  return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
}

app.get('/login', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'login.html')));
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const c = readCreds();
  const ok = username === c.user && c.passHash && sha256(password || '') === c.passHash;
  if (!ok) return res.redirect('/login?err=1');
  res.setHeader('Set-Cookie', `sid=${encodeURIComponent(sign(username))}; HttpOnly; Path=/; SameSite=Lax; Max-Age=86400`);
  const next = typeof req.query.next === 'string' ? req.query.next : '/';
  res.redirect(next.startsWith('/') ? next : '/');
});
app.post('/logout', (req, res) => { res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0'); res.redirect('/login'); });

app.get('/api/me', requireAuth, (req, res) => res.json({ user: req.user, services: SERVICES, priorities: PRIORITIES, statuses: STATUSES }));

app.post('/api/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const c = readCreds();
  if (!c.passHash || sha256(currentPassword || '') !== c.passHash) return res.status(401).json({ error: 'Current password is incorrect' });
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  writeCreds({ user: c.user, passHash: sha256(newPassword) });
  res.json({ ok: true });
});

// ---- Leads API ----
const FIELDS = ['name', 'company', 'email', 'phone', 'serviceInterest', 'priority', 'companySize', 'source', 'notes', 'status'];
app.get('/api/leads', requireAuth, (req, res) => res.json(readLeads()));
app.post('/api/leads', requireAuth, (req, res) => {
  const b = req.body || {};
  if (!b.name) return res.status(400).json({ error: 'name is required' });
  const leads = readLeads();
  const lead = {
    id: crypto.randomUUID(),
    name: b.name, company: b.company || '', email: b.email || '', phone: b.phone || '',
    serviceInterest: SERVICES.includes(b.serviceInterest) ? b.serviceInterest : 'Other',
    priority: PRIORITIES.includes(b.priority) ? b.priority : 'Medium',
    companySize: b.companySize || '', source: b.source || 'manual', notes: b.notes || '',
    status: 'new', createdAt: new Date().toISOString(), createdBy: req.user,
  };
  leads.unshift(lead);
  writeLeads(leads);
  res.status(201).json(lead);
});
app.patch('/api/leads/:id', requireAuth, (req, res) => {
  const leads = readLeads();
  const lead = leads.find(l => l.id === req.params.id);
  if (!lead) return res.status(404).json({ error: 'not found' });
  for (const k of FIELDS) if (k in (req.body || {})) lead[k] = req.body[k];
  lead.updatedAt = new Date().toISOString();
  writeLeads(leads);
  res.json(lead);
});
app.delete('/api/leads/:id', requireAuth, (req, res) => {
  const leads = readLeads();
  const next = leads.filter(l => l.id !== req.params.id);
  if (next.length === leads.length) return res.status(404).json({ error: 'not found' });
  writeLeads(next);
  res.json({ ok: true });
});

// ---- MX scanner ----
function normalizeDomain(s) {
  if (!s) return '';
  s = String(s).trim().toLowerCase();
  if (!s) return '';
  if (s.includes('@')) s = s.split('@').pop();
  s = s.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '').replace(/[),.;:]+$/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(s)) return '';
  return s;
}
function classifyMx(records) {
  if (!records || records.length === 0) return { provider: 'None', qualified: false, score: 50, reason: 'No mail server (no MX)' };
  const hosts = records.map(r => (r.exchange || '').toLowerCase());
  const joined = hosts.join(' ');
  const isGoogle = joined.includes('google.com') || joined.includes('googlemail.com') || joined.includes('aspmx.l.google');
  const isMicrosoft = joined.includes('protection.outlook.com') || joined.includes('.outlook.com') || joined.includes('office365');
  if (isGoogle) return { provider: 'Google Workspace', qualified: false, score: 10, reason: 'Uses Google' };
  if (isMicrosoft) return { provider: 'Microsoft 365', qualified: false, score: 10, reason: 'Uses Microsoft' };
  let provider = 'Other / self-hosted';
  if (joined.includes('zoho')) provider = 'Zoho';
  else if (joined.includes('pphosted') || joined.includes('proofpoint')) provider = 'Proofpoint';
  else if (joined.includes('mimecast')) provider = 'Mimecast';
  else if (joined.includes('barracuda')) provider = 'Barracuda';
  else if (joined.includes('yandex')) provider = 'Yandex';
  else if (joined.includes('secureserver.net')) provider = 'GoDaddy';
  else if (joined.includes('hostinger')) provider = 'Hostinger';
  else if (joined.includes('ovh')) provider = 'OVH';
  else provider = (hosts[0] || 'Other').replace(/\.$/, '');
  return { provider, qualified: true, score: 100, reason: 'Not Microsoft/Google' };
}
function withTimeout(p, ms) {
  return Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })), ms))]);
}
app.post('/api/mx-scan', requireAuth, async (req, res) => {
  const input = Array.isArray(req.body?.domains) ? req.body.domains : [];
  const uniq = [...new Set(input.map(normalizeDomain).filter(Boolean))];
  const out = [];
  let i = 0;
  const CONC = 8;
  async function worker() {
    while (i < uniq.length) {
      const d = uniq[i++];
      try {
        const recs = await withTimeout(resolveMx(d), 6000);
        recs.sort((a, b) => a.priority - b.priority);
        out.push({ domain: d, mx: recs.map(r => r.exchange), ...classifyMx(recs) });
      } catch (e) {
        const code = e && e.code;
        if (code === 'ENODATA') out.push({ domain: d, mx: [], ...classifyMx([]) });
        else if (code === 'ENOTFOUND' || code === 'NXDOMAIN') out.push({ domain: d, mx: [], provider: 'Domain not found', qualified: false, score: 0, reason: 'Domain not found' });
        else out.push({ domain: d, mx: [], provider: 'Lookup error', qualified: false, score: 0, reason: code || 'error' });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONC, uniq.length) || 1 }, worker));
  out.sort((a, b) => b.score - a.score || a.domain.localeCompare(b.domain));
  res.json({ total: uniq.length, qualified: out.filter(r => r.qualified).length, results: out });
});

// ---- Mail settings (SES relay, applied to Postfix by root systemd watcher) ----
function readMail() { try { return JSON.parse(fs.readFileSync(MAIL_FILE, 'utf8')); } catch { return { region: 'eu-west-1', fromAddress: '', smtpUser: '', smtpPass: '' }; } }
function writeMail(m) { fs.writeFileSync(MAIL_FILE, JSON.stringify(m, null, 2), { mode: 0o600 }); }

app.get('/api/mail-settings', requireAuth, (req, res) => {
  const m = readMail();
  res.json({ region: m.region || 'eu-west-1', fromAddress: m.fromAddress || '', smtpUser: m.smtpUser || '', hasPassword: !!m.smtpPass, updatedAt: m.updatedAt || null });
});
app.post('/api/mail-settings', requireAuth, (req, res) => {
  const b = req.body || {};
  const cur = readMail();
  const m = {
    region: (b.region || cur.region || 'eu-west-1').trim(),
    fromAddress: (b.fromAddress !== undefined ? b.fromAddress : (cur.fromAddress || '')).trim(),
    smtpUser: (b.smtpUser !== undefined ? b.smtpUser : (cur.smtpUser || '')).trim(),
    smtpPass: (b.smtpPass ? b.smtpPass : (cur.smtpPass || '')),
    updatedAt: new Date().toISOString(),
  };
  writeMail(m);
  res.json({ ok: true, hasPassword: !!m.smtpPass });
});
app.post('/api/mail-test', requireAuth, async (req, res) => {
  const to = (req.body?.to || '').trim();
  const m = readMail();
  if (!to) return res.status(400).json({ error: 'Recipient is required' });
  if (!m.fromAddress) return res.status(400).json({ error: 'Set and save a From address first' });
  try {
    const t = nodemailer.createTransport({ host: '127.0.0.1', port: 25, secure: false, tls: { rejectUnauthorized: false } });
    const info = await t.sendMail({ from: m.fromAddress, to, subject: 'IT Leads — SES test email', text: 'This is a test email from leads-it, relayed through Postfix to AWS SES.' });
    res.json({ ok: true, messageId: info.messageId, response: info.response });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---- AI settings (Anthropic API key for tender extraction + IT-relevance scoring) ----
// Stored in /var/lib/leads-it/ai.json (0600), never returned to the client, never logged.
function readAi() { try { return JSON.parse(fs.readFileSync(AI_FILE, 'utf8')); } catch { return { apiKey: '', model: 'claude-haiku-5-5', threshold: 50 }; } }
function writeAi(a) { fs.writeFileSync(AI_FILE, JSON.stringify(a, null, 2), { mode: 0o600 }); }

app.get('/api/ai-settings', requireAuth, (req, res) => {
  const a = readAi();
  res.json({ hasApiKey: !!a.apiKey, model: a.model || 'claude-haiku-5-5', threshold: Number.isFinite(a.threshold) ? a.threshold : 50, models: AI_MODELS, updatedAt: a.updatedAt || null });
});
app.post('/api/ai-settings', requireAuth, (req, res) => {
  const b = req.body || {};
  const cur = readAi();
  const key = (b.apiKey !== undefined && b.apiKey !== '') ? String(b.apiKey).trim() : (cur.apiKey || '');
  const a = {
    apiKey: key,
    model: AI_MODELS.includes(b.model) ? b.model : (cur.model || 'claude-haiku-5-5'),
    threshold: Number.isFinite(+b.threshold) ? Math.max(0, Math.min(100, Math.round(+b.threshold))) : (Number.isFinite(cur.threshold) ? cur.threshold : 50),
    updatedAt: new Date().toISOString(),
  };
  writeAi(a);
  res.json({ ok: true, hasApiKey: !!a.apiKey });
});
app.post('/api/ai-test', requireAuth, async (req, res) => {
  const a = readAi();
  if (!a.apiKey) return res.status(400).json({ error: 'Save an API key first' });
  try {
    const r = await withTimeout(fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': a.apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: a.model || 'claude-haiku-5-5', max_tokens: 16, messages: [{ role: 'user', content: 'Reply with the single word: OK' }] }),
    }), 30000);
    const data = await r.json().catch(() => ({}));
    if (!r.ok) return res.status(502).json({ error: 'Anthropic API ' + r.status + ': ' + (data?.error?.message || 'request failed') });
    const text = (data.content || []).filter(x => x.type === 'text').map(x => x.text).join('').trim();
    res.json({ ok: true, model: data.model || a.model, reply: text });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// ---- Remote deploy hook: stages new server code; a root systemd watcher validates + applies it ----
// Admin-only. Writes the posted code to /var/lib/leads-it/pending-server.js; leads-it-code.path
// (running as root) then node --checks it, backs up, copies into place, and restarts the service.
app.post('/api/_deploy', requireAuth, (req, res) => {
  const code = (req.body && req.body.code) || '';
  if (typeof code !== 'string' || code.length < 2000 || !code.includes('express()')) {
    return res.status(400).json({ error: 'invalid code payload' });
  }
  const pending = path.join(DATA_DIR, 'pending-server.js');
  const tmp = pending + '.tmp';
  try {
    fs.writeFileSync(tmp, code);
    try { execFileSync(process.execPath, ['--check', tmp], { stdio: 'pipe' }); }
    catch (e) { try { fs.unlinkSync(tmp); } catch {} return res.status(400).json({ error: 'syntax check failed: ' + String(e.stderr || e.message).slice(0, 500) }); }
    fs.renameSync(tmp, pending);
  } catch (e) { return res.status(500).json({ error: e.message }); }
  res.json({ ok: true, bytes: code.length, note: 'validated + staged; root watcher applies within a few seconds' });
});

// ---- Tenders scraper ----
const TENDER_KEYWORDS = ['tender', 'tenders', 'bid', 'bids', 'rfp', 'rfq', 'procurement', 'proposal', 'مناقصة', 'مناقصات', 'عطاء', 'عطاءات'];
function readJson(file, fallback) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; } }
function writeJson(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

// Parse a deadline like "20 Oct 2026" into an ISO date (yyyy-mm-dd), or null.
function parseDeadline(text) {
  if (!text) return null;
  const d = new Date(String(text).trim());
  return isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}

// Keyword fallback scorer (used only when the AI pipeline is unavailable).
// AI / chatbot — Aligned's flagship offering, weighted highest.
const FIT_AI = ['chatbot', 'chat bot', 'artificial intelligence', ' ai ', ' ai-', 'ai-powered', 'conversational', 'virtual assistant', 'machine learning', ' llm ', 'whatsapp', 'voicebot', 'intelligent automation', 'generative'];
const FIT_STRONG = ['software', 'system', 'website', 'web ', 'web-', 'webapp', 'application', 'network', 'server', 'cloud', 'hosting', 'cyber', 'security', 'surveillance', 'cctv', 'erp', 'crm', 'database', 'digital', 'hardware', 'computer', 'laptop', 'desktop', 'printer', 'e-mail', 'email', 'infrastructure', 'firewall', 'automation', 'portal', 'platform', 'antivirus', 'backup', 'storage', 'router', 'switch', 'virtualization', 'microsoft', 'office 365', 'information technology', ' ict', 'data center', 'datacenter', 'it equipment', 'it services', 'it support', 'wifi', 'wi-fi', ' api '];
const FIT_MED = ['equipment', 'technology', 'maintenance', 'electronic', 'telecom', 'communication', 'monitoring', 'integration', 'camera', 'access control', 'smart', 'supply of', 'installation', 'license', 'licens'];
const FIT_NEG = ['catering', 'food', 'construction', 'cleaning', 'furniture', 'vehicle', 'fuel', 'medical', 'medicine', 'pharmaceutical', 'drug', 'agriculture', 'farmer', 'renovation', 'rehabilitation', 'civil works', 'insurance', 'stationery', 'books', 'printing of', 'transportation', 'customs', 'legal', 'audit'];
function scoreTender(title) {
  const t = ' ' + String(title || '').toLowerCase() + ' ';
  let score = 0; const reasons = [];
  FIT_AI.forEach(k => { if (t.includes(k)) { score += 60; reasons.push('AI: ' + k.trim()); } });
  FIT_STRONG.forEach(k => { if (t.includes(k)) { score += 35; reasons.push(k.trim()); } });
  FIT_MED.forEach(k => { if (t.includes(k)) { score += 16; reasons.push(k.trim()); } });
  FIT_NEG.forEach(k => { if (t.includes(k)) { score -= 30; } });
  score = Math.max(0, Math.min(100, score));
  return { fitScore: score, fitReasons: [...new Set(reasons)].slice(0, 6) };
}

// Submission assistant: fetch a tender's detail page and extract everything needed to bid.
async function fetchTenderBrief(url) {
  const r = await withTimeout(fetch(url, { headers: { 'user-agent': 'Mozilla/5.0 (leads-it)' }, redirect: 'follow' }), 20000);
  const html = await r.text();
  const fields = {};
  const labels = ['Deadline', 'Competition', 'Financier', 'Purchaser Ownership', 'Tender Value', 'Notice Type'];
  for (const lab of labels) {
    const re = new RegExp(lab.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*:?\\s*(?:<[^>]+>\\s*)*([^<{}]{1,100})', 'i');
    const m = html.match(re);
    if (m) { const val = cleanText(m[1]); if (val && val.length > 1 && val.length < 100 && !/^[:."]/.test(val) && !val.includes('.php')) fields[lab] = val; }
  }
  const doc = html.match(/href=["']([^"']+)["'][^>]*>\s*(?:<[^>]+>\s*)*Download Documents/i);
  const documentsUrl = doc ? (() => { try { return new URL(doc[1], url).href; } catch { return doc[1]; } })() : '';
  const desc = html.match(/<meta[^>]+(?:name|property)=["'](?:description|og:description)["'][^>]+content=["']([^"']+)["']/i);
  const description = desc ? cleanText(desc[1]) : '';
  return { fields, documentsUrl, description, fetchedAt: new Date().toISOString() };
}
function enrichTender(t) {
  const fit = scoreTender(t.title);
  const score = Number.isFinite(t.fitScore) ? t.fitScore : fit.fitScore;
  const reasons = (Array.isArray(t.fitReasons) && t.fitReasons.length) ? t.fitReasons : fit.fitReasons;
  return { ...t, fitScore: score, fitReasons: reasons, deadlineDate: parseDeadline(t.deadline) };
}

function cleanText(s) { return String(s || '').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&#?[a-z0-9]+;/gi, ' ').replace(/\s+/g, ' ').trim(); }

// Structured parser for tender-card listing pages (e.g. lebanontenders.com):
// each card has a heading link, a "Ref No." and a "Deadline".
function parseTenderCards(html, baseUrl) {
  const items = []; const seen = new Set();
  const headRe = /<a\s+href=["']([^"']+)["']>\s*<p[^>]*class=["'][^"']*tender-card-heading[^"']*["'][^>]*>([\s\S]*?)<\/p>\s*<\/a>/gi;
  const marks = []; let m;
  while ((m = headRe.exec(html))) marks.push({ url: m[1], title: cleanText(m[2]), idx: m.index });
  for (let i = 0; i < marks.length; i++) {
    const block = html.slice(marks[i].idx, (i + 1 < marks.length) ? marks[i + 1].idx : Math.min(html.length, marks[i].idx + 1800));
    const ref = (block.match(/Ref\s*No\.?:(?:&nbsp;|\s)*([A-Za-z0-9\-\/]+)/i) || [])[1] || '';
    const deadline = cleanText((block.match(/Deadline:(?:&nbsp;|\s)*([\s\S]*?)<\/p>/i) || [])[1] || '');
    let abs; try { abs = new URL(marks[i].url, baseUrl).href; } catch { abs = marks[i].url; }
    if (seen.has(abs)) continue; seen.add(abs);
    items.push({ title: marks[i].title.slice(0, 240), url: abs, ref, deadline });
  }
  return items;
}

// ---- AI pipeline: extract tenders from any site layout + score IT relevance ----
// Trims a listing page down to the markup the model needs (keeps anchors + text).
function htmlForAI(html) {
  return String(html || '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<head[\s\S]*?<\/head>/gi, ' ')
    .replace(/\s+/g, ' ')
    .slice(0, 60000);
}
// Pull a JSON array out of the model's reply, tolerating code fences / stray prose.
function parseJsonArray(text) {
  if (!text) return [];
  let t = String(text).trim().replace(/^```(?:json)?/i, '').replace(/```$/, '').trim();
  try { const v = JSON.parse(t); if (Array.isArray(v)) return v; } catch {}
  const s = t.indexOf('['), e = t.lastIndexOf(']');
  if (s >= 0 && e > s) { try { const v = JSON.parse(t.slice(s, e + 1)); if (Array.isArray(v)) return v; } catch {} }
  return [];
}
const AI_SYSTEM = [
  'You extract public tender / bid / RFP listings from a procurement web page and rate how relevant each one is to an IT services & solutions company.',
  'The company, ALIGNED, provides: IT support, networking, cybersecurity, cloud services, Microsoft / Azure licensing, servers & hardware, software and web/app development, databases, surveillance / CCTV, structured cabling, and AI chatbots (its flagship offering).',
  'Score each tender\'s IT relevance from 0 to 100:',
  '  80-100 = clearly IT / software / network / cloud / security / AI.',
  '  50-79  = plausibly IT-related (e.g. an "information system", electronics, technology equipment that may be computing).',
  '  0-49   = not IT (construction, vehicles, food, medical, furniture, fuel, civil works, agriculture, generic "equipment" with no IT signal, fire/rescue gear, etc.).',
  'Only list ACTUAL tenders/bids shown on the page. Never invent tenders. Copy each tender\'s detail-page link EXACTLY as the href appears in the HTML; do not rewrite or guess it.',
  'Return ONLY a JSON array, no prose, no code fences. Each element: {"title": string, "ref": string, "deadline": string, "url": string, "itRelevance": number, "reason": string}. Use "" for any field you cannot find. "reason" is a short phrase explaining the score.',
].join('\n');

async function aiExtractAndScore(html, src) {
  const a = readAi();
  const user = 'Source name: ' + src.name + '\nPage URL: ' + src.url + '\n\nHTML:\n' + htmlForAI(html);
  const r = await withTimeout(fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': a.apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: a.model || 'claude-haiku-5-5', max_tokens: 8000, system: AI_SYSTEM, messages: [{ role: 'user', content: user }] }),
  }), 90000);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error('Anthropic API ' + r.status + ': ' + (data?.error?.message || 'request failed'));
  const text = (data.content || []).filter(x => x.type === 'text').map(x => x.text).join('');
  const arr = parseJsonArray(text);
  const out = [];
  for (const it of arr) {
    if (!it || !it.title) continue;
    let abs = src.url;
    try { abs = new URL(String(it.url || ''), src.url).href; } catch { abs = src.url; }
    const rel = Math.max(0, Math.min(100, Math.round(Number(it.itRelevance) || 0)));
    out.push({
      title: String(it.title).slice(0, 240),
      url: abs,
      ref: String(it.ref || '').slice(0, 60),
      deadline: String(it.deadline || '').slice(0, 60),
      fitScore: rel,
      fitReasons: it.reason ? [String(it.reason).slice(0, 140)] : [],
    });
  }
  return out;
}

app.get('/api/tender-sources', requireAuth, (req, res) => res.json(readJson(SOURCES_FILE, [])));
app.post('/api/tender-sources', requireAuth, (req, res) => {
  const b = req.body || {};
  let url = (b.url || '').trim();
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  try { new URL(url); } catch { return res.status(400).json({ error: 'Invalid URL' }); }
  const sources = readJson(SOURCES_FILE, []);
  const src = { id: crypto.randomUUID(), name: (b.name || '').trim() || new URL(url).hostname, url, keywords: Array.isArray(b.keywords) ? b.keywords : [], addedAt: new Date().toISOString() };
  sources.push(src);
  writeJson(SOURCES_FILE, sources);
  res.status(201).json(src);
});
app.delete('/api/tender-sources/:id', requireAuth, (req, res) => {
  const sources = readJson(SOURCES_FILE, []).filter(s => s.id !== req.params.id);
  writeJson(SOURCES_FILE, sources);
  res.json({ ok: true });
});

app.get('/api/tenders', requireAuth, (req, res) => res.json(readJson(TENDERS_FILE, []).map(enrichTender)));
async function runScrape() {
  const sources = readJson(SOURCES_FILE, []);
  const existing = readJson(TENDERS_FILE, []);
  const haveUrls = new Set(existing.map(t => t.url));
  const ai = readAi();
  const aiEnabled = !!ai.apiKey;
  const threshold = Number.isFinite(ai.threshold) ? ai.threshold : 50;
  const summary = [];
  let added = 0;
  for (const src of sources) {
    let items = [], error = null, mode = 'keyword';
    try {
      const r = await withTimeout(fetch(src.url, { headers: { 'user-agent': 'Mozilla/5.0 (leads-it tender scanner)' }, redirect: 'follow' }), 20000);
      const html = await r.text();
      if (aiEnabled) {
        try { items = await aiExtractAndScore(html, src); mode = 'ai'; }
        catch (e) { error = 'AI failed (' + e.message + '); used keyword fallback'; items = parseTenderCards(html, src.url).map(it => ({ ...it, ...scoreTender(it.title) })); mode = 'keyword-fallback'; }
      } else {
        items = parseTenderCards(html, src.url).map(it => ({ ...it, ...scoreTender(it.title) }));
      }
    } catch (e) { error = e.message; }
    let newCount = 0, below = 0;
    for (const it of items) {
      const score = Number.isFinite(it.fitScore) ? it.fitScore : 0;
      if (score < threshold) { below++; continue; }
      if (haveUrls.has(it.url)) continue;
      haveUrls.add(it.url);
      existing.unshift({ id: crypto.randomUUID(), title: it.title, url: it.url, ref: it.ref || '', deadline: it.deadline || '', source: src.name, sourceId: src.id, status: 'new', scrapedAt: new Date().toISOString(), fitScore: score, fitReasons: it.fitReasons || [] });
      newCount++; added++;
    }
    summary.push({ source: src.name, mode, found: items.length, added: newCount, belowThreshold: below, error: error || null });
  }
  writeJson(TENDERS_FILE, existing);
  return { added, threshold, aiEnabled, summary, total: existing.length };
}
app.post('/api/tenders/scrape', requireAuth, async (req, res) => {
  const sources = readJson(SOURCES_FILE, []);
  if (!sources.length) return res.status(400).json({ error: 'Add at least one tender source first' });
  res.json(await runScrape());
});
// Localhost-only, token-protected trigger for the scheduled daily scrape.
app.post('/internal/scrape', async (req, res) => {
  const tok = process.env.SCRAPE_TOKEN;
  if (!tok || req.headers['x-internal-token'] !== tok) return res.status(403).json({ error: 'forbidden' });
  res.json(await runScrape());
});
app.patch('/api/tenders/:id', requireAuth, (req, res) => {
  const tenders = readJson(TENDERS_FILE, []);
  const t = tenders.find(x => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'not found' });
  if (req.body && req.body.status) t.status = req.body.status;
  if (req.body && 'submissionNotes' in req.body) t.submissionNotes = req.body.submissionNotes;
  writeJson(TENDERS_FILE, tenders);
  res.json(t);
});
// Submission assistant: build (and cache) a brief for a tender.
app.get('/api/tenders/:id/brief', requireAuth, async (req, res) => {
  const tenders = readJson(TENDERS_FILE, []);
  const t = tenders.find(x => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'not found' });
  if (!t.brief || req.query.refresh) {
    try { t.brief = await fetchTenderBrief(t.url); writeJson(TENDERS_FILE, tenders); }
    catch (e) { return res.status(502).json({ error: 'Could not fetch tender page: ' + e.message }); }
  }
  res.json({ tender: enrichTender(t), brief: t.brief, submissionNotes: t.submissionNotes || '' });
});
app.delete('/api/tenders/:id', requireAuth, (req, res) => {
  const tenders = readJson(TENDERS_FILE, []).filter(t => t.id !== req.params.id);
  writeJson(TENDERS_FILE, tenders);
  res.json({ ok: true });
});
app.post('/api/tenders/:id/promote', requireAuth, (req, res) => {
  const tenders = readJson(TENDERS_FILE, []);
  const t = tenders.find(x => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'not found' });
  const leads = readLeads();
  let company = t.source;
  try { company = new URL(t.url).hostname.replace(/^www\./, ''); } catch {}
  leads.unshift({
    id: crypto.randomUUID(), name: t.title.slice(0, 120), company, email: '', phone: '',
    serviceInterest: 'Other', priority: 'Medium', companySize: '', source: 'tender: ' + t.source,
    notes: [t.ref ? 'Ref: ' + t.ref : '', t.deadline ? 'Deadline: ' + t.deadline : '', t.url].filter(Boolean).join(' · '),
    status: 'new', createdAt: new Date().toISOString(), createdBy: req.user,
  });
  writeLeads(leads);
  t.status = 'promoted';
  writeJson(TENDERS_FILE, tenders);
  res.json({ ok: true });
});

// ---- Self-contained Settings page: Email/SMTP + Claude AI (served here so no index.html change is needed) ----
const SETTINGS_PAGE = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Settings — IT Leads</title>
<style>
  :root { --sapphire:#0b1f3a; --accent:#2f6fed; --bg:#f4f6fb; --card:#fff; --line:#e3e8f0; --muted:#5b6b85; --ok:#1a7f4b; --err:#c0392b; }
  * { box-sizing:border-box; } body { margin:0; font-family:'IBM Plex Sans',system-ui,Segoe UI,Roboto,sans-serif; background:var(--bg); color:#13213a; }
  .wrap { max-width:720px; margin:0 auto; padding:32px 20px 64px; }
  a.back { color:var(--accent); text-decoration:none; font-size:14px; } a.back:hover { text-decoration:underline; }
  h1 { font-size:24px; margin:12px 0 4px; } p.sub { color:var(--muted); margin:0 0 24px; }
  h2 { font-size:18px; margin:0 0 4px; } .card > p.cardsub { color:var(--muted); font-size:13px; margin:0 0 8px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:24px; margin-bottom:20px; }
  label { display:block; font-weight:600; font-size:14px; margin:16px 0 6px; }
  input, select { width:100%; padding:10px 12px; border:1px solid var(--line); border-radius:8px; font-size:15px; font-family:inherit; }
  .hint { color:var(--muted); font-size:13px; margin-top:6px; }
  .row { display:flex; gap:12px; flex-wrap:wrap; margin-top:20px; }
  button { background:var(--accent); color:#fff; border:0; padding:11px 18px; border-radius:8px; font-size:15px; font-weight:600; cursor:pointer; }
  button.ghost { background:#eef2fb; color:var(--sapphire); }
  button:disabled { opacity:.6; cursor:default; }
  .status { margin-top:16px; font-size:14px; padding:12px 14px; border-radius:8px; display:none; white-space:pre-wrap; }
  .status.ok { background:#e8f6ee; color:var(--ok); display:block; } .status.err { background:#fdecea; color:var(--err); display:block; }
  .pill { display:inline-block; font-size:12px; padding:2px 10px; border-radius:999px; background:#eef2fb; color:var(--sapphire); font-weight:600; }
  code { background:#eef2fb; padding:1px 6px; border-radius:5px; font-size:13px; }
</style></head>
<body><div class="wrap">
  <a class="back" href="/">← Back to dashboard</a>
  <h1>Settings</h1>
  <p class="sub">Outgoing email (AWS SES) and the Claude AI tender engine.</p>

  <div class="card">
    <h2>Email / SMTP</h2>
    <p class="cardsub">Outgoing mail relayed through Postfix to AWS SES. Status: <span id="mailState" class="pill">checking…</span></p>
    <label for="region">AWS region</label>
    <input id="region" type="text" placeholder="eu-west-1">
    <label for="fromAddress">From address</label>
    <input id="fromAddress" type="email" placeholder="leads@aligned-tech.com">
    <div class="hint">Must be a verified sender/domain in AWS SES.</div>
    <label for="smtpUser">SES SMTP username</label>
    <input id="smtpUser" type="text" autocomplete="off" placeholder="AKIA… SMTP user">
    <label for="smtpPass">SES SMTP password</label>
    <input id="smtpPass" type="password" autocomplete="off" placeholder="leave blank to keep the saved password">
    <div class="hint">Stored on this server only (<code>/var/lib/leads-it/mail.json</code>, chmod 600).</div>
    <div class="row">
      <button id="saveMail">Save email settings</button>
    </div>
    <label for="testTo">Send a test email to</label>
    <input id="testTo" type="email" placeholder="you@example.com">
    <div class="row">
      <button id="testMail" class="ghost" type="button">Send test email</button>
    </div>
    <div id="mailStatus" class="status"></div>
  </div>

  <div class="card">
    <h2>Claude AI — Tender Engine</h2>
    <p class="cardsub">Claude reads each tender source and keeps only IT-relevant tenders — works on any site layout. Status: <span id="keyState" class="pill">checking…</span></p>
    <label for="apiKey">Anthropic API key</label>
    <input id="apiKey" type="password" placeholder="sk-ant-api03-…  (leave blank to keep the saved key)" autocomplete="off">
    <div class="hint">Create a <b>Workspace</b>-scoped key at console.anthropic.com. Stored on this server only (<code>/var/lib/leads-it/ai.json</code>, chmod 600).</div>
    <label for="model">Model</label>
    <select id="model"></select>
    <div class="hint">Claude Haiku is cheapest and recommended (≈ $0.001 per page scanned).</div>
    <label for="threshold">IT-relevance threshold (0–100)</label>
    <input id="threshold" type="number" min="0" max="100" step="5" value="50">
    <div class="hint">Only tenders scoring at or above this are kept. 50 is a good default.</div>
    <div class="row">
      <button id="saveBtn">Save AI settings</button>
      <button id="testBtn" class="ghost" type="button">Test API key</button>
      <button id="scrapeBtn" class="ghost" type="button">Run scrape now</button>
    </div>
    <div id="status" class="status"></div>
  </div>
</div>
<script>
  var $ = function(id){ return document.getElementById(id); };
  function setStatus(el, ok, msg){ el.className='status '+(ok?'ok':'err'); el.textContent=msg; }
  function show(ok,msg){ setStatus($('status'),ok,msg); }
  function showMail(ok,msg){ setStatus($('mailStatus'),ok,msg); }

  function loadMail(){
    fetch('/api/mail-settings').then(function(r){ return r.json(); }).then(function(d){
      $('region').value=d.region||'eu-west-1'; $('fromAddress').value=d.fromAddress||''; $('smtpUser').value=d.smtpUser||'';
      var k=$('mailState');
      if(d.hasPassword && d.fromAddress){ k.textContent='Configured'+(d.updatedAt?(' · '+new Date(d.updatedAt).toLocaleString()):''); k.style.background='#e8f6ee'; k.style.color='#1a7f4b'; }
      else { k.textContent='Not configured yet'; k.style.background='#fdecea'; k.style.color='#c0392b'; }
    });
  }
  function loadAi(){
    fetch('/api/ai-settings').then(function(r){ return r.json(); }).then(function(d){
      var sel=$('model'); sel.innerHTML='';
      (d.models||['claude-haiku-5-5']).forEach(function(m){ var o=document.createElement('option'); o.value=m; o.textContent=m; if(m===d.model)o.selected=true; sel.appendChild(o); });
      $('threshold').value = (d.threshold!=null? d.threshold : 50);
      var k=$('keyState');
      if(d.hasApiKey){ k.textContent='API key saved'+(d.updatedAt?(' · '+new Date(d.updatedAt).toLocaleString()):''); k.style.background='#e8f6ee'; k.style.color='#1a7f4b'; }
      else { k.textContent='No API key yet'; k.style.background='#fdecea'; k.style.color='#c0392b'; }
    });
  }

  $('saveMail').onclick=function(){
    this.disabled=true; var self=this;
    fetch('/api/mail-settings',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({region:$('region').value,fromAddress:$('fromAddress').value,smtpUser:$('smtpUser').value,smtpPass:$('smtpPass').value})})
      .then(function(r){ return r.json().then(function(d){ return {ok:r.ok,d:d}; }); })
      .then(function(x){ self.disabled=false; if(x.ok){ $('smtpPass').value=''; showMail(true,'Saved.'); loadMail(); } else { showMail(false,x.d.error||'Save failed'); } })
      .catch(function(e){ self.disabled=false; showMail(false,String(e)); });
  };
  $('testMail').onclick=function(){
    this.disabled=true; var self=this; showMail(true,'Sending…');
    fetch('/api/mail-test',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({to:$('testTo').value})})
      .then(function(r){ return r.json().then(function(d){ return {ok:r.ok,d:d}; }); })
      .then(function(x){ self.disabled=false; if(x.ok){ showMail(true,'Sent. '+(x.d.response||'')); } else { showMail(false,x.d.error||'Send failed'); } })
      .catch(function(e){ self.disabled=false; showMail(false,String(e)); });
  };

  $('saveBtn').onclick=function(){
    this.disabled=true; var self=this;
    fetch('/api/ai-settings',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({apiKey:$('apiKey').value,model:$('model').value,threshold:Number($('threshold').value)})})
      .then(function(r){ return r.json().then(function(d){ return {ok:r.ok,d:d}; }); })
      .then(function(x){ self.disabled=false; if(x.ok){ $('apiKey').value=''; show(true,'Saved.'); loadAi(); } else { show(false,x.d.error||'Save failed'); } })
      .catch(function(e){ self.disabled=false; show(false,String(e)); });
  };
  $('testBtn').onclick=function(){
    this.disabled=true; var self=this; show(true,'Testing…');
    fetch('/api/ai-test',{method:'POST'}).then(function(r){ return r.json().then(function(d){ return {ok:r.ok,d:d}; }); })
      .then(function(x){ self.disabled=false; if(x.ok){ show(true,'Key works. Model replied: '+(x.d.reply||'(ok)')); } else { show(false,x.d.error||'Test failed'); } })
      .catch(function(e){ self.disabled=false; show(false,String(e)); });
  };
  $('scrapeBtn').onclick=function(){
    this.disabled=true; var self=this; show(true,'Scraping all sources… this can take a minute.');
    fetch('/api/tenders/scrape',{method:'POST'}).then(function(r){ return r.json().then(function(d){ return {ok:r.ok,d:d}; }); })
      .then(function(x){ self.disabled=false; if(!x.ok){ show(false,x.d.error||'Scrape failed'); return; }
        var d=x.d; var lines=['Added '+d.added+' tender(s). Total now '+d.total+'. (AI '+(d.aiEnabled?'on':'off')+', threshold '+d.threshold+')'];
        (d.summary||[]).forEach(function(s){ lines.push('• '+s.source+' ['+s.mode+'] — found '+s.found+', added '+s.added+', below-threshold '+(s.belowThreshold||0)+(s.error?(' — '+s.error):'')); });
        show(true,lines.join('\\n'));
      })
      .catch(function(e){ self.disabled=false; show(false,String(e)); });
  };
  loadMail(); loadAi();
</script>
</body></html>`;
app.get('/settings', requireAuth, (req, res) => res.type('html').send(SETTINGS_PAGE));
app.get('/ai', requireAuth, (req, res) => res.redirect('/settings'));

app.get('/', requireAuth, (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));
app.use(express.static(PUBLIC_DIR));
app.listen(PORT, HOST, () => console.log(`leads-it listening on http://${HOST}:${PORT}`));
