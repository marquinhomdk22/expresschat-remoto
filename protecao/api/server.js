'use strict'
// ExpressChat Proteção — servidor de regras + ponte com os agentes.
// Guarda regras por loja/setor/PC, entrega a configuração para o agente Windows
// e recebe heartbeat/relatórios. Autentica o painel reusando o login do RustDesk.

const express = require('express')
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

const PORT = process.env.PORT || 3000
const DATA_DIR = process.env.DATA_DIR || '/data'
const DB_FILE = path.join(DATA_DIR, 'db.json')
// Base interna do painel RustDesk, para validar o token do admin.
const RUSTDESK_API_BASE = (process.env.RUSTDESK_API_BASE || 'http://remoto-painel:21114').replace(/\/+$/, '')
const PANEL_ORIGINS = (process.env.PANEL_ORIGINS || 'https://painel-remoto.link-br.site').split(',').map(s => s.trim())

// ---------- armazenamento simples em arquivo JSON ----------
const EMPTY = { tenants: {}, devices: {}, events: {} }
let db = structuredClone(EMPTY)
function load () {
  try { db = Object.assign(structuredClone(EMPTY), JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))) } catch (_) { db = structuredClone(EMPTY) }
}
let saveTimer = null
function save () {
  if (saveTimer) return
  saveTimer = setTimeout(() => {
    saveTimer = null
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true })
      const tmp = DB_FILE + '.tmp'
      fs.writeFileSync(tmp, JSON.stringify(db))
      fs.renameSync(tmp, DB_FILE)
    } catch (e) { console.error('save error', e.message) }
  }, 300)
}
load()

function tenant (id) {
  if (!db.tenants[id]) {
    db.tenants[id] = { id, enrollToken: 'ec_' + crypto.randomBytes(9).toString('hex'), rules: {} }
    save()
  }
  return db.tenants[id]
}
const rid = () => crypto.randomBytes(8).toString('hex')
const now = () => Date.now()

// ---------- app ----------
const BASE_PATH = (process.env.BASE_PATH || '').replace(/\/+$/, '') // ex.: /ec-protecao
const root = express()
const app = express.Router()
root.disable('x-powered-by')
root.use(BASE_PATH || '/', app)
app.use(express.json({ limit: '512kb' }))
app.use((req, res, next) => {
  const o = req.headers.origin
  if (o && PANEL_ORIGINS.includes(o)) {
    res.setHeader('Access-Control-Allow-Origin', o)
    res.setHeader('Vary', 'Origin')
    res.setHeader('Access-Control-Allow-Headers', 'content-type,x-ec-token')
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204)
  next()
})
app.get('/health', (_req, res) => res.json({ ok: true }))

// ---------- auth do painel: valida o api-token no RustDesk ----------
const tokenCache = new Map() // token -> { user, exp }
async function authAdmin (req, res, next) {
  const token = req.headers['x-ec-token']
  if (!token) return res.status(401).json({ error: 'sem token' })
  const c = tokenCache.get(token)
  if (c && c.exp > now()) { req.user = c.user; req.tenant = tenant(String(c.user.id)); return next() }
  try {
    const r = await fetch(RUSTDESK_API_BASE + '/api/admin/user/current', { headers: { 'api-token': token } })
    const j = await r.json().catch(() => ({}))
    const user = j && (j.data || (j.id ? j : null))
    if (!r.ok || !user || !user.id) return res.status(401).json({ error: 'token inválido' })
    tokenCache.set(token, { user, exp: now() + 60000 })
    req.user = user
    req.tenant = tenant(String(user.id))
    next()
  } catch (e) {
    res.status(502).json({ error: 'não deu para validar o login' })
  }
}

// ---------- regras ----------
const DEFAULT_RULE = {
  blockInstall: false, installAllow: [],
  blockSites: false, sitesMode: 'block', sitesList: [],
  adultBlock: false, forceStandardUser: false,
}
const scopeKey = (scope, key) => scope === 'global' ? 'global' : `${scope}:${key}`
function getRule (t, scope, key) {
  return Object.assign({}, DEFAULT_RULE, t.rules[scopeKey(scope, key)]?.data || {})
}
// resolução: global < loja < setor < pc (o mais específico vence por campo definido)
function effectiveRule (t, dev) {
  const layers = [
    t.rules['global'],
    dev.storeName ? t.rules[scopeKey('store', dev.storeName)] : null,
    (dev.storeName && dev.sector) ? t.rules[scopeKey('sector', dev.storeName + ' / ' + dev.sector)] : null,
    t.rules[scopeKey('pc', dev.id)],
  ]
  const out = Object.assign({}, DEFAULT_RULE)
  for (const l of layers) if (l && l.data) Object.assign(out, l.data)
  return out
}

// ---------- endpoints do painel ----------
app.get('/admin/me', authAdmin, (req, res) => {
  res.json({ user: { id: req.user.id, username: req.user.username }, enrollToken: req.tenant.enrollToken })
})

app.get('/admin/rules', authAdmin, (req, res) => {
  const { scope = 'global', key = '' } = req.query
  res.json({ rule: getRule(req.tenant, scope, key), raw: req.tenant.rules[scopeKey(scope, key)] || null })
})

app.post('/admin/rules', authAdmin, (req, res) => {
  const { scope = 'global', key = '', data = {} } = req.body || {}
  if (!['global', 'store', 'sector', 'pc'].includes(scope)) return res.status(400).json({ error: 'scope inválido' })
  const clean = Object.assign({}, DEFAULT_RULE)
  for (const k of Object.keys(DEFAULT_RULE)) if (k in data) clean[k] = data[k]
  clean.installAllow = (clean.installAllow || []).slice(0, 200).map(String)
  clean.sitesList = (clean.sitesList || []).slice(0, 2000).map(String)
  req.tenant.rules[scopeKey(scope, key)] = { scope, key, data: clean, updatedAt: now(), by: req.user.username }
  save()
  res.json({ ok: true, rule: clean })
})

app.get('/admin/overview', authAdmin, (req, res) => {
  const t = req.tenant
  const list = Object.values(db.devices).filter(d => d.tenant === t.id)
  const online = (d) => d.lastSeen && now() - d.lastSeen < 120000
  const released = (d) => d.release && d.release.until > now()
  let installsToday = 0, sitesToday = 0
  const dayStart = new Date(); dayStart.setHours(0, 0, 0, 0)
  for (const d of list) {
    installsToday += d.stats?.installsBlockedToday || 0
    sitesToday += d.stats?.sitesBlockedToday || 0
  }
  res.json({
    kpis: {
      protected: list.filter(d => { const r = effectiveRule(t, d); return r.blockInstall || r.blockSites || r.adultBlock }).length,
      installsToday, sitesToday,
      releasesActive: list.filter(released).length,
    },
    devices: list.map(d => ({
      id: d.id, hostname: d.hostname, peerId: d.peerId, storeName: d.storeName || '', sector: d.sector || '',
      online: online(d), lastSeen: d.lastSeen || 0,
      release: released(d) ? d.release.until : 0,
      stats: d.stats || {}, agentVersion: d.agentVersion || '',
    })),
  })
})

app.post('/admin/device/assign', authAdmin, (req, res) => {
  const { deviceId, storeName = '', sector = '' } = req.body || {}
  const d = db.devices[deviceId]
  if (!d || d.tenant !== req.tenant.id) return res.status(404).json({ error: 'computador não encontrado' })
  d.storeName = String(storeName); d.sector = String(sector); save()
  res.json({ ok: true })
})

app.post('/admin/release', authAdmin, (req, res) => {
  const { deviceId, minutes } = req.body || {}
  const d = db.devices[deviceId]
  if (!d || d.tenant !== req.tenant.id) return res.status(404).json({ error: 'computador não encontrado' })
  if (minutes === 0) d.release = null
  else d.release = { until: now() + Math.min(Number(minutes) || 30, 24 * 60) * 60000, by: req.user.username }
  save()
  res.json({ ok: true, release: d.release })
})

app.get('/admin/events', authAdmin, (req, res) => {
  const ev = (db.events[req.tenant.id] || []).slice(-200).reverse()
  res.json({ events: ev })
})

// ---------- endpoints do agente ----------
app.post('/agent/enroll', (req, res) => {
  const { enrollToken, guid, hostname = '', peerId = '', agentVersion = '' } = req.body || {}
  const t = Object.values(db.tenants).find(x => x.enrollToken === enrollToken)
  if (!t) return res.status(401).json({ error: 'token de instalação inválido' })
  let dev = Object.values(db.devices).find(d => d.tenant === t.id && d.guid === guid)
  if (!dev) {
    dev = { id: rid(), tenant: t.id, guid: guid || rid(), token: 'tok_' + crypto.randomBytes(12).toString('hex'), createdAt: now(), stats: {} }
    db.devices[dev.id] = dev
  }
  dev.hostname = String(hostname).slice(0, 120)
  dev.peerId = String(peerId).slice(0, 40)
  dev.agentVersion = String(agentVersion).slice(0, 20)
  dev.lastSeen = now()
  // auto-vincula à loja pelo hostname igual ao de um PC já batizado, se houver (apenas sugestão)
  save()
  res.json({ deviceId: dev.id, token: dev.token })
})

function agentAuth (req) {
  const deviceId = req.query.device || req.body?.device
  const token = req.query.token || req.body?.token
  const d = db.devices[deviceId]
  if (!d || d.token !== token) return null
  return d
}

app.get('/agent/config', (req, res) => {
  const d = agentAuth(req)
  if (!d) return res.status(401).json({ error: 'agente não autorizado' })
  d.lastSeen = now(); save()
  const t = db.tenants[d.tenant]
  const rule = effectiveRule(t, d)
  const releaseUntil = d.release && d.release.until > now() ? d.release.until : 0
  res.json({
    pollSeconds: 30,
    release: releaseUntil,                 // enquanto > agora, o agente NÃO bloqueia
    active: !!(rule.blockInstall || rule.blockSites || rule.adultBlock || rule.forceStandardUser),
    rules: rule,
    neverKill: ['ExpressChatRemoto.exe', 'ExpressChatProtecao.exe'],
    serverTime: now(),
  })
})

app.post('/agent/report', (req, res) => {
  const d = agentAuth(req)
  if (!d) return res.status(401).json({ error: 'agente não autorizado' })
  const { events = [], counters = {}, hostname, peerId, agentVersion } = req.body || {}
  d.lastSeen = now()
  if (hostname) d.hostname = String(hostname).slice(0, 120)
  if (peerId) d.peerId = String(peerId).slice(0, 40)
  if (agentVersion) d.agentVersion = String(agentVersion).slice(0, 20)
  d.stats = Object.assign({}, d.stats, {
    installsBlockedToday: Number(counters.installsBlockedToday) || d.stats?.installsBlockedToday || 0,
    sitesBlockedToday: Number(counters.sitesBlockedToday) || d.stats?.sitesBlockedToday || 0,
  })
  if (Array.isArray(events) && events.length) {
    const arr = db.events[d.tenant] || (db.events[d.tenant] = [])
    for (const e of events.slice(0, 50)) {
      arr.push({ at: now(), device: d.id, hostname: d.hostname, type: String(e.type || '').slice(0, 20), detail: String(e.detail || '').slice(0, 200) })
    }
    while (arr.length > 2000) arr.shift()
  }
  save()
  res.json({ ok: true })
})

root.listen(PORT, () => console.log('ExpressChat Proteção API na porta ' + PORT + ' base=' + (BASE_PATH || '/')))
