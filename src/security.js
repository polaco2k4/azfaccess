'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Segredo do servidor (gerado no primeiro arranque e persistido em data/)
// ---------------------------------------------------------------------------
const DATA_DIR = path.join(__dirname, '..', 'data');
const KEY_FILE = path.join(DATA_DIR, 'secret.key');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(KEY_FILE)) {
  fs.writeFileSync(KEY_FILE, crypto.randomBytes(48).toString('hex'), { encoding: 'utf8' });
}
const SECRET = Buffer.from(fs.readFileSync(KEY_FILE, 'utf8').trim(), 'hex');

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const hmac = (data) => crypto.createHmac('sha256', SECRET).update(data).digest('base64url');

// ---------------------------------------------------------------------------
// Palavras-passe (scrypt)
// ---------------------------------------------------------------------------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 32).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const candidate = crypto.scryptSync(password, salt, 32).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(candidate, 'hex'));
}

// ---------------------------------------------------------------------------
// Tokens genéricos assinados: base64url(json).assinatura
// ---------------------------------------------------------------------------
function sign(payload) {
  const body = b64url(JSON.stringify(payload));
  return `${body}.${hmac(body)}`;
}

function verify(token) {
  if (typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = hmac(body);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Sessões (cookie assinado, 12 horas)
// ---------------------------------------------------------------------------
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

function createSession(employeeId) {
  return sign({ k: 'sess', uid: employeeId, exp: Date.now() + SESSION_TTL_MS });
}

function readSession(token) {
  const p = verify(token);
  if (!p || p.k !== 'sess' || typeof p.uid !== 'number') return null;
  if (Date.now() > p.exp) return null;
  return p.uid;
}

// ---------------------------------------------------------------------------
// Tokens de passe (conteúdo do QR Code) — estáticos e assinados.
// O mesmo QR é válido durante todo o período de validade do passe; a data
// de expiração, o estado (revogado) e o limite de utilizações são sempre
// verificados na base de dados no momento da leitura.
// ---------------------------------------------------------------------------
function issuePassToken(passCode) {
  return sign({ k: 'pass', c: passCode });
}

function readPassToken(token) {
  const p = verify(token);
  if (!p || p.k !== 'pass' || typeof p.c !== 'string') return { error: 'invalid' };
  return { code: p.c };
}

module.exports = {
  hashPassword,
  verifyPassword,
  createSession,
  readSession,
  issuePassToken,
  readPassToken,
  newPassCode: () => crypto.randomUUID(),
};
