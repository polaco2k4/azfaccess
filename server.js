'use strict';
const path = require('path');
const express = require('express');
const QRCode = require('qrcode');
const db = require('./src/db');
const sec = require('./src/security');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/vendor/jsqr.js', (req, res) =>
  res.sendFile(require.resolve('jsqr/dist/jsQR.js')));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

function currentUser(req) {
  const uid = sec.readSession(getCookie(req, 'sid'));
  if (!uid) return null;
  return db.prepare('SELECT id, name, email, department, role, active FROM employees WHERE id = ? AND active = 1').get(uid) || null;
}

function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'Sessão inválida. Inicie sessão novamente.' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso reservado a administradores.' });
    next();
  });
}

const nowISO = () => new Date().toISOString();

function passWindowState(pass) {
  const now = nowISO();
  if (pass.status === 'revoked') return 'revoked';
  if (now < pass.valid_from) return 'not_yet';
  if (now > pass.valid_until) return 'expired';
  return 'valid';
}

async function qrDataUrl(text) {
  return QRCode.toDataURL(text, { errorCorrectionLevel: 'M', margin: 2, width: 340 });
}

// ---------------------------------------------------------------------------
// Autenticação (colaboradores e administradores)
// ---------------------------------------------------------------------------
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare('SELECT * FROM employees WHERE email = ? AND active = 1').get(String(email || '').trim().toLowerCase());
  if (!user || !sec.verifyPassword(String(password || ''), user.password_hash)) {
    return res.status(401).json({ error: 'Credenciais inválidas.' });
  }
  const token = sec.createSession(user.id);
  res.setHeader('Set-Cookie', `sid=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=43200`);
  res.json({ id: user.id, name: user.name, email: user.email, department: user.department, role: user.role });
});

app.post('/api/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => res.json(req.user));

// ---------------------------------------------------------------------------
// Portal do Colaborador — passes temporários para o próprio
// ---------------------------------------------------------------------------
app.post('/api/passes', requireAuth, (req, res) => {
  const { purpose, hours } = req.body || {};
  const h = Math.min(Math.max(Number(hours) || 8, 1), 24 * 7);
  const from = new Date();
  const until = new Date(from.getTime() + h * 3600 * 1000);
  const code = sec.newPassCode();
  const info = db.prepare(`
    INSERT INTO passes (code, type, employee_id, purpose, valid_from, valid_until)
    VALUES (?, 'employee', ?, ?, ?, ?)
  `).run(code, req.user.id, String(purpose || 'Acesso temporário').slice(0, 200), from.toISOString(), until.toISOString());
  res.json({ id: Number(info.lastInsertRowid), code, valid_from: from.toISOString(), valid_until: until.toISOString() });
});

app.get('/api/passes/mine', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT id, code, purpose, valid_from, valid_until, status, created_at
    FROM passes WHERE employee_id = ? AND type = 'employee'
    ORDER BY created_at DESC LIMIT 50
  `).all(req.user.id);
  res.json(rows.map(r => ({ ...r, state: passWindowState(r) })));
});

app.post('/api/passes/mine/:id/revoke', requireAuth, (req, res) => {
  const info = db.prepare(`UPDATE passes SET status = 'revoked' WHERE id = ? AND employee_id = ?`).run(Number(req.params.id), req.user.id);
  if (!info.changes) return res.status(404).json({ error: 'Passe não encontrado.' });
  res.json({ ok: true });
});

// Visitas em que o colaborador é anfitrião
app.get('/api/host/visits', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT v.id, v.name, v.company, v.document_type, v.document_number, v.created_at,
           p.id AS pass_id, p.status, p.valid_from, p.valid_until,
           (SELECT l.direction FROM access_logs l WHERE l.pass_id = p.id AND l.result = 'granted' ORDER BY l.id DESC LIMIT 1) AS last_move,
           (SELECT COUNT(*) FROM access_logs l WHERE l.pass_id = p.id AND l.direction = 'out' AND l.result = 'granted') AS outs
    FROM visitors v JOIN passes p ON p.visitor_id = v.id
    WHERE v.host_id = ?
    ORDER BY v.created_at DESC LIMIT 50
  `).all(req.user.id);
  res.json(rows.map(r => ({ ...r, state: r.outs >= 1 ? 'used' : passWindowState(r) })));
});

// ---------------------------------------------------------------------------
// QR do passe — devolve o token assinado (estático, válido durante todo o
// período do passe) + imagem do QR. O conhecimento do "code" (UUID opaco)
// do passe é a credencial de obtenção.
// ---------------------------------------------------------------------------
app.get('/api/qr/:code', async (req, res) => {
  const pass = db.prepare('SELECT * FROM passes WHERE code = ?').get(req.params.code);
  if (!pass) return res.status(404).json({ error: 'Passe não encontrado.' });
  const state = passWindowState(pass);
  if (state === 'revoked') return res.status(410).json({ error: 'Este passe foi revogado.' });
  if (state === 'expired') return res.status(410).json({ error: 'Este passe expirou.' });
  const token = sec.issuePassToken(pass.code);
  res.json({
    qr: await qrDataUrl(token),
    valid_until: pass.valid_until,
    type: pass.type,
    state,
  });
});

// ---------------------------------------------------------------------------
// Totem de Auto-Serviço do Visitante (endpoints públicos do quiosque)
// ---------------------------------------------------------------------------
app.get('/api/totem/hosts', (req, res) => {
  const q = `%${String(req.query.q || '').trim()}%`;
  if (q.length < 4) return res.json([]); // exige pelo menos 2 caracteres
  const rows = db.prepare(`
    SELECT id, name, department FROM employees
    WHERE active = 1 AND name LIKE ? ORDER BY name LIMIT 8
  `).all(q);
  res.json(rows);
});

app.post('/api/totem/checkin', (req, res) => {
  const { name, document_type, document_number, company, host_id } = req.body || {};
  if (!String(name || '').trim()) return res.status(400).json({ error: 'Indique o seu nome completo.' });
  if (!String(document_number || '').trim()) return res.status(400).json({ error: 'Indique o número do documento.' });
  const host = db.prepare('SELECT id, name, department FROM employees WHERE id = ? AND active = 1').get(Number(host_id));
  if (!host) return res.status(400).json({ error: 'Selecione o anfitrião que vai visitar.' });

  const vInfo = db.prepare(`
    INSERT INTO visitors (name, document_type, document_number, company, host_id)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    String(name).trim().slice(0, 120),
    ['CC', 'Passaporte', 'Outro'].includes(document_type) ? document_type : 'Outro',
    String(document_number).trim().slice(0, 40),
    String(company || '').trim().slice(0, 120),
    host.id
  );

  const from = new Date();
  const until = new Date(from.getTime() + 8 * 3600 * 1000); // passe de visitante válido 8h
  const code = sec.newPassCode();
  const pInfo = db.prepare(`
    INSERT INTO passes (code, type, visitor_id, purpose, valid_from, valid_until)
    VALUES (?, 'visitor', ?, ?, ?, ?)
  `).run(code, Number(vInfo.lastInsertRowid), `Visita a ${host.name}`, from.toISOString(), until.toISOString());

  res.json({
    pass_id: Number(pInfo.lastInsertRowid),
    code,
    host: host.name,
    valid_until: until.toISOString(),
  });
});

// ---------------------------------------------------------------------------
// Scanner da portaria — valida o token lido do QR e regista o movimento
// ---------------------------------------------------------------------------
app.post('/api/scan', async (req, res) => {
  const { token, direction, gate } = req.body || {};
  // 'in' | 'out' explícitos, ou automático: o mesmo QR alterna entrada/saída
  let dir = direction === 'out' ? 'out' : direction === 'in' ? 'in' : null;
  const gateName = String(gate || 'Portaria Principal').slice(0, 60);

  const deny = (reason, passId = null) => {
    db.prepare(`INSERT INTO access_logs (pass_id, direction, result, reason, gate) VALUES (?, ?, 'denied', ?, ?)`)
      .run(passId, dir || 'in', reason, gateName);
    return res.status(403).json({ result: 'denied', reason });
  };

  const parsed = sec.readPassToken(String(token || ''));
  if (parsed.error) return deny('QR Code inválido ou adulterado (assinatura não confere).');

  const pass = db.prepare('SELECT * FROM passes WHERE code = ?').get(parsed.code);
  if (!pass) return deny('Passe inexistente.');

  const state = passWindowState(pass);
  if (state === 'revoked') return deny('Passe revogado.', pass.id);
  if (state === 'expired') return deny('Passe fora do período de validade (expirado).', pass.id);
  if (state === 'not_yet') return deny('Passe ainda não está dentro do período de validade.', pass.id);

  // Direção automática: se o último movimento autorizado foi uma entrada,
  // esta leitura é uma saída — e vice-versa. O QR é o mesmo nos dois sentidos.
  const lastMove = db.prepare(`
    SELECT direction FROM access_logs
    WHERE pass_id = ? AND result = 'granted'
    ORDER BY id DESC LIMIT 1
  `).get(pass.id);
  if (!dir) dir = lastMove && lastMove.direction === 'in' ? 'out' : 'in';

  // Regras de utilização:
  //  - visitante: o passe vale exatamente 1 entrada e 1 saída
  //  - colaborador: utilizações ilimitadas durante o período de validade
  if (pass.type === 'visitor') {
    const used = db.prepare(`
      SELECT
        COALESCE(SUM(CASE WHEN direction = 'in'  THEN 1 ELSE 0 END), 0) AS ins,
        COALESCE(SUM(CASE WHEN direction = 'out' THEN 1 ELSE 0 END), 0) AS outs
      FROM access_logs WHERE pass_id = ? AND result = 'granted'
    `).get(pass.id);
    if (dir === 'in' && used.ins >= 1) return deny('Passe de visitante já utilizado: a entrada única já foi consumida.', pass.id);
    if (dir === 'out' && used.outs >= 1) return deny('Passe de visitante já utilizado: a saída única já foi consumida.', pass.id);
    if (dir === 'out' && used.ins === 0) return deny('Saída negada: este passe de visitante não tem entrada registada.', pass.id);
  }

  let holder, detail;
  if (pass.type === 'employee') {
    const e = db.prepare('SELECT name, department, active FROM employees WHERE id = ?').get(pass.employee_id);
    if (!e || !e.active) return deny('Colaborador inativo.', pass.id);
    holder = e.name;
    detail = `Colaborador — ${e.department || 's/ departamento'}`;
  } else {
    const v = db.prepare(`
      SELECT v.name, v.company, e.name AS host_name FROM visitors v
      JOIN employees e ON e.id = v.host_id WHERE v.id = ?
    `).get(pass.visitor_id);
    holder = v ? v.name : 'Visitante';
    detail = v ? `Visitante${v.company ? ' — ' + v.company : ''} · Anfitrião: ${v.host_name}` : 'Visitante';
  }

  db.prepare(`INSERT INTO access_logs (pass_id, direction, result, reason, gate) VALUES (?, ?, 'granted', '', ?)`)
    .run(pass.id, dir, gateName);

  res.json({
    result: 'granted',
    direction: dir,
    holder,
    detail,
    type: pass.type,
    purpose: pass.purpose,
    valid_until: pass.valid_until,
  });
});

app.get('/api/scan/recent', (req, res) => {
  const rows = db.prepare(`
    SELECT l.id, l.direction, l.result, l.reason, l.gate, l.created_at,
           COALESCE(e.name, v.name, '—') AS holder, p.type
    FROM access_logs l
    LEFT JOIN passes p ON p.id = l.pass_id
    LEFT JOIN employees e ON e.id = p.employee_id
    LEFT JOIN visitors v ON v.id = p.visitor_id
    ORDER BY l.id DESC LIMIT 15
  `).all();
  res.json(rows);
});

// ---------------------------------------------------------------------------
// Administração
// ---------------------------------------------------------------------------
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  res.json({
    employees: db.prepare('SELECT COUNT(*) c FROM employees WHERE active = 1').get().c,
    active_passes: db.prepare(`SELECT COUNT(*) c FROM passes WHERE status = 'active' AND valid_until > ?`).get(nowISO()).c,
    visitors_today: db.prepare(`SELECT COUNT(*) c FROM visitors WHERE date(created_at) = ?`).get(today).c,
    accesses_today: db.prepare(`SELECT COUNT(*) c FROM access_logs WHERE date(created_at) = ? AND result = 'granted'`).get(today).c,
    denied_today: db.prepare(`SELECT COUNT(*) c FROM access_logs WHERE date(created_at) = ? AND result = 'denied'`).get(today).c,
  });
});

app.get('/api/admin/employees', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT id, name, email, department, role, active, created_at FROM employees ORDER BY name').all());
});

app.post('/api/admin/employees', requireAdmin, (req, res) => {
  const { name, email, password, department, role } = req.body || {};
  if (!String(name || '').trim() || !String(email || '').trim() || !String(password || '')) {
    return res.status(400).json({ error: 'Nome, e-mail e palavra-passe são obrigatórios.' });
  }
  try {
    const info = db.prepare(`
      INSERT INTO employees (name, email, password_hash, department, role)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      String(name).trim(),
      String(email).trim().toLowerCase(),
      sec.hashPassword(String(password)),
      String(department || '').trim(),
      role === 'admin' ? 'admin' : 'employee'
    );
    res.json({ id: Number(info.lastInsertRowid) });
  } catch (e) {
    res.status(400).json({ error: 'E-mail já registado.' });
  }
});

app.post('/api/admin/employees/:id/toggle', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: 'Não pode desativar a sua própria conta.' });
  db.prepare('UPDATE employees SET active = 1 - active WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.get('/api/admin/passes', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT p.id, p.type, p.purpose, p.valid_from, p.valid_until, p.status, p.created_at,
           COALESCE(e.name, v.name) AS holder,
           h.name AS host_name,
           (SELECT COUNT(*) FROM access_logs l WHERE l.pass_id = p.id AND l.direction = 'out' AND l.result = 'granted') AS outs
    FROM passes p
    LEFT JOIN employees e ON e.id = p.employee_id
    LEFT JOIN visitors v ON v.id = p.visitor_id
    LEFT JOIN employees h ON h.id = v.host_id
    ORDER BY p.created_at DESC LIMIT 200
  `).all();
  res.json(rows.map(r => ({ ...r, state: r.type === 'visitor' && r.outs >= 1 ? 'used' : passWindowState(r) })));
});

app.post('/api/admin/passes/:id/revoke', requireAdmin, (req, res) => {
  db.prepare(`UPDATE passes SET status = 'revoked' WHERE id = ?`).run(Number(req.params.id));
  res.json({ ok: true });
});

app.get('/api/admin/logs', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT l.id, l.direction, l.result, l.reason, l.gate, l.created_at, p.type,
           COALESCE(e.name, v.name, '—') AS holder
    FROM access_logs l
    LEFT JOIN passes p ON p.id = l.pass_id
    LEFT JOIN employees e ON e.id = p.employee_id
    LEFT JOIN visitors v ON v.id = p.visitor_id
    ORDER BY l.id DESC LIMIT 300
  `).all();
  res.json(rows);
});

// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`\n  Plataforma de Controlo de Acesso a correr em http://localhost:${PORT}\n`);
  console.log('  Portal do Colaborador : http://localhost:' + PORT + '/portal.html');
  console.log('  Totem do Visitante    : http://localhost:' + PORT + '/totem.html');
  console.log('  Scanner da Portaria   : http://localhost:' + PORT + '/scanner.html');
  console.log('  Administração         : http://localhost:' + PORT + '/admin.html\n');
});
