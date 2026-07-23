'use strict';
const path = require('path');
const express = require('express');
const QRCode = require('qrcode');
const { supabaseAdmin, supabaseAuth, DOCS_BUCKET, ensureDocsBucket } = require('./src/supabaseClient');
const sec = require('./src/security');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '8mb' })); // fotografias de documentos em base64
app.use(express.static(path.join(__dirname, 'public')));
app.use('/vendor/jsqr.js', (req, res) =>
  res.sendFile(require.resolve('jsqr/dist/jsQR.js')));
// OCR local (tesseract.js) para leitura da zona MRZ dos documentos no totem
app.use('/vendor/tesseract', express.static(path.dirname(require.resolve('tesseract.js/dist/tesseract.min.js'))));
app.use('/vendor/tesseract-core', express.static(path.dirname(require.resolve('tesseract.js-core/tesseract-core.wasm.js'))));
app.use('/vendor/chart.js', (req, res) =>
  res.sendFile(path.join(path.dirname(require.resolve('chart.js')), 'chart.umd.js')));

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

const COOKIE_SECURE = process.env.VERCEL ? '; Secure' : '';

function setAuthCookies(res, session) {
  const atMaxAge = Math.max(60, Math.floor(session.expires_in || 3600));
  const rtMaxAge = 60 * 60 * 24 * 30; // 30 dias — a sessão renova-se sozinha enquanto o refresh token for válido
  res.setHeader('Set-Cookie', [
    `sb_at=${encodeURIComponent(session.access_token)}; HttpOnly; Path=/; SameSite=Lax${COOKIE_SECURE}; Max-Age=${atMaxAge}`,
    `sb_rt=${encodeURIComponent(session.refresh_token)}; HttpOnly; Path=/; SameSite=Lax${COOKIE_SECURE}; Max-Age=${rtMaxAge}`,
  ]);
}

function clearAuthCookies(res) {
  res.setHeader('Set-Cookie', [
    `sb_at=; HttpOnly; Path=/; SameSite=Lax${COOKIE_SECURE}; Max-Age=0`,
    `sb_rt=; HttpOnly; Path=/; SameSite=Lax${COOKIE_SECURE}; Max-Age=0`,
  ]);
}

// Autentica pelo cookie sb_at (access token do Supabase Auth); se estiver
// expirado tenta renovar com sb_rt e emite novos cookies. O perfil de
// aplicação (nome, departamento, perfil, estado) vive em public.employees.
async function requireAuth(req, res, next) {
  const invalid = () => res.status(401).json({ error: 'Sessão inválida. Inicie sessão novamente.' });
  try {
    const at = getCookie(req, 'sb_at');
    const rt = getCookie(req, 'sb_rt');
    if (!at) return invalid();

    let userId = null;
    const { data: got } = await supabaseAuth.auth.getUser(at);
    if (got && got.user) {
      userId = got.user.id;
    } else if (rt) {
      const { data: refreshed, error: rErr } = await supabaseAuth.auth.refreshSession({ refresh_token: rt });
      if (rErr || !refreshed.session) return invalid();
      setAuthCookies(res, refreshed.session);
      userId = refreshed.user.id;
    } else {
      return invalid();
    }

    const { data: profile } = await supabaseAdmin
      .from('employees')
      .select('id, name, email, department, role, active')
      .eq('id', userId)
      .eq('active', true)
      .maybeSingle();
    if (!profile) return invalid();
    req.user = profile;
    next();
  } catch {
    invalid();
  }
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

function todayBounds() {
  const now = new Date();
  const start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const end = new Date(start.getTime() + 24 * 3600 * 1000);
  return { start: start.toISOString(), end: end.toISOString() };
}

async function qrDataUrl(text) {
  return QRCode.toDataURL(text, { errorCorrectionLevel: 'M', margin: 2, width: 340 });
}

async function signedDocUrl(storagePath) {
  if (!storagePath) return null;
  const { data, error } = await supabaseAdmin.storage.from(DOCS_BUCKET).createSignedUrl(storagePath, 60);
  return error ? null : data.signedUrl;
}

// ---------------------------------------------------------------------------
// Autenticação (colaboradores e administradores) — via Supabase Auth
// ---------------------------------------------------------------------------
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const emailNorm = String(email || '').trim().toLowerCase();

  const { data, error } = await supabaseAuth.auth.signInWithPassword({ email: emailNorm, password: String(password || '') });
  if (error || !data.session) return res.status(401).json({ error: 'Credenciais inválidas.' });

  const { data: profile } = await supabaseAdmin
    .from('employees')
    .select('id, name, email, department, role, active')
    .eq('id', data.user.id)
    .maybeSingle();
  if (!profile || !profile.active) return res.status(401).json({ error: 'Credenciais inválidas.' });

  setAuthCookies(res, data.session);
  res.json({ id: profile.id, name: profile.name, email: profile.email, department: profile.department, role: profile.role });
});

app.post('/api/auth/logout', (req, res) => {
  clearAuthCookies(res);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => res.json(req.user));

// ---------------------------------------------------------------------------
// Portal do Colaborador — passes temporários para o próprio
// ---------------------------------------------------------------------------
app.post('/api/passes', requireAuth, async (req, res) => {
  const { purpose, hours } = req.body || {};
  const h = Math.min(Math.max(Number(hours) || 8, 1), 24 * 7);
  const from = new Date();
  const until = new Date(from.getTime() + h * 3600 * 1000);
  const code = sec.newPassCode();

  const { data, error } = await supabaseAdmin.from('passes').insert({
    code,
    type: 'employee',
    employee_id: req.user.id,
    purpose: String(purpose || 'Acesso temporário').slice(0, 200),
    valid_from: from.toISOString(),
    valid_until: until.toISOString(),
  }).select('id').single();
  if (error) return res.status(500).json({ error: 'Erro ao criar passe.' });

  res.json({ id: data.id, code, valid_from: from.toISOString(), valid_until: until.toISOString() });
});

app.get('/api/passes/mine', requireAuth, async (req, res) => {
  const { data: rows, error } = await supabaseAdmin
    .from('passes')
    .select('id, code, purpose, valid_from, valid_until, status, created_at')
    .eq('employee_id', req.user.id)
    .eq('type', 'employee')
    .order('created_at', { ascending: false })
    .limit(50);
  if (error) return res.status(500).json({ error: 'Erro ao obter passes.' });
  res.json(rows.map(r => ({ ...r, state: passWindowState(r) })));
});

app.post('/api/passes/mine/:id/revoke', requireAuth, async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('passes')
    .update({ status: 'revoked' })
    .eq('id', Number(req.params.id))
    .eq('employee_id', req.user.id)
    .select('id');
  if (error) return res.status(500).json({ error: 'Erro ao revogar passe.' });
  if (!data.length) return res.status(404).json({ error: 'Passe não encontrado.' });
  res.json({ ok: true });
});

// Visitas em que o colaborador é anfitrião
app.get('/api/host/visits', requireAuth, async (req, res) => {
  const { data: rows, error } = await supabaseAdmin
    .from('visitors')
    .select(`
      id, name, company, document_type, document_number, created_at,
      passes ( id, status, valid_from, valid_until, access_logs ( id, direction, result ) )
    `)
    .eq('host_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(50);
  if (error) return res.status(500).json({ error: 'Erro ao obter visitas.' });

  const out = rows.filter(v => v.passes && v.passes.length).map(v => {
    const p = v.passes[0];
    const granted = p.access_logs.filter(l => l.result === 'granted');
    const outs = granted.filter(l => l.direction === 'out').length;
    const state = outs >= 1 ? 'used' : passWindowState(p);
    return {
      id: v.id, name: v.name, company: v.company, document_type: v.document_type,
      document_number: v.document_number, created_at: v.created_at,
      pass_id: p.id, status: p.status, valid_from: p.valid_from, valid_until: p.valid_until,
      last_move: granted.length ? granted[granted.length - 1].direction : null,
      outs, state,
    };
  });
  res.json(out);
});

// ---------------------------------------------------------------------------
// QR do passe — devolve o token assinado (estático, válido durante todo o
// período do passe) + imagem do QR. O conhecimento do "code" (UUID opaco)
// do passe é a credencial de obtenção.
// ---------------------------------------------------------------------------
app.get('/api/qr/:code', async (req, res) => {
  const { data: pass } = await supabaseAdmin.from('passes').select('*').eq('code', req.params.code).maybeSingle();
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
app.get('/api/totem/hosts', async (req, res) => {
  const q = String(req.query.q || '').trim();
  if (q.length < 2) return res.json([]); // exige pelo menos 2 caracteres
  const { data: rows, error } = await supabaseAdmin
    .from('employees')
    .select('id, name, department')
    .eq('active', true)
    .ilike('name', `%${q}%`)
    .order('name')
    .limit(8);
  if (error) return res.status(500).json({ error: 'Erro ao pesquisar colaboradores.' });
  res.json(rows);
});

app.post('/api/totem/checkin', async (req, res) => {
  const { name, document_type, document_number, company, host_id, document_image } = req.body || {};
  if (!String(name || '').trim()) return res.status(400).json({ error: 'Indique o seu nome completo.' });
  if (!String(document_number || '').trim()) return res.status(400).json({ error: 'Indique o número do documento.' });

  const { data: host } = await supabaseAdmin
    .from('employees').select('id, name, department').eq('id', String(host_id || '')).eq('active', true).maybeSingle();
  if (!host) return res.status(400).json({ error: 'Selecione o anfitrião que vai visitar.' });

  const { data: visitor, error: vErr } = await supabaseAdmin.from('visitors').insert({
    name: String(name).trim().slice(0, 120),
    document_type: ['BI', 'CC', 'Passaporte', 'Outro'].includes(document_type) ? document_type : 'Outro',
    document_number: String(document_number).trim().slice(0, 40),
    company: String(company || '').trim().slice(0, 120),
    host_id: host.id,
  }).select('id').single();
  if (vErr) return res.status(500).json({ error: 'Erro ao registar visitante.' });
  const visitorId = visitor.id;

  // fotografia do documento digitalizada no totem (JPEG em data-URL) -> Supabase Storage
  if (typeof document_image === 'string' && document_image.startsWith('data:image/jpeg;base64,')) {
    try {
      const jpeg = Buffer.from(document_image.slice('data:image/jpeg;base64,'.length), 'base64');
      if (jpeg.length > 0 && jpeg.length <= 5 * 1024 * 1024) {
        const filePath = `v${visitorId}.jpg`;
        const { error: upErr } = await supabaseAdmin.storage.from(DOCS_BUCKET)
          .upload(filePath, jpeg, { contentType: 'image/jpeg', upsert: true });
        if (!upErr) await supabaseAdmin.from('visitors').update({ document_image: filePath }).eq('id', visitorId);
      }
    } catch { /* documento fica sem imagem; o registo manual continua válido */ }
  }

  const from = new Date();
  const until = new Date(from.getTime() + 8 * 3600 * 1000); // passe de visitante válido 8h
  const code = sec.newPassCode();
  const { data: pass, error: pErr } = await supabaseAdmin.from('passes').insert({
    code, type: 'visitor', visitor_id: visitorId, purpose: `Visita a ${host.name}`,
    valid_from: from.toISOString(), valid_until: until.toISOString(),
  }).select('id').single();
  if (pErr) return res.status(500).json({ error: 'Erro ao emitir passe.' });

  res.json({ pass_id: pass.id, code, host: host.name, valid_until: until.toISOString() });
});

// Fotografia do documento — acessível pela portaria através do código opaco
// (UUID) do passe, que só é conhecido após uma leitura de QR válida.
app.get('/api/visitor-doc/:passCode', async (req, res) => {
  const { data: row } = await supabaseAdmin
    .from('passes')
    .select('visitor:visitors!passes_visitor_id_fkey ( document_image )')
    .eq('code', req.params.passCode)
    .eq('type', 'visitor')
    .maybeSingle();
  const url = row && row.visitor ? await signedDocUrl(row.visitor.document_image) : null;
  if (!url) return res.status(404).json({ error: 'Sem documento digitalizado.' });
  res.redirect(url);
});

app.get('/api/admin/visitor-doc/:visitorId', requireAdmin, async (req, res) => {
  const { data: row } = await supabaseAdmin.from('visitors').select('document_image').eq('id', Number(req.params.visitorId)).maybeSingle();
  const url = row ? await signedDocUrl(row.document_image) : null;
  if (!url) return res.status(404).json({ error: 'Sem documento digitalizado.' });
  res.redirect(url);
});

// ---------------------------------------------------------------------------
// Scanner da portaria — valida o token lido do QR e regista o movimento
// ---------------------------------------------------------------------------
app.post('/api/scan', async (req, res) => {
  const { token, direction, gate } = req.body || {};
  // 'in' | 'out' explícitos, ou automático: o mesmo QR alterna entrada/saída
  let dir = direction === 'out' ? 'out' : direction === 'in' ? 'in' : null;
  const gateName = String(gate || 'Portaria Principal').slice(0, 60);

  const deny = async (reason, passId = null) => {
    await supabaseAdmin.from('access_logs').insert({ pass_id: passId, direction: dir || 'in', result: 'denied', reason, gate: gateName });
    return res.status(403).json({ result: 'denied', reason });
  };

  const parsed = sec.readPassToken(String(token || ''));
  if (parsed.error) return deny('QR Code inválido ou adulterado (assinatura não confere).');

  const { data: pass } = await supabaseAdmin.from('passes').select('*').eq('code', parsed.code).maybeSingle();
  if (!pass) return deny('Passe inexistente.');

  const state = passWindowState(pass);
  if (state === 'revoked') return deny('Passe revogado.', pass.id);
  if (state === 'expired') return deny('Passe fora do período de validade (expirado).', pass.id);
  if (state === 'not_yet') return deny('Passe ainda não está dentro do período de validade.', pass.id);

  const { data: grantedLogs } = await supabaseAdmin
    .from('access_logs').select('direction').eq('pass_id', pass.id).eq('result', 'granted').order('id', { ascending: false });
  const logs = grantedLogs || [];

  // Direção automática: se o último movimento autorizado foi uma entrada,
  // esta leitura é uma saída — e vice-versa. O QR é o mesmo nos dois sentidos.
  if (!dir) dir = logs[0] && logs[0].direction === 'in' ? 'out' : 'in';

  // Regras de utilização:
  //  - visitante: o passe vale exatamente 1 entrada e 1 saída
  //  - colaborador: utilizações ilimitadas durante o período de validade
  if (pass.type === 'visitor') {
    const ins = logs.filter(l => l.direction === 'in').length;
    const outs = logs.filter(l => l.direction === 'out').length;
    if (dir === 'in' && ins >= 1) return deny('Passe de visitante já utilizado: a entrada única já foi consumida.', pass.id);
    if (dir === 'out' && outs >= 1) return deny('Passe de visitante já utilizado: a saída única já foi consumida.', pass.id);
    if (dir === 'out' && ins === 0) return deny('Saída negada: este passe de visitante não tem entrada registada.', pass.id);
  }

  let holder, detail, docInfo = null;
  if (pass.type === 'employee') {
    const { data: e } = await supabaseAdmin.from('employees').select('name, department, active').eq('id', pass.employee_id).maybeSingle();
    if (!e || !e.active) return deny('Colaborador inativo.', pass.id);
    holder = e.name;
    detail = `Colaborador — ${e.department || 's/ departamento'}`;
  } else {
    const { data: v } = await supabaseAdmin
      .from('visitors')
      .select('name, company, document_type, document_number, document_image, host:employees!visitors_host_id_fkey ( name )')
      .eq('id', pass.visitor_id)
      .maybeSingle();
    holder = v ? v.name : 'Visitante';
    detail = v ? `Visitante${v.company ? ' — ' + v.company : ''} · Anfitrião: ${v.host.name}` : 'Visitante';
    if (v) {
      docInfo = {
        type: v.document_type,
        number: v.document_number,
        image_url: v.document_image ? `/api/visitor-doc/${pass.code}` : null,
      };
    }
  }

  await supabaseAdmin.from('access_logs').insert({ pass_id: pass.id, direction: dir, result: 'granted', reason: '', gate: gateName });

  res.json({
    result: 'granted',
    direction: dir,
    holder,
    detail,
    type: pass.type,
    purpose: pass.purpose,
    valid_until: pass.valid_until,
    document: docInfo,
  });
});

function mapLogRow(l) {
  const p = l.pass;
  return {
    id: l.id, pass_id: l.pass_id, direction: l.direction, result: l.result, reason: l.reason, gate: l.gate, created_at: l.created_at,
    holder: (p && (p.employee?.name || p.visitor?.name)) || '—',
    type: p ? p.type : null,
  };
}

app.get('/api/scan/recent', async (req, res) => {
  const { data: rows, error } = await supabaseAdmin
    .from('access_logs')
    .select(`
      id, direction, result, reason, gate, created_at,
      pass:passes!access_logs_pass_id_fkey (
        type,
        employee:employees!passes_employee_id_fkey ( name ),
        visitor:visitors!passes_visitor_id_fkey ( name )
      )
    `)
    .order('id', { ascending: false })
    .limit(15);
  if (error) return res.status(500).json({ error: 'Erro ao obter registos.' });
  res.json(rows.map(mapLogRow));
});

// ---------------------------------------------------------------------------
// Administração
// ---------------------------------------------------------------------------
async function countInsideNow() {
  const { data, error } = await supabaseAdmin
    .from('access_logs')
    .select('pass_id, direction')
    .eq('result', 'granted')
    .order('created_at', { ascending: true });
  if (error) throw error;
  const lastDirection = new Map();
  for (const log of data) lastDirection.set(log.pass_id, log.direction);
  return [...lastDirection.values()].filter(d => d === 'in').length;
}

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const { start, end } = todayBounds();
  const count = async (query) => {
    const { count, error } = await query;
    if (error) throw error;
    return count || 0;
  };
  try {
    const [employees, active_passes, visitors_today, accesses_today, denied_today, inside_now] = await Promise.all([
      count(supabaseAdmin.from('employees').select('*', { count: 'exact', head: true }).eq('active', true)),
      count(supabaseAdmin.from('passes').select('*', { count: 'exact', head: true }).eq('status', 'active').gt('valid_until', nowISO())),
      count(supabaseAdmin.from('visitors').select('*', { count: 'exact', head: true }).gte('created_at', start).lt('created_at', end)),
      count(supabaseAdmin.from('access_logs').select('*', { count: 'exact', head: true }).eq('result', 'granted').gte('created_at', start).lt('created_at', end)),
      count(supabaseAdmin.from('access_logs').select('*', { count: 'exact', head: true }).eq('result', 'denied').gte('created_at', start).lt('created_at', end)),
      countInsideNow(),
    ]);
    res.json({ employees, active_passes, visitors_today, accesses_today, denied_today, inside_now });
  } catch {
    res.status(500).json({ error: 'Erro ao obter estatísticas.' });
  }
});

app.get('/api/admin/employees', requireAdmin, async (req, res) => {
  const { data: rows, error } = await supabaseAdmin
    .from('employees').select('id, name, email, department, role, active, created_at').order('name');
  if (error) return res.status(500).json({ error: 'Erro ao obter colaboradores.' });
  res.json(rows);
});

app.post('/api/admin/employees', requireAdmin, async (req, res) => {
  const { name, email, password, department, role } = req.body || {};
  if (!String(name || '').trim() || !String(email || '').trim() || !String(password || '')) {
    return res.status(400).json({ error: 'Nome, e-mail e palavra-passe são obrigatórios.' });
  }
  const emailNorm = String(email).trim().toLowerCase();

  const { data: created, error: authErr } = await supabaseAdmin.auth.admin.createUser({
    email: emailNorm,
    password: String(password),
    email_confirm: true,
  });
  if (authErr || !created.user) return res.status(400).json({ error: 'E-mail já registado.' });

  const { error: dbErr } = await supabaseAdmin.from('employees').insert({
    id: created.user.id,
    name: String(name).trim(),
    email: emailNorm,
    department: String(department || '').trim(),
    role: role === 'admin' ? 'admin' : 'employee',
  });
  if (dbErr) {
    await supabaseAdmin.auth.admin.deleteUser(created.user.id).catch(() => {});
    return res.status(400).json({ error: 'Erro ao criar colaborador.' });
  }
  res.json({ id: created.user.id });
});

app.post('/api/admin/employees/:id/toggle', requireAdmin, async (req, res) => {
  const id = req.params.id;
  if (id === req.user.id) return res.status(400).json({ error: 'Não pode desativar a sua própria conta.' });
  const { data: emp } = await supabaseAdmin.from('employees').select('active').eq('id', id).maybeSingle();
  if (!emp) return res.status(404).json({ error: 'Colaborador não encontrado.' });
  await supabaseAdmin.from('employees').update({ active: !emp.active }).eq('id', id);
  res.json({ ok: true });
});

app.get('/api/admin/passes', requireAdmin, async (req, res) => {
  const { data: rows, error } = await supabaseAdmin
    .from('passes')
    .select(`
      id, type, purpose, valid_from, valid_until, status, created_at,
      employee:employees!passes_employee_id_fkey ( name ),
      visitor:visitors!passes_visitor_id_fkey (
        id, name, document_type, document_number, document_image,
        host:employees!visitors_host_id_fkey ( name )
      ),
      access_logs ( direction, result )
    `)
    .order('created_at', { ascending: false })
    .limit(200);
  if (error) return res.status(500).json({ error: 'Erro ao obter passes.' });

  res.json(rows.map(p => {
    const outs = p.access_logs.filter(l => l.direction === 'out' && l.result === 'granted').length;
    return {
      id: p.id, type: p.type, purpose: p.purpose, valid_from: p.valid_from, valid_until: p.valid_until,
      status: p.status, created_at: p.created_at,
      holder: p.employee?.name || p.visitor?.name || null,
      host_name: p.visitor?.host?.name || null,
      visitor_id: p.visitor?.id ?? null,
      document_type: p.visitor?.document_type ?? null,
      document_number: p.visitor?.document_number ?? null,
      has_doc: !!p.visitor?.document_image,
      state: p.type === 'visitor' && outs >= 1 ? 'used' : passWindowState(p),
    };
  }));
});

app.post('/api/admin/passes/:id/revoke', requireAdmin, async (req, res) => {
  await supabaseAdmin.from('passes').update({ status: 'revoked' }).eq('id', Number(req.params.id));
  res.json({ ok: true });
});

app.get('/api/admin/visitors', requireAdmin, async (req, res) => {
  const { data: rows, error } = await supabaseAdmin
    .from('visitors')
    .select(`
      id, name, company, document_type, document_number, document_image, created_at,
      host:employees!visitors_host_id_fkey ( name ),
      passes ( id, status, valid_from, valid_until, access_logs ( direction, result, created_at ) )
    `)
    .order('created_at', { ascending: false })
    .limit(200);
  if (error) return res.status(500).json({ error: 'Erro ao obter visitantes.' });

  res.json(rows.map(v => {
    const pass = v.passes?.[0] || null;
    const granted = (pass?.access_logs || [])
      .filter(l => l.result === 'granted')
      .sort((a, b) => a.created_at.localeCompare(b.created_at));
    const entry = granted.find(l => l.direction === 'in') || null;
    const exit = granted.find(l => l.direction === 'out') || null;
    const dwell_minutes = entry && exit ? Math.round((new Date(exit.created_at) - new Date(entry.created_at)) / 60000) : null;

    let state;
    if (!pass) state = 'no_pass';
    else if (pass.status === 'revoked') state = 'revoked';
    else if (entry && exit) state = 'left';
    else if (entry && !exit) state = 'inside';
    else state = passWindowState(pass) === 'expired' ? 'expired' : 'pending';

    return {
      id: v.id, name: v.name, company: v.company,
      document_type: v.document_type, document_number: v.document_number, has_doc: !!v.document_image,
      host_name: v.host?.name || null,
      created_at: v.created_at,
      entry_at: entry?.created_at || null,
      exit_at: exit?.created_at || null,
      dwell_minutes,
      pass_id: pass?.id ?? null,
      state,
    };
  }));
});

app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  const { data: rows, error } = await supabaseAdmin
    .from('access_logs')
    .select(`
      id, direction, result, reason, gate, created_at,
      pass:passes!access_logs_pass_id_fkey (
        type,
        employee:employees!passes_employee_id_fkey ( name ),
        visitor:visitors!passes_visitor_id_fkey ( name )
      )
    `)
    .order('id', { ascending: false })
    .limit(300);
  if (error) return res.status(500).json({ error: 'Erro ao obter registos.' });
  res.json(rows.map(mapLogRow));
});

function reportBounds(from, to) {
  const start = from && !isNaN(new Date(from)) ? new Date(from) : new Date(Date.now() - 30 * 24 * 3600 * 1000);
  const endBase = to && !isNaN(new Date(to)) ? new Date(to) : new Date();
  const end = new Date(endBase.getFullYear(), endBase.getMonth(), endBase.getDate() + 1);
  return { start: start.toISOString(), end: end.toISOString() };
}

// Tempo de permanência dos visitantes: calculado à parte dos filtros de
// tipo/resultado/movimento do relatório principal (senão, p.ex. filtrar por
// "Movimento: Saída" eliminava as entradas e quebrava o pareamento entrada/saída).
// Respeita apenas o intervalo de datas e a portaria.
async function computeVisitorDwell(start, end, gate) {
  let query = supabaseAdmin
    .from('access_logs')
    .select('pass_id, direction, created_at, pass:passes!access_logs_pass_id_fkey!inner(type)')
    .eq('result', 'granted')
    .eq('pass.type', 'visitor')
    .gte('created_at', start)
    .lt('created_at', end)
    .order('created_at', { ascending: true })
    .limit(2000);
  if (String(gate || '').trim()) query = query.ilike('gate', `%${String(gate).trim()}%`);

  const { data, error } = await query;
  if (error || !data) return { avg_dwell_minutes: null, dwell_by_day: [], byPassId: new Map() };

  const byPass = new Map();
  for (const r of data) {
    if (!byPass.has(r.pass_id)) byPass.set(r.pass_id, {});
    const v = byPass.get(r.pass_id);
    if (r.direction === 'in' && !v.in) v.in = r.created_at;
    if (r.direction === 'out' && !v.out) v.out = r.created_at;
  }

  const completed = [];
  for (const [passId, v] of byPass) {
    if (v.in && v.out) {
      const minutes = (new Date(v.out) - new Date(v.in)) / 60000;
      if (minutes >= 0) completed.push({ pass_id: passId, minutes, day: v.in.slice(0, 10) });
    }
  }

  const avg_dwell_minutes = completed.length
    ? completed.reduce((s, c) => s + c.minutes, 0) / completed.length
    : null;

  const byDayMap = {};
  for (const c of completed) {
    if (!byDayMap[c.day]) byDayMap[c.day] = { date: c.day, total_minutes: 0, visits: 0 };
    byDayMap[c.day].total_minutes += c.minutes;
    byDayMap[c.day].visits++;
  }
  const dwell_by_day = Object.values(byDayMap)
    .map(d => ({ date: d.date, avg_dwell_minutes: d.total_minutes / d.visits, visits: d.visits }))
    .sort((a, b) => a.date.localeCompare(b.date));

  const byPassId = new Map(completed.map(c => [c.pass_id, c.minutes]));
  return { avg_dwell_minutes, dwell_by_day, byPassId };
}

app.get('/api/admin/reports', requireAdmin, async (req, res) => {
  const { from, to, type, result, direction, gate } = req.query;
  const { start, end } = reportBounds(from, to);

  let query = supabaseAdmin
    .from('access_logs')
    .select(`
      id, pass_id, direction, result, reason, gate, created_at,
      pass:passes!access_logs_pass_id_fkey!inner (
        type,
        employee:employees!passes_employee_id_fkey ( id, name ),
        visitor:visitors!passes_visitor_id_fkey (
          id, name,
          host:employees!visitors_host_id_fkey ( name )
        )
      )
    `)
    .gte('created_at', start)
    .lt('created_at', end)
    .order('created_at', { ascending: false })
    .limit(1000);

  if (type === 'employee' || type === 'visitor') query = query.eq('pass.type', type);
  if (result === 'granted' || result === 'denied') query = query.eq('result', result);
  if (direction === 'in' || direction === 'out') query = query.eq('direction', direction);
  if (String(gate || '').trim()) query = query.ilike('gate', `%${String(gate).trim()}%`);

  const [{ data: rows, error }, dwell] = await Promise.all([
    query,
    computeVisitorDwell(start, end, gate),
  ]);
  if (error) return res.status(500).json({ error: 'Erro ao gerar relatório.' });

  const mapped = rows.map(mapLogRow);
  for (const r of mapped) {
    if (r.direction === 'out' && dwell.byPassId.has(r.pass_id)) {
      r.dwell_minutes = Math.round(dwell.byPassId.get(r.pass_id));
    }
  }

  const summary = {
    total: mapped.length,
    granted: mapped.filter(r => r.result === 'granted').length,
    denied: mapped.filter(r => r.result === 'denied').length,
    visits: new Set(rows.filter(r => r.pass?.type === 'visitor' && r.pass.visitor?.id).map(r => r.pass.visitor.id)).size,
    unique_employees: new Set(rows.filter(r => r.pass?.type === 'employee' && r.pass.employee?.id).map(r => r.pass.employee.id)).size,
    avg_dwell_minutes: dwell.avg_dwell_minutes,
  };

  const byDayMap = {};
  for (const r of mapped) {
    const day = r.created_at.slice(0, 10);
    if (!byDayMap[day]) byDayMap[day] = { date: day, total: 0, granted: 0, denied: 0 };
    byDayMap[day].total++;
    byDayMap[day][r.result]++;
  }
  const by_day = Object.values(byDayMap).sort((a, b) => b.date.localeCompare(a.date));

  const byHourMap = {};
  for (const r of mapped) {
    const h = new Date(r.created_at).getHours();
    if (!byHourMap[h]) byHourMap[h] = { hour: h, total: 0, granted: 0, denied: 0 };
    byHourMap[h].total++;
    byHourMap[h][r.result]++;
  }
  const by_hour = Array.from({ length: 24 }, (_, h) => byHourMap[h] || { hour: h, total: 0, granted: 0, denied: 0 });

  const hostCounts = {};
  for (const r of rows) {
    if (r.pass?.type === 'visitor' && r.direction === 'in' && r.result === 'granted') {
      const name = r.pass.visitor?.host?.name || 'Sem anfitrião';
      hostCounts[name] = (hostCounts[name] || 0) + 1;
    }
  }
  const top_hosts = Object.entries(hostCounts)
    .map(([name, visits]) => ({ name, visits }))
    .sort((a, b) => b.visits - a.visits)
    .slice(0, 8);

  res.json({ summary, by_day, by_hour, top_hosts, dwell_by_day: dwell.dwell_by_day, rows: mapped.slice(0, 500) });
});

// ---------------------------------------------------------------------------
ensureDocsBucket().catch(e => console.error('Aviso: não foi possível preparar o bucket de Storage:', e.message));

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`\n  Plataforma de Controlo de Acesso a correr em http://localhost:${PORT}\n`);
    console.log('  Portal do Colaborador : http://localhost:' + PORT + '/portal.html');
    console.log('  Totem do Visitante    : http://localhost:' + PORT + '/totem.html');
    console.log('  Scanner da Portaria   : http://localhost:' + PORT + '/scanner.html');
    console.log('  Administração         : http://localhost:' + PORT + '/admin.html\n');
  });
}

module.exports = app;
