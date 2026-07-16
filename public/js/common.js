'use strict';

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* sem corpo */ }
  if (!res.ok) throw new Error((data && data.error) || `Erro ${res.status}`);
  return data;
}

function $(sel, root = document) { return root.querySelector(sel); }
function $all(sel, root = document) { return [...root.querySelectorAll(sel)]; }

function showMsg(el, text, kind = 'err') {
  el.textContent = text;
  el.className = `msg show ${kind}`;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = 'msg'; }, 6000);
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso.includes('T') || iso.includes('Z') ? iso : iso.replace(' ', 'T'));
  if (isNaN(d)) return iso;
  return d.toLocaleString('pt-PT', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const STATE_BADGE = {
  valid:   '<span class="badge ok">Ativo</span>',
  expired: '<span class="badge muted">Expirado</span>',
  revoked: '<span class="badge bad">Revogado</span>',
  not_yet: '<span class="badge warn">Agendado</span>',
  used:    '<span class="badge muted">Utilizado</span>',
};

/**
 * Carrega o QR (estático) de um passe para um contentor.
 * O mesmo código é válido durante todo o período de validade do passe.
 */
async function showPassQR(code, imgEl, infoEl, onError) {
  try {
    const data = await api(`/api/qr/${encodeURIComponent(code)}`);
    imgEl.src = data.qr;
    if (infoEl) {
      infoEl.textContent = data.type === 'visitor'
        ? `Válido para 1 entrada e 1 saída, até ${fmtDate(data.valid_until)}`
        : `Entradas e saídas ilimitadas até ${fmtDate(data.valid_until)}`;
    }
  } catch (e) {
    if (onError) onError(e.message);
  }
}
