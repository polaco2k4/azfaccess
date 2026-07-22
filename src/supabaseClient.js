'use strict';
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const { SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY } = process.env;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error(
    'Configuração do Supabase incompleta. Defina SUPABASE_URL, SUPABASE_ANON_KEY e ' +
    'SUPABASE_SERVICE_ROLE_KEY num ficheiro .env (ver .env.example).'
  );
}

// Cliente com a service_role key: usado por todo o backend para aceder à
// base de dados, ao Storage e à Admin API do Auth. Ignora RLS — nunca deve
// ser exposto ao browser.
const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

// Cliente com a chave anon: usado apenas para operações de autenticação de
// utilizador final (login, refresh de sessão) que devem passar pelo GoTrue
// como um utilizador normal, não como administrador.
const supabaseAuth = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const DOCS_BUCKET = 'visitor-docs';

async function ensureDocsBucket() {
  const { data: buckets, error } = await supabaseAdmin.storage.listBuckets();
  if (error) throw error;
  if (buckets.some((b) => b.name === DOCS_BUCKET)) return;
  const { error: createErr } = await supabaseAdmin.storage.createBucket(DOCS_BUCKET, { public: false });
  if (createErr) throw createErr;
}

module.exports = { supabaseAdmin, supabaseAuth, DOCS_BUCKET, ensureDocsBucket };
