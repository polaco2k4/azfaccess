'use strict';
// Popula o Supabase com contas de demonstração (idempotente).
// Cria o utilizador no Supabase Auth e o respetivo perfil em public.employees.
const { supabaseAdmin } = require('./supabaseClient');

const users = [
  ['Administrador do Sistema', 'admin@empresa.com',  'admin123',  'Segurança',        'admin'],
  ['Ana Ferreira',             'ana@empresa.com',    'ana123',    'Recursos Humanos', 'employee'],
  ['Bruno Costa',              'bruno@empresa.com',  'bruno123',  'Engenharia',       'employee'],
  ['Carla Mendes',             'carla@empresa.com',  'carla123',  'Financeiro',       'employee'],
  ['Diogo Santos',             'diogo@empresa.com',  'diogo123',  'Comercial',        'employee'],
];

async function main() {
  let created = 0;
  for (const [name, email, pwd, dept, role] of users) {
    const { data: existing } = await supabaseAdmin.from('employees').select('id').eq('email', email).maybeSingle();
    if (existing) continue;

    const { data: authUser, error: authErr } = await supabaseAdmin.auth.admin.createUser({
      email,
      password: pwd,
      email_confirm: true,
    });
    if (authErr) {
      console.error(`Falha ao criar utilizador Auth para ${email}:`, authErr.message);
      continue;
    }

    const { error: dbErr } = await supabaseAdmin.from('employees').insert({
      id: authUser.user.id,
      name,
      email,
      department: dept,
      role,
    });
    if (dbErr) {
      console.error(`Falha ao criar perfil para ${email}:`, dbErr.message);
      await supabaseAdmin.auth.admin.deleteUser(authUser.user.id).catch(() => {});
      continue;
    }
    created++;
  }

  console.log(created ? `Criadas ${created} contas de demonstração.` : 'Contas de demonstração já existem.');
  console.log('\nCredenciais:');
  for (const [name, email, pwd, , role] of users) {
    console.log(`  ${role === 'admin' ? '[ADMIN]      ' : '[COLABORADOR]'} ${email} / ${pwd}  (${name})`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
