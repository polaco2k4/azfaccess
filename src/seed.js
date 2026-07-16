'use strict';
// Popula a base de dados com contas de demonstração (idempotente).
const db = require('./db');
const sec = require('./security');

const users = [
  ['Administrador do Sistema', 'admin@empresa.com',  'admin123',  'Segurança',        'admin'],
  ['Ana Ferreira',             'ana@empresa.com',    'ana123',    'Recursos Humanos', 'employee'],
  ['Bruno Costa',              'bruno@empresa.com',  'bruno123',  'Engenharia',       'employee'],
  ['Carla Mendes',             'carla@empresa.com',  'carla123',  'Financeiro',       'employee'],
  ['Diogo Santos',             'diogo@empresa.com',  'diogo123',  'Comercial',        'employee'],
];

const insert = db.prepare(`
  INSERT INTO employees (name, email, password_hash, department, role)
  VALUES (?, ?, ?, ?, ?)
`);
const exists = db.prepare('SELECT 1 FROM employees WHERE email = ?');

let created = 0;
for (const [name, email, pwd, dept, role] of users) {
  if (exists.get(email)) continue;
  insert.run(name, email, sec.hashPassword(pwd), dept, role);
  created++;
}

console.log(created ? `Criadas ${created} contas de demonstração.` : 'Contas de demonstração já existem.');
console.log('\nCredenciais:');
for (const [name, email, pwd, , role] of users) {
  console.log(`  ${role === 'admin' ? '[ADMIN]      ' : '[COLABORADOR]'} ${email} / ${pwd}  (${name})`);
}
