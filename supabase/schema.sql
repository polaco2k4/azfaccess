-- SecurePass — schema Postgres para Supabase.
-- Execute isto uma vez no SQL Editor do projeto Supabase (Project -> SQL Editor -> New query).
--
-- Os colaboradores autenticam-se via Supabase Auth (auth.users); esta tabela
-- guarda apenas o perfil de aplicação (nome, departamento, perfil, estado)
-- ligado a auth.users pelo mesmo id (uuid).
--
-- Todas as tabelas têm RLS ativo e SEM políticas: só a service_role key
-- (usada exclusivamente pelo backend Express, nunca exposta ao browser)
-- consegue ler/escrever, porque a service_role ignora RLS. Um pedido feito
-- com a chave anon (ou por um utilizador autenticado a aceder diretamente à
-- API REST do Supabase) é sempre negado.

create extension if not exists pgcrypto;

create table if not exists public.employees (
  id            uuid primary key references auth.users(id) on delete cascade,
  name          text not null,
  email         text not null unique,
  department    text not null default '',
  role          text not null default 'employee' check (role in ('employee','admin')),
  active        boolean not null default true,
  created_at    timestamptz not null default now()
);

create table if not exists public.visitors (
  id              bigint generated always as identity primary key,
  name            text not null,
  document_type   text not null,
  document_number text not null,
  company         text not null default '',
  host_id         uuid not null references public.employees(id),
  document_image  text,
  created_at      timestamptz not null default now()
);

create table if not exists public.passes (
  id          bigint generated always as identity primary key,
  code        uuid not null unique default gen_random_uuid(),
  type        text not null check (type in ('employee','visitor')),
  employee_id uuid references public.employees(id),
  visitor_id  bigint references public.visitors(id),
  purpose     text not null default '',
  valid_from  timestamptz not null,
  valid_until timestamptz not null,
  status      text not null default 'active' check (status in ('active','revoked')),
  created_at  timestamptz not null default now()
);

create table if not exists public.access_logs (
  id         bigint generated always as identity primary key,
  pass_id    bigint references public.passes(id),
  direction  text not null check (direction in ('in','out')),
  result     text not null check (result in ('granted','denied')),
  reason     text not null default '',
  gate       text not null default 'Portaria Principal',
  created_at timestamptz not null default now()
);

create index if not exists idx_passes_code  on public.passes(code);
create index if not exists idx_logs_created on public.access_logs(created_at);

alter table public.employees   enable row level security;
alter table public.visitors    enable row level security;
alter table public.passes      enable row level security;
alter table public.access_logs enable row level security;
