# 🛡️ SecurePass — Plataforma de Gestão e Controlo de Acesso Físico

Plataforma integrada para gerir com segurança a entrada e saída de **colaboradores** e **visitantes** em edifícios corporativos, através de **passes digitais com QR Codes dinâmicos assinados criptograficamente**.

## Módulos

| Módulo | URL | Descrição |
|---|---|---|
| Página inicial | `http://localhost:3000/` | Acesso a todos os módulos |
| Portal do Colaborador | `/portal.html` | O colaborador autentica-se e gera QR Codes de acesso temporários para si mesmo (1h a 3 dias), consulta e revoga os seus passes, e vê as visitas de que é anfitrião |
| Totem do Visitante | `/totem.html` | Quiosque de auto-registo: o visitante **digitaliza o documento de identificação com a câmara** (a zona MRZ é lida por OCR local e o nome/número são pré-preenchidos; a fotografia fica arquivada), pesquisa e seleciona o anfitrião, e recebe no momento um passe com QR Code (válido 8h, 1 entrada + 1 saída) |
| Scanner da Portaria | `/scanner.html` | Leitura de QR por câmara (ou validação manual), resultado visual e sonoro, e registo de movimentos em tempo real. O mesmo QR serve para entrada e saída: no modo automático a primeira leitura regista a entrada e a seguinte a saída (com forçagem manual opcional) |
| Administração | `/admin.html` | Estatísticas, registo completo de acessos, gestão de passes (revogação) e gestão de colaboradores (criação/desativação) |

## Segurança e regras dos passes

- O QR Code **não contém dados pessoais** — apenas um token assinado com **HMAC-SHA256** por um segredo do servidor (gerado no primeiro arranque em `data/secret.key`).
- O QR é **estático**: o mesmo código vale durante todo o período de validade do passe e serve tanto para a entrada como para a saída. O visitante pode fotografá-lo no totem.
- **Regras de utilização**: passe de **visitante** vale exatamente **1 entrada + 1 saída** (leituras adicionais são negadas e registadas); passe de **colaborador** permite **entradas/saídas ilimitadas** dentro da validade.
- Qualquer adulteração do token invalida a assinatura e o acesso é negado (e registado).
- Passes podem ser **revogados** a qualquer momento pelo próprio colaborador ou pelo administrador, com efeito imediato.
- Login e sessões dos colaboradores são geridos pelo **Supabase Auth** (e-mail + palavra-passe); as fotografias dos documentos ficam no **Supabase Storage** (bucket privado, acesso por URL assinada e temporária).
- Todas as tentativas de acesso — autorizadas e negadas, com o motivo — ficam no registo de auditoria (Postgres, no Supabase).

## Como executar

1. Crie um projeto em [supabase.com](https://supabase.com) (ou use um já existente).
2. Em **SQL Editor**, execute o conteúdo de [`supabase/schema.sql`](supabase/schema.sql) para criar as tabelas (`employees`, `visitors`, `passes`, `access_logs`).
3. Em **Project Settings → API**, copie a `Project URL`, a chave `anon` e a chave `service_role`.
4. Copie `.env.example` para `.env` e preencha `SUPABASE_URL`, `SUPABASE_ANON_KEY` e `SUPABASE_SERVICE_ROLE_KEY`.

```bash
npm install     # instalar dependências (express, qrcode, jsqr, @supabase/supabase-js)
npm run seed    # criar contas de demonstração no Supabase Auth + tabela employees
npm start       # arrancar em http://localhost:3000
```

> O bucket de Storage `visitor-docs` (privado) é criado automaticamente no arranque do servidor, caso não exista.
> A `service_role key` tem acesso total à base de dados e nunca deve ser exposta ao browser — é usada apenas no backend.

## Contas de demonstração

| Perfil | E-mail | Palavra-passe |
|---|---|---|
| Administrador | admin@empresa.com | admin123 |
| Colaboradora (RH) | ana@empresa.com | ana123 |
| Colaborador (Engenharia) | bruno@empresa.com | bruno123 |
| Colaboradora (Financeiro) | carla@empresa.com | carla123 |
| Colaborador (Comercial) | diogo@empresa.com | diogo123 |

## Fluxos principais

**Colaborador** — entra no Portal → gera passe temporário (motivo + validade) → apresenta o QR dinâmico no scanner da portaria → entrada registada.

**Visitante** — no totem da receção: digitaliza o documento (OCR preenche nome e número automaticamente; a foto fica arquivada) → pesquisa o anfitrião → passe emitido no ecrã → passa na portaria, onde o segurança vê a foto do documento para conferência → o anfitrião vê no seu portal que o visitante está no edifício.

> A leitura automática usa **tesseract.js servido localmente** (sem chamadas a serviços externos) e interpreta a zona MRZ — ICAO 9303, formatos TD1 (cartões de identificação) e TD3 (passaportes). Se a leitura falhar, os campos preenchem-se manualmente e a fotografia fica na mesma arquivada.

**Portaria** — abre o scanner → escolhe Entrada ou Saída → aponta a câmara ao QR → o sistema valida assinatura, validade e estado do passe e regista o movimento.

## Estrutura

```
server.js               # API Express + rotas
src/supabaseClient.js   # clientes Supabase (admin/service_role e anon) + bucket de Storage
src/security.js         # HMAC e tokens assinados do QR do passe
src/seed.js             # contas de demonstração (Supabase Auth + tabela employees)
supabase/schema.sql     # esquema Postgres a executar no projeto Supabase
public/                 # frontends (portal, totem, scanner, admin)
data/                   # segredo local do HMAC (data/secret.key, criado no arranque)
```
