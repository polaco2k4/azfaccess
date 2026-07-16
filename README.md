# 🛡️ SecurePass — Plataforma de Gestão e Controlo de Acesso Físico

Plataforma integrada para gerir com segurança a entrada e saída de **colaboradores** e **visitantes** em edifícios corporativos, através de **passes digitais com QR Codes dinâmicos assinados criptograficamente**.

## Módulos

| Módulo | URL | Descrição |
|---|---|---|
| Página inicial | `http://localhost:3000/` | Acesso a todos os módulos |
| Portal do Colaborador | `/portal.html` | O colaborador autentica-se e gera QR Codes de acesso temporários para si mesmo (1h a 3 dias), consulta e revoga os seus passes, e vê as visitas de que é anfitrião |
| Totem do Visitante | `/totem.html` | Quiosque de auto-registo: o visitante insere nome, documento e empresa, pesquisa e seleciona o anfitrião, e recebe no momento um passe com QR Code (válido 8h, 1 entrada + 1 saída) |
| Scanner da Portaria | `/scanner.html` | Leitura de QR por câmara (ou validação manual), resultado visual e sonoro, e registo de movimentos em tempo real. O mesmo QR serve para entrada e saída: no modo automático a primeira leitura regista a entrada e a seguinte a saída (com forçagem manual opcional) |
| Administração | `/admin.html` | Estatísticas, registo completo de acessos, gestão de passes (revogação) e gestão de colaboradores (criação/desativação) |

## Segurança e regras dos passes

- O QR Code **não contém dados pessoais** — apenas um token assinado com **HMAC-SHA256** por um segredo do servidor (gerado no primeiro arranque em `data/secret.key`).
- O QR é **estático**: o mesmo código vale durante todo o período de validade do passe e serve tanto para a entrada como para a saída. O visitante pode fotografá-lo no totem.
- **Regras de utilização**: passe de **visitante** vale exatamente **1 entrada + 1 saída** (leituras adicionais são negadas e registadas); passe de **colaborador** permite **entradas/saídas ilimitadas** dentro da validade.
- Qualquer adulteração do token invalida a assinatura e o acesso é negado (e registado).
- Passes podem ser **revogados** a qualquer momento pelo próprio colaborador ou pelo administrador, com efeito imediato.
- Palavras-passe guardadas com **scrypt** + salt; sessões via cookie `HttpOnly` assinado (12h).
- Todas as tentativas de acesso — autorizadas e negadas, com o motivo — ficam no registo de auditoria.

## Como executar

```bash
npm install     # instalar dependências (express, qrcode, jsqr)
npm run seed    # criar contas de demonstração
npm start       # arrancar em http://localhost:3000
```

> Requer Node.js 22.5+ (usa o módulo nativo `node:sqlite`). A base de dados é criada automaticamente em `data/access.db`.

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

**Visitante** — no totem da receção: insere dados → pesquisa o anfitrião → passe emitido no ecrã com QR dinâmico → passa na portaria → o anfitrião vê no seu portal que o visitante está no edifício.

**Portaria** — abre o scanner → escolhe Entrada ou Saída → aponta a câmara ao QR → o sistema valida assinatura, validade e estado do passe e regista o movimento.

## Estrutura

```
server.js            # API Express + rotas
src/db.js            # esquema SQLite (node:sqlite)
src/security.js      # HMAC, scrypt, sessões e tokens de passe
src/seed.js          # contas de demonstração
public/              # frontends (portal, totem, scanner, admin)
data/                # base de dados + segredo (criados no arranque)
```
