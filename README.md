# Cadastro RECNC - Sistema Completo de Cadastro de Pessoas

## Visão Geral

O **Cadastro RECNC** é um aplicativo web completo para cadastro e gestão de pessoas, com autenticação, controle de administradores, upload de arquivos e painel administrativo. O sistema é um Progressive Web App (PWA) que funciona em qualquer dispositivo (desktop ou móvel).

---

## 🛠 Tecnologias Utilizadas

### Frontend (Interface do Usuário)
- **HTML5** - Estrutura das páginas
- **CSS3** - Estilização e layout responsivo
- **JavaScript Puro** - Lógica interativa
- **Bootstrap 5** - Framework CSS via CDN (gratuitamente)
- **PWA** - Progressive Web App com manifest e service worker
- **Font Awesome 6** - Ícones

### Backend (Servidor)
- **Node.js** - Ambiente de execução JavaScript
- **Express** - Framework web gratuito e open-source
- **SQLite** - Banco de dados local (arquivo `.db`, sem custo de servidor)
- **JWT (JSON Web Tokens)** - Autenticação segura
- **BcryptJS** - Hash de senhas
- **Express Rate Limit** - Proteção contra ataques de força bruta

### Deploy Gratuito
- **Vercel** - Para hospedar o frontend
- **Render.com** - Para hospedar o backend
- **Railway.app** - Alternativa para deploy full-stack

---

## 📁 Estrutura do Projeto

```
Cadastro RECNC/
├── backend/              # Servidor Node.js + Express
│   ├── server.js         # Rotas e lógica do backend
│   ├── package.json      # Dependências do npm
│   ├── .env.example      # Variáveis de ambiente
│   └── database.db       # Banco de dados SQLite (gerado automaticamente)
│
├── frontend/             # Aplicação web PWA
│   ├── index.html        # Tela de Login
│   ├── dashboard.html    # Painel administrativo
│   ├── lista.html        # Lista de pessoas cadastradas
│   ├── formulario.html   # Formulário de cadastro/edição
│   ├── usuarios.html     # Gerenciar usuários (admin)
│   ├── css/style.css     # Estilos customizados
│   ├── manifest.json     # Configuração PWA
│   └── service-worker.js # Funcionalidade offline
│
└── public/               # Arquivos públicos (ícones, etc.)
```

---

## ⚙️ Instalação e Execução Local

### Prerequisites
- [Node.js](https://nodejs.org/) (versão 14 ou superior)
- [Git](https://git-scm.com/) (opcional, para clonagem)

### Passo a Passo

1. **Clone ou extraia o projeto** na pasta desejada:
   ```
   C:\Users\bezal\DevHub\workspace\Cadastro RECNC
   ```

2. **Instale as dependências do backend**:
   ```bash
   cd "Cadastro RECNC\backend"
   npm install
   ```

3. **Inicie o servidor**:
   ```bash
   npm run dev
   # ou
   node server.js
   ```
   
   O servidor será iniciado em `http://localhost:3000`

4. **Abra o navegador** e acesse:
   - `http://localhost:3000` (Login)
   
   OU basta abrir os arquivos HTML diretamente do frontend (o backend precisa rodando em outro terminal).

---

## 🔐 Primeiro Acesso

Ao iniciar o aplicativo pela primeira vez:

1. Acesse a tela de login em `http://localhost:3000`
2. Como não existem usuários cadastrados, clique em "Cadastre-se" (link na tela de login)
3. O primeiro usuário criado será automaticamente promovido a **Administrador**
4. Faça login com as credenciais criadas

---

## 📸 Telas do Sistema

### 1. Tela de Login (`index.html`)
- E-mail e senha de acesso
- Link para cadastro de novo usuário
- Design responsivo

### 2. Dashboard (`dashboard.html`)
- Estatísticas gerais (total de pessoas, tipos de cadastro)
- Últimos 5 cadastros
- Acesso rápido às funcionalidades

### 3. Lista de Pessoas (`lista.html`)
- Tabela com todos os cadastros
- Pesquisa por nome
- Filtro por tipo (Novo Nascimento / Reconciliação)
- Paginação (10 registros por página)
- Botões de Editar e Excluir (apenas admin)

### 4. Formulário de Cadastro (`formulario.html`)
- Campos: nome, endereço, ponto de referência, telefone, tipo de cadastro
- Upload de foto (JPG, PNG, WEBP - max 4MB)
- Upload de arquivo (PDF, DOC, DOCX - max 10MB)
- Radio buttons para tipo de cadastro
- Validação de campos obrigatórios

### 5. Gerenciar Usuários (`usuarios.html`)
- Lista de todos os usuários do sistema
- Adicionar novo administrador
- Remover usuários
- Alterar senha
- (Apenas para perfis admin)

---

## 🌐 Deploy Gratuito

### Opção 1: Vercel (Frontend) + Render (Backend)

#### No Frontend (Vercel):
1. Crie uma conta gratuita em [vercel.com](https://vercel.com)
2. Conecte seu repositório GitHub
3. Importar o projeto da pasta `frontend`
4. O Vercel detectará automaticamente que é um aplicativo HTML/static
5. Deploy automático será iniciado

#### No Backend (Render):
1. Crie uma conta gratuita em [render.com](https://render.com)
2. Crie um novo Web Service
3. Conecte o repositório GitHub
4. Configure as seguintes variáveis de ambiente no painel:
   - `PORT=10000` (Render define isso automaticamente)
   - `JWT_SECRET=sua-chave-secreta`
   - `DATABASE_PATH=./database.db`
5. Build Command: `npm install`
6. Start Command: `node server.js`
7. O Render fornecerá uma URL como `https://seu-app.onrender.com`

#### Configurar CORS no backend:
No `server.js`, adicione o domínio da Vercel nas variáveis de ambiente ou modifique o CORS para aceitar o domínio da Render.

---

### Opção 2: Railway.app (Full-Stack)

1. Crie conta gratuita em [railway.app](https://railway.app)
2. Novo projeto > Deploy from GitHub
3. O Railway detectará o `package.json` e o `server.js`
4. Variáveis de ambiente podem ser adicionadas no painel
5. O domínio será fornecido automaticamente (`.railway.app`)

---

### Opção 3: Netlify (Frontend + Functions)

1. Crie conta em [netlify.com](https://netlify.com)
2. Deploy da pasta `frontend` via Git ou upload
3. Para o backend, use "Netlify Functions" ou conecte um repositório separado
4. Configure as variáveis de ambiente no painel do Netlify

---

## 🔧 Variáveis de Ambiente

### Backend (.env)

Crie um arquivo `.env` na pasta `backend/` com:

```
PORT=3000
JWT_SECRET=uma-chave-secreta-muito-dificil-de-adivinhar
DATABASE_PATH=./database.db
```

**Obs:** O `JWT_SECRET` deve ser uma string longa e única. Nunca comite o arquivo `.env` no GitHub.

---

## 🗄 Banco de Dados

O sistema usa **SQLite** com o arquivo `database.db` na pasta `backend/`.

### Tabelas Criadas Automaticamente:

1. **usuarios** - Armazena login e perfis
   - `id`, `nome`, `email`, `senha_hash`, `perfil`, `data_criacao`

2. **pessoas** - Armazena cadastros de pessoas
   - `id`, `nome_completo`, `endereco`, `ponto_referencia`, `telefone`
   - `tipo_cadastro` (novo_nascimento ou reconciliacao)
   - `foto_url`, `arquivo_url`, `cadastrado_por`, `data_cadastro`

### Soft Delete

O sistema utiliza "soft delete" - registros excluídos são marcados mas não removidos fisicamente do banco. Para restaurar, basta atualizar o registro.

---

## 🔒 Segurança

### Implementadas:
- ✅ Hash de senhas com BcryptJS
- ✅ JWT para autenticação (token expira em 24 horas)
- ✅ Proteção de rotas (exceto login)
- ✅ Rate limiting no login (100 requests/15min)
- ✅ Validação de inputs no frontend e backend
- ✅ Sanitização básica contra XSS
- ✅ CORS configurado

### Recomendações para Produção:
- Usar HTTPS em produção (ambientes Vercel/Render já fornecem isso)
- Substituir o SQLite por PostgreSQL (Supabase) para aplicações maiores
- Configurar Certificado Pinning para apps críticos
- Fazer backups regulares do `database.db`

---

## 📱 Como Instalar no Celular (PWA)

1. Abra o navegador no celular (Chrome Android ou Safari iOS)
2. Acesse o endereço do seu deploy (ex: `https://seu-app.vercel.com`)
3. No Chrome Android: Toque no menu (⋮) > "Instalar aplicativo" > "Instalar"
   Ou: Toque na barra de endereço > ícone de "aparelho" com "+"
4. No Safari iOS: Compartilhar > "Para a Tela Inicial"
5. O aplicativo será adicionado à tela inicial e poderá ser aberto como um app nativo

---

## 📞 Suporte

Para dúvidas ou personalizações:
- Verifique o arquivo `README` em cada pasta
- As variáveis de ambiente são documentadas no `.env.example`
- O código fonte está comentado para facilitar a manutenção

---

**Desenvolvido com ❤️ pelo AppForge Nexus**