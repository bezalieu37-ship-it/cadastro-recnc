require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// No-cache para HTML (força WebView do Capacitor a sempre buscar do servidor)
app.use((req, res, next) => {
  if (req.path.endsWith('.html')) {
    res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
  }
  next();
});

app.use(express.static(path.join(__dirname, '..', 'frontend')));
app.use(express.static(path.join(__dirname, '..', 'android-app', 'www')));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 2000,
  message: { error: 'Muitas requisicoes deste IP, tente novamente mais tarde.' }
});
app.use('/api', limiter);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('supabase')
    ? { rejectUnauthorized: false }
    : false
});

// Supabase Storage (service_role para uploads)
const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY || ''
);

// Multer config - armazenar em memoria (buffer)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Tipo de arquivo nao permitido.'), false);
  }
});

function buildPlaceholders(values, startIndex = 1) {
  return values.map((_, i) => '$' + (startIndex + i)).join(', ');
}

async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nome TEXT NOT NULL UNIQUE,
        senha TEXT NOT NULL,
        perfil TEXT DEFAULT 'usuario' CHECK (perfil IN ('admin', 'usuario')),
        data_criacao TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS pessoas (
        id SERIAL PRIMARY KEY,
        nome_completo TEXT NOT NULL,
        data_nascimento TEXT,
        endereco TEXT NOT NULL,
        ponto_referencia TEXT NOT NULL,
        telefone TEXT NOT NULL,
        tipo_cadastro TEXT NOT NULL CHECK (tipo_cadastro IN ('novo_nascimento', 'reconciliacao', 'novo_congregado')),
        acompanhante TEXT,
        foto_url TEXT,
        cadastrado_por INTEGER REFERENCES usuarios(id),
        data_cadastro TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS relatorios (
        id SERIAL PRIMARY KEY,
        titulo TEXT NOT NULL,
        email_destino TEXT,
        mensagem TEXT,
        tipo_filtro TEXT,
        filtro_valor TEXT,
        total_registros INTEGER DEFAULT 0,
        data_geracao TIMESTAMPTZ DEFAULT NOW(),
        criado_por INTEGER REFERENCES usuarios(id),
        conteudo_html TEXT
      )
    `);
    // Configuracoes da organizacao (perfil da congregacao)
    await client.query(`
      CREATE TABLE IF NOT EXISTS config_org (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        nome_org TEXT DEFAULT '',
        endereco TEXT DEFAULT '',
        telefone TEXT DEFAULT '',
        email TEXT DEFAULT '',
        responsavel TEXT DEFAULT '',
        formato_data TEXT DEFAULT 'BR',
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        updated_by INTEGER REFERENCES usuarios(id)
      )
    `);
    await client.query(`
      INSERT INTO config_org (id) VALUES (1)
      ON CONFLICT (id) DO NOTHING
    `);
    // Rótulos customizados dos tipos de cadastro
    await client.query(`
      CREATE TABLE IF NOT EXISTS config_tipos (
        chave TEXT PRIMARY KEY,
        rotulo TEXT NOT NULL,
        cor TEXT DEFAULT ''
      )
    `);
    await client.query(`
      INSERT INTO config_tipos (chave, rotulo, cor) VALUES
        ('novo_nascimento', 'Novo Nascimento', '#4f46e5'),
        ('reconciliacao', 'Reconciliação', '#b45309'),
        ('novo_congregado', 'Novo Congregado', '#0369a1')
      ON CONFLICT (chave) DO NOTHING
    `);
    console.log('Database initialized');
  } finally {
    client.release();
  }
}

initializeDatabase().catch(err => {
  console.error('Failed to initialize database:', err);
});

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const queryToken = req.query.token;
  let token;
  if (authHeader) {
    token = authHeader.split(' ')[1];
  } else if (queryToken) {
    token = queryToken;
  }
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET || 'cadastro-remc-secret-key');
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ error: 'Invalid or expired token.' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user.perfil !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });
  }
  next();
}
app.post('/api/register', async (req, res) => {
  const { nome, senha } = req.body;
  if (!nome || !senha) {
    return res.status(400).json({ error: 'Nome e senha sao obrigatorios.' });
  }
  try {
    const senha_hash = await bcrypt.hash(senha, 10);
    const existingUser = await pool.query('SELECT id FROM usuarios WHERE nome = $1', [nome]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Este nome ja esta cadastrado.' });
    }
    const countResult = await pool.query('SELECT COUNT(*) as count FROM usuarios');
    const perfil = parseInt(countResult.rows[0].count) === 0 ? 'admin' : 'usuario';
    const result = await pool.query(
      'INSERT INTO usuarios (nome, senha, perfil) VALUES ($1, $2, $3) RETURNING id',
      [nome, senha_hash, perfil]
    );
    const userId = result.rows[0].id;
    const token = jwt.sign(
      { id: userId, nome, perfil },
      process.env.JWT_SECRET || 'cadastro-remc-secret-key',
      { expiresIn: '24h' }
    );
    res.status(201).json({
      message: 'Usuário criado com sucesso.',
      token,
      user: { id: userId, nome, perfil }
    });
  } catch (error) {
    console.error('Erro ao registrar usuário:', error);
    res.status(500).json({ error: 'Erro no servidor.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { nome, senha } = req.body;
  if (!nome || !senha) {
    return res.status(400).json({ error: 'Nome e senha sao obrigatorios.' });
  }
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE nome = $1', [nome]);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: 'Credenciais invalidas.' });
    }
    const validPassword = await bcrypt.compare(senha, user.senha);
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciais invalidas.' });
    }
    const token = jwt.sign(
      { id: user.id, nome: user.nome, perfil: user.perfil },
      process.env.JWT_SECRET || 'cadastro-remc-secret-key',
      { expiresIn: '24h' }
    );
    res.json({
      message: 'Login bem-sucedido.',
      token,
      user: { id: user.id, nome: user.nome, perfil: user.perfil }
    });
  } catch (error) {
    console.error('Erro ao fazer login:', error);
    res.status(500).json({ error: 'Erro no servidor.' });
  }
});

app.get('/api/profile', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/usuarios', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, nome, perfil, data_criacao FROM usuarios');
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar usuários:', error);
    res.status(500).json({ error: 'Erro ao buscar usuários.' });
  }
});

app.get('/api/usuarios/list', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, nome FROM usuarios ORDER BY nome');
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar lista de usuários:', error);
    res.status(500).json({ error: 'Erro ao buscar lista de usuários.' });
  }
});

app.post('/api/usuarios', authMiddleware, adminMiddleware, async (req, res) => {
  const { nome, senha, perfil } = req.body;
  if (!nome || !senha) {
    return res.status(400).json({ error: 'Nome e senha sao obrigatorios.' });
  }
  try {
    const saltHash = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (nome, senha, perfil) VALUES ($1, $2, $3) RETURNING id',
      [nome, saltHash, perfil || 'usuario']
    );
    res.json({ message: 'Usuário criado com sucesso.', userId: result.rows[0].id });
  } catch (error) {
    console.error('Erro ao criar usuário:', error);
    res.status(500).json({ error: 'Erro ao criar usuário. Nome já existe?' });
  }
});
app.post('/api/pessoas', authMiddleware, upload.single('foto'), async (req, res) => {
  const { nome_completo, data_nascimento, data_cadastro, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante } = req.body;
  if (!nome_completo || !endereco || !ponto_referencia || !telefone || !tipo_cadastro) {
    return res.status(400).json({ error: 'Todos os campos obrigatorios devem ser preenchidos.' });
  }
  const cadastrado_por = req.user.id;
  let fotoUrl = '';

  try {
    // Upload da foto para Supabase Storage
    if (req.file) {
      const ext = req.file.mimetype === 'image/png' ? 'png' : req.file.mimetype === 'image/webp' ? 'webp' : 'jpg';
      const fileName = `fotos/${crypto.randomUUID()}.${ext}`;
      const { data: uploadData, error: uploadError } = await supabase.storage
        .from('Cadastro-Fotos')
        .upload(fileName, req.file.buffer, { contentType: req.file.mimetype });

      if (uploadError) {
        console.error('Erro ao upload foto:', uploadError);
      } else {
        const { data: urlData } = supabase.storage.from('Cadastro-Fotos').getPublicUrl(fileName);
        fotoUrl = urlData.publicUrl;
      }
    }

    const result = await pool.query(
      `INSERT INTO pessoas (nome_completo, data_nascimento, data_cadastro, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante, foto_url, cadastrado_por)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
      [nome_completo, data_nascimento || null, data_cadastro || new Date().toISOString(), endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante || '', fotoUrl, cadastrado_por]
    );
    res.json({ message: 'Pessoa cadastrada com sucesso.', pessoaId: result.rows[0].id });
  } catch (error) {
    console.error('Erro ao cadastrar pessoa:', error);
    res.status(500).json({ error: 'Erro ao cadastrar pessoa.' });
  }
});

app.get('/api/pessoas', authMiddleware, async (req, res) => {
  const { tipo, search, page = 1, limit = 10 } = req.query;
  let whereClause = '';
  const params = [];
  let paramIndex = 1;

  // Usuarios nao-admin so veem pessoas onde sao acompanhante
  if (req.user.perfil !== 'admin') {
    whereClause += ' AND p.acompanhante = $' + paramIndex;
    params.push(req.user.id.toString());
    paramIndex++;
  }

  if (tipo && tipo !== 'all') {
    whereClause += ' AND p.tipo_cadastro = $' + paramIndex;
    params.push(tipo);
    paramIndex++;
  }
  if (search) {
    whereClause += ' AND (p.nome_completo ILIKE $' + paramIndex + ' OR p.telefone ILIKE $' + (paramIndex + 1) + ')';
    params.push('%' + search + '%');
    params.push('%' + search + '%');
    paramIndex += 2;
  }

  const countQuery = 'SELECT COUNT(*) as total FROM pessoas p WHERE 1=1' + whereClause;
  const dataQuery = 'SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id WHERE 1=1' + whereClause + ' ORDER BY p.data_cadastro DESC LIMIT $' + paramIndex + ' OFFSET $' + (paramIndex + 1);

  const limitNum = parseInt(limit);
  const offset = (parseInt(page) - 1) * limitNum;

  try {
    const countResult = await pool.query(countQuery, params);
    const total = parseInt(countResult.rows[0].total);
    const totalPages = Math.ceil(total / limitNum);
    const dataResult = await pool.query(dataQuery, [...params, limitNum, offset]);
    res.json({ pessoas: dataResult.rows, total, totalPages, page: parseInt(page) });
  } catch (error) {
    console.error('Erro ao buscar pessoas:', error);
    res.status(500).json({ error: 'Erro ao buscar pessoas.' });
  }
});

app.get('/api/pessoas/meus-acompanhamentos', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const { page = 1, limit = 10 } = req.query;
  const limitNum = parseInt(limit);
  const offset = (parseInt(page) - 1) * limitNum;

  try {
    const countResult = await pool.query(
      'SELECT COUNT(*) as total FROM pessoas p WHERE p.acompanhante = $1',
      [userId.toString()]
    );
    const total = parseInt(countResult.rows[0].total);
    const totalPages = Math.ceil(total / limitNum);
    const dataResult = await pool.query(
      'SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id WHERE p.acompanhante = $1 ORDER BY p.data_cadastro DESC LIMIT $2 OFFSET $3',
      [userId.toString(), limitNum, offset]
    );
    res.json({ pessoas: dataResult.rows, total, totalPages, page: parseInt(page) });
  } catch (error) {
    console.error('Erro ao buscar acompanhamentos:', error);
    res.status(500).json({ error: 'Erro ao buscar acompanhamentos.' });
  }
});

app.get('/api/usuarios/acompanhamentos-por-usuario', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    // Para cada usuário, contar quantos cadastros acompanha e listar os nomes
    const result = await pool.query(`
      SELECT
        u.id,
        u.nome,
        u.perfil,
        COUNT(p.id) as total_acompanhamentos,
        COALESCE(json_agg(
          json_build_object(
            'id', p.id,
            'nome_completo', p.nome_completo,
            'telefone', p.telefone,
            'endereco', p.endereco,
            'tipo_cadastro', p.tipo_cadastro,
            'data_cadastro', p.data_cadastro
          ) ORDER BY p.data_cadastro DESC
        ) FILTER (WHERE p.id IS NOT NULL), '[]') as pessoas
      FROM usuarios u
      LEFT JOIN pessoas p ON CAST(p.acompanhante AS INTEGER) = u.id
      GROUP BY u.id, u.nome, u.perfil
      ORDER BY total_acompanhamentos DESC
    `);

    const usuarios = result.rows.map(u => ({
      id: u.id,
      nome: u.nome,
      perfil: u.perfil,
      total_acompanhamentos: parseInt(u.total_acompanhamentos),
      pessoas: u.pessoas
    }));

    // Também incluir total geral
    const totalGeral = usuarios.reduce((acc, u) => acc + u.total_acompanhamentos, 0);
    res.json({ usuarios, total_geral: totalGeral });
  } catch (error) {
    console.error('Erro ao buscar acompanhamentos por usuário:', error);
    res.status(500).json({ error: 'Erro ao buscar acompanhamentos por usuário.' });
  }
});

app.get('/api/pessoas/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id WHERE p.id = $1',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pessoa nao encontrada.' });
    }
    const pessoa = result.rows[0];
    // Admin pode ver tudo; usuario so ve se for o acompanhante
    if (req.user.perfil !== 'admin' && String(pessoa.acompanhante) !== String(req.user.id)) {
      return res.status(403).json({ error: 'Acesso negado.' });
    }
    res.json(pessoa);
  } catch (error) {
    console.error('Erro ao buscar pessoa:', error);
    res.status(500).json({ error: 'Erro ao buscar pessoa.' });
  }
});
app.put('/api/pessoas/:id', authMiddleware, async (req, res) => {
  // Processar body — pode vir como JSON ou como multipart (com foto)
  // Se veio multipart, multer não rodou como middleware, então parseamos manualmente
  let body = req.body || {};
  let fotoFile = null;

  // Se o Content-Type é multipart, o express.json() não parseou — precisamos do multer
  if (req.is('multipart/form-data')) {
    // Usar multer de forma promise-based para este request específico
    await new Promise((resolve, reject) => {
      upload.single('foto')(req, res, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    body = req.body || {};
    fotoFile = req.file || null;
  }

  const { nome_completo, data_nascimento, data_cadastro, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante, foto_url } = body;
  let fotoUrl = foto_url || '';

  console.log('[PUT /api/pessoas/' + req.params.id + '] body keys:', Object.keys(body), 'nome:', nome_completo);

  try {
    // Verificar permissao: admin ou acompanhante
    if (req.user.perfil !== 'admin') {
      const check = await pool.query('SELECT acompanhante FROM pessoas WHERE id = $1', [req.params.id]);
      if (check.rows.length === 0) return res.status(404).json({ error: 'Pessoa nao encontrada.' });
      if (String(check.rows[0].acompanhante) !== String(req.user.id)) {
        return res.status(403).json({ error: 'Acesso negado.' });
      }
    }

    // Se enviou nova foto, fazer upload
    if (fotoFile) {
      const ext = fotoFile.mimetype === 'image/png' ? 'png' : fotoFile.mimetype === 'image/webp' ? 'webp' : 'jpg';
      const fileName = `fotos/${crypto.randomUUID()}.${ext}`;
      const { data: uploadData, error: uploadError } = await supabase.storage
        .from('Cadastro-Fotos')
        .upload(fileName, fotoFile.buffer, { contentType: fotoFile.mimetype });

      if (!uploadError) {
        const { data: urlData } = supabase.storage.from('Cadastro-Fotos').getPublicUrl(fileName);
        fotoUrl = urlData.publicUrl;
      }
    }

    const result = await pool.query(
      'UPDATE pessoas SET nome_completo = $1, data_nascimento = $2, data_cadastro = $3, endereco = $4, ponto_referencia = $5, telefone = $6, tipo_cadastro = $7, acompanhante = $8, foto_url = $9 WHERE id = $10',
      [nome_completo, data_nascimento || null, data_cadastro || new Date().toISOString(), endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante || '', fotoUrl, req.params.id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Pessoa nao encontrada.' });
    }
    console.log('[PUT OK] Pessoa', req.params.id, 'atualizada');
    res.json({ message: 'Pessoa atualizada com sucesso.' });
  } catch (error) {
    console.error('Erro ao atualizar pessoa:', error);
    res.status(500).json({ error: 'Erro ao atualizar pessoa.' });
  }
});

app.delete('/api/pessoas/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM pessoas WHERE id = $1', [req.params.id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Pessoa nao encontrada.' });
    }
    res.json({ message: 'Pessoa excluida com sucesso.' });
  } catch (error) {
    console.error('Erro ao excluir pessoa:', error);
    res.status(500).json({ error: 'Erro ao excluir pessoa.' });
  }
});

app.delete('/api/usuarios/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT perfil FROM usuarios WHERE id = $1', [req.params.id]);
    const user = userResult.rows[0];
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }
    if (user.perfil === 'admin') {
      const countResult = await pool.query("SELECT COUNT(*) as admin_count FROM usuarios WHERE perfil = 'admin'");
      const adminCount = parseInt(countResult.rows[0].admin_count);
      if (adminCount <= 1) {
        return res.status(400).json({ error: 'Nao e possivel excluir o ultimo administrador.' });
      }
      }
      // Desvincular cadastros antes de excluir (setar cadastrado_por como NULL)
      await pool.query('UPDATE pessoas SET cadastrado_por = NULL WHERE cadastrado_por = $1', [req.params.id]);
      await pool.query('DELETE FROM usuarios WHERE id = $1', [req.params.id]);
    res.json({ message: 'Usuário excluído com sucesso.' });
  } catch (error) {
    console.error('Erro ao excluir usuário:', error);
    res.status(500).json({ error: 'Erro ao excluir usuário.' });
  }
});

app.put('/api/usuarios/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { nome, senha, perfil } = req.body;
  const userId = req.params.id;
  if (!nome) {
    return res.status(400).json({ error: 'Nome e obrigatorio.' });
  }
  try {
    if (senha && senha.length >= 6) {
      const hash = await bcrypt.hash(senha, 10);
      const result = await pool.query(
        'UPDATE usuarios SET nome = $1, senha = $2, perfil = $3 WHERE id = $4',
        [nome, hash, perfil || 'usuario', userId]
      );
      if (result.rowCount === 0) return res.status(404).json({ error: 'Usuário não encontrado.' });
      res.json({ message: 'Usuário atualizado com sucesso.' });
    } else {
      const result = await pool.query(
        'UPDATE usuarios SET nome = $1, perfil = $2 WHERE id = $3',
        [nome, perfil || 'usuario', userId]
      );
      if (result.rowCount === 0) return res.status(404).json({ error: 'Usuário não encontrado.' });
      res.json({ message: 'Usuário atualizado com sucesso.' });
    }
  } catch (error) {
    console.error('Erro ao atualizar usuário:', error);
    res.status(500).json({ error: 'Erro ao atualizar usuário. Nome já existe?' });
  }
});

// ============ CONFIGURAÇÕES DO APP ============

// GET configuração da organização (perfil da congregação) - autenticado, retorna defaults se vazio
app.get('/api/config/org', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT nome_org, endereco, telefone, email, responsavel, formato_data FROM config_org WHERE id = 1');
    const row = result.rows[0] || {};
    res.json({
      nome_org: row.nome_org || '',
      endereco: row.endereco || '',
      telefone: row.telefone || '',
      email: row.email || '',
      responsavel: row.responsavel || '',
      formato_data: row.formato_data || 'BR'
    });
  } catch (error) {
    console.error('Erro ao buscar config:', error);
    res.status(500).json({ error: 'Erro ao buscar configurações.' });
  }
});

// PUT configuração da organização - admin
app.put('/api/config/org', authMiddleware, adminMiddleware, async (req, res) => {
  const { nome_org, endereco, telefone, email, responsavel, formato_data } = req.body || {};
  try {
    await pool.query(
      `UPDATE config_org SET
         nome_org = $1, endereco = $2, telefone = $3, email = $4,
         responsavel = $5, formato_data = $6, updated_at = NOW(), updated_by = $7
       WHERE id = 1`,
      [nome_org || '', endereco || '', telefone || '', email || '', responsavel || '', formato_data || 'BR', req.user.id]
    );
    res.json({ message: 'Configurações salvas com sucesso.' });
  } catch (error) {
    console.error('Erro ao salvar config:', error);
    res.status(500).json({ error: 'Erro ao salvar configurações.' });
  }
});

// GET rótulos dos tipos de cadastro
app.get('/api/config/tipos', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT chave, rotulo, cor FROM config_tipos ORDER BY chave');
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar tipos:', error);
    res.status(500).json({ error: 'Erro ao buscar tipos.' });
  }
});

// PUT rótulos dos tipos de cadastro - admin
app.put('/api/config/tipos', authMiddleware, adminMiddleware, async (req, res) => {
  const items = req.body; // array de { chave, rotulo, cor }
  if (!Array.isArray(items)) {
    return res.status(400).json({ error: 'Formato inválido. Envie um array de tipos.' });
  }
  try {
    for (const item of items) {
      if (!item || !item.chave || !item.rotulo) continue;
      await pool.query(
        `UPDATE config_tipos SET rotulo = $1, cor = $2 WHERE chave = $3`,
        [item.rotulo, item.cor || '', item.chave]
      );
    }
    res.json({ message: 'Tipos atualizados com sucesso.' });
  } catch (error) {
    console.error('Erro ao salvar tipos:', error);
    res.status(500).json({ error: 'Erro ao salvar tipos.' });
  }
});

// Rótulo resolvido de um tipo (com fallback) - helper para páginas
// GET /api/config/tipos/mapa -> retorna map chave->{rotulo,cor} para uso nas telas
app.get('/api/config/tipos/mapa', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT chave, rotulo, cor FROM config_tipos');
    const mapa = {};
    result.rows.forEach(r => { mapa[r.chave] = { rotulo: r.rotulo, cor: r.cor }; });
    res.json(mapa);
  } catch (error) {
    console.error('Erro ao buscar mapa de tipos:', error);
    res.status(500).json({ error: 'Erro ao buscar tipos.' });
  }
});

// ============ PERFIL DO USUÁRIO LOGADO ============

// Alterar nome do usuário logado
app.put('/api/usuarios/me', authMiddleware, async (req, res) => {
  const { nome } = req.body || {};
  if (!nome || !nome.trim()) {
    return res.status(400).json({ error: 'Nome é obrigatório.' });
  }
  const novoNome = nome.trim();
  try {
    const exists = await pool.query('SELECT id FROM usuarios WHERE nome = $1 AND id <> $2', [novoNome, req.user.id]);
    if (exists.rows.length > 0) {
      return res.status(409).json({ error: 'Este nome já está em uso.' });
    }
    const result = await pool.query('UPDATE usuarios SET nome = $1 WHERE id = $2', [novoNome, req.user.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Usuário não encontrado.' });
    res.json({ message: 'Nome atualizado com sucesso.', nome: novoNome });
  } catch (error) {
    console.error('Erro ao atualizar nome:', error);
    res.status(500).json({ error: 'Erro ao atualizar nome.' });
  }
});

// Alterar senha do usuário logado (exige senha atual)
app.put('/api/usuarios/me/senha', authMiddleware, async (req, res) => {
  const { senha_atual, nova_senha } = req.body || {};
  if (!senha_atual || !nova_senha) {
    return res.status(400).json({ error: 'Senha atual e nova senha são obrigatórias.' });
  }
  if (nova_senha.length < 6) {
    return res.status(400).json({ error: 'A nova senha deve ter pelo menos 6 caracteres.' });
  }
  try {
    const result = await pool.query('SELECT senha FROM usuarios WHERE id = $1', [req.user.id]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
    const valid = await bcrypt.compare(senha_atual, user.senha);
    if (!valid) return res.status(401).json({ error: 'Senha atual incorreta.' });
    const hash = await bcrypt.hash(nova_senha, 10);
    await pool.query('UPDATE usuarios SET senha = $1 WHERE id = $2', [hash, req.user.id]);
    res.json({ message: 'Senha alterada com sucesso.' });
  } catch (error) {
    console.error('Erro ao alterar senha:', error);
    res.status(500).json({ error: 'Erro ao alterar senha.' });
  }
});

app.get('/api/estatisticas', authMiddleware, async (req, res) => {
  try {
    const isAdmin = req.user.perfil === 'admin';
    const [totalResult, nascResult, reconcResult, ncgrResult] = await Promise.all([
      isAdmin
        ? pool.query('SELECT COUNT(*) as total FROM pessoas')
        : pool.query('SELECT COUNT(*) as total FROM pessoas WHERE acompanhante = $1', [req.user.id.toString()]),
      isAdmin
        ? pool.query("SELECT COUNT(*) as total FROM pessoas WHERE tipo_cadastro = 'novo_nascimento'")
        : pool.query("SELECT COUNT(*) as total FROM pessoas WHERE tipo_cadastro = 'novo_nascimento' AND acompanhante = $1", [req.user.id.toString()]),
      isAdmin
        ? pool.query("SELECT COUNT(*) as total FROM pessoas WHERE tipo_cadastro = 'reconciliacao'")
        : pool.query("SELECT COUNT(*) as total FROM pessoas WHERE tipo_cadastro = 'reconciliacao' AND acompanhante = $1", [req.user.id.toString()]),
      isAdmin
        ? pool.query("SELECT COUNT(*) as total FROM pessoas WHERE tipo_cadastro = 'novo_congregado'")
        : pool.query("SELECT COUNT(*) as total FROM pessoas WHERE tipo_cadastro = 'novo_congregado' AND acompanhante = $1", [req.user.id.toString()])
    ]);
    res.json({
      totalPessoas: parseInt(totalResult.rows[0].total),
      totalNascimento: parseInt(nascResult.rows[0].total),
      totalReconciliacao: parseInt(reconcResult.rows[0].total),
      totalNcgr: parseInt(ncgrResult.rows[0].total)
    });
  } catch (error) {
    console.error('Erro ao buscar estatisticas:', error);
    res.status(500).json({ error: 'Erro ao buscar estatisticas.' });
  }
});

// Endpoint para ultimos cadastros (usado no dashboard)
app.get('/api/ultimos-cadastros', authMiddleware, async (req, res) => {
  try {
    const isAdmin = req.user.perfil === 'admin';
    const result = isAdmin
      ? await pool.query('SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id ORDER BY p.data_cadastro DESC LIMIT 5')
      : await pool.query('SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id WHERE p.acompanhante = $1 ORDER BY p.data_cadastro DESC LIMIT 5', [req.user.id.toString()]);
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar ultimos cadastros:', error);
    res.status(500).json({ error: 'Erro ao buscar ultimos cadastros.' });
  }
});

app.get('/api/export/csv', authMiddleware, async (req, res) => {
  const { tipo, search, ids } = req.query;
  let whereClause = '';
  const params = [];
  let paramIndex = 1;

  if (ids) {
    const idList = ids.split(',').map(Number);
    whereClause += ' AND p.id IN (' + buildPlaceholders(idList, paramIndex) + ')';
    params.push(...idList);
    paramIndex += idList.length;
  } else {
    if (tipo && tipo !== 'all') {
      whereClause += ' AND p.tipo_cadastro = $' + paramIndex;
      params.push(tipo);
      paramIndex++;
    }
    if (search) {
      whereClause += ' AND (p.nome_completo ILIKE $' + paramIndex + ' OR p.telefone ILIKE $' + (paramIndex + 1) + ')';
      params.push('%' + search + '%');
      params.push('%' + search + '%');
      paramIndex += 2;
    }
  }

  // Non-admin users only see their accompanied people
  if (!req.user || req.user.perfil?.toLowerCase() !== 'admin') {
    whereClause += ' AND p.acompanhante = $' + paramIndex;
    params.push(req.user.id);
    paramIndex++;
  }

  const csvQuery = 'SELECT p.*, u.nome as admin_nome, u2.nome as acomp_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id LEFT JOIN usuarios u2 ON CAST(p.acompanhante AS INTEGER) = u2.id WHERE 1=1' + whereClause + ' ORDER BY p.data_cadastro DESC';

  try {
    const result = await pool.query(csvQuery, params);
    const pessoas = result.rows;

    // Dados da congregação para o cabeçalho do CSV
    let org = { nome_org:'', endereco:'', telefone:'', email:'', responsavel:'' };
    try {
      const orgRes = await pool.query('SELECT nome_org, endereco, telefone, email, responsavel FROM config_org WHERE id = 1');
      if (orgRes.rows[0]) org = orgRes.rows[0];
    } catch (e) { /* mantém vazio */ }

    const BOM = '\uFEFF';
    const csvInfo = [];
    if (org.nome_org) csvInfo.push('Congregação: ' + org.nome_org);
    if (org.endereco) csvInfo.push('Endereço: ' + org.endereco);
    if (org.telefone) csvInfo.push('Telefone: ' + org.telefone);
    if (org.responsavel) csvInfo.push('Responsável: ' + org.responsavel);
    const header = (csvInfo.length ? csvInfo.join(' | ') + '\n' : '') + 'ID,Nome Completo,Data Nascimento,Endereço,Ponto Referência,Telefone,Tipo,Acompanhado Por,Cadastrado Por,Data Cadastro\n';
    const rows = pessoas.map(p => {
      const tipoLabel = p.tipo_cadastro === 'novo_nascimento' ? 'Novo Nascimento' : p.tipo_cadastro === 'reconciliacao' ? 'Reconciliação' : 'Novo Congregado';
      const acompName = p.acomp_nome || p.acompanhante || '-';
      return `${p.id},"${(p.nome_completo||'').replace(/"/g,'""')}","${p.data_nascimento||''}","${(p.endereco||'').replace(/"/g,'""')}","${(p.ponto_referencia||'').replace(/"/g,'""')}","${(p.telefone||'').replace(/"/g,'""')}","${tipoLabel}","${(acompName+'').replace(/"/g,'""')}","${(p.admin_nome||'').replace(/"/g,'""')}","${p.data_cadastro}"`;
    }).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename=cadastro_recnc_' + new Date().toISOString().slice(0,10) + '.csv');
    res.send(BOM + header + rows);
  } catch (error) {
    console.error('Erro ao exportar CSV:', error);
    res.status(500).json({ error: 'Erro ao exportar.' });
  }
});
app.get('/api/export/pdf', authMiddleware, async (req, res) => {
  const { tipo, search, ids } = req.query;
  let whereClause = '';
  const params = [];
  let paramIndex = 1;

  if (ids) {
    const idList = ids.split(',').map(Number);
    whereClause += ' AND p.id IN (' + buildPlaceholders(idList, paramIndex) + ')';
    params.push(...idList);
    paramIndex += idList.length;
  } else {
    if (tipo && tipo !== 'all') {
      whereClause += ' AND p.tipo_cadastro = $' + paramIndex;
      params.push(tipo);
      paramIndex++;
    }
    if (search) {
      whereClause += ' AND (p.nome_completo ILIKE $' + paramIndex + ' OR p.telefone ILIKE $' + (paramIndex + 1) + ')';
      params.push('%' + search + '%');
      params.push('%' + search + '%');
      paramIndex += 2;
    }
  }

  // Non-admin users only see their accompanied people
  if (!req.user || req.user.perfil?.toLowerCase() !== 'admin') {
    whereClause += ' AND p.acompanhante = $' + paramIndex;
    params.push(req.user.id);
    paramIndex++;
  }

  const query = 'SELECT p.*, u.nome as admin_nome, u2.nome as acomp_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id LEFT JOIN usuarios u2 ON CAST(p.acompanhante AS INTEGER) = u2.id WHERE 1=1' + whereClause + ' ORDER BY p.data_cadastro DESC';

  try {
    const result = await pool.query(query, params);
    const pessoas = result.rows;

    // Dados da congregação para o cabeçalho do PDF
    let org = { nome_org:'', endereco:'', telefone:'', email:'', responsavel:'' };
    try {
      const orgRes = await pool.query('SELECT nome_org, endereco, telefone, email, responsavel FROM config_org WHERE id = 1');
      if (orgRes.rows[0]) org = orgRes.rows[0];
    } catch (e) { /* mantém vazio */ }

    // Gerar PDF real com PDFKit
    const PDFDocument = require('pdfkit');
    const doc = new PDFDocument({ margin: 30, size: 'A4', layout: 'landscape' });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename=relatorio_recnc_' + new Date().toISOString().slice(0,10) + '.pdf');
    doc.pipe(res);

    // --- CABEÇALHO ---
    const tituloOrg = (org.nome_org || 'CADASTRO RECNC');
    // Bloco da congregação (se configurado) no canto superior direito
    let orgInfoLines = [];
    if (org.endereco) orgInfoLines.push(org.endereco);
    if (org.telefone) orgInfoLines.push('Tel: ' + org.telefone);
    if (org.email) orgInfoLines.push(org.email);
    if (org.responsavel) orgInfoLines.push('Resp.: ' + org.responsavel);
    if (orgInfoLines.length) {
      let orgY = 30;
      doc.fontSize(8).font('Helvetica-Bold').fillColor('#0d6efd').text(tituloOrg, 30, orgY, { align: 'left' });
      doc.font('Helvetica').fillColor('#666');
      orgInfoLines.forEach(line => {
        doc.fontSize(8).text(line, 630, orgY, { width: 195, align: 'right' });
        orgY += 12;
      });
    } else {
      doc.fontSize(20).font('Helvetica-Bold').fillColor('#0d6efd').text('CADASTRO RECNC', 30, 30);
    }
    doc.fontSize(11).font('Helvetica').fillColor('#333').text('Relatório de Cadastros', 30, 55);
    doc.moveDown(0.2);
    doc.fontSize(9).fillColor('#666')
      .text('Gerado em: ' + new Date().toLocaleString('pt-BR') + '  |  Total: ' + pessoas.length + ' registro(s)', 30, 72);
    doc.moveTo(30, 90).lineTo(822, 90).lineWidth(1).strokeColor('#0d6efd').stroke();

    // --- TABELA ---
    const startY = 100;
    // 9 colunas: ID, Nome, Data Nasc, Endereco, Ponto Ref, Telefone, Acompanhado Por, Tipo, Data Cad
    const colX = [30, 65, 215, 300, 445, 575, 660, 740, 795];
    const colW = [35, 150, 85, 145, 130, 85, 80, 55, 27];
    const headers = ['ID', 'Nome Completo', 'Data Nasc.', 'Endereço', 'Ponto Ref.', 'Telefone', 'Acomp. por', 'Tipo', 'Data'];

    // Header row
    doc.rect(30, startY, 792, 18).fill('#0d6efd');
    doc.fillColor('#fff').font('Helvetica-Bold').fontSize(7);
    headers.forEach((h, i) => doc.text(h, colX[i] + 3, startY + 5, { width: colW[i] }));

    // Data rows
    let y = startY + 20;
    doc.font('Helvetica').fontSize(7).fillColor('#333');

    function tipoLabel(t) {
      if (t === 'novo_nascimento') return 'Novo Nas.';
      if (t === 'reconciliacao') return 'Reconcil.';
      return 'Novo Cong.';
    }

    // Resolver nome do acompanhante
    const userMap = {};
    pessoas.forEach(p => {
      if (p.acompanhante && !userMap[p.acompanhante]) userMap[p.acompanhante] = String(p.acompanhante);
    });

    pessoas.forEach((p, idx) => {
      // Quebra de página
      if (y > 570) {
        doc.addPage();
        y = 30;
        doc.rect(30, y, 792, 18).fill('#0d6efd');
        doc.fillColor('#fff').font('Helvetica-Bold').fontSize(7);
        headers.forEach((h, i) => doc.text(h, colX[i] + 3, y + 5, { width: colW[i] }));
        y += 20;
        doc.font('Helvetica').fontSize(7).fillColor('#333');
      }

      // Alternating row bg
      if (idx % 2 === 0) {
        doc.rect(30, y, 792, 14).fill('#f8f9fa');
      }

      const rowY = y + 2;
      const nome = (p.nome_completo || '-');
      const ender = (p.endereco || '-');
      const ref = (p.ponto_referencia || '-');
      const tel = (p.telefone || '-');
      const data = p.data_cadastro ? new Date(p.data_cadastro).toLocaleDateString('pt-BR') : '-';
      const acomp = p.acomp_nome || String(p.acompanhante || '-');

      doc.fillColor('#333');
      doc.text(String(p.id), colX[0] + 3, rowY, { width: colW[0], ellipsis: true });
      doc.text(nome, colX[1] + 3, rowY, { width: colW[1], ellipsis: true });
      doc.text(p.data_nascimento || '-', colX[2] + 3, rowY, { width: colW[2], ellipsis: true });
      doc.text(ender, colX[3] + 3, rowY, { width: colW[3], ellipsis: true });
      doc.text(ref, colX[4] + 3, rowY, { width: colW[4], ellipsis: true });
      doc.text(tel, colX[5] + 3, rowY, { width: colW[5], ellipsis: true });
      doc.text(acomp, colX[6] + 3, rowY, { width: colW[6], ellipsis: true });
      doc.text(tipoLabel(p.tipo_cadastro), colX[7] + 3, rowY, { width: colW[7], ellipsis: true });
      doc.text(data, colX[8] + 3, rowY, { width: colW[8], ellipsis: true });

      y += 14;
    });

    // --- RODAPÉ ---
    const lastPage = doc.page;
    if (lastPage) {
      doc.moveTo(30, 575).lineTo(822, 575).lineWidth(0.5).strokeColor('#ccc').stroke();
      doc.fontSize(7).fillColor('#999').text(
        'Cadastro RECNC - Relatório gerado automaticamente  |  ' + new Date().toLocaleString('pt-BR'),
        30, 578, { align: 'center', width: 792 }
      );
    }

    doc.end();
  } catch (error) {
    console.error('Erro ao gerar PDF:', error);
    res.status(500).json({ error: 'Erro ao gerar PDF.' });
  }
});
app.get('/api/export/txt', authMiddleware, async (req, res) => {
  const { tipo, search, ids } = req.query;
  let whereClause = '';
  const params = [];
  let paramIndex = 1;

  if (ids) {
    const idList = ids.split(',').map(Number);
    whereClause += ' AND p.id IN (' + buildPlaceholders(idList, paramIndex) + ')';
    params.push(...idList);
    paramIndex += idList.length;
  } else {
    if (tipo && tipo !== 'all') {
      whereClause += ' AND p.tipo_cadastro = $' + paramIndex;
      params.push(tipo);
      paramIndex++;
    }
    if (search) {
      whereClause += ' AND (p.nome_completo ILIKE $' + paramIndex + ' OR p.telefone ILIKE $' + (paramIndex + 1) + ')';
      params.push('%' + search + '%');
      params.push('%' + search + '%');
      paramIndex += 2;
    }
  }

  // Non-admin users only see their accompanied people
  if (!req.user || req.user.perfil?.toLowerCase() !== 'admin') {
    whereClause += ' AND p.acompanhante = $' + paramIndex;
    params.push(req.user.id);
    paramIndex++;
  }

  const query = 'SELECT p.*, u.nome as admin_nome, u2.nome as acomp_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id LEFT JOIN usuarios u2 ON CAST(p.acompanhante AS INTEGER) = u2.id WHERE 1=1' + whereClause + ' ORDER BY p.data_cadastro DESC';

  try {
    const result = await pool.query(query, params);
    const pessoas = result.rows;

    // Dados da congregação para o cabeçalho
    let org = { nome_org:'', endereco:'', telefone:'', email:'', responsavel:'' };
    try {
      const orgRes = await pool.query('SELECT nome_org, endereco, telefone, email, responsavel FROM config_org WHERE id = 1');
      if (orgRes.rows[0]) org = orgRes.rows[0];
    } catch (e) { /* mantém vazio */ }

    const BOM = '\uFEFF';
    const W = 96; // largura total da tabela (linha de texto)

    // Helper: preencher célula com largura fixa, sem quebrar palavra ao meio
    function cell(str, width) {
      const s = (str == null ? '' : String(str)).trim();
      if (s.length <= width) return s.padEnd(width);
      // trunca na largura, cortando no espaço mais próximo (não corta palavra)
      let cut = s.slice(0, width);
      if (s[width] && s[width] !== ' ' && cut.lastIndexOf(' ') > 0) {
        cut = cut.slice(0, cut.lastIndexOf(' ')).trimEnd();
      }
      return cut.padEnd(width);
    }
    // Definição das colunas da tabela
    const cols = [
      { h: 'ID',    w: 6 },
      { h: 'Nome',  w: 30 },
      { h: 'Telefone', w: 18 },
      { h: 'Tipo',  w: 22 },
      { h: 'Data',  w: 12 }
    ];
    const colWidths = cols.map(c => c.w);
    // Linha de separação da tabela gerada dinamicamente (bordas + |  +)
    const sepLine = '+' + colWidths.map(w => '-'.repeat(w + 2)).join('+') + '+';
    // Linha de separação fina para o topo (traço contínuo)
    const thinLine = '-'.repeat(W);

    const linhas = [];
    const nomeIgreja = (org.nome_org || 'Cadastro RECNC');
    const tituloCustom = (req.query.titulo || '').trim();

    // === TOPO: NOME DA IGREJA (do cadastro principal) ===
    linhas.push('='.repeat(W));
    linhas.push(nomeIgreja.toUpperCase());
    if (org.endereco) linhas.push(org.endereco);
    if (org.telefone) linhas.push('Telefone: ' + org.telefone);
    if (org.email) linhas.push('E-mail: ' + org.email);
    if (org.responsavel) linhas.push('Responsável: ' + org.responsavel);
    linhas.push('='.repeat(W));

    // Subtítulo do relatório (título custom se fornecido, senão genérico)
    linhas.push(tituloCustom || 'Relatório de Cadastros');
    linhas.push('Gerado em: ' + new Date().toLocaleString('pt-BR') + '  |  Total: ' + pessoas.length + ' registro(s)');
    linhas.push(thinLine);

    if (pessoas.length === 0) {
      linhas.push('Nenhum registro encontrado para os filtros informados.');
    } else {
      function tipoLabelTxt(t) {
        if (t === 'novo_nascimento') return 'Novo Nascimento';
        if (t === 'reconciliacao') return 'Reconciliação';
        return 'Novo Congregado';
      }
      // Cabeçalho da tabela
      const headerRow = '| ' + cols.map(c => cell(c.h, c.w)).join(' | ') + ' |';
      linhas.push(headerRow);
      linhas.push(sepLine);
      pessoas.forEach(p => {
        const data = p.data_cadastro ? new Date(p.data_cadastro).toLocaleDateString('pt-BR') : '-';
        const row = '| ' + cell(String(p.id), cols[0].w) + ' | '
          + cell(p.nome_completo || '-', cols[1].w) + ' | '
          + cell(p.telefone || '-', cols[2].w) + ' | '
          + cell(tipoLabelTxt(p.tipo_cadastro), cols[3].w) + ' | '
          + cell(data, cols[4].w) + ' |';
        linhas.push(row);
      });
      linhas.push(sepLine);
    }

    // === RODAPÉ ===
    linhas.push(nomeIgreja + ' - Relatório gerado automaticamente | ' + new Date().toLocaleString('pt-BR'));

    const content = linhas.join('\r\n') + '\r\n';
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename=relatorio_dock_' + new Date().toISOString().slice(0,10) + '.txt');
    res.send(BOM + content);
  } catch (error) {
    console.error('Erro ao gerar relatório TXT:', error);
    res.status(500).json({ error: 'Erro ao gerar relatório.' });
  }
});
app.post('/api/reports/send', authMiddleware, adminMiddleware, async (req, res) => {
  const { email, tipo, search, ids, titulo, mensagem } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email do destinatario e obrigatorio.' });
  }

  let whereClause = '';
  const params = [];
  let paramIndex = 1;

  if (ids && ids.length > 0) {
    whereClause += ' AND p.id IN (' + buildPlaceholders(ids, paramIndex) + ')';
    params.push(...ids);
    paramIndex += ids.length;
  } else {
    if (tipo && tipo !== 'all') {
      whereClause += ' AND p.tipo_cadastro = $' + paramIndex;
      params.push(tipo);
      paramIndex++;
    }
    if (search) {
      whereClause += ' AND (p.nome_completo ILIKE $' + paramIndex + ' OR p.telefone ILIKE $' + (paramIndex + 1) + ')';
      params.push('%' + search + '%');
      params.push('%' + search + '%');
      paramIndex += 2;
    }
  }

  const query = 'SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id WHERE 1=1' + whereClause + ' ORDER BY p.data_cadastro DESC';

  try {
    const result = await pool.query(query, params);
    const pessoas = result.rows;

    const rows = pessoas.map(p => {
      const tipoLabel = p.tipo_cadastro === 'novo_nascimento' ? 'Novo Nascimento' : p.tipo_cadastro === 'reconciliacao' ? 'Reconciliação' : 'Novo Congregado';
      return '<tr>\n        <td style="padding:6px;border:1px solid #dee2e6">' + p.id + '</td>\n        <td style="padding:6px;border:1px solid #dee2e6">' + (p.nome_completo || '') + '</td>\n        <td style="padding:6px;border:1px solid #dee2e6">' + (p.endereco || '') + '</td>\n        <td style="padding:6px;border:1px solid #dee2e6">' + (p.telefone || '') + '</td>\n        <td style="padding:6px;border:1px solid #dee2e6">' + tipoLabel + '</td>\n        <td style="padding:6px;border:1px solid #dee2e6">' + (p.acompanhante || '-') + '</td>\n        <td style="padding:6px;border:1px solid #dee2e6">' + new Date(p.data_cadastro).toLocaleDateString('pt-BR') + '</td>\n      </tr>';
    }).join('');

    const reportHtml = '<h2 style="color:#0d6efd">' + (titulo || 'Relatorio de Cadastros - Cadastro RECNC') + '</h2>\n<p style="color:#666">' + (mensagem || '') + '</p>\n<p><strong>Gerado em:</strong> ' + new Date().toLocaleString('pt-BR') + ' | <strong>Total:</strong> ' + pessoas.length + ' registro(s)</p>\n<table style="width:100%;border-collapse:collapse;font-size:12px">\n  <thead><tr style="background:#0d6efd;color:white">\n    <th style="padding:8px;border:1px solid #0d6efd">ID</th>\n    <th style="padding:8px;border:1px solid #0d6efd">Nome</th>\n    <th style="padding:8px;border:1px solid #0d6efd">Endereco</th>\n    <th style="padding:8px;border:1px solid #0d6efd">Telefone</th>\n    <th style="padding:8px;border:1px solid #0d6efd">Tipo</th>\n    <th style="padding:8px;border:1px solid #0d6efd">Acompanhante</th>\n    <th style="padding:8px;border:1px solid #0d6efd">Data</th>\n  </tr></thead>\n  <tbody>' + rows + '</tbody>\n</table>';

    const reportData = {
      id: Date.now(),
      titulo: titulo || 'Relatorio de Cadastros',
      email_destino: email,
      mensagem: mensagem || '',
      total_registros: pessoas.length,
      filtros: { tipo: tipo || 'all', search: search || '' },
      criado_por: req.user.id,
      data_geracao: new Date().toISOString(),
      conteudo_html: reportHtml
    };

    if (!global.reports) global.reports = [];
    global.reports.push(reportData);

    res.json({
      message: 'Relatorio gerado com sucesso. ' + pessoas.length + ' registro(s) incluido(s).',
      report: {
        id: reportData.id,
        titulo: reportData.titulo,
        email: reportData.email_destino,
        total: reportData.total_registros,
        data: reportData.data_geracao
      },
      html_content: reportHtml
    });
  } catch (error) {
    console.error('Erro ao gerar relatorio:', error);
    res.status(500).json({ error: 'Erro ao gerar relatorio.' });
  }
});

app.get('/api/reports', authMiddleware, adminMiddleware, (req, res) => {
  const reports = (global.reports || []).map(r => ({
    id: r.id,
    titulo: r.titulo,
    email: r.email_destino,
    total: r.total_registros,
    data: r.data_geracao,
    criado_por: r.criado_por
  }));
  res.json(reports);
});
app.get('/api/backup', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const [usuariosResult, pessoasResult, relatoriosResult] = await Promise.all([
      pool.query('SELECT * FROM usuarios'),
      pool.query('SELECT * FROM pessoas'),
      pool.query('SELECT * FROM relatorios')
    ]);
    const backup = {
      version: 1,
      createdAt: new Date().toISOString(),
      tables: {
        usuarios: usuariosResult.rows || [],
        pessoas: pessoasResult.rows || [],
        relatorios: relatoriosResult.rows || []
      }
    };
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename=backup_recnc_' + new Date().toISOString().slice(0,10) + '.json');
    res.json(backup);
  } catch (error) {
    console.error('Erro ao gerar backup:', error);
    res.status(500).json({ error: 'Erro ao gerar backup.' });
  }
});

app.post('/api/backup/restore', authMiddleware, adminMiddleware, async (req, res) => {
  const { backup } = req.body;
  if (!backup || !backup.tables) {
    return res.status(400).json({ error: 'Arquivo de backup inválido.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query('DELETE FROM relatorios');
    await client.query('DELETE FROM pessoas');
    await client.query('DELETE FROM usuarios');

    const errors = [];

    if (backup.tables.usuarios && backup.tables.usuarios.length > 0) {
      for (const u of backup.tables.usuarios) {
        try {
          await client.query(
            'INSERT INTO usuarios (id, nome, senha, perfil, data_criacao) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO UPDATE SET nome = EXCLUDED.nome, senha = EXCLUDED.senha, perfil = EXCLUDED.perfil, data_criacao = EXCLUDED.data_criacao',
            [u.id, u.nome, u.senha, u.perfil || 'usuario', u.data_criacao || new Date().toISOString()]
          );
        } catch (err) {
          errors.push('Erro ao restaurar usuário ' + u.nome + ': ' + err.message);
        }
      }
    }

    if (backup.tables.pessoas && backup.tables.pessoas.length > 0) {
      for (const p of backup.tables.pessoas) {
        try {
          await client.query(
            'INSERT INTO pessoas (id, nome_completo, data_nascimento, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante, foto_url, cadastrado_por, data_cadastro) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (id) DO UPDATE SET nome_completo = EXCLUDED.nome_completo, data_nascimento = EXCLUDED.data_nascimento, endereco = EXCLUDED.endereco, ponto_referencia = EXCLUDED.ponto_referencia, telefone = EXCLUDED.telefone, tipo_cadastro = EXCLUDED.tipo_cadastro, acompanhante = EXCLUDED.acompanhante, foto_url = EXCLUDED.foto_url, cadastrado_por = EXCLUDED.cadastrado_por, data_cadastro = EXCLUDED.data_cadastro',
            [p.id, p.nome_completo, p.data_nascimento, p.endereco, p.ponto_referencia, p.telefone, p.tipo_cadastro, p.acompanhante, p.foto_url, p.cadastrado_por, p.data_cadastro]
          );
        } catch (err) {
          errors.push('Erro ao restaurar pessoa ' + p.nome_completo + ': ' + err.message);
        }
      }
    }

    if (backup.tables.relatorios && backup.tables.relatorios.length > 0) {
      for (const r of backup.tables.relatorios) {
        try {
          await client.query(
            'INSERT INTO relatorios (id, titulo, email_destino, tipo_filtro, filtro_valor, total_registros, data_geracao, criado_por) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (id) DO UPDATE SET titulo = EXCLUDED.titulo, email_destino = EXCLUDED.email_destino, tipo_filtro = EXCLUDED.tipo_filtro, filtro_valor = EXCLUDED.filtro_valor, total_registros = EXCLUDED.total_registros, data_geracao = EXCLUDED.data_geracao, criado_por = EXCLUDED.criado_por',
            [r.id, r.titulo, r.email_destino, r.tipo_filtro, r.filtro_valor, r.total_registros, r.data_geracao, r.criado_por]
          );
        } catch (err) {
          errors.push('Erro ao restaurar relatorio ' + r.titulo + ': ' + err.message);
        }
      }
    }

    await client.query("SELECT setval('usuarios_id_seq', (SELECT COALESCE(MAX(id),1) FROM usuarios))");
    await client.query("SELECT setval('pessoas_id_seq', (SELECT COALESCE(MAX(id),1) FROM pessoas))");
    await client.query("SELECT setval('relatorios_id_seq', (SELECT COALESCE(MAX(id),1) FROM relatorios))");

    await client.query('COMMIT');

    if (errors.length > 0) {
      res.json({ message: 'Backup restaurado com ' + errors.length + ' erro(s).', errors });
    } else {
      res.json({ message: 'Backup restaurado com sucesso!' });
    }
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erro ao restaurar backup:', error);
    res.status(500).json({ error: 'Erro ao restaurar backup.' });
  } finally {
    client.release();
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

app.listen(PORT, () => {
  console.log('Servidor rodando em http://localhost:' + PORT);
});

module.exports = app;

