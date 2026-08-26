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

// Supabase Storage
const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_KEY || ''
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
      message: 'Usuario criado com sucesso.',
      token,
      user: { id: userId, nome, perfil }
    });
  } catch (error) {
    console.error('Erro ao registrar usuario:', error);
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
    console.error('Erro ao buscar usuarios:', error);
    res.status(500).json({ error: 'Erro ao buscar usuarios.' });
  }
});

app.get('/api/usuarios/list', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, nome FROM usuarios ORDER BY nome');
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar lista de usuarios:', error);
    res.status(500).json({ error: 'Erro ao buscar lista de usuarios.' });
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
    res.json({ message: 'Usuario criado com sucesso.', userId: result.rows[0].id });
  } catch (error) {
    console.error('Erro ao criar usuario:', error);
    res.status(500).json({ error: 'Erro ao criar usuario. Nome ja existe?' });
  }
});
app.post('/api/pessoas', authMiddleware, upload.single('foto'), async (req, res) => {
  const { nome_completo, data_nascimento, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante } = req.body;
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
        .from('cadastro-fotos')
        .upload(fileName, req.file.buffer, { contentType: req.file.mimetype });

      if (uploadError) {
        console.error('Erro ao upload foto:', uploadError);
      } else {
        const { data: urlData } = supabase.storage.from('cadastro-fotos').getPublicUrl(fileName);
        fotoUrl = urlData.publicUrl;
      }
    }

    const result = await pool.query(
      `INSERT INTO pessoas (nome_completo, data_nascimento, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante, foto_url, cadastrado_por, data_cadastro)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) RETURNING id`,
      [nome_completo, data_nascimento || null, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante || '', fotoUrl, cadastrado_por]
    );
    res.json({ message: 'Pessoa cadastrada com sucesso.', pessoaId: result.rows[0].id });
  } catch (error) {
    console.error('Erro ao cadastrar pessoa:', error);
    res.status(500).json({ error: 'Erro ao cadastrar pessoa.' });
  }
});

app.get('/api/pessoas', authMiddleware, adminMiddleware, async (req, res) => {
  const { tipo, search, page = 1, limit = 10 } = req.query;
  let whereClause = '';
  const params = [];
  let paramIndex = 1;

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

app.get('/api/pessoas/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id WHERE p.id = $1',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pessoa nao encontrada.' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao buscar pessoa:', error);
    res.status(500).json({ error: 'Erro ao buscar pessoa.' });
  }
});

app.get('/api/pessoas/meus-acompanhamentos', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const { page = 1, limit = 10 } = req.query;
  const limitNum = parseInt(limit);
  const offset = (parseInt(page) - 1) * limitNum;
  const params = [userId.toString()];

  try {
    const countResult = await pool.query(
      'SELECT COUNT(*) as total FROM pessoas p WHERE p.acompanhante = $1',
      params
    );
    const total = parseInt(countResult.rows[0].total);
    const totalPages = Math.ceil(total / limitNum);
    const dataResult = await pool.query(
      'SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id WHERE p.acompanhante = $1 ORDER BY p.data_cadastro DESC LIMIT $2 OFFSET $3',
      [...params, limitNum, offset]
    );
    res.json({ pessoas: dataResult.rows, total, totalPages, page: parseInt(page) });
  } catch (error) {
    console.error('Erro ao buscar acompanhamentos:', error);
    res.status(500).json({ error: 'Erro ao buscar acompanhamentos.' });
  }
});
app.put('/api/pessoas/:id', authMiddleware, adminMiddleware, upload.single('foto'), async (req, res) => {
  const { nome_completo, data_nascimento, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante, foto_url } = req.body;
  let fotoUrl = foto_url || '';

  try {
    // Se enviou nova foto, fazer upload
    if (req.file) {
      const ext = req.file.mimetype === 'image/png' ? 'png' : req.file.mimetype === 'image/webp' ? 'webp' : 'jpg';
      const fileName = `fotos/${crypto.randomUUID()}.${ext}`;
      const { data: uploadData, error: uploadError } = await supabase.storage
        .from('cadastro-fotos')
        .upload(fileName, req.file.buffer, { contentType: req.file.mimetype });

      if (!uploadError) {
        const { data: urlData } = supabase.storage.from('cadastro-fotos').getPublicUrl(fileName);
        fotoUrl = urlData.publicUrl;
      }
    }

    const result = await pool.query(
      'UPDATE pessoas SET nome_completo = $1, data_nascimento = $2, endereco = $3, ponto_referencia = $4, telefone = $5, tipo_cadastro = $6, acompanhante = $7, foto_url = $8 WHERE id = $9',
      [nome_completo, data_nascimento || null, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante || '', fotoUrl, req.params.id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Pessoa nao encontrada.' });
    }
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
      return res.status(404).json({ error: 'Usuario nao encontrado.' });
    }
    if (user.perfil === 'admin') {
      const countResult = await pool.query("SELECT COUNT(*) as admin_count FROM usuarios WHERE perfil = 'admin'");
      const adminCount = parseInt(countResult.rows[0].admin_count);
      if (adminCount <= 1) {
        return res.status(400).json({ error: 'Nao e possivel excluir o ultimo administrador.' });
      }
    }
    await pool.query('DELETE FROM usuarios WHERE id = $1', [req.params.id]);
    res.json({ message: 'Usuario excluido com sucesso.' });
  } catch (error) {
    console.error('Erro ao excluir usuario:', error);
    res.status(500).json({ error: 'Erro ao excluir usuario.' });
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
      if (result.rowCount === 0) return res.status(404).json({ error: 'Usuario nao encontrado.' });
      res.json({ message: 'Usuario atualizado com sucesso.' });
    } else {
      const result = await pool.query(
        'UPDATE usuarios SET nome = $1, perfil = $2 WHERE id = $3',
        [nome, perfil || 'usuario', userId]
      );
      if (result.rowCount === 0) return res.status(404).json({ error: 'Usuario nao encontrado.' });
      res.json({ message: 'Usuario atualizado com sucesso.' });
    }
  } catch (error) {
    console.error('Erro ao atualizar usuario:', error);
    res.status(500).json({ error: 'Erro ao atualizar usuario. Nome ja existe?' });
  }
});
app.get('/api/estatisticas', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const [totalResult, nascResult, reconcResult, ncgrResult, recentResult] = await Promise.all([
      pool.query('SELECT COUNT(*) as total FROM pessoas'),
      pool.query("SELECT COUNT(*) as total FROM pessoas WHERE tipo_cadastro = 'novo_nascimento'"),
      pool.query("SELECT COUNT(*) as total FROM pessoas WHERE tipo_cadastro = 'reconciliacao'"),
      pool.query("SELECT COUNT(*) as total FROM pessoas WHERE tipo_cadastro = 'novo_congregado'"),
      pool.query('SELECT * FROM pessoas ORDER BY data_cadastro DESC LIMIT 5')
    ]);
    res.json({
      totalPessoas: parseInt(totalResult.rows[0].total),
      totalNascimento: parseInt(nascResult.rows[0].total),
      totalReconciliacao: parseInt(reconcResult.rows[0].total),
      totalNcgr: parseInt(ncgrResult.rows[0].total),
      ultimosCadastros: recentResult.rows.length
    });
  } catch (error) {
    console.error('Erro ao buscar estatisticas:', error);
    res.status(500).json({ error: 'Erro ao buscar estatisticas.' });
  }
});

app.get('/api/export/csv', authMiddleware, adminMiddleware, async (req, res) => {
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

  const query = 'SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id WHERE 1=1' + whereClause + ' ORDER BY p.data_cadastro DESC';

  try {
    const result = await pool.query(query, params);
    const pessoas = result.rows;
    const BOM = '\uFEFF';
    const header = 'ID,Nome Completo,Data Nascimento,Endereco,Ponto Referencia,Telefone,Tipo,Acompanhamento,Cadastrado Por,Data Cadastro\n';
    const rows = pessoas.map(p => {
      const tipoLabel = p.tipo_cadastro === 'novo_nascimento' ? 'Novo Nascimento' : p.tipo_cadastro === 'reconciliacao' ? 'Reconciliacao' : 'Novo Congregado';
      return `${p.id},"${(p.nome_completo||'').replace(/"/g,'""')}","${p.data_nascimento||''}","${(p.endereco||'').replace(/"/g,'""')}","${(p.ponto_referencia||'').replace(/"/g,'""')}","${(p.telefone||'').replace(/"/g,'""')}","${tipoLabel}","${(p.acompanhante||'').replace(/"/g,'""')}","${(p.admin_nome||'').replace(/"/g,'""')}","${p.data_cadastro}"`;
    }).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename=cadastro_recnc_' + new Date().toISOString().slice(0,10) + '.csv');
    res.send(BOM + header + rows);
  } catch (error) {
    console.error('Erro ao exportar CSV:', error);
    res.status(500).json({ error: 'Erro ao exportar.' });
  }
});
app.get('/api/export/pdf', authMiddleware, adminMiddleware, async (req, res) => {
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

  const query = 'SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id WHERE 1=1' + whereClause + ' ORDER BY p.data_cadastro DESC';

  try {
    const result = await pool.query(query, params);
    const pessoas = result.rows;
    const rows = pessoas.map(p => {
      const tipoLabel = p.tipo_cadastro === 'novo_nascimento' ? 'Novo Nascimento' : p.tipo_cadastro === 'reconciliacao' ? 'Reconciliacao' : 'Novo Congregado';
      return '<tr>\n        <td>' + p.id + '</td>\n        <td>' + (p.nome_completo || '') + '</td>\n        <td>' + (p.data_nascimento || '-') + '</td>\n        <td>' + (p.endereco || '') + '</td>\n        <td>' + (p.ponto_referencia || '') + '</td>\n        <td>' + (p.telefone || '') + '</td>\n        <td>' + tipoLabel + '</td>\n        <td>' + (p.acompanhante || '-') + '</td>\n        <td>' + (p.admin_nome || '') + '</td>\n        <td>' + new Date(p.data_cadastro).toLocaleDateString('pt-BR') + '</td>\n      </tr>';
    }).join('');

    const html = '<!DOCTYPE html>\n<html lang="pt-BR"><head><meta charset="UTF-8">\n<title>Cadastro RECNC - Relatorio</title>\n<style>\n  body{font-family:Arial,sans-serif;margin:20px;color:#333}\n  h1{color:#0d6efd;font-size:20px;border-bottom:2px solid #0d6efd;padding-bottom:8px}\n  .info{margin:10px 0;font-size:13px;color:#666}\n  table{width:100%;border-collapse:collapse;margin-top:15px;font-size:11px}\n  th{background:#0d6efd;color:white;padding:8px 6px;text-align:left;border:1px solid #0d6efd}\n  td{padding:6px;border:1px solid #dee2e6}\n  tr:nth-child(even){background:#f8f9fa}\n  @media print{body{margin:10px}}\n</style></head><body>\n<h1>Cadastro RECNC - Relatorio de Cadastros</h1>\n<div class="info">Gerado em: ' + new Date().toLocaleString('pt-BR') + ' | Total: ' + pessoas.length + ' registro(s)</div>\n<table><thead><tr>\n  <th>ID</th><th>Nome</th><th>Data Nasc.</th><th>Endereco</th><th>Ref.</th><th>Telefone</th><th>Tipo</th><th>Acompanhamento</th><th>Cadastrado por</th><th>Data</th>\n</tr></thead><tbody>' + rows + '</tbody></table>\n</body></html>';

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (error) {
    console.error('Erro ao gerar PDF:', error);
    res.status(500).json({ error: 'Erro ao gerar PDF.' });
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
      const tipoLabel = p.tipo_cadastro === 'novo_nascimento' ? 'Novo Nascimento' : p.tipo_cadastro === 'reconciliacao' ? 'Reconciliacao' : 'Novo Congregado';
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
    return res.status(400).json({ error: 'Arquivo de backup invalido.' });
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
          errors.push('Erro ao restaurar usuario ' + u.nome + ': ' + err.message);
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

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message, code: err.code });
  }
});

app.listen(PORT, () => {
  console.log('Servidor rodando em http://localhost:' + PORT);
});

module.exports = app;

