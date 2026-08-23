require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve frontend static files
const path = require('path');
app.use(express.static(path.join(__dirname, '..', 'frontend')));
// Also serve android-app/www files (for Capacitor APK)
app.use(express.static(path.join(__dirname, '..', 'android-app', 'www')));

// Rate limiting - API routes only (not static files)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 2000, // limit each IP to 2000 requests per windowMs
  message: { error: 'Muitas requisicoes deste IP, tente novamente mais tarde.' }
});
app.use('/api', limiter);

// Database setup
const db = new sqlite3.Database(process.env.DATABASE_PATH || './database.db');

// Initialize database tables
function initializeDatabase() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      db.run(`
        CREATE TABLE IF NOT EXISTS usuarios (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          nome TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL,
          senha_hash TEXT NOT NULL,
          perfil TEXT DEFAULT 'usuario' CHECK (perfil IN ('admin', 'usuario')),
          data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS pessoas (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          nome_completo TEXT NOT NULL,
          data_nascimento TEXT,
          endereco TEXT NOT NULL,
          ponto_referencia TEXT NOT NULL,
          telefone TEXT NOT NULL,
          tipo_cadastro TEXT NOT NULL CHECK (tipo_cadastro IN ('novo_nascimento', 'reconciliacao', 'novo_congregado')),
          acompanhante TEXT,
          foto_url TEXT,
          cadastrado_por INTEGER,
          data_cadastro DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (cadastrado_por) REFERENCES usuarios(id)
        )
      `);

      // Migration: add acompanhante column if missing
      db.run("PRAGMA table_info(pessoas)", [], (err, columns) => {
        if (!err && columns) {
          const hasAcomp = columns.some(c => c.name === 'acompanhante');
          if (!hasAcomp) {
            db.run("ALTER TABLE pessoas ADD COLUMN acompanhante TEXT", [], () => {
              console.log('Migration: added acompanhante column');
            });
          }
          const hasDataNasc = columns.some(c => c.name === 'data_nascimento');
          if (!hasDataNasc) {
            db.run("ALTER TABLE pessoas ADD COLUMN data_nascimento TEXT", [], () => {
              console.log('Migration: added data_nascimento column');
            });
          }
          // Remove arquivo_url if exists (deprecated)
          // SQLite doesn't support DROP COLUMN in older versions, we just ignore it
        }
      });

      // Create admin user if not exists (first user becomes admin)
      const bcrypt = require('bcryptjs');
      const saltRounds = 10;
      
      // We'll handle first-user-admin logic in the register route

      resolve();
    });
  });
}

initializeDatabase().then(() => {
  console.log('Database initialized');
});

// Auth middleware
function authMiddleware(req, res, next) {
  // Support both Authorization header and query param token (for downloads)
  const authHeader = req.headers['authorization'];
  const queryToken = req.query.token;
  
  let token;
  if (authHeader) {
    token = authHeader.split(' ')[1]; // "Bearer <token>"
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

// Role middleware
function adminMiddleware(req, res, next) {
  if (req.user.perfil !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });
  }
  next();
}

// Routes

// 1. Register - First user becomes admin
app.post('/api/register', async (req, res) => {
  const { nome, email, senha } = req.body;
  
  if (!nome || !email || !senha) {
    return res.status(400).json({ error: 'Nome, email e senha são obrigatórios.' });
  }

  try {
    const saltRounds = 10;
    const senha_hash = await bcrypt.hash(senha, saltRounds);
    
    // Check if user exists
    db.get('SELECT id FROM usuarios WHERE email = ?', [email], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Erro ao verificar usuário.' });
      }
      
      if (user) {
        return res.status(409).json({ error: 'Este email já está cadastrado.' });
      }
      
      // Determine perfil: first user becomes admin, others are 'usuario'
      // Simple approach: check total users count
      db.get('SELECT COUNT(*) as count FROM usuarios', [], (err, row) => {
        if (err) {
          return res.status(500).json({ error: 'Erro ao contar usuários.' });
        }
        
        const perfil = row.count === 0 ? 'admin' : 'usuario';
        
        const stmt = `INSERT INTO usuarios (nome, email, senha_hash, perfil) VALUES (?, ?, ?, ?)`;
        db.run(stmt, [nome, email, senha_hash, perfil], function(err) {
          if (err) {
            return res.status(500).json({ error: 'Erro ao criar usuário.' });
          }
          
          // Generate JWT token
          const token = jwt.sign(
            { id: this.lastID, email, perfil },
            process.env.JWT_SECRET || 'cadastro-remc-secret-key',
            { expiresIn: '24h' }
          );
          
          res.status(201).json({
            message: 'Usuário criado com sucesso.',
            token,
            user: { id: this.lastID, nome, email, perfil }
          });
        });
      });
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro no servidor.' });
  }
});

// 2. Login
app.post('/api/login', (req, res) => {
  const { email, senha } = req.body;
  
  if (!email || !senha) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
  }

  db.get('SELECT * FROM usuarios WHERE email = ?', [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Erro no servidor.' });
    }
    
    if (!user) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }
    
    const validPassword = await bcrypt.compare(senha, user.senha_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }
    
    const token = jwt.sign(
      { id: user.id, email: user.email, perfil: user.perfil },
      process.env.JWT_SECRET || 'cadastro-remc-secret-key',
      { expiresIn: '24h' }
    );
    
    res.json({
      message: 'Login bem-sucedido.',
      token,
      user: { id: user.id, nome: user.nome, email: user.email, perfil: user.perfil }
    });
  });
});

// 3. Get current user profile
app.get('/api/profile', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// 4. Get all users (admin only)
app.get('/api/usuarios', authMiddleware, adminMiddleware, (req, res) => {
  db.all('SELECT id, nome, email, perfil, data_criacao FROM usuarios', [], (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao buscar usuários.' });
    }
    res.json(users);
  });
});

// 4b. Simple user list for Acompanhante dropdown (all authenticated users)
app.get('/api/usuarios/list', authMiddleware, (req, res) => {
  db.all('SELECT id, nome FROM usuarios ORDER BY nome', [], (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao buscar lista de usuários.' });
    }
    res.json(users);
  });
});

// 5. Create new user (admin only)
app.post('/api/usuarios', authMiddleware, adminMiddleware, (req, res) => {
  const { nome, email, senha, perfil } = req.body;
  
  if (!nome || !email || !senha) {
    return res.status(400).json({ error: 'Nome, email e senha são obrigatórios.' });
  }
  
  bcrypt.hash(senha, 10, (err, saltHash) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao hashear senha.' });
    }
    
    const stmt = `INSERT INTO usuarios (nome, email, senha_hash, perfil) VALUES (?, ?, ?, ?)`;
    db.run(stmt, [nome, email, saltHash, perfil || 'usuario'], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Erro ao criar usuário. Email já existe?' });
      }
      res.json({ message: 'Usuário criado com sucesso.', userId: this.lastID });
    });
  });
});

// 6. Create new pessoa (all authenticated users)
app.post('/api/pessoas', authMiddleware, (req, res) => {
  const { nome_completo, data_nascimento, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante, foto_url } = req.body;
  
  if (!nome_completo || !endereco || !ponto_referencia || !telefone || !tipo_cadastro) {
    return res.status(400).json({ error: 'Todos os campos obrigatorios devem ser preenchidos.' });
  }
  
  const cadastrado_por = req.user.id;
  
  const stmt = `INSERT INTO pessoas (nome_completo, data_nascimento, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante, foto_url, cadastrado_por, data_cadastro) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`;
  db.run(stmt, [nome_completo, data_nascimento || null, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante || '', foto_url || '', cadastrado_por], function(err) {
    if (err) {
      console.error('Erro ao cadastrar pessoa:', err);
      return res.status(500).json({ error: 'Erro ao cadastrar pessoa.' });
    }
    res.json({ message: 'Pessoa cadastrada com sucesso.', pessoaId: this.lastID });
  });
});

// 7. Get all pessoas (admin only - with pagination and filters)
app.get('/api/pessoas', authMiddleware, adminMiddleware, (req, res) => {
  const { tipo, search, page = 1, limit = 10 } = req.query;
  let whereClause = ' WHERE 1=1';
  const params = [];
  
  if (tipo && tipo !== 'all') {
    whereClause += ' AND p.tipo_cadastro = ?';
    params.push(tipo);
  }
  
  if (search) {
    whereClause += ' AND (p.nome_completo LIKE ? OR p.telefone LIKE ?)';
    params.push(`%${search}%`);
    params.push(`%${search}%`);
  }
  
  // Count total
  const countQuery = `SELECT COUNT(*) as total FROM pessoas p${whereClause}`;
  
  db.get(countQuery, params, (err, countResult) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao contar pessoas.' });
    }
    
    const total = countResult.total;
    const totalPages = Math.ceil(total / parseInt(limit));
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    const dataQuery = `SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id${whereClause} ORDER BY p.data_cadastro DESC LIMIT ? OFFSET ?`;
    
    db.all(dataQuery, [...params, parseInt(limit), offset], (err, pessoas) => {
      if (err) {
        return res.status(500).json({ error: 'Erro ao buscar pessoas.' });
      }
      res.json({ pessoas, total, totalPages, page: parseInt(page) });
    });
  });
});

// 8. Get single pessoa (admin only)
app.get('/api/pessoas/:id', authMiddleware, adminMiddleware, (req, res) => {
  db.get('SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id WHERE p.id = ?', [req.params.id], (err, pessoa) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao buscar pessoa.' });
    }
    if (!pessoa) {
      return res.status(404).json({ error: 'Pessoa não encontrada.' });
    }
    res.json(pessoa);
  });
});

// 8.1 Get my acompanhamentos (regular users see only people assigned to them)
app.get('/api/pessoas/meus-acompanhamentos', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const { page = 1, limit = 10 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  
  const whereClause = ' WHERE p.acompanhante = ?';
  const params = [userId.toString()];
  
  // Count total
  const countQuery = `SELECT COUNT(*) as total FROM pessoas p${whereClause}`;
  
  db.get(countQuery, params, (err, countResult) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao contar acompanhamentos.' });
    }
    
    const total = countResult.total;
    const totalPages = Math.ceil(total / parseInt(limit));
    
    const query = `SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id${whereClause} ORDER BY p.data_cadastro DESC LIMIT ? OFFSET ?`;
    
    db.all(query, [...params, parseInt(limit), offset], (err, pessoas) => {
      if (err) {
        return res.status(500).json({ error: 'Erro ao buscar acompanhamentos.' });
      }
      res.json({ pessoas, total, totalPages, page: parseInt(page) });
    });
  });
});

// 9. Update pessoa (admin only)
app.put('/api/pessoas/:id', authMiddleware, adminMiddleware, (req, res) => {
  const { nome_completo, data_nascimento, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante, foto_url } = req.body;
  
  const stmt = `UPDATE pessoas SET nome_completo = ?, data_nascimento = ?, endereco = ?, ponto_referencia = ?, telefone = ?, tipo_cadastro = ?, acompanhante = ?, foto_url = ? WHERE id = ?`;
  db.run(stmt, [nome_completo, data_nascimento || null, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante || '', foto_url || '', req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Erro ao atualizar pessoa.' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Pessoa nao encontrada.' });
    }
    res.json({ message: 'Pessoa atualizada com sucesso.' });
  });
});

// 10. Delete pessoa (admin only)
app.delete('/api/pessoas/:id', authMiddleware, adminMiddleware, (req, res) => {
  db.run('DELETE FROM pessoas WHERE id = ?', [req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Erro ao excluir pessoa.' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Pessoa não encontrada.' });
    }
    res.json({ message: 'Pessoa excluída com sucesso.' });
  });
});

// 11. Delete user (admin only)
app.delete('/api/usuarios/:id', authMiddleware, adminMiddleware, (req, res) => {
  // Can't delete the last admin
  db.get('SELECT perfil FROM usuarios WHERE id = ?', [req.params.id], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao verificar usuário.' });
    }
    
    if (user.perfil === 'admin') {
      db.get('SELECT COUNT(*) as admin_count FROM usuarios WHERE perfil = ?', ['admin'], (err, count) => {
        if (err) {
          return res.status(500).json({ error: 'Erro ao contar admins.' });
        }
        
        if (count.admin_count <= 1 && user.perfil === 'admin') {
          return res.status(400).json({ error: 'Não é possível excluir o último administrador.' });
        }
      });
    }
    
    db.run('DELETE FROM usuarios WHERE id = ?', [req.params.id], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Erro ao excluir usuário.' });
      }
      res.json({ message: 'Usuário excluído com sucesso.' });
    });
  });
});

// 12. Update user (admin only)
app.put('/api/usuarios/:id', authMiddleware, adminMiddleware, (req, res) => {
  const { nome, email, senha, perfil } = req.body;
  const userId = req.params.id;
  
  if (!nome || !email) {
    return res.status(400).json({ error: 'Nome e email são obrigatórios.' });
  }
  
  // If password provided, hash it and update with password
  if (senha && senha.length >= 6) {
    bcrypt.hash(senha, 10, (err, hash) => {
      if (err) return res.status(500).json({ error: 'Erro ao processar senha.' });
      db.run('UPDATE usuarios SET nome = ?, email = ?, senha_hash = ?, perfil = ? WHERE id = ?',
        [nome, email, hash, perfil || 'usuario', userId], function(err) {
          if (err) return res.status(500).json({ error: 'Erro ao atualizar usuário. Email já existe?' });
          if (this.changes === 0) return res.status(404).json({ error: 'Usuário não encontrado.' });
          res.json({ message: 'Usuário atualizado com sucesso.' });
      });
    });
  } else {
    // Update without password
    db.run('UPDATE usuarios SET nome = ?, email = ?, perfil = ? WHERE id = ?',
      [nome, email, perfil || 'usuario', userId], function(err) {
        if (err) return res.status(500).json({ error: 'Erro ao atualizar usuário. Email já existe?' });
        if (this.changes === 0) return res.status(404).json({ error: 'Usuário não encontrado.' });
        res.json({ message: 'Usuário atualizado com sucesso.' });
    });
  }
});

// API: Get statistics (admin only)
app.get('/api/estatisticas', authMiddleware, adminMiddleware, (req, res) => {
  const results = {};
  
  db.get('SELECT COUNT(*) as total FROM pessoas', [], (err, row) => {
    if (err) return res.status(500).json({ error: 'Erro ao buscar estatísticas.' });
    results.totalPessoas = row.total;
    
    db.get("SELECT COUNT(*) as total FROM pessoas WHERE tipo_cadastro = 'novo_nascimento'", [], (err, row) => {
      if (err) return res.status(500).json({ error: 'Erro ao buscar estatísticas.' });
      results.totalNascimento = row.total;
      
      db.get("SELECT COUNT(*) as total FROM pessoas WHERE tipo_cadastro = 'reconciliacao'", [], (err, row) => {
        if (err) return res.status(500).json({ error: 'Erro ao buscar estatísticas.' });
        results.totalReconciliacao = row.total;
        
        db.get("SELECT COUNT(*) as total FROM pessoas WHERE tipo_cadastro = 'novo_congregado'", [], (err, row) => {
          if (err) return res.status(500).json({ error: 'Erro ao buscar estatísticas.' });
          results.totalNcgr = row.total;
          
          db.all('SELECT * FROM pessoas ORDER BY data_cadastro DESC LIMIT 5', [], (err, ultimos) => {
            if (err) return res.status(500).json({ error: 'Erro ao buscar últimos cadastros.' });
            results.ultimosCadastros = ultimos.length;
            res.json(results);
          });
        });
      });
    });
  });
});

// ===== EXPORT ROUTES =====

// Export CSV (admin only)
app.get('/api/export/csv', authMiddleware, adminMiddleware, (req, res) => {
  const { tipo, search, ids } = req.query;
  let whereClause = ' WHERE 1=1';
  const params = [];
  
  if (ids) {
    const idList = ids.split(',').map(Number);
    whereClause += ` AND p.id IN (${idList.map(() => '?').join(',')})`;
    params.push(...idList);
  } else {
    if (tipo && tipo !== 'all') {
      whereClause += ' AND p.tipo_cadastro = ?';
      params.push(tipo);
    }
    if (search) {
      whereClause += ' AND (p.nome_completo LIKE ? OR p.telefone LIKE ?)';
      params.push(`%${search}%`);
      params.push(`%${search}%`);
    }
  }
  
  const query = `SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id${whereClause} ORDER BY p.data_cadastro DESC`;
  
  db.all(query, params, (err, pessoas) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao exportar.' });
    }
    
    const BOM = '\uFEFF';
    const header = 'ID,Nome Completo,Data Nascimento,Endereco,Ponto Referencia,Telefone,Tipo,Acompanhamento,Cadastrado Por,Data Cadastro\n';
    const rows = pessoas.map(p => {
      const tipoLabel = p.tipo_cadastro === 'novo_nascimento' ? 'Novo Nascimento' : p.tipo_cadastro === 'reconciliacao' ? 'Reconciliacao' : 'Novo Congregado';
      return `${p.id},"${(p.nome_completo||'').replace(/"/g,'""')}","${p.data_nascimento||''}","${(p.endereco||'').replace(/"/g,'""')}","${(p.ponto_referencia||'').replace(/"/g,'""')}","${(p.telefone||'').replace(/"/g,'""')}","${tipoLabel}","${(p.acompanhante||'').replace(/"/g,'""')}","${(p.admin_nome||'').replace(/"/g,'""')}","${p.data_cadastro}"`;
    }).join('\n');
    
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename=cadastro_recnc_${new Date().toISOString().slice(0,10)}.csv`);
    res.send(BOM + header + rows);
  });
});

// Export PDF (admin only - generates HTML that browser prints as PDF)
app.get('/api/export/pdf', authMiddleware, adminMiddleware, (req, res) => {
  const { tipo, search, ids } = req.query;
  let whereClause = ' WHERE 1=1';
  const params = [];
  
  if (ids) {
    const idList = ids.split(',').map(Number);
    whereClause += ` AND p.id IN (${idList.map(() => '?').join(',')})`;
    params.push(...idList);
  } else {
    if (tipo && tipo !== 'all') {
      whereClause += ' AND p.tipo_cadastro = ?';
      params.push(tipo);
    }
    if (search) {
      whereClause += ' AND (p.nome_completo LIKE ? OR p.telefone LIKE ?)';
      params.push(`%${search}%`);
      params.push(`%${search}%`);
    }
  }
  
  const query = `SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id${whereClause} ORDER BY p.data_cadastro DESC`;
  
  db.all(query, params, (err, pessoas) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao gerar PDF.' });
    }
    
    const rows = pessoas.map(p => {
      const tipo = p.tipo_cadastro === 'novo_nascimento' ? 'Novo Nascimento' : p.tipo_cadastro === 'reconciliacao' ? 'Reconciliacao' : 'Novo Congregado';
      return `<tr>
        <td>${p.id}</td>
        <td>${p.nome_completo || ''}</td>
        <td>${p.data_nascimento || '-'}</td>
        <td>${p.endereco || ''}</td>
        <td>${p.ponto_referencia || ''}</td>
        <td>${p.telefone || ''}</td>
        <td>${tipo}</td>
        <td>${p.acompanhante || '-'}</td>
        <td>${p.admin_nome || ''}</td>
        <td>${new Date(p.data_cadastro).toLocaleDateString('pt-BR')}</td>
      </tr>`;
    }).join('');
    
    const html = `<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8">
<title>Cadastro RECNC - Relatorio</title>
<style>
  body{font-family:Arial,sans-serif;margin:20px;color:#333}
  h1{color:#0d6efd;font-size:20px;border-bottom:2px solid #0d6efd;padding-bottom:8px}
  .info{margin:10px 0;font-size:13px;color:#666}
  table{width:100%;border-collapse:collapse;margin-top:15px;font-size:11px}
  th{background:#0d6efd;color:white;padding:8px 6px;text-align:left;border:1px solid #0d6efd}
  td{padding:6px;border:1px solid #dee2e6}
  tr:nth-child(even){background:#f8f9fa}
  @media print{body{margin:10px}}
</style></head><body>
<h1>Cadastro RECNC - Relatorio de Cadastros</h1>
<div class="info">Gerado em: ${new Date().toLocaleString('pt-BR')} | Total: ${pessoas.length} registro(s)</div>
<table><thead><tr>
  <th>ID</th><th>Nome</th><th>Data Nasc.</th><th>Endereco</th><th>Ref.</th><th>Telefone</th><th>Tipo</th><th>Acompanhamento</th><th>Cadastrado por</th><th>Data</th>
</tr></thead><tbody>${rows}</tbody></table>
</body></html>`;
    
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  });
});

// Send report (admin email)
app.post('/api/reports/send', authMiddleware, adminMiddleware, (req, res) => {
  const { email, tipo, search, ids, titulo, mensagem } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email do destinatario e obrigatorio.' });
  }
  
  let whereClause = ' WHERE 1=1';
  const params = [];
  
  if (ids && ids.length > 0) {
    whereClause += ` AND p.id IN (${ids.map(() => '?').join(',')})`;
    params.push(...ids);
  } else {
    if (tipo && tipo !== 'all') {
      whereClause += ' AND p.tipo_cadastro = ?';
      params.push(tipo);
    }
    if (search) {
      whereClause += ' AND (p.nome_completo LIKE ? OR p.telefone LIKE ?)';
      params.push(`%${search}%`);
      params.push(`%${search}%`);
    }
  }
  
  const query = `SELECT p.*, u.nome as admin_nome FROM pessoas p LEFT JOIN usuarios u ON p.cadastrado_por = u.id${whereClause} ORDER BY p.data_cadastro DESC`;
  
  db.all(query, params, (err, pessoas) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao gerar relatorio.' });
    }
    
    // Generate report HTML content
    const rows = pessoas.map(p => {
      const tipo = p.tipo_cadastro === 'novo_nascimento' ? 'Novo Nascimento' : p.tipo_cadastro === 'reconciliacao' ? 'Reconciliacao' : 'Novo Congregado';
      return `<tr>
        <td style="padding:6px;border:1px solid #dee2e6">${p.id}</td>
        <td style="padding:6px;border:1px solid #dee2e6">${p.nome_completo || ''}</td>
        <td style="padding:6px;border:1px solid #dee2e6">${p.endereco || ''}</td>
        <td style="padding:6px;border:1px solid #dee2e6">${p.telefone || ''}</td>
        <td style="padding:6px;border:1px solid #dee2e6">${tipo}</td>
        <td style="padding:6px;border:1px solid #dee2e6">${p.acompanhante || '-'}</td>
        <td style="padding:6px;border:1px solid #dee2e6">${new Date(p.data_cadastro).toLocaleDateString('pt-BR')}</td>
      </tr>`;
    }).join('');
    
    const reportHtml = `
      <h2 style="color:#0d6efd">${titulo || 'Relatorio de Cadastros - Cadastro RECNC'}</h2>
      <p style="color:#666">${mensagem || ''}</p>
      <p><strong>Gerado em:</strong> ${new Date().toLocaleString('pt-BR')} | <strong>Total:</strong> ${pessoas.length} registro(s)</p>
      <table style="width:100%;border-collapse:collapse;font-size:12px">
        <thead><tr style="background:#0d6efd;color:white">
          <th style="padding:8px;border:1px solid #0d6efd">ID</th>
          <th style="padding:8px;border:1px solid #0d6efd">Nome</th>
          <th style="padding:8px;border:1px solid #0d6efd">Endereco</th>
          <th style="padding:8px;border:1px solid #0d6efd">Telefone</th>
          <th style="padding:8px;border:1px solid #0d6efd">Tipo</th>
          <th style="padding:8px;border:1px solid #0d6efd">Acompanhante</th>
          <th style="padding:8px;border:1px solid #0d6efd">Data</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    `;
    
    // In production, use nodemailer/sendgrid. For now, store report and return success
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
    
    // Store in memory (in production, save to DB)
    if (!global.reports) global.reports = [];
    global.reports.push(reportData);
    
    // Return the HTML content so frontend can open in new window for printing/sending
    res.json({
      message: `Relatorio gerado com sucesso. ${pessoas.length} registro(s) incluido(s).`,
      report: {
        id: reportData.id,
        titulo: reportData.titulo,
        email: reportData.email_destino,
        total: reportData.total_registros,
        data: reportData.data_geracao
      },
      html_content: reportHtml
    });
  });
});

// Get all reports (admin only)
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

// ===== BACKUP & RESTORE (Admin only) =====

// Generate backup JSON
app.get('/api/backup', authMiddleware, adminMiddleware, (req, res) => {
  const backup = { version: 1, createdAt: new Date().toISOString(), tables: {} };
  
  db.all('SELECT * FROM usuarios', [], (err, usuarios) => {
    if (err) return res.status(500).json({ error: 'Erro ao gerar backup.' });
    backup.tables.usuarios = usuarios || [];
    
    db.all('SELECT * FROM pessoas', [], (err, pessoas) => {
      if (err) return res.status(500).json({ error: 'Erro ao gerar backup.' });
      backup.tables.pessoas = pessoas || [];
      
      db.all('SELECT * FROM relatorios', [], (err, relatorios) => {
        if (err) return res.status(500).json({ error: 'Erro ao gerar backup.' });
        backup.tables.relatorios = relatorios || [];
        
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename=backup_recnc_${new Date().toISOString().slice(0,10)}.json`);
        res.json(backup);
      });
    });
  });
});

// Restore from backup JSON
app.post('/api/backup/restore', authMiddleware, adminMiddleware, (req, res) => {
  const { backup } = req.body;
  
  if (!backup || !backup.tables) {
    return res.status(400).json({ error: 'Arquivo de backup invalido.' });
  }
  
  // Clear existing data
  db.run('DELETE FROM relatorios', [], (err) => {
    if (err) return res.status(500).json({ error: 'Erro ao limpar dados antigos.' });
    
    db.run('DELETE FROM pessoas', [], (err) => {
      if (err) return res.status(500).json({ error: 'Erro ao limpar dados antigos.' });
      
      db.run('DELETE FROM usuarios', [], (err) => {
        if (err) return res.status(500).json({ error: 'Erro ao limpar dados antigos.' });
        
        const errors = [];
        let completed = 0;
        const total = (backup.tables.usuarios?.length || 0) + 
                      (backup.tables.pessoas?.length || 0) + 
                      (backup.tables.relatorios?.length || 0);
        
        if (total === 0) {
          return res.json({ message: 'Backup restaurado com sucesso (vazio).' });
        }
        
        function checkDone() {
          completed++;
          if (completed >= total) {
            if (errors.length > 0) {
              res.json({ message: `Backup restaurado com ${errors.length} erro(s).`, errors });
            } else {
              res.json({ message: 'Backup restaurado com sucesso!' });
            }
          }
        }
        
        // Restore usuarios
        if (backup.tables.usuarios && backup.tables.usuarios.length > 0) {
          backup.tables.usuarios.forEach(u => {
            const stmt = `INSERT OR REPLACE INTO usuarios (id, nome, email, senha, perfil, data_criacao) VALUES (?, ?, ?, ?, ?, ?)`;
            db.run(stmt, [u.id, u.nome, u.email, u.senha, u.perfil || 'usuario', u.data_criacao || new Date().toISOString()], (err) => {
              if (err) errors.push(`Erro ao restaurar usuario ${u.nome}: ${err.message}`);
              checkDone();
            });
          });
        } else {
          // No usuarios to restore, skip
        }
        
        // Restore pessoas
        if (backup.tables.pessoas && backup.tables.pessoas.length > 0) {
          backup.tables.pessoas.forEach(p => {
            const stmt = `INSERT OR REPLACE INTO pessoas (id, nome_completo, data_nascimento, endereco, ponto_referencia, telefone, tipo_cadastro, acompanhante, foto_url, cadastrado_por, data_cadastro) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
            db.run(stmt, [p.id, p.nome_completo, p.data_nascimento, p.endereco, p.ponto_referencia, p.telefone, p.tipo_cadastro, p.acompanhante, p.foto_url, p.cadastrado_por, p.data_cadastro], (err) => {
              if (err) errors.push(`Erro ao restaurar pessoa ${p.nome_completo}: ${err.message}`);
              checkDone();
            });
          });
        }
        
        // Restore relatorios
        if (backup.tables.relatorios && backup.tables.relatorios.length > 0) {
          backup.tables.relatorios.forEach(r => {
            const stmt = `INSERT OR REPLACE INTO relatorios (id, titulo, email_destino, tipo_filtro, filtro_valor, total_registros, data_geracao, criado_por) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
            db.run(stmt, [r.id, r.titulo, r.email_destino, r.tipo_filtro, r.filtro_valor, r.total_registros, r.data_geracao, r.criado_por], (err) => {
              if (err) errors.push(`Erro ao restaurar relatorio ${r.titulo}: ${err.message}`);
              checkDone();
            });
          });
        }
      });
    });
  });
});

// Default route - serve login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});

module.exports = app;