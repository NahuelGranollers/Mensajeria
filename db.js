// Eliminar mensaje por id
async function deleteMessage(messageId) {
  if (type === 'sqlite') {
    db.prepare('DELETE FROM messages WHERE id = ?').run(messageId);
  } else {
    await db.query('DELETE FROM messages WHERE id = $1', [messageId]);
  }
}
const Database = require('better-sqlite3');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');

// Configuración
const isProduction = process.env.NODE_ENV === 'production';
const dbUrl = process.env.DATABASE_URL;

let db;
let type; // 'sqlite' | 'postgres'

// Inicializar conexión
function initDB() {
  if (isProduction && dbUrl) {
    // Producción: PostgreSQL
    console.log('🚀 [DB] Inicializando PostgreSQL (Producción)...');
    type = 'postgres';
    db = new Pool({
      connectionString: dbUrl,
      ssl: {
        rejectUnauthorized: false, // Necesario para Render
      },
    });
  } else {
    // Desarrollo: SQLite
    console.log('🛠️ [DB] Inicializando SQLite (Desarrollo)...');
    type = 'sqlite';
    const dbPath = path.join(__dirname, 'database.sqlite');
    db = new Database(dbPath);
    // Optimizaciones para SQLite
    db.pragma('journal_mode = WAL');
  }

  createTables();
  return db;
}

// Crear tablas si no existen
async function createTables() {
  const queries = [
    // Tabla de Usuarios
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      avatar TEXT,
      color TEXT DEFAULT '#5865F2',
      score INTEGER DEFAULT 0,
      role TEXT DEFAULT 'user',
      status TEXT DEFAULT 'offline',
      last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`,

    // Tabla de Mensajes
    `CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      channel_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      avatar TEXT,
      content TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_system BOOLEAN DEFAULT 0
    );`,

    // Tabla de Noticias
    `CREATE TABLE IF NOT EXISTS news (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      excerpt TEXT,
      author_id TEXT NOT NULL,
      author_name TEXT NOT NULL,
      image_url TEXT,
      category TEXT DEFAULT 'announcement',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`,
  ];

  try {
    if (type === 'sqlite') {
      queries.forEach(query => db.exec(query));
      console.log('✅ [DB] Tablas SQLite verificadas/creadas.');
      // Ensure color column exists (migration)
      try {
        const cols = db.prepare("PRAGMA table_info('users')").all();
        const hasColor = cols.some(c => c.name === 'color');
        const hasScore = cols.some(c => c.name === 'score');
        const hasVerified = cols.some(c => c.name === 'verified');
        
        if (!hasColor) {
          db.exec("ALTER TABLE users ADD COLUMN color TEXT DEFAULT '#5865F2'");
          console.log('✅ [DB] Columna color añadida a users (migración)');
        }
        if (!hasScore) {
          db.exec('ALTER TABLE users ADD COLUMN score INTEGER DEFAULT 0');
          console.log('✅ [DB] Columna score añadida a users (migración)');
        }
        if (!hasVerified) {
          db.exec('ALTER TABLE users ADD COLUMN verified BOOLEAN DEFAULT 0');
          console.log('✅ [DB] Columna verified añadida a users (migración)');
        }
      } catch (merr) {
        console.warn('No se pudo verificar/añadir columnas:', merr);
      }
    } else {
      const client = await db.connect();
      try {
        for (const query of queries) {
          // Ajustes para Postgres
          let pgQuery = query;
          if (query.includes('is_system BOOLEAN DEFAULT 0')) {
            pgQuery = query.replace('is_system BOOLEAN DEFAULT 0', 'is_system BOOLEAN DEFAULT FALSE');
          }
          if (query.includes('verified BOOLEAN DEFAULT 0')) {
            pgQuery = query.replace('verified BOOLEAN DEFAULT 0', 'verified BOOLEAN DEFAULT FALSE');
          }
          await client.query(pgQuery);
        }
        console.log('✅ [DB] Tablas PostgreSQL verificadas/creadas.');
        // Ensure columns exist in Postgres
        try {
          await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS color TEXT DEFAULT '#5865F2'`);
          await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS score INTEGER DEFAULT 0`);
          await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT FALSE`);
        } catch (merr) {
          console.warn('No se pudo verificar/añadir columnas en Postgres:', merr);
        }
      } finally {
        client.release();
      }
    }
  } catch (error) {
    console.error('❌ [DB] Error creando tablas:', error);
  }
}

// --- Helpers de Base de Datos (Abstracción) ---

// Guardar o actualizar usuario
async function saveUser(user) {
  const { id, username, avatar, role, status, color } = user;
  const score = user.score || 0;
  const verified = user.verified ? 1 : 0; // SQLite
  const verifiedPg = !!user.verified; // Postgres

  if (type === 'sqlite') {
    const stmt = db.prepare(`
      INSERT INTO users (id, username, avatar, color, score, role, status, verified, last_seen)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(id) DO UPDATE SET
      username = excluded.username,
      avatar = excluded.avatar,
      color = excluded.color,
      score = excluded.score,
      role = excluded.role,
      status = excluded.status,
      verified = excluded.verified,
      last_seen = datetime('now')
    `);
    stmt.run(id, username, avatar, color || '#5865F2', score, role, status, verified);
  } else {
    const query = `
      INSERT INTO users (id, username, avatar, color, score, role, status, verified, last_seen)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      ON CONFLICT(id) DO UPDATE SET
      username = EXCLUDED.username,
      avatar = EXCLUDED.avatar,
      color = EXCLUDED.color,
      score = EXCLUDED.score,
      role = EXCLUDED.role,
      status = EXCLUDED.status,
      verified = EXCLUDED.verified,
      last_seen = NOW()
    `;
    await db.query(query, [id, username, avatar, color || '#5865F2', score, role, status, verifiedPg]);
  }
}

// Obtener usuario
async function getUser(id) {
  if (type === 'sqlite') {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (user) user.verified = !!user.verified;
    return user;
  } else {
    const res = await db.query('SELECT * FROM users WHERE id = $1', [id]);
    return res.rows[0];
  }
}

// Guardar noticia
async function saveNews(news) {
  const { id, title, content, excerpt, authorId, authorName, imageUrl, category } = news;
  
  if (type === 'sqlite') {
    const stmt = db.prepare(`
      INSERT INTO news (id, title, content, excerpt, author_id, author_name, image_url, category, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `);
    stmt.run(id, title, content, excerpt, authorId, authorName, imageUrl, category);
  } else {
    const query = `
      INSERT INTO news (id, title, content, excerpt, author_id, author_name, image_url, category, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
    `;
    await db.query(query, [id, title, content, excerpt, authorId, authorName, imageUrl, category]);
  }
}

// Obtener noticias
async function getNews(limit = 20) {
  const safeLimit = Math.max(1, Math.min(Number(limit) || 20, 50));
  if (type === 'sqlite') {
    return db.prepare('SELECT * FROM news ORDER BY created_at DESC LIMIT ?').all(safeLimit);
  } else {
    const res = await db.query('SELECT * FROM news ORDER BY created_at DESC LIMIT $1', [safeLimit]);
    return res.rows;
  }
}

// Guardar mensaje
async function saveMessage(msg) {
  const { id, channelId, userId, username, avatar, content, timestamp, isSystem } = msg;
  const isSys = isSystem ? 1 : 0; // SQLite
  const isSysPg = isSystem ? true : false; // Postgres

  if (type === 'sqlite') {
    const stmt = db.prepare(`
      INSERT INTO messages (id, channel_id, user_id, username, avatar, content, timestamp, is_system)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(id, channelId, userId, username, avatar, content, timestamp, isSys);
  } else {
    const query = `
      INSERT INTO messages (id, channel_id, user_id, username, avatar, content, timestamp, is_system)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `;
    await db.query(query, [id, channelId, userId, username, avatar, content, timestamp, isSysPg]);
  }
}

// Obtener historial de mensajes
async function getChannelHistory(channelId, limit = 50) {
  // Limitar máximo a 200 mensajes por petición para evitar cuellos de botella
  const safeLimit = Math.max(1, Math.min(Number(limit) || 50, 200));
  if (type === 'sqlite') {
    const msgs = db
      .prepare(
        `
      SELECT * FROM messages 
      WHERE channel_id = ? 
      ORDER BY timestamp DESC 
      LIMIT ?
    `
      )
      .all(channelId, safeLimit);
    // Convertir 1/0 a boolean para consistencia
    return msgs.map(m => ({
      ...m,
      isSystem: !!m.is_system,
      channelId: m.channel_id,
      userId: m.user_id,
    }));
  } else {
    const query = `
      SELECT * FROM messages 
      WHERE channel_id = $1 
      ORDER BY timestamp DESC 
      LIMIT $2
    `;
    const res = await db.query(query, [channelId, safeLimit]);
    return res.rows.map(m => ({
      ...m,
      isSystem: m.is_system,
      channelId: m.channel_id,
      userId: m.user_id,
    }));
  }
}

module.exports = {
  initDB,
  saveUser,
  getUser,
  saveMessage,
  getChannelHistory,
  deleteMessage,
  saveNews,
  getNews,
  isConnected: function() {
    if (!db) return false;
    if (type === 'sqlite') {
      return db.open;
    }
    return true;
  },
  // Protección de datos: eliminar datos sensibles antes de enviar al frontend
  sanitizeUserOutput: function (user) {
    const { id, username, avatar, role, status, last_seen, color, score, verified } = user;
    return {
      id,
      username,
      avatar,
      role,
      status,
      color: color || '#5865F2',
      score: score || 0,
      verified: !!verified,
      lastSeen: last_seen,
    };
  },
  sanitizeMessageOutput: function (msg) {
    if (!msg) return null;
    // Normalize both DB rows (snake_case) and in-memory objects (camelCase)
    const id = msg.id || msg.message_id || null;
    const channelId = msg.channelId || msg.channel_id || null;
    const userId = msg.userId || msg.user_id || null;
    const username = msg.username || msg.user_name || null;
    const avatar = msg.avatar || null;
    const content = msg.content || '';
    const timestamp = msg.timestamp || msg.time || null;
    const isSystem = typeof msg.isSystem !== 'undefined' ? !!msg.isSystem : !!msg.is_system;

    return { id, channelId, userId, username, avatar, content, timestamp, isSystem };
  },
  // Limpieza de mensajes de canal o todos los mensajes
  clearChannelMessages: async function (channelId) {
    if (type === 'sqlite') {
      if (channelId) {
        db.prepare('DELETE FROM messages WHERE channel_id = ?').run(channelId);
      } else {
        db.prepare('DELETE FROM messages').run();
      }
    } else {
      if (channelId) {
        await db.query('DELETE FROM messages WHERE channel_id = $1', [channelId]);
      } else {
        await db.query('DELETE FROM messages');
      }
    }
  },
  // Banear usuario (stub, debe implementarse persistencia real)
  banUser: async function (userId) {
    // Aquí se debería guardar el baneo en una tabla o archivo
    // Por ahora solo stub
    if (type === 'sqlite') {
      // Implementar tabla banned si se requiere
    } else {
      // Implementar tabla banned en Postgres
    }
  },
  // Eliminar todos los usuarios (con precaución)
  deleteAllUsers: async function () {
    if (type === 'sqlite') {
      db.prepare('DELETE FROM users WHERE id != ?').run('bot');
    } else {
      await db.query('DELETE FROM users WHERE id != $1', ['bot']);
    }
  },
  // Migración de datos (stub)
  migrate: async function () {
    // Implementar lógica de migración si se requiere
    return true;
  },
};
