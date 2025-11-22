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
        rejectUnauthorized: false // Necesario para Render
      }
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
    );`
  ];

  try {
    if (type === 'sqlite') {
      queries.forEach(query => db.exec(query));
      console.log('✅ [DB] Tablas SQLite verificadas/creadas.');
    } else {
      const client = await db.connect();
      try {
        for (const query of queries) {
          // Ajustes para Postgres (BOOLEAN 0/1 -> TRUE/FALSE es automático en muchos casos pero mejor ser explícito si falla, por ahora estándar SQL)
          // Postgres usa TRUE/FALSE para boolean, SQLite 0/1. 
          // Ajustamos la query de mensajes para Postgres si es necesario, pero el driver suele manejarlo.
          // Sin embargo, 'DEFAULT 0' para boolean en Postgres puede fallar si la columna es BOOLEAN estricto.
          // Vamos a normalizar la query de mensajes para Postgres.
          let pgQuery = query;
          if (query.includes('is_system BOOLEAN DEFAULT 0')) {
             pgQuery = query.replace('is_system BOOLEAN DEFAULT 0', 'is_system BOOLEAN DEFAULT FALSE');
          }
          await client.query(pgQuery);
        }
        console.log('✅ [DB] Tablas PostgreSQL verificadas/creadas.');
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
  const { id, username, avatar, role, status } = user;
  
  if (type === 'sqlite') {
    const stmt = db.prepare(`
      INSERT INTO users (id, username, avatar, role, status, last_seen)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(id) DO UPDATE SET
      username = excluded.username,
      avatar = excluded.avatar,
      role = excluded.role,
      status = excluded.status,
      last_seen = datetime('now')
    `);
    stmt.run(id, username, avatar, role, status);
  } else {
    const query = `
      INSERT INTO users (id, username, avatar, role, status, last_seen)
      VALUES ($1, $2, $3, $4, $5, NOW())
      ON CONFLICT(id) DO UPDATE SET
      username = EXCLUDED.username,
      avatar = EXCLUDED.avatar,
      role = EXCLUDED.role,
      status = EXCLUDED.status,
      last_seen = NOW()
    `;
    await db.query(query, [id, username, avatar, role, status]);
  }
}

// Obtener usuario
async function getUser(id) {
  if (type === 'sqlite') {
    return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  } else {
    const res = await db.query('SELECT * FROM users WHERE id = $1', [id]);
    return res.rows[0];
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
    const msgs = db.prepare(`
      SELECT * FROM messages 
      WHERE channel_id = ? 
      ORDER BY timestamp DESC 
      LIMIT ?
    `).all(channelId, safeLimit);
    // Convertir 1/0 a boolean para consistencia
    return msgs.map(m => ({...m, isSystem: !!m.is_system, channelId: m.channel_id, userId: m.user_id})); 
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
        userId: m.user_id
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
  // Protección de datos: eliminar datos sensibles antes de enviar al frontend
  sanitizeUserOutput: function(user) {
    if (!user) return null;
    // Nunca exponer datos internos, solo los necesarios
    const { id, username, avatar, role, status, last_seen } = user;
    return { id, username, avatar, role, status, lastSeen: last_seen };
  },
  sanitizeMessageOutput: function(msg) {
    if (!msg) return null;
    // Nunca exponer datos internos, solo los necesarios
    const { id, channel_id, user_id, username, avatar, content, timestamp, is_system } = msg;
    return {
      id,
      channelId: channel_id,
      userId: user_id,
      username,
      avatar,
      content,
      timestamp,
      isSystem: !!is_system
    };
  },
  // Limpieza de mensajes de canal
  async clearChannelMessages(channelId) {
    if (type === 'sqlite') {
      db.prepare('DELETE FROM messages WHERE channel_id = ?').run(channelId);
    } else {
      await db.query('DELETE FROM messages WHERE channel_id = $1', [channelId]);
    }
  },
  // Banear usuario (stub, debe implementarse persistencia real)
  async banUser(userId) {
    // Aquí se debería guardar el baneo en una tabla o archivo
    // Por ahora solo stub
    if (type === 'sqlite') {
      // Implementar tabla banned si se requiere
    } else {
      // Implementar tabla banned en Postgres
    }
  },
  // Migración de datos (stub)
  async migrate() {
    // Implementar lógica de migración si se requiere
    return true;
  }
};
