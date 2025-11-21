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
    // ============================================
    // 👤 Tabla de Usuarios
    // ============================================
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      avatar TEXT,
      role TEXT DEFAULT 'user',
      status TEXT DEFAULT 'offline',
      is_bot BOOLEAN DEFAULT 0,
      is_guest BOOLEAN DEFAULT 0,
      color TEXT,
      last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`,

    // ============================================
    // 💬 Tabla de Mensajes
    // ============================================
    `CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      channel_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      avatar TEXT,
      content TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_system BOOLEAN DEFAULT 0,
      attachments TEXT,
      role TEXT
    );`,

    // ============================================
    // 📁 Tabla de Categorías
    // ============================================
    `CREATE TABLE IF NOT EXISTS categories (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      position INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`,

    // ============================================
    // 📢 Tabla de Canales
    // ============================================
    `CREATE TABLE IF NOT EXISTS channels (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      category_id TEXT,
      position INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (category_id) REFERENCES categories(id)
    );`,

    // ============================================
    // 🗳️ Tabla de Encuestas (Polls)
    // ============================================
    `CREATE TABLE IF NOT EXISTS polls (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      author_id TEXT NOT NULL,
      author_username TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      closes_at DATETIME,
      FOREIGN KEY (author_id) REFERENCES users(id)
    );`,

    // ============================================
    // ✅ Tabla de Opciones de Encuestas
    // ============================================
    `CREATE TABLE IF NOT EXISTS poll_options (
      id TEXT PRIMARY KEY,
      poll_id TEXT NOT NULL,
      text TEXT NOT NULL,
      position INTEGER DEFAULT 0,
      FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE
    );`,

    // ============================================
    // 🗳️ Tabla de Votos
    // ============================================
    `CREATE TABLE IF NOT EXISTS poll_votes (
      id TEXT PRIMARY KEY,
      poll_id TEXT NOT NULL,
      option_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      voted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE,
      FOREIGN KEY (option_id) REFERENCES poll_options(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id),
      UNIQUE(poll_id, user_id)
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
          // Ajustes para PostgreSQL
          let pgQuery = query
            .replace(/BOOLEAN DEFAULT 0/g, 'BOOLEAN DEFAULT FALSE')
            .replace(/BOOLEAN DEFAULT 1/g, 'BOOLEAN DEFAULT TRUE')
            .replace(/DATETIME/g, 'TIMESTAMP');

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
  const { id, username, avatar, role, status, isBot, is_bot, isGuest, is_guest, color } = user;

  // Normalizar campos (aceptar ambas formas camelCase y snake_case)
  const isBotValue = isBot ?? is_bot ?? false;
  const isGuestValue = isGuest ?? is_guest ?? false;

  if (type === 'sqlite') {
    const stmt = db.prepare(`
      INSERT INTO users (id, username, avatar, role, status, is_bot, is_guest, color, last_seen)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(id) DO UPDATE SET
      username = excluded.username,
      avatar = excluded.avatar,
      role = excluded.role,
      status = excluded.status,
      is_bot = excluded.is_bot,
      is_guest = excluded.is_guest,
      color = excluded.color,
      last_seen = datetime('now')
    `);
    stmt.run(id, username, avatar, role, status, isBotValue ? 1 : 0, isGuestValue ? 1 : 0, color);
  } else {
    const query = `
      INSERT INTO users (id, username, avatar, role, status, is_bot, is_guest, color, last_seen)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      ON CONFLICT(id) DO UPDATE SET
      username = EXCLUDED.username,
      avatar = EXCLUDED.avatar,
      role = EXCLUDED.role,
      status = EXCLUDED.status,
      is_bot = EXCLUDED.is_bot,
      is_guest = EXCLUDED.is_guest,
      color = EXCLUDED.color,
      last_seen = NOW()
    `;
    await db.query(query, [id, username, avatar, role, status, isBotValue, isGuestValue, color]);
  }
}

// Obtener usuario
async function getUser(id) {
  if (type === 'sqlite') {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!user) return null;

    // Convertir campos snake_case a camelCase y boolean
    return {
      ...user,
      isBot: !!user.is_bot,
      isGuest: !!user.is_guest,
      lastSeen: user.last_seen,
      createdAt: user.created_at
    };
  } else {
    const res = await db.query('SELECT * FROM users WHERE id = $1', [id]);
    if (res.rows.length === 0) return null;

    const user = res.rows[0];
    return {
      ...user,
      isBot: user.is_bot,
      isGuest: user.is_guest,
      lastSeen: user.last_seen,
      createdAt: user.created_at
    };
  }
}

// Guardar mensaje
async function saveMessage(msg) {
  const { id, channelId, userId, username, avatar, content, timestamp, isSystem, attachments, role } = msg;
  const isSys = isSystem ? 1 : 0; // SQLite
  const isSysPg = isSystem ? true : false; // Postgres
  const attachmentsStr = attachments ? JSON.stringify(attachments) : null;

  if (type === 'sqlite') {
    const stmt = db.prepare(`
      INSERT INTO messages (id, channel_id, user_id, username, avatar, content, timestamp, is_system, attachments, role)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(id, channelId, userId, username, avatar, content, timestamp, isSys, attachmentsStr, role);
  } else {
    const query = `
      INSERT INTO messages (id, channel_id, user_id, username, avatar, content, timestamp, is_system, attachments, role)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `;
    await db.query(query, [id, channelId, userId, username, avatar, content, timestamp, isSysPg, attachmentsStr, role]);
  }
}

// Obtener historial de mensajes
async function getChannelHistory(channelId, limit = 50) {
  if (type === 'sqlite') {
    const msgs = db.prepare(`
      SELECT * FROM messages 
      WHERE channel_id = ? 
      ORDER BY timestamp ASC 
      LIMIT ?
    `).all(channelId, limit);

    // Convertir 1/0 a boolean y snake_case a camelCase
    return msgs.map(m => ({
      id: m.id,
      channelId: m.channel_id,
      userId: m.user_id,
      username: m.username,
      avatar: m.avatar,
      content: m.content,
      timestamp: m.timestamp,
      isSystem: !!m.is_system,
      attachments: m.attachments ? JSON.parse(m.attachments) : null,
      role: m.role
    }));
  } else {
    const query = `
      SELECT * FROM messages 
      WHERE channel_id = $1 
      ORDER BY timestamp ASC 
      LIMIT $2
    `;
    const res = await db.query(query, [channelId, limit]);

    return res.rows.map(m => ({
      id: m.id,
      channelId: m.channel_id,
      userId: m.user_id,
      username: m.username,
      avatar: m.avatar,
      content: m.content,
      timestamp: m.timestamp,
      isSystem: m.is_system,
      attachments: m.attachments ? JSON.parse(m.attachments) : null,
      role: m.role
    }));
  }
}

module.exports = {
  initDB,
  saveUser,
  getUser,
  saveMessage,
  getChannelHistory
};
