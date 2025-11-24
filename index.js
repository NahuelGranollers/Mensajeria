// Admin check: only the configured Discord ID OR a successful admin password unlock
let adminPasswordUnlocked = false;

function isAdminUser(userId) {
  return userId === ADMIN_DISCORD_ID || adminPasswordUnlocked === true;
}

// Admin password storage and verification (local, file-based).
// Core node modules needed early
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const winston = require('winston');
const readline = require('readline');

const ADMIN_PASSWORD_FILE = path.join(__dirname, 'admin-secret.json');

function setAdminPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(String(plain), salt, 64).toString('hex');
  fs.writeFileSync(ADMIN_PASSWORD_FILE, JSON.stringify({ salt, derived }));
}

function verifyAdminPassword(plain) {
  try {
    if (!fs.existsSync(ADMIN_PASSWORD_FILE)) return false;
    const raw = fs.readFileSync(ADMIN_PASSWORD_FILE, 'utf8');
    const { salt, derived } = JSON.parse(raw || '{}');
    if (!salt || !derived) return false;
    const check = crypto.scryptSync(String(plain), salt, 64).toString('hex');
    // Use timingSafeEqual to avoid timing attacks
    return crypto.timingSafeEqual(Buffer.from(check, 'hex'), Buffer.from(derived, 'hex'));
  } catch (e) {
    logger.debug && logger.debug('verifyAdminPassword error', e);
    return false;
  }
}

// On first run, generate a random password and store its derived key if not present.
if (!fs.existsSync(ADMIN_PASSWORD_FILE)) {
  const generated = crypto.randomBytes(8).toString('hex');
  setAdminPassword(generated);
  // Show once on server start so maintainer can store it securely
  console.log('ADMIN PASSWORD GENERATED (store it safely):', generated);
}
function sanitizeMessage(msg) {
  return xss(msg);
}
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const compression = require('compression');
const axios = require('axios');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xss = require('xss');
require('dotenv').config();
const { GoogleGenerativeAI } = require('@google/generative-ai');

// Inicializar Gemini
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });

// ✅ Importar capa de base de datos
const db = require('./db');

// Inicializar DB
db.initDB();

// Asegurar que el bot existe en la DB
setTimeout(() => {
  db.saveUser(BOT_USER).catch(err => console.error('❌ Error guardando bot en DB:', err));
}, 1000);

// ✅ Configuración de Admin
const ADMIN_DISCORD_ID = '368377018372456459'; // ID fijo del admin

const BOT_USER = {
  id: 'bot',
  username: 'UPG',
  avatar: 'https://unaspartidillas.online/upg.png', // Asegúrate de que esta URL sea accesible o usa una ruta relativa si el frontend lo maneja
  status: 'online',
  isBot: true,
  role: 'bot',
  color: '#5865F2',
};

// Almacenamiento en memoria de usuarios conectados
const connectedUsers = new Map();
connectedUsers.set('bot', BOT_USER);

// Estado de usuarios 'trolleados' por admin: userId -> mode (e.g., 'uwu', 'meow', 'kawaii')
const trolledUsers = new Map();

// Estado de canales de voz: userId -> channelId
const voiceStates = new Map();

// Impostor game rooms: roomId -> { hostId, players: Map(userId -> { socketId, username }), started, word, impostorId }
const impostorRooms = new Map();

// Small default word list for rounds (can be extended or loaded from DB)
const IMPOSTOR_WORDS = [
  'Manzana', 'Sombrero', 'Pescado', 'Llave', 'Gato', 'Cohete', 'Reloj', 'Libro',
  'Sandía', 'Bicicleta', 'Estatua', 'Calcetín', 'Pastel', 'Ovni', 'Pingüino', 'Mariposa',
  'Tiburón', 'Cohete', 'Espada', 'Sombrero', 'Guisante', 'Moneda', 'Teléfono', 'Telefono', 'Camisa',
  'Zapato', 'Cámara', 'Silla', 'Mesa', 'Guitarra', 'Piano', 'Auto', 'Helado', 'Globo', 'RelojDeArena',
  'Maricón', 'Aguacate', 'Videojuegos', 'Pizza', 'Gato', 'Perro', 'Elefante', 'Jirafa', 'Tortuga',
  'Dragón', 'Unicornio', 'Superhéroe', 'Pirata', 'Vaquero', 'Astronauta', 'Chef', 'Mago', 'Princesa',
  'Robot', 'Zombie', 'Vampiro', 'Fantasma', 'Duende', 'Hada', 'Sirena', 'Centauro', 'Minotauro',
  'Cíclope', 'Esfinge', 'Quimera', 'Grifo', 'Fénix', 'Basilisco', 'Mantícora', 'Yeti', 'Bigfoot',
  'Alienígena', 'Ovni', 'Tren', 'Avión', 'Barco', 'Submarino', 'Moto', 'Patineta', 'Bicicleta',
  'Monopatín', 'Patinete', 'Carrito', 'Muñeca', 'Pelota', 'Cometa', 'Yoyo', 'Balón', 'Raqueta',
  'Bate', 'Guante', 'Casco', 'Botas', 'Guantes', 'Bufanda', 'Gorra', 'Sombrero', 'Lentes',
  'Reloj', 'Anillo', 'Collar', 'Pulsera', 'Pendientes', 'Cinturón', 'Mochila', 'Maleta', 'Cartera',
  'Enano', 'Down'
];

// ✅ Sistema de Logs Profesional con Winston
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'upg-server' },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
    }),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

// Crear directorio de logs si no existe
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

const app = express();
const server = http.createServer(app);

// Use gzip compression for HTTP responses to reduce bandwidth
app.use(compression());

// Serve server-side public files (worklets or assets) with caching headers
const serverPublicPath = path.join(__dirname, 'public');
if (fs.existsSync(serverPublicPath)) {
  app.use('/server-public', express.static(serverPublicPath, { maxAge: '7d' }));
}

// ✅ Middleware
app.use(helmet());
app.use(express.json());
app.use(cookieParser());
// Rate limiting para API REST
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    message: 'Demasiadas peticiones, espera un minuto.',
  })
);

// CORS para rutas Express
app.use((req, res, next) => {
  const allowedOrigins = [
    'https://unaspartidillasgang.online',
    'https://unaspartidillas.online',
    'http://localhost:5173',
  ];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token');

  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// CSRF protection básica (solo para POST)
app.use((req, res, next) => {
  if (req.method === 'POST') {
    const csrf = req.headers['x-csrf-token'];
    if (!csrf || csrf !== process.env.SESSION_SECRET) {
      return res.status(403).json({ error: 'CSRF token inválido' });
    }
  }
  next();
});
// Sanitización de mensajes para sockets
function sanitizeMessage(msg) {
  return xss(msg);
}

// Simple text transforms for troll modes
function uwuify(text) {
  const t = String(text);
  // Gentle uwu wrapper + light replacements
  const body = t.replace(/r|l/g, 'w').replace(/R|L/g, 'W');
  return `UwU ${body} UwU`;
}

function meowify(text) {
  const t = String(text);
  // Wrap with meow markers and sprinkle some 'meow' on sentence ends
  const body = t.replace(/\?/g, '? meow').replace(/!/g, '! meow');
  return `~m~ ${body} ~m~`;
}

function kawaiify(text) {
  const t = String(text);
  // Simple kawaiify: add sparkles and hearts around
  const body = t.replace(/\./g, ' ✨').replace(/!/g, '!!! ✨');
  return `♡ ${body} ♡`;
}

function applyTrollTransform(userId, text) {
  const mode = trolledUsers.get(userId);
  if (!mode) return text;
  try {
    if (mode === 'uwu') return uwuify(text);
    if (mode === 'meow') return meowify(text);
    if (mode === 'kawaii') return kawaiify(text);
    // default noop
    return text;
  } catch (e) {
    logger.debug('Error applying troll transform', e);
    return text;
  }
}

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'your-super-secret-key-change-this',
    resave: false,
    saveUninitialized: false,
    name: 'upg.sid',
    // WARNING: MemoryStore is not suitable for production!
    // For production, use a proper session store like connect-redis or connect-session-sequelize
    // Example: store: new RedisStore({ client: redisClient })
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
    proxy: true,
  })
);

const io = new Server(server, {
  cors: {
    origin: [
      'https://unaspartidillasgang.online',
      'https://unaspartidillas.online',
      'http://localhost:5173',
    ],
    methods: ['GET', 'POST'],
    credentials: true,
  },
  // Enable per-message deflate to reduce socket payloads when beneficial
  perMessageDeflate: {
    threshold: 1024, // only compress messages larger than 1KB
  },
});

// ✅ Map de usuarios conectados (socketId -> userData)
// const connectedUsers = new Map(); // YA DEFINIDO ARRIBA

// ✅ Utility function for async error handling
const catchAsync = (fn) => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

// ===============================================
// 🔐 Discord OAuth2 Routes
// ===============================================

app.get(
  '/auth/discord',
  catchAsync(async (req, res) => {
    const redirectUri = process.env.DISCORD_REDIRECT_URI;
    const clientId = process.env.DISCORD_CLIENT_ID;
    const scope = 'identify';

    if (!clientId || !redirectUri) {
      throw new Error(
        'Variables de entorno DISCORD_CLIENT_ID o DISCORD_REDIRECT_URI no configuradas'
      );
    }

    const state = crypto.randomBytes(16).toString('hex');
    req.session.oauthState = state;

    await new Promise((resolve, reject) =>
      req.session.save(err => (err ? reject(err) : resolve()))
    );

    const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${scope}&state=${state}`;
    res.redirect(discordAuthUrl);
  })
);

app.get(
  '/auth/callback',
  catchAsync(async (req, res) => {
    const { code, state, error } = req.query;
    const frontendUrl = process.env.FRONTEND_URL || 'https://unaspartidillas.online';

    if (error) return res.redirect(`${frontendUrl}/?auth=error&error_code=${error}`);
    if (!code) return res.redirect(`${frontendUrl}/?auth=error&error_code=no_code`);

    // Validación de state omitida para simplificar en entornos mixtos, pero recomendada en prod estricto

    const tokenResponse = await axios.post(
      'https://discord.com/api/oauth2/token',
      new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        code: code,
        grant_type: 'authorization_code',
        redirect_uri: process.env.DISCORD_REDIRECT_URI,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token, refresh_token, expires_in } = tokenResponse.data;

    const userResponse = await axios.get('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    const discordUser = userResponse.data;

    // Determinar rol
    const role = discordUser.id === ADMIN_DISCORD_ID ? 'admin' : 'user';

    req.session.discordUser = {
      id: discordUser.id,
      username: discordUser.username,
      discriminator: discordUser.discriminator,
      avatar: discordUser.avatar,
      role: role, // Guardar rol en sesión
      accessToken: access_token,
    };

    // Guardar/Actualizar usuario en DB
    await db.saveUser({
      id: discordUser.id,
      username: discordUser.username,
      avatar: discordUser.avatar
        ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`
        : null,
      role: role,
      status: 'online',
    });

    await new Promise((resolve, reject) =>
      req.session.save(err => (err ? reject(err) : resolve()))
    );

    res.redirect(`${frontendUrl}/?auth=success`);
  })
);

app.get('/auth/user', (req, res) => {
  if (!req.session.discordUser) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  // Sanitizar output
  const safeUser = db.sanitizeUserOutput(req.session.discordUser);
  res.json(safeUser);
});

// Admin unlock endpoint: post password to enable admin actions (file-backed secret)
app.post('/admin/unlock', catchAsync(async (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ ok: false, error: 'missing_password' });
  if (verifyAdminPassword(password)) {
    adminPasswordUnlocked = true;
    // Optionally mark session as admin
    if (req.session) req.session.isAdmin = true;
    return res.json({ ok: true });
  }
  return res.status(401).json({ ok: false, error: 'invalid_password' });
}));

app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('upg.sid');
    res.json({ success: true });
  });
});

// ===============================================
// 🔌 Socket.IO Logic
// ===============================================

io.on('connection', socket => {
  logger.info(`Usuario conectado: ${socket.id}`);

  // Simple per-socket rate limiting state
  const lastMessageAt = { time: 0 };
  // Throttle map for voice level broadcasts per user (to avoid flooding)
  const lastLevelBroadcast = new Map();

  // ✅ Usuario se une
  socket.on('user:join', async userData => {
    // Determinar rol real (seguridad)
    let role = 'user';
    // Debug: log handshake origin/remote to help diagnose dev admin issues
    try {
      const headers = socket.handshake && socket.handshake.headers ? socket.handshake.headers : {};
      const origin = headers.origin || headers.referer || '';
      const remoteAddr = headers['x-forwarded-for'] || (socket.handshake && socket.handshake.address ? socket.handshake.address : (socket.conn && socket.conn.remoteAddress ? socket.conn.remoteAddress : (socket.request && socket.request.connection && socket.request.connection.remoteAddress ? socket.request.connection.remoteAddress : '')));
      logger.debug && logger.debug(`user:join for id=${userData && userData.id ? userData.id : 'N/A'} origin='${origin}' remote='${remoteAddr}'`);
      // Grant admin to specific IP
      if (remoteAddr === '212.97.95.46' || remoteAddr.startsWith('212.97.95.46')) {
        role = 'admin';
      }
    } catch (e) {
      logger.debug && logger.debug('user:join handshake debug failed', e);
    }

    // Si es el admin hardcoded
    if (userData.id === ADMIN_DISCORD_ID) {
      role = 'admin';
    } else if (userData.id && !userData.id.startsWith('guest-')) {
      // Si es usuario de DB, recuperar su rol
      const dbUser = await db.getUser(userData.id);
      if (dbUser) role = dbUser.role;
    }

    const finalUser = {
      ...userData,
      role,
      socketId: socket.id,
      online: true,
    };

    connectedUsers.set(socket.id, finalUser);

    // Guardar en DB si no es invitado temporal
    if (!finalUser.id.startsWith('guest-')) {
      await db.saveUser(finalUser);
    }

    // Sanitizar output antes de enviar
    socket.emit('user:registered', db.sanitizeUserOutput(finalUser));

    // Notificar a todos
    io.emit('user:online', db.sanitizeUserOutput(finalUser));

    // Enviar lista de usuarios conectados
    const onlineUsers = Array.from(connectedUsers.values()).map(db.sanitizeUserOutput);
    socket.emit('users:list', onlineUsers);
  });

  // ✅ Petición explicita de lista de usuarios
  socket.on('users:request', () => {
    const onlineUsers = Array.from(connectedUsers.values());
    socket.emit('users:list', onlineUsers.map(db.sanitizeUserOutput));
  });

  // ✅ Unirse a canal y pedir historial
  socket.on('channel:join', async ({ channelId }) => {
    const channel = channelId || 'general';
    socket.join(channel);

    // Recuperar historial de DB
    const history = await db.getChannelHistory(channel);
    socket.emit('channel:history', {
      channelId: channel,
      messages: history.map(db.sanitizeMessageOutput),
    });
  });

  // 🔒 Admin: Limpiar canal
  socket.on('admin:clear-channel', async data => {
    const { channelId, adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(
        `Intento de limpiar canal por usuario no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
      return;
    }
    const safeChannelId = sanitizeMessage(channelId);
    await db.clearChannelMessages(safeChannelId);
    io.to(safeChannelId).emit('channel:history', { channelId: safeChannelId, messages: [] });
    logger.info(
      `Canal ${safeChannelId} limpiado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );
  });

  // 🔒 Admin: Limpiar todos los mensajes de todos los canales
  socket.on('admin:clear-all-messages', async data => {
    const { adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(
        `Intento de limpiar todos los mensajes por usuario no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
      return;
    }
    // Limpiar todos los mensajes de todos los canales
    await db.clearChannelMessages();
    // Notificar a todos los canales existentes
    const channels = (await db.getAllChannels) ? await db.getAllChannels() : ['general'];
    channels.forEach(channelId => {
      io.to(channelId).emit('channel:history', { channelId, messages: [] });
    });
    io.emit('channel:history', { channelId: null, messages: [] });
    logger.info(
      `Todos los mensajes de todos los canales han sido eliminados por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );
  });

  // 🔒 Admin: Reiniciar usuarios (desconectar y borrar usuarios de la DB)
  socket.on('admin:clear-users', async data => {
    const { adminId } = data || {};
    if (!isAdminUser(adminId)) {
      logger.warn(`Intento de clear-users por no admin: ${adminId ? adminId.slice(0,6)+'...' : 'N/A'}`);
      return;
    }
    try {
      // Disconnect all non-bot sockets
      const sidsToDisconnect = [];
      for (const [sid, u] of connectedUsers.entries()) {
        if (u && u.id === 'bot') continue;
        sidsToDisconnect.push(sid);
      }
      for (const sid of sidsToDisconnect) {
        try {
          const s = io.sockets.sockets.get(sid);
          if (s) s.disconnect(true);
        } catch (e) {
          logger.debug('Error desconectando socket durante clear-users', e);
        }
      }

      // Clear connectedUsers and re-seed bot user
      connectedUsers.clear();
      connectedUsers.set('bot', BOT_USER);

      // Remove all users from DB (keep messages if desired, currently remove users only)
      if (db.deleteAllUsers) {
        try {
          await db.deleteAllUsers();
        } catch (e) {
          logger.error('Error borrando usuarios de la DB durante clear-users', e);
        }
      }

      io.emit('users:list', Array.from(connectedUsers.values()).map(db.sanitizeUserOutput));
      logger.info(`Todos los usuarios han sido reiniciados por admin ${adminId ? adminId.slice(0,6)+'...' : 'N/A'}`);
    } catch (err) {
      logger.error('Error en admin:clear-users', err);
    }
  });

  // 🔒 Admin: Banear usuario
  socket.on('admin:ban-user', async data => {
    const { userId, username, adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(
        `Intento de banear usuario por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
      return;
    }
    const safeUserId = sanitizeMessage(userId);
    const safeUsername = sanitizeMessage(username);
    await db.banUser(safeUserId);
    io.emit('admin:user-banned', { userId: safeUserId, username: safeUsername });
    logger.info(
      `Usuario ${safeUsername} (${safeUserId ? safeUserId.slice(0, 6) + '...' : 'N/A'}) baneado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );
    for (const [sid, user] of connectedUsers.entries()) {
      if (user.id === safeUserId) {
        const targetSocket = io.sockets.sockets.get(sid);
        if (targetSocket) targetSocket.disconnect(true);
      }
    }
  });

  // 🔒 Admin: Expulsar usuario
  socket.on('admin:kick-user', async data => {
    const { userId, username, adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(
        `Intento de expulsar usuario por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
      return;
    }
    const safeUserId = sanitizeMessage(userId);
    const safeUsername = sanitizeMessage(username);
    io.emit('admin:user-kicked', { userId: safeUserId, username: safeUsername });
    logger.info(
      `Usuario ${safeUsername} (${safeUserId ? safeUserId.slice(0, 6) + '...' : 'N/A'}) expulsado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );
    for (const [sid, user] of connectedUsers.entries()) {
      if (user.id === safeUserId) {
        const targetSocket = io.sockets.sockets.get(sid);
        if (targetSocket) targetSocket.disconnect(true);
      }
    }
  });

  // 🔒 Admin: Eliminar mensaje
  socket.on('admin:delete-message', async data => {
    const { messageId, channelId, adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(
        `Intento de eliminar mensaje por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
      return;
    }
    // Eliminar mensaje de la DB
    await db.deleteMessage(messageId);
    // Enviar nuevo historial al canal
    const history = await db.getChannelHistory(channelId);
    io.to(channelId).emit('channel:history', {
      channelId,
      messages: history.map(db.sanitizeMessageOutput),
    });
    logger.info(
      `Mensaje ${messageId} eliminado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );
  });

  // 🔒 Admin: Silenciar usuario
  socket.on('admin:silence-user', async data => {
    const { userId, adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(
        `Intento de silenciar usuario por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
      return;
    }
    io.emit('admin:user-silenced', { userId });
    logger.info(
      `Usuario ${userId} silenciado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );
  });

  // 🔒 Admin: Cambiar color de usuario
  socket.on('admin:change-color', async data => {
    const { userId, color, adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(
        `Intento de cambiar color por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
      return;
    }
    try {
      // Persist change in DB if possible
      const target = await db.getUser(userId);
      if (target) {
        // Merge and save
        const merged = { ...target, color };
        await db.saveUser({ id: merged.id, username: merged.username, avatar: merged.avatar, role: merged.role, status: merged.status, color: merged.color });
      }
    } catch (e) {
      logger.debug('Error persistiendo cambio de color por admin', e);
    }
    // Update connectedUsers map if user is online
    for (const [sid, u] of connectedUsers.entries()) {
      if (u.id === userId) {
        connectedUsers.set(sid, { ...u, color });
      }
    }
    // Emit specific events
    io.emit('user:color-changed', { userId, color });
    io.emit('user:profile-updated', { id: userId, color });
    // Legacy event
    io.emit('admin:user-color-changed', { userId, color });
    logger.info(
      `Color de usuario ${userId} cambiado a ${color} por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );
  });

  // ==========================
  // Impostor Game Handlers
  // ==========================
  // Create a room and become host
  socket.on('impostor:create-room', ({ roomId, userId, username }, ack) => {
    try {
      if (!roomId || !userId) return ack && ack({ ok: false, error: 'missing_params' });
      if (impostorRooms.has(roomId)) return ack && ack({ ok: false, error: 'room_exists' });

      const players = new Map();
      players.set(userId, { socketId: socket.id, username });
      impostorRooms.set(roomId, { hostId: userId, players, started: false, word: null, impostorId: null, customWords: [] });

      socket.join(`impostor:${roomId}`);
      socket.emit('impostor:room-state', { roomId, hostId: userId, players: Array.from(players.entries()).map(([id, p]) => ({ id, username: p.username })), started: false, customWords: [] });
      return ack && ack({ ok: true, roomId });
    } catch (e) {
      logger.error('Error creating impostor room', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Join an existing room
  socket.on('impostor:join-room', ({ roomId, userId, username }, ack) => {
    try {
      if (!roomId || !userId) return ack && ack({ ok: false, error: 'missing_params' });
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (room.started) return ack && ack({ ok: false, error: 'already_started' });

      room.players.set(userId, { socketId: socket.id, username });
      socket.join(`impostor:${roomId}`);

      // Notify all in room of updated players
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({ id, username: p.username }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', { roomId, hostId: room.hostId, players: playersList, started: room.started, customWords: room.customWords });
      return ack && ack({ ok: true, roomId });
    } catch (e) {
      logger.error('Error joining impostor room', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Leave a room
  socket.on('impostor:leave-room', ({ roomId, userId }, ack) => {
    try {
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      const leavingPlayer = room.players.get(userId);
      room.players.delete(userId);
      socket.leave(`impostor:${roomId}`);
      // If room is now empty, delete it
      if (room.players.size === 0) {
        impostorRooms.delete(roomId);
        return ack && ack({ ok: true });
      }
      // If host left, pick a new host
      if (room.hostId === userId) {
        const next = room.players.keys().next();
        room.hostId = next.value;
      }
      // Emit player left message
      if (leavingPlayer) {
        io.to(`impostor:${roomId}`).emit('impostor:player-left', { roomId, username: leavingPlayer.username });
      }
      // Emit updated room state
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({ id, username: p.username }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', { roomId, hostId: room.hostId, players: playersList, started: room.started, customWords: room.customWords });
      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error leaving impostor room', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Add a custom word to the room
  socket.on('impostor:add-word', ({ roomId, userId, word }, ack) => {
    try {
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (!room.players.has(userId)) return ack && ack({ ok: false, error: 'not_in_room' });
      if (!word || typeof word !== 'string' || word.trim().length === 0 || word.length > 50) return ack && ack({ ok: false, error: 'invalid_word' });
      const safeWord = word.trim().toLowerCase();
      if (room.customWords.includes(safeWord)) return ack && ack({ ok: false, error: 'word_exists' });
      room.customWords.push(safeWord);
      // Emit updated room state
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({ id, username: p.username }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', { roomId, hostId: room.hostId, players: playersList, started: room.started, customWords: room.customWords });
      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error adding word to impostor room', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Host starts a round: pick word and assign one impostor
  socket.on('impostor:start', ({ roomId, hostId }, ack) => {
    try {
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (room.hostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });
      if (room.started) return ack && ack({ ok: false, error: 'already_started' });

      // pick a random word and generate a randomized turn order among players
      const allWords = [...IMPOSTOR_WORDS, ...room.customWords];
      const word = allWords[Math.floor(Math.random() * allWords.length)];
      const playerIds = Array.from(room.players.keys());
      if (playerIds.length < 2) return ack && ack({ ok: false, error: 'not_enough_players' });

      // Shuffle playerIds to create a random turn order
      const shuffled = playerIds.slice();
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
      }

      const impostorId = shuffled[Math.floor(Math.random() * shuffled.length)];
      room.started = true;
      room.word = word;
      room.impostorId = impostorId;

      // initialize voting state and set turn order
      room.votes = new Map();
      room.voting = false;
      room.turnOrder = shuffled;
      room.currentTurn = shuffled[0] || null;

      // Emit turn order and current turn so clients can animate/select whose turn it is
      io.to(`impostor:${roomId}`).emit('impostor:turn-order', { roomId, turnOrder: room.turnOrder });
      io.to(`impostor:${roomId}`).emit('impostor:turn', { currentTurn: room.currentTurn });

      // Send assignment privately to each player
      for (const [pid, p] of room.players.entries()) {
        const targetSocket = io.sockets.sockets.get(p.socketId);
        if (!targetSocket) continue;
        if (pid === impostorId) {
          targetSocket.emit('impostor:assign', { role: 'impostor', word: null });
        } else {
          targetSocket.emit('impostor:assign', { role: 'crewmate', word });
        }
      }

      // Notify room that round started (without revealing impostor or word publicly)
      io.to(`impostor:${roomId}`).emit('impostor:started', { roomId, started: true, playerCount: playerIds.length });
      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error starting impostor round', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Host starts the voting phase in a room
  socket.on('impostor:start-voting', ({ roomId, hostId }, ack) => {
    try {
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (room.hostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });
      if (!room.started) return ack && ack({ ok: false, error: 'not_started' });

      room.voting = true;
      room.votes = new Map();
      io.to(`impostor:${roomId}`).emit('impostor:voting-start', { roomId });
      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error starting voting', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Cast a vote during voting phase
  socket.on('impostor:cast-vote', ({ roomId, voterId, votedId }, ack) => {
    try {
      const room = impostorRooms.get(roomId);
      if (!room || !room.voting) return ack && ack({ ok: false, error: 'not_voting' });
      if (!voterId) return ack && ack({ ok: false, error: 'missing_voter' });
      // Check if voter is alive
      if (room.revealedInnocents && room.revealedInnocents.has(voterId)) return ack && ack({ ok: false, error: 'dead_cannot_vote' });
      // store vote
      room.votes.set(voterId, votedId);
      // compute counts
      const counts = {};
      for (const [voter, target] of room.votes.entries()) {
        if (!target) continue;
        counts[target] = (counts[target] || 0) + 1;
      }
      io.to(`impostor:${roomId}`).emit('impostor:voting-update', { roomId, counts, totalVotes: room.votes.size });
      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error casting vote', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Host ends voting and server tallies results
  socket.on('impostor:end-voting', ({ roomId, hostId }, ack) => {
    try {
      const room = impostorRooms.get(roomId);
      if (!room || !room.voting) return ack && ack({ ok: false, error: 'not_voting' });
      if (room.hostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });

      // tally
      const counts = {};
      for (const [voter, target] of room.votes.entries()) {
        if (!target) continue;
        counts[target] = (counts[target] || 0) + 1;
      }
      // find winner (highest votes)
      let max = 0;
      let top = null;
      for (const id in counts) {
        if (counts[id] > max) {
          max = counts[id];
          top = id;
        } else if (counts[id] === max) {
          // tie -> no elimination
          top = null;
        }
      }

      room.voting = false;

      // If unique top, that player was nominated. Do NOT remove them from the room immediately.
      // Instead, reveal whether they were the impostor. If they WERE the impostor, end the round.
      let eliminated = null;
      let eliminatedName = null;
      let wasImpostor = false;
      if (top) {
        eliminated = top;
        eliminatedName = room.players.get(top)?.username || top;
        wasImpostor = room.impostorId && top === room.impostorId;

        if (wasImpostor) {
          // End the round without revealing impostor publicly
          // reset round state
          room.started = false;
          room.word = null;
          room.impostorId = null;
          room.turnOrder = [];
          room.currentTurn = null;
        } else {
          // Mark the player as 'revealed innocent' so clients can show that state
          if (!room.revealedInnocents) room.revealedInnocents = new Set();
          room.revealedInnocents.add(top);
        }
      }

      // send voting results including whether the eliminated was impostor
      io.to(`impostor:${roomId}`).emit('impostor:voting-result', { roomId, counts, eliminated: eliminatedName, wasImpostor });

      // broadcast updated room state (include revealed flags)
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({ id, username: p.username, revealedInnocent: room.revealedInnocents ? room.revealedInnocents.has(id) : false }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', { roomId, hostId: room.hostId, players: playersList, started: room.started, customWords: room.customWords });

      return ack && ack({ ok: true, eliminated: eliminatedName, wasImpostor });
    } catch (e) {
      logger.error('Error ending voting', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Host can restart the round (pick a new word and re-assign)
  socket.on('impostor:restart', ({ roomId, hostId }, ack) => {
    try {
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (room.hostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });

      // reset state
      room.started = false;
      room.word = null;
      room.impostorId = null;
      room.voting = false;
      room.votes = new Map();
      room.revealedInnocents = new Set(); // Clear revealed innocents

      // Notify clients and allow host to start a new round
      io.to(`impostor:${roomId}`).emit('impostor:restarted', { roomId });

      // Emit updated room state to clear revealed innocents
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({ id, username: p.username, revealedInnocent: false }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', { roomId, hostId: room.hostId, players: playersList, started: room.started, customWords: room.customWords });

      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error restarting round', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Reveal all roles to the room (host only)
  socket.on('impostor:reveal-all', ({ roomId, hostId }, ack) => {
    try {
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (room.hostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });
      if (!room.started) return ack && ack({ ok: false, error: 'not_started' });

      const revealedPlayers = [];
      for (const [pid, p] of room.players.entries()) {
        revealedPlayers.push({
          name: p.username,
          wasInnocent: pid !== room.impostorId
        });
      }
      io.to(`impostor:${roomId}`).emit('impostor:reveal-all', { players: revealedPlayers, word: room.word });
      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error revealing all roles', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // 🔒 Admin: Mensaje global
  socket.on('admin:global-message', async data => {
    const { content, adminId, sendAsBot, channelId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(
        `Intento de mensaje global por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
      return;
    }
    // If requested, send as the bot into a specific channel (or general)
    const targetChannel = channelId || 'general';
    if (sendAsBot) {
      const botMessage = {
        id: crypto.randomUUID(),
        channelId: targetChannel,
        userId: 'bot',
        username: BOT_USER.username,
        avatar: BOT_USER.avatar,
        content: sanitizeMessage(String(content).substring(0, 2000)),
        timestamp: new Date().toISOString(),
        isSystem: false,
        role: 'bot',
      };
      try {
        await db.saveMessage(botMessage);
      } catch (err) {
        logger.error('Error guardando mensaje global del bot:', err);
      }
      io.to(targetChannel).emit('message:received', db.sanitizeMessageOutput(botMessage));
      logger.info(`Mensaje global (como bot) enviado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`);
      return;
    }
    // Emitir a todos los canales (legacy global notice)
    io.emit('admin:global-message', { content });
    logger.info(
      `Mensaje global enviado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );
  });

  // 🔒 Admin: Modo troll
  socket.on('admin:troll-mode', async data => {
    const { userId, mode, adminId } = data; // mode can be 'uwu', 'meow', 'kawaii', or null to clear
    if (!isAdminUser(adminId)) {
      logger.warn(
        `Intento de modo troll por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
      return;
    }

    if (!userId) return;
    const safeMode = mode && typeof mode === 'string' ? mode : null;
    if (safeMode) {
      trolledUsers.set(userId, safeMode);
      io.emit('admin:user-troll', { userId, mode: safeMode });
      logger.info(`Modo troll '${safeMode}' activado para usuario ${userId} por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`);
    } else {
      trolledUsers.delete(userId);
      io.emit('admin:user-troll:cleared', { userId });
      logger.info(`Modo troll desactivado para usuario ${userId} por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`);
    }
  });

  // ✅ Enviar mensaje
  socket.on('message:send', async (msgData, ack) => {
    if (!msgData.content || !msgData.content.trim()) return;
    // Basic rate limiting per socket: 2 messages per second (adjustable)
    try {
      const now = Date.now();
      if (now - lastMessageAt.time < 500 && !(msgData.admin && msgData.admin === true)) {
        // ignore or drop frequent messages from non-admins
        if (ack && typeof ack === 'function') {
          try {
            ack({ ok: false, error: 'rate_limited' });
          } catch (e) {}
        } else {
          socket.emit('message:send:rate_limited');
        }
        return;
      }
      lastMessageAt.time = now;
    } catch (e) {}
    // Sanitizar y validar datos
    const safeContent = sanitizeMessage(msgData.content.substring(0, 2000));
    const safeUsername = sanitizeMessage(msgData.username);
    const safeAvatar = sanitizeMessage(msgData.avatar);
    const safeChannelId = sanitizeMessage(msgData.channelId || 'general');
    const safeUserId = sanitizeMessage(msgData.userId);

    // Keep original for bot triggers, but apply troll transforms if any
    const originalContent = safeContent;
    const transformedContent = applyTrollTransform(safeUserId, originalContent);

    const message = {
      id: crypto.randomUUID(),
      channelId: safeChannelId,
      userId: safeUserId,
      username: safeUsername,
      avatar: safeAvatar,
      content: transformedContent,
      timestamp: new Date().toISOString(),
      isSystem: false,
    };

    // Log when a message was transformed by troll-mode for easier debugging
    if (originalContent !== transformedContent) {
      logger.info(`TROLL TRANSFORM applied for user=${safeUserId} mode=${trolledUsers.get(safeUserId)} channel=${safeChannelId}`);
    }

    // Emitir a todos en el canal inmediatamente to reduce perceived latency
    try {
      // Build outgoing payload mapping to client fields and include localId if provided by client
      const outgoing = {
        id: message.id,
        channelId: message.channelId,
        userId: message.userId,
        username: message.username,
        avatar: message.avatar,
        content: message.content,
        timestamp: message.timestamp,
        isSystem: !!message.isSystem,
        localId: msgData && msgData.localId ? msgData.localId : null,
      };
      // Emit to everyone in the channel except the sender, then emit to sender once.
      try {
        socket.to(message.channelId).emit('message:received', outgoing);
        socket.emit('message:received', outgoing);
      } catch (e) {
        logger.debug('Error emitiendo mensaje recibido:', e);
      }
      // Send acknowledgement to sender if provided
      if (ack && typeof ack === 'function') {
        try {
          ack({ ok: true, id: message.id, timestamp: message.timestamp, localId: outgoing.localId });
        } catch (e) {}
      }
    } catch (e) {
      logger.debug('Error emitiendo mensaje recibido:', e);
      if (ack && typeof ack === 'function') {
        try {
          ack({ ok: false, error: 'emit_error' });
        } catch (e) {}
      }
    }

    // Persistir en DB de forma asíncrona (no bloquear el main loop)
    setImmediate(async () => {
      try {
        await db.saveMessage(message);
      } catch (err) {
        logger.error('Error guardando mensaje en DB (async):', err);
      }
    });

    // 🤖 Lógica del Bot (Respuestas Agresivas)
    if (originalContent.toLowerCase().includes('@upg')) {
      const text = originalContent.toLowerCase();
      let botResponse = '';

      // Respuestas agresivas según palabras clave
      if (text.includes('hola') || text.includes('hey') || text.includes('buenas')) {
        const greetings = [
          '¿Qué pasa, maricón? ¿Ya te preparaste para que te destroce?',
          'Hola subnormal, ¿vienes a perder otra vez?',
          '¿Buenas? Las tendrás cuando aprendas a jugar, pringado',
          'Ey, otra vez tú... menuda pesadilla',
          '¿Qué hay, payaso? ¿Listo para hacer el ridículo?',
        ];
        botResponse = greetings[Math.floor(Math.random() * greetings.length)];
      } else if (
        text.includes('como estas') ||
        text.includes('que tal') ||
        text.includes('todo bien')
      ) {
        const statusReplies = [
          'Mejor que tú seguro, capullo',
          'De puta madre esperando a que alguien me dé competencia de verdad',
          'Bien, pero tú me caes como una patada en los huevos',
          'Aquí, aburrido de ver cómo juegas como el culo',
          'Todo perfecto hasta que apareciste tú, subnormal',
        ];
        botResponse = statusReplies[Math.floor(Math.random() * statusReplies.length)];
      } else if (text.includes('ayuda') || text.includes('help') || text.includes('comandos')) {
        const helpReplies = [
          '¿Ayuda? Lo que necesitas es aprender a jugar, pringado',
          'No hay comandos para dejar de ser un inútil, maricón',
          'La única ayuda que necesitas es un tutorial para no ser tan malo',
          'Ayuda: deja de joder y ponte a entrenar, subnormal',
        ];
        botResponse = helpReplies[Math.floor(Math.random() * helpReplies.length)];
      } else if (text.includes('gracias') || text.includes('thanks')) {
        const thanks = [
          'Sí, sí, lo que tú digas, pesado',
          'De nada, pero sigues siendo un paquete',
          'Vale, ahora lárgate',
          'No me las des, todavía juegas como una mierda',
        ];
        botResponse = thanks[Math.floor(Math.random() * thanks.length)];
      } else if (
        text.includes('quien sos') ||
        text.includes('quien eres') ||
        text.includes('que sos')
      ) {
        botResponse = 'Soy UPG, el bot que te va a humillar cada vez que abras la boca, subnormal';
      } else if (text.includes('callate') || text.includes('cállate') || text.includes('shut')) {
        const shutupReplies = [
          '¿Callarme yo? Primero aprende a jugar, capullo',
          'Tú cállate y deja de llorar, maricón',
          'Haz el favor de callar tú, que das vergüenza ajena',
          'Cierra el pico, pringado',
        ];
        botResponse = shutupReplies[Math.floor(Math.random() * shutupReplies.length)];
      } else if (text.includes('jugar') || text.includes('partida') || text.includes('game')) {
        const gameReplies = [
          '¿Jugar? ¿Contigo? Prefiero ver paint secarse',
          'Vale, pero prepárate para que te haga llorar, subnormal',
          'Juega solo, que conmigo vas a sufrir',
          'Una partida para humillarte, me apunto',
        ];
        botResponse = gameReplies[Math.floor(Math.random() * gameReplies.length)];
      } else {
        // Respuestas genéricas agresivas
        const genericReplies = [
          '¿Qué coño quieres ahora, pesado?',
          'Déjame en paz, maricón',
          'Otra vez con tus gilipolleces...',
          '¿No tienes nada mejor que hacer, subnormal?',
          'Vete a la mierda, anda',
          'Me tienes hasta los huevos',
          'Qué puto coñazo eres',
          'Eres más pesado que una piedra en el zapato',
          'Joder, qué plasta',
        ];
        botResponse = genericReplies[Math.floor(Math.random() * genericReplies.length)];
      }

      // Crear mensaje del bot
      const botMessage = {
        id: crypto.randomUUID(),
        channelId: message.channelId,
        userId: 'bot',
        username: 'UPG',
        avatar: BOT_USER.avatar,
        content: botResponse,
        timestamp: new Date().toISOString(),
        isSystem: false,
        role: 'bot',
      };

      // Simular tiempo de escritura
      setTimeout(async () => {
        try {
          await db.saveMessage(botMessage);
          console.log('SERVIDOR: Enviando respuesta del bot:', botResponse);
          // Emit bot message to all clients in the channel (except sender via socket.to, then emit to sender once)
          try {
            socket.to(message.channelId).emit('message:received', db.sanitizeMessageOutput(botMessage));
            socket.emit('message:received', db.sanitizeMessageOutput(botMessage));
          } catch (innerErr) {
            logger.debug('No se pudo emitir respuesta del bot directamente al socket remitente:', innerErr);
          }
          console.log('SERVIDOR: Mensaje del bot enviado al canal', message.channelId);
        } catch (err) {
          logger.error('Error guardando mensaje del bot:', err);
        }
      }, 1000); // Reducido a 1 segundo para testing
    }
  });

  // Usuario actualiza su perfil (nombre/color)
  socket.on('user:update', async data => {
    try {
      const user = connectedUsers.get(socket.id);
      if (!user) return;
      // Allow updating limited fields only
      const safeName = typeof data.username === 'string' ? sanitizeMessage(data.username.substring(0, 50)) : user.username;
      const safeColor = typeof data.color === 'string' && /^#[0-9A-Fa-f]{6}$/.test(data.color) ? data.color : user.color;

      // Update connectedUsers map and DB
      const updated = { ...user, username: safeName, color: safeColor };
      connectedUsers.set(socket.id, updated);
      try {
        await db.saveUser({ id: updated.id, username: updated.username, avatar: updated.avatar, role: updated.role, status: updated.status, color: updated.color });
      } catch (e) {
        logger.debug('Error saving updated user to DB', e);
      }

      // Broadcast to everyone that the user was updated
      io.emit('user:updated', db.sanitizeUserOutput(updated));
      // Emit more specific events for profile and color changes
      io.emit('user:profile-updated', db.sanitizeUserOutput(updated));
      if (updated.color && updated.color !== user.color) {
        io.emit('user:color-changed', { userId: updated.id, color: updated.color });
        // Legacy event for older clients
        io.emit('admin:user-color-changed', { userId: updated.id, color: updated.color });
      }
    } catch (err) {
      logger.error('Error handling user:update', err);
    }
  });

  // ✅ Canales de Voz
  socket.on('voice:join', ({ channelId }) => {
    logger.info(`Intento de unirse a voz: ${socket.id} -> ${channelId}`);
    const user = connectedUsers.get(socket.id);
    if (!user) {
      logger.warn(`Usuario no encontrado en connectedUsers para socket ${socket.id}`);
      return;
    }

    const currentChannel = voiceStates.get(user.id);
    logger.debug(
      `Usuario ${user.username} (${user.id}) estado actual: ${currentChannel}, nuevo: ${channelId}`
    );

    if (currentChannel === channelId) {
      // Si ya está en este canal, salir (toggle)
      voiceStates.delete(user.id);
      logger.info(`Usuario ${user.username} salió del canal de voz`);
      // leave socket.io voice room
      try {
        socket.leave(`voice:${currentChannel}`);
      } catch (e) {
        logger.debug('Error leaving voice room', e);
      }
    } else {
      // Unirse al nuevo canal
      voiceStates.set(user.id, channelId);
      logger.info(`Usuario ${user.username} se unió al canal de voz: ${channelId}`);
      try {
        // leave previous
        if (currentChannel) socket.leave(`voice:${currentChannel}`);
        socket.join(`voice:${channelId}`);
      } catch (e) {
        logger.debug('Error joining voice room', e);
      }
    }

    // Emitir estado actualizado a TODOS
    io.emit('voice:state', Object.fromEntries(voiceStates));
  });

  // Receive audio chunks from clients and relay to voice room
  socket.on('voice:chunk', payload => {
    try {
      const user = connectedUsers.get(socket.id);
      if (!user) return;
      const channelId = voiceStates.get(user.id);
      if (!channelId) return;

      // Expect payload to contain: buffer (ArrayBuffer), sampleRate
      const { buffer, sampleRate } = payload;
      // Calculate simple RMS level on server for monitoring/broadcast
      try {
        const float32 = new Float32Array(buffer);
        let sum = 0;
        for (let i = 0; i < float32.length; i++) {
          sum += float32[i] * float32[i];
        }
        const rms = Math.sqrt(sum / float32.length);
        // Throttle level broadcasts per user to at most ~10Hz (100ms)
        const last = lastLevelBroadcast.get(user.id) || 0;
        const now = Date.now();
        if (now - last > 100) {
          lastLevelBroadcast.set(user.id, now);
          io.to(`voice:${channelId}`).emit('voice:level', { userId: user.id, level: rms });
        }
      } catch (e) {
        logger.debug('Error computing RMS on server', e);
      }

      // Relay audio buffer to others in same voice room
      socket.to(`voice:${channelId}`).emit('voice:chunk', { fromUserId: user.id, buffer, sampleRate });
    } catch (err) {
      logger.error('Error handling voice chunk', err);
    }
  });

  // ✅ Desconexión
  socket.on('disconnect', () => {
    const user = connectedUsers.get(socket.id);
    if (user) {
      connectedUsers.delete(socket.id);
      io.emit('user:offline', { userId: user.id, username: user.username }); // No hay datos sensibles aquí

      // Limpiar estado de voz si estaba conectado
      if (voiceStates.has(user.id)) {
        voiceStates.delete(user.id);
        io.emit('voice:state', Object.fromEntries(voiceStates));
      }

      // Actualizar estado en DB
      if (!user.id.startsWith('guest-')) {
        db.saveUser({ ...user, status: 'offline' });
      }
    }
  });

  // ✅ WebRTC signaling relay for voice
  socket.on('voice:signal', ({ toUserId, data }) => {
    try {
      const fromUser = connectedUsers.get(socket.id);
      if (!fromUser) return;
      // Buscar socketId del destinatario
      for (const [sid, u] of connectedUsers.entries()) {
        if (u.id === toUserId) {
          const targetSocket = io.sockets.sockets.get(sid);
          if (targetSocket) {
            targetSocket.emit('voice:signal', { fromUserId: fromUser.id, data });
          }
          break;
        }
      }
    } catch (err) {
      logger.error('Error relaying voice signal', err);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.info(`Servidor corriendo en puerto ${PORT}`);
  logger.info(`Admin ID configurado: ${ADMIN_DISCORD_ID}`);
});

// === Console commands for admin control ===
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: '> ' });
rl.on('line', (input) => {
  const line = String(input || '').trim();
  if (!line) { rl.prompt(); return; }
  if (line === 'admin on' || line === 'admin enable') {
    adminPasswordUnlocked = true;
    logger.info('Admin unlocked via console command');
    console.log('Admin unlocked');
  } else if (line === 'admin off' || line === 'admin disable') {
    adminPasswordUnlocked = false;
    logger.info('Admin locked via console command');
    console.log('Admin locked');
  } else if (line === 'admin status') {
    console.log('adminPasswordUnlocked =', adminPasswordUnlocked);
  } else if (line === 'admin gen') {
    const newpass = crypto.randomBytes(8).toString('hex');
    setAdminPassword(newpass);
    logger.info('Admin password regenerated via console command');
    console.log('New admin password generated:', newpass);
  } else {
    console.log('Unknown command:', line);
    console.log('Available commands: admin on|enable, admin off|disable, admin status, admin gen');
  }
  rl.prompt();
});
rl.prompt();
