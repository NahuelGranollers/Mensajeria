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

// Optimization: Reverse lookup for faster disconnect handling
// userId -> { type: 'cs16' | 'impostor', roomId: string }
const userRoomMap = new Map();

// Estado de canales de voz: userId -> channelId
const voiceStates = new Map();

// Impostor game rooms: roomId -> { hostId, players: Map(userId -> { socketId, username }), started, word, impostorId }
const impostorRooms = new Map();

// CS16 game rooms: roomId -> { hostId, players: Map(userId -> { socketId, username, position, rotation, health, team }), gameState, bots: Map(botId -> botData) }
const cs16Rooms = new Map();

// Public server list: gameType -> Map(roomId -> { name, hostId, hostName, playerCount, maxPlayers, hasPassword, createdAt, gameState })
const publicServers = new Map([
  ['impostor', new Map()],
  ['cs16', new Map()]
]);

// Bot AI function
function startBotAI(roomId) {
  const aiInterval = setInterval(() => {
    const room = cs16Rooms.get(roomId);
    if (!room || !room.gameState.gameStarted) {
      clearInterval(aiInterval);
      return;
    }

    // Process each bot
    for (const [botId, bot] of room.bots.entries()) {
      if (!bot.isAlive) continue;

      const now = Date.now();
      if (now - bot.lastAction < 1000) continue; // Act every second

      bot.lastAction = now;

      // Simple AI logic
      updateBotAI(room, botId, bot);
    }
  }, 500); // Check every 500ms
}

function updateBotAI(room, botId, bot) {
  // Find nearest enemy
  let nearestEnemy = null;
  let nearestDistance = Infinity;

  const allPlayers = [...Array.from(room.players.entries()), ...Array.from(room.bots.entries())];

  for (const [id, player] of allPlayers) {
    if (id === botId || !player.isAlive || player.team === bot.team) continue;

    const distance = Math.sqrt(
      Math.pow(player.position.x - bot.position.x, 2) +
      Math.pow(player.position.z - bot.position.z, 2)
    );

    if (distance < nearestDistance) {
      nearestDistance = distance;
      nearestEnemy = { id, ...player };
    }
  }

  if (nearestEnemy && nearestDistance < 15) { // Within shooting range
    // Move towards enemy
    const dx = nearestEnemy.position.x - bot.position.x;
    const dz = nearestEnemy.position.z - bot.position.z;
    const distance = Math.sqrt(dx * dx + dz * dz);

    if (distance > 2) { // Don't get too close
      bot.position.x += (dx / distance) * 0.5;
      bot.position.z += (dz / distance) * 0.5;
    }

    // Face enemy
    bot.rotation.y = Math.atan2(dx, dz);

    // Shoot at enemy (30% chance per action)
    if (Math.random() < 0.3) {
      // Simulate shooting
      if (nearestEnemy.isBot) {
        // Bot vs Bot combat
        const targetBot = room.bots.get(nearestEnemy.id);
        if (targetBot) {
          targetBot.health = Math.max(0, targetBot.health - 25);
          if (targetBot.health <= 0) {
            targetBot.isAlive = false;
          }

          io.to(`cs16:${roomId}`).emit('cs16:player-hit', {
            shooterId: botId,
            targetId: nearestEnemy.id,
            damage: 25,
            killed: targetBot.health <= 0
          });
        }
      } else {
        // Bot vs Player combat
        const targetPlayer = room.players.get(nearestEnemy.id);
        if (targetPlayer) {
          targetPlayer.health = Math.max(0, targetPlayer.health - 25);
          if (targetPlayer.health <= 0) {
            targetPlayer.isAlive = false;
          }

          io.to(`cs16:${roomId}`).emit('cs16:player-hit', {
            shooterId: botId,
            targetId: nearestEnemy.id,
            damage: 25,
            killed: targetPlayer.health <= 0
          });
        }
      }
    }
  } else {
    // Random movement when no enemy nearby
    if (Math.random() < 0.2) {
      bot.position.x += (Math.random() - 0.5) * 2;
      bot.position.z += (Math.random() - 0.5) * 2;

      // Keep bots within bounds
      bot.position.x = Math.max(-15, Math.min(15, bot.position.x));
      bot.position.z = Math.max(-15, Math.min(15, bot.position.z));
    }
  }

  // Bot actions (plant bomb if terrorist, defuse if counter-terrorist)
  if (bot.team === 'terrorist' && !room.gameState.bombPlanted && Math.random() < 0.05) {
    room.gameState.bombPlanted = true;
    io.to(`cs16:${roomId}`).emit('cs16:bomb-planted', { planterId: botId });
  } else if (bot.team === 'counter-terrorist' && room.gameState.bombPlanted && Math.random() < 0.05) {
    room.gameState.bombDefused = true;
    room.gameState.winner = 'counter-terrorists';
    room.gameState.gameStarted = false;
    io.to(`cs16:${roomId}`).emit('cs16:bomb-defused', { defuserId: botId });
  }

  // Broadcast bot position updates
  io.to(`cs16:${roomId}`).emit('cs16:player-update', {
    userId: botId,
    position: bot.position,
    rotation: bot.rotation
  });
}

// Categorized word lists
const IMPOSTOR_CATEGORIES = {
  'General': [
    'Manzana', 'Sombrero', 'Pescado', 'Llave', 'Gato', 'Cohete', 'Reloj', 'Libro', 'Sandía', 'Bicicleta',
    'Estatua', 'Calcetín', 'Pastel', 'Ovni', 'Pingüino', 'Mariposa', 'Tiburón', 'Espada', 'Guisante', 'Moneda',
    'Teléfono', 'Camisa', 'Zapato', 'Cámara', 'Silla', 'Mesa', 'Guitarra', 'Piano', 'Auto', 'Helado',
    'Globo', 'RelojDeArena', 'Aguacate', 'Videojuegos', 'Pizza', 'Perro', 'Elefante', 'Jirafa', 'Tortuga'
  ],
  'Fantasía': [
    'Dragón', 'Unicornio', 'Superhéroe', 'Pirata', 'Vaquero', 'Astronauta', 'Mago', 'Princesa', 'Robot', 'Zombie',
    'Vampiro', 'Fantasma', 'Duende', 'Hada', 'Sirena', 'Centauro', 'Minotauro', 'Cíclope', 'Esfinge', 'Quimera',
    'Grifo', 'Fénix', 'Basilisco', 'Mantícora', 'Yeti', 'Bigfoot', 'Alienígena', 'Enano'
  ],
  'Transporte': [
    'Tren', 'Avión', 'Barco', 'Submarino', 'Moto', 'Patineta', 'Bicicleta', 'Monopatín', 'Patinete', 'Carrito',
    'Cohete', 'Helicóptero', 'Globo Aerostático', 'Trineo', 'Carruaje', 'Taxi', 'Autobús', 'Camión'
  ],
  'Objetos': [
    'Muñeca', 'Pelota', 'Cometa', 'Yoyo', 'Balón', 'Raqueta', 'Bate', 'Guante', 'Casco', 'Botas',
    'Bufanda', 'Gorra', 'Lentes', 'Anillo', 'Collar', 'Pulsera', 'Pendientes', 'Cinturón', 'Mochila',
    'Maleta', 'Cartera', 'Paraguas', 'Espejo', 'Peine', 'Cepillo', 'Llave Inglesa', 'Martillo'
  ],
  'Lugares': [
    'Playa', 'Montaña', 'Bosque', 'Desierto', 'Ciudad', 'Pueblo', 'Escuela', 'Hospital', 'Aeropuerto', 'Estación',
    'Parque', 'Cine', 'Teatro', 'Museo', 'Biblioteca', 'Restaurante', 'Hotel', 'Estadio', 'Gimnasio', 'Piscina',
    'Zoológico', 'Granja', 'Castillo', 'Palacio', 'Cueva', 'Isla', 'Volcán', 'Espacio'
  ]
};

// Flatten for backward compatibility or random "Mix" mode
const IMPOSTOR_WORDS = Object.values(IMPOSTOR_CATEGORIES).flat();

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
  const allowedOrigins = ['https://unaspartidillas.online'];
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
    origin: ['https://unaspartidillas.online'],
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
const catchAsync = fn => {
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
app.post(
  '/admin/unlock',
  catchAsync(async (req, res) => {
    const { password } = req.body || {};
    if (!password) return res.status(400).json({ ok: false, error: 'missing_password' });
    if (verifyAdminPassword(password)) {
      adminPasswordUnlocked = true;
      // Optionally mark session as admin
      if (req.session) req.session.isAdmin = true;
      return res.json({ ok: true });
    }
    return res.status(401).json({ ok: false, error: 'invalid_password' });
  })
);

app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('upg.sid');
    res.json({ success: true });
  });
});

// Get public server list
app.get('/api/servers', (req, res) => {
  try {
    const servers = buildPublicServersSnapshot();
    res.json({ servers });
  } catch (e) {
    logger.error('Error getting server list', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Build a snapshot of public servers to send via API or sockets
function buildPublicServersSnapshot() {
  const servers = {};
  for (const [gameType, gameServers] of publicServers.entries()) {
    servers[gameType] = Array.from(gameServers.entries()).map(([roomId, server]) => ({
      roomId: roomId,
      name: server.name,
      hostId: server.hostId,
      hostName: server.hostName,
      playerCount: server.playerCount,
      maxPlayers: server.maxPlayers,
      hasPassword: server.hasPassword,
      createdAt: server.createdAt,
      gameState: server.gameState,
      botCount: server.botCount || 0
    }));
  }
  return servers;
}

// Utility to broadcast current servers to all connected clients
function broadcastPublicServers() {
  try {
    const snapshot = buildPublicServersSnapshot();
    io.emit('servers:updated', { servers: snapshot });
  } catch (e) {
    logger.debug('Error broadcasting public servers', e);
  }
}

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
      const remoteAddr =
        socket.handshake && socket.handshake.address
          ? socket.handshake.address
          : socket.conn && socket.conn.remoteAddress
            ? socket.conn.remoteAddress
            : socket.request && socket.request.connection && socket.request.connection.remoteAddress
              ? socket.request.connection.remoteAddress
              : '';
      logger.debug &&
        logger.debug(
          `user:join for id=${userData && userData.id ? userData.id : 'N/A'} origin='${origin}' remote='${remoteAddr}'`
        );
      // Grant admin to specific IP
      if (remoteAddr === '212.97.95.46') {
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
      logger.warn(
        `Intento de clear-users por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
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
      logger.info(
        `Todos los usuarios han sido reiniciados por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
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
        await db.saveUser({
          id: merged.id,
          username: merged.username,
          avatar: merged.avatar,
          role: merged.role,
          status: merged.status,
          color: merged.color,
        });
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
  // 💬 Chat Handlers
  // ==========================
  socket.on('message:send', async (data, ack) => {
    try {
      const { channelId, content, userId, username, avatar, localId } = data;
      if (!content || !content.trim()) return ack && ack({ ok: false, error: 'empty_message' });

      // Rate limit check
      const now = Date.now();
      if (now - lastMessageAt.time < 100) {
        // Simple global throttle per socket if needed
      }
      lastMessageAt.time = now;

      let finalContent = sanitizeMessage(content.trim());
      
      // Apply troll transforms
      finalContent = applyTrollTransform(userId, finalContent);

      const messageId = crypto.randomUUID();
      const timestamp = new Date().toISOString();

      const messageData = {
        id: messageId,
        channelId,
        userId,
        username,
        avatar,
        content: finalContent,
        timestamp,
        isSystem: false,
        localId // Pass back for optimistic UI reconciliation
      };

      // Save to DB
      await db.saveMessage(messageData);

      // Broadcast to channel
      io.to(channelId).emit('message:received', messageData);

      // Bot commands
      if (finalContent.startsWith('/')) {
        // Simple bot response for testing
        if (finalContent === '/ping') {
           const botMsg = {
             id: crypto.randomUUID(),
             channelId,
             userId: 'bot',
             username: 'UPG Bot',
             avatar: BOT_USER.avatar,
             content: 'Pong! 🏓',
             timestamp: new Date().toISOString(),
             isSystem: false
           };
           await db.saveMessage(botMsg);
           io.to(channelId).emit('message:received', botMsg);
        }
      }

      return ack && ack({ ok: true, messageId });
    } catch (e) {
      logger.error('Error sending message', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Helper to get global voice state (userId -> channelId)
  function getGlobalVoiceState() {
    const state = {};
    for (const [sid, cid] of voiceStates.entries()) {
      const u = connectedUsers.get(sid);
      if (u) {
        state[u.id] = cid;
      }
    }
    return state;
  }

  // ==========================
  // 🎤 Voice Handlers
  // ==========================
  socket.on('voice:join', ({ channelId }) => {
    // Leave previous channel if any
    const previousChannel = voiceStates.get(socket.id);
    if (previousChannel) {
      socket.leave(`voice:${previousChannel}`);
    }
    
    if (channelId) {
      voiceStates.set(socket.id, channelId);
      socket.join(`voice:${channelId}`);
    } else {
      voiceStates.delete(socket.id);
    }

    // Broadcast global state to ALL clients so UI updates and P2P can initiate
    io.emit('voice:state', getGlobalVoiceState());
  });

  socket.on('voice:signal', ({ toUserId, data }) => {
    // Find socket for target user
    for (const [sid, user] of connectedUsers.entries()) {
      if (user.id === toUserId) {
        io.to(sid).emit('voice:signal', { fromUserId: connectedUsers.get(socket.id)?.id, data });
        break;
      }
    }
  });

  // ==========================
  // Impostor Game Handlers
  // ==========================
  // Create a room and become host
  socket.on('impostor:create-room', ({ roomId, userId, username, name, password }, ack) => {
    try {
      if (!roomId || !userId) return ack && ack({ ok: false, error: 'missing_params' });
      if (impostorRooms.has(roomId)) return ack && ack({ ok: false, error: 'room_exists' });

      const safeName = name ? sanitizeMessage(name.substring(0, 50)) : `Sala de ${username}`;
      const hasPassword = password && password.trim().length > 0;

      const players = new Map();
      players.set(userId, { socketId: socket.id, username });
      impostorRooms.set(roomId, {
        hostId: userId,
        players,
        started: false,
        word: null,
        impostorId: null,
        customWords: [],
        name: safeName,
        password: hasPassword ? password.trim() : null,
        createdAt: new Date().toISOString()
      });

      // Register as public server
      publicServers.get('impostor').set(roomId, {
        name: safeName,
        hostId: userId,
        hostName: username,
        playerCount: 1,
        maxPlayers: 10,
        hasPassword,
        createdAt: new Date().toISOString(),
        gameState: { started: false }
      });
      // Register as public server
      publicServers.get('impostor').set(roomId, {
        name: safeName,
        hostId: userId,
        hostName: username,
        playerCount: 1,
        maxPlayers: 10,
        hasPassword,
        createdAt: new Date().toISOString(),
        gameState: { started: false }
      });

      // Track user room for optimization
      userRoomMap.set(userId, { type: 'impostor', roomId });

      // Broadcast updated server list so all clients see the new room
      broadcastPublicServers();
      return ack && ack({ ok: true, roomId });
    } catch (e) {
      logger.error('Error creating impostor room', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Join an existing room
  socket.on('impostor:join-room', ({ roomId, userId, username, password }, ack) => {
    try {
      if (!roomId || !userId) return ack && ack({ ok: false, error: 'missing_params' });
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (room.started) return ack && ack({ ok: false, error: 'already_started' });

      // Check password if room has one
      if (room.password && room.password !== password) {
        return ack && ack({ ok: false, error: 'wrong_password' });
      }

      // Update public server info
      const publicServer = publicServers.get('impostor').get(roomId);
      if (publicServer) {
        publicServer.playerCount = room.players.size;
      }

      // Track user room for optimization
      userRoomMap.set(userId, { type: 'impostor', roomId });

      // Broadcast updated server list so everyone sees the new player count
      broadcastPublicServers();

      // Broadcast updated server list so everyone sees the new player count
      broadcastPublicServers();

      // Notify all in room of updated players
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({
        id,
        username: p.username,
      }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', {
        roomId,
        hostId: room.hostId,
        players: playersList,
        started: room.started,
        customWords: room.customWords,
        name: room.name,
        hasPassword: !!room.password
      });
      return ack && ack({ ok: true, roomId });
    } catch (e) {
      logger.error('Error joining impostor room', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Leave a room
  socket.on('impostor:leave-room', ({ roomId, userId }, ack) => {
      // If room is now empty, delete it
      if (room.players.size === 0) {
        impostorRooms.delete(roomId);
        publicServers.get('impostor').delete(roomId);
        // Broadcast removal
        broadcastPublicServers();
        userRoomMap.delete(userId);
        return ack && ack({ ok: true });
      }
      // If host left, pick a new host
      if (room.hostId === userId) {
        const next = room.players.keys().next();
        room.hostId = next.value;
      }

      userRoomMap.delete(userId);

      // Update public server infohost
      if (room.hostId === userId) {
        const next = room.players.keys().next();
        room.hostId = next.value;
      }

      // Update public server info
      const publicServer = publicServers.get('impostor').get(roomId);
      if (publicServer) {
        publicServer.playerCount = room.players.size;
        publicServer.hostId = room.hostId;
        // Update host name
        const newHost = room.players.get(room.hostId);
        if (newHost) {
          publicServer.hostName = newHost.username;
        }
      }

      // Broadcast updated server list (player counts, host changes)
      broadcastPublicServers();

      // Emit player left message
      if (leavingPlayer) {
        io.to(`impostor:${roomId}`).emit('impostor:player-left', {
          roomId,
          username: leavingPlayer.username,
        });
      }
      // Emit updated room state
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({
        id,
        username: p.username,
      }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', {
        roomId,
        hostId: room.hostId,
        players: playersList,
        started: room.started,
        customWords: room.customWords,
        name: room.name,
        hasPassword: !!room.password
      });
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
      if (!word || typeof word !== 'string' || word.trim().length === 0 || word.length > 50)
        return ack && ack({ ok: false, error: 'invalid_word' });
      const safeWord = word.trim().toLowerCase();
      if (room.customWords.includes(safeWord))
        return ack && ack({ ok: false, error: 'word_exists' });
      room.customWords.push(safeWord);
      // Emit updated room state
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({
        id,
        username: p.username,
      }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', {
        roomId,
        hostId: room.hostId,
        players: playersList,
        started: room.started,
        customWords: room.customWords,
      });
      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error adding word to impostor room', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Impostor attempts to guess the word
  socket.on('impostor:guess-word', ({ roomId, userId, guess }, ack) => {
    try {
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (!room.started) return ack && ack({ ok: false, error: 'not_started' });
      if (room.impostorId !== userId) return ack && ack({ ok: false, error: 'not_impostor' });
      
      const correctWord = room.word;
      const safeGuess = guess.trim().toLowerCase();
      const safeWord = correctWord.trim().toLowerCase();
      
      // Check similarity (exact match for now)
      if (safeGuess === safeWord) {
        // Impostor wins!
        room.started = false;
        io.to(`impostor:${roomId}`).emit('impostor:game-over', { 
          winner: 'impostor', 
          word: correctWord,
          impostorName: room.players.get(userId)?.username 
        });
      } else {
        // Impostor loses (Crewmates win)
        room.started = false;
        io.to(`impostor:${roomId}`).emit('impostor:game-over', { 
          winner: 'crewmates', 
          word: correctWord,
          guess: guess,
          impostorName: room.players.get(userId)?.username 
        });
      }
      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error guessing word', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // Host starts a round: pick word and assign one impostor
  socket.on('impostor:start', ({ roomId, hostId, category, timerDuration }, ack) => {
    try {
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (room.hostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });
      if (room.started) return ack && ack({ ok: false, error: 'already_started' });

      // pick a random word based on category
      let wordList = IMPOSTOR_WORDS;
      if (category && IMPOSTOR_CATEGORIES[category]) {
        wordList = IMPOSTOR_CATEGORIES[category];
      }
      
      const allWords = [...wordList, ...room.customWords];
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

      // Timer logic
      if (room.timerInterval) clearInterval(room.timerInterval);
      if (timerDuration && timerDuration > 0) {
        room.timeLeft = timerDuration;
        room.timerInterval = setInterval(() => {
          if (!impostorRooms.has(roomId)) {
            clearInterval(room.timerInterval);
            return;
          }
          room.timeLeft--;
          io.to(`impostor:${roomId}`).emit('impostor:timer-update', { timeLeft: room.timeLeft });
          
          if (room.timeLeft <= 0) {
            clearInterval(room.timerInterval);
            io.to(`impostor:${roomId}`).emit('impostor:timer-end');
          }
        }, 1000);
      }

      // Emit turn order and current turn so clients can animate/select whose turn it is
      io.to(`impostor:${roomId}`).emit('impostor:turn-order', {
        roomId,
        turnOrder: room.turnOrder,
      });
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
      io.to(`impostor:${roomId}`).emit('impostor:started', {
        roomId,
        started: true,
        playerCount: playerIds.length,
        category: category || 'General',
        timerDuration: timerDuration || 0
      });
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
      if (room.revealedInnocents && room.revealedInnocents.has(voterId))
        return ack && ack({ ok: false, error: 'dead_cannot_vote' });
      // store vote
      room.votes.set(voterId, votedId);
      // compute counts
      const counts = {};
      for (const [voter, target] of room.votes.entries()) {
        if (!target) continue;
        counts[target] = (counts[target] || 0) + 1;
      }
      io.to(`impostor:${roomId}`).emit('impostor:voting-update', {
        roomId,
        counts,
        totalVotes: room.votes.size,
      });
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
          if (room.timerInterval) clearInterval(room.timerInterval);
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
      io.to(`impostor:${roomId}`).emit('impostor:voting-result', {
        roomId,
        counts,
        eliminated: eliminatedName,
        wasImpostor,
      });

      // broadcast updated room state (include revealed flags)
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({
        id,
        username: p.username,
        revealedInnocent: room.revealedInnocents ? room.revealedInnocents.has(id) : false,
      }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', {
        roomId,
        hostId: room.hostId,
        players: playersList,
        started: room.started,
        customWords: room.customWords,
      });

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
      if (room.timerInterval) clearInterval(room.timerInterval);
      room.started = false;
      room.word = null;
      room.impostorId = null;
      room.voting = false;
      room.votes = new Map();
      room.revealedInnocents = new Set(); // Clear revealed innocents
      room.timeLeft = 0;

      // Notify clients and allow host to start a new round
      io.to(`impostor:${roomId}`).emit('impostor:restarted', { roomId });

      // Emit updated room state to clear revealed innocents
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({
        id,
        username: p.username,
        revealedInnocent: false,
      }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', {
        roomId,
        hostId: room.hostId,
        players: playersList,
        started: room.started,
        customWords: room.customWords,
      });

      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error restarting round', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  // ==========================
  // CS 1.6 Game Handlers
  // ==========================
  
  socket.on('cs16:create-room', ({ roomId, userId, username, botCount, name, password }, ack) => {
    try {
      if (!roomId || !userId) return ack && ack({ ok: false, error: 'missing_params' });
      if (cs16Rooms.has(roomId)) return ack && ack({ ok: false, error: 'room_exists' });

      const safeName = name ? sanitizeMessage(name.substring(0, 50)) : `Sala CS16 de ${username}`;
      const hasPassword = password && password.trim().length > 0;

      const players = new Map();
      players.set(userId, { 
        socketId: socket.id, 
        username, 
        position: { x: 0, y: 0, z: 0 }, 
        rotation: { x: 0, y: 0, z: 0 },
        health: 100,
        team: 'counter-terrorist', // Host is CT by default
        isAlive: true
      });

      // Initialize bots
      const bots = new Map();
      const count = botCount || 0;
      for (let i = 0; i < count; i++) {
        const botId = `bot_${i}_${Date.now()}`;
        bots.set(botId, {
          id: botId,
          username: `Bot ${i+1}`,
          isBot: true,
          position: { x: 0, y: 0, z: 0 },
          rotation: { x: 0, y: 0, z: 0 },
          health: 100,
          team: 'terrorist', // Bots are T by default
          isAlive: true,
          lastAction: 0
        });
      }

      cs16Rooms.set(roomId, {
        hostId: userId,
        players,
        bots,
        gameState: {
          gameStarted: false,
      // Register as public server
      publicServers.get('cs16').set(roomId, {
        name: safeName,
        hostId: userId,
        hostName: username,
        playerCount: 1,
        maxPlayers: 10,
        hasPassword,
        createdAt: new Date().toISOString(),
        gameState: { started: false },
        botCount: count
      });

      // Track user room for optimization
      userRoomMap.set(userId, { type: 'cs16', roomId });

      broadcastPublicServers();
        playerCount: 1,
        maxPlayers: 10,
        hasPassword,
        createdAt: new Date().toISOString(),
        gameState: { started: false },
        botCount: count
      });

      broadcastPublicServers();

      socket.join(`cs16:${roomId}`);
      
      // Send initial state
      const playersList = Array.from(players.entries()).map(([id, p]) => ({ id, ...p }));
      const botsList = Array.from(bots.entries()).map(([id, b]) => ({ id, ...b }));
      
      socket.emit('cs16:room-state', {
        roomId,
        hostId: userId,
        players: playersList,
        bots: botsList,
        gameState: { gameStarted: false }
      });

      return ack && ack({ ok: true, roomId });
    } catch (e) {
      logger.error('Error creating CS16 room', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  socket.on('cs16:join-room', ({ roomId, userId, username, password }, ack) => {
    try {
      if (!roomId || !userId) return ack && ack({ ok: false, error: 'missing_params' });
      const room = cs16Rooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      
      if (room.password && room.password !== password) {
        return ack && ack({ ok: false, error: 'wrong_password' });
      }

      if (room.players.size >= 10) return ack && ack({ ok: false, error: 'room_full' });

      // Update public server info
      const publicServer = publicServers.get('cs16').get(roomId);
      if (publicServer) {
        publicServer.playerCount = room.players.size;
      }
      
      // Track user room for optimization
      userRoomMap.set(userId, { type: 'cs16', roomId });
      
      broadcastPublicServers();
        team: 'counter-terrorist', // Joiners are CT
        isAlive: true
      });

      socket.join(`cs16:${roomId}`);

      // Update public server info
      const publicServer = publicServers.get('cs16').get(roomId);
      if (publicServer) {
        publicServer.playerCount = room.players.size;
      }
      broadcastPublicServers();

      // Notify room
      io.to(`cs16:${roomId}`).emit('cs16:player-joined', {
        userId,
        username,
        position: { x: 0, y: 0, z: 0 }
      });

      // Send full state to joiner
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({ id, ...p }));
      const botsList = Array.from(room.bots.entries()).map(([id, b]) => ({ id, ...b }));

      socket.emit('cs16:room-state', {
        roomId,
        hostId: room.hostId,
        players: playersList,
        bots: botsList,
        gameState: room.gameState
      });

      return ack && ack({ ok: true, roomId });
    } catch (e) {
      logger.error('Error joining CS16 room', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  socket.on('cs16:leave-room', ({ roomId, userId }, ack) => {
    try {
      const room = cs16Rooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });

      room.players.delete(userId);
      socket.leave(`cs16:${roomId}`);

      if (room.players.size === 0) {
        cs16Rooms.delete(roomId);
        publicServers.get('cs16').delete(roomId);
        broadcastPublicServers();
        return ack && ack({ ok: true });
      }

      if (room.hostId === userId) {
        const next = room.players.keys().next();
        room.hostId = next.value;
        const publicServer = publicServers.get('cs16').get(roomId);
        if (publicServer) {
          const newHost = room.players.get(room.hostId);
          if (newHost) publicServer.hostName = newHost.username;
        }
      }

      const publicServer = publicServers.get('cs16').get(roomId);
      if (publicServer) publicServer.playerCount = room.players.size;
      broadcastPublicServers();

      io.to(`cs16:${roomId}`).emit('cs16:player-left', { userId });
      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error leaving CS16 room', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  socket.on('cs16:start-game', ({ roomId, hostId }, ack) => {
    try {
      const room = cs16Rooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (room.hostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });

      room.gameState.gameStarted = true;
      room.gameState.bombPlanted = false;
      room.gameState.bombDefused = false;
      room.gameState.winner = null;

      // Reset players
      for (const player of room.players.values()) {
        player.health = 100;
        player.isAlive = true;
        player.position = { x: 0, y: 0, z: 0 }; // Should be spawn points
      }

      // Reset bots
      for (const bot of room.bots.values()) {
        bot.health = 100;
        bot.isAlive = true;
        bot.position = { x: 0, y: 0, z: 0 };
      }

      // Start AI loop
      startBotAI(roomId);

      // Update public server state
      const publicServer = publicServers.get('cs16').get(roomId);
      if (publicServer) publicServer.gameState.started = true;
      broadcastPublicServers();

      io.to(`cs16:${roomId}`).emit('cs16:game-update', { gameState: room.gameState });
      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error starting CS16 game', e);
      return ack && ack({ ok: false, error: 'internal' });
    }
  });

  socket.on('cs16:player-move', ({ roomId, userId, position, rotation }) => {
    const room = cs16Rooms.get(roomId);
    if (!room) return;
    const player = room.players.get(userId);
    if (player) {
      player.position = position;
      player.rotation = rotation;
      // Broadcast to others
      socket.to(`cs16:${roomId}`).emit('cs16:player-update', { userId, position, rotation });
    }
  });

  socket.on('cs16:player-action', ({ roomId, userId, action, targetId }) => {
    const room = cs16Rooms.get(roomId);
    if (!room) return;

    if (action === 'shoot') {
      // Simple hitscan logic could go here, or trust client for now (not secure but easier)
      // For now, just broadcast shot event
      socket.to(`cs16:${roomId}`).emit('cs16:player-shoot', { userId });
    }
  });

  // ✅ Desconexión
  socket.on('disconnect', () => {
    const user = connectedUsers.get(socket.id);
    if (user) {
      logger.info(`Usuario desconectado: ${user.username} (${socket.id})`);
      connectedUsers.delete(socket.id);
      
      // Remove from voice channels
      const voiceChannel = voiceStates.get(socket.id);
      if (voiceChannel) {
        voiceStates.delete(socket.id);
        // Broadcast new global state
        io.emit('voice:state', getGlobalVoiceState());
      }

      // Remove from impostor rooms if in one
      // This is a bit expensive (iterating all rooms), but safe for now
      for (const [roomId, room] of impostorRooms.entries()) {
        if (room.players.has(user.id)) {
          room.players.delete(user.id);
          // If room empty, delete
          if (room.players.size === 0) {
            impostorRooms.delete(roomId);
            publicServers.get('impostor').delete(roomId);
          } else {
            // If host left, reassign
            if (room.hostId === user.id) {
              const next = room.players.keys().next();
              room.hostId = next.value;
              // Update public server host name
              const publicServer = publicServers.get('impostor').get(roomId);
              if (publicServer) {
                const newHost = room.players.get(room.hostId);
                if (newHost) publicServer.hostName = newHost.username;
              }
            }
            // Update public server count
            const publicServer = publicServers.get('impostor').get(roomId);
            if (publicServer) publicServer.playerCount = room.players.size;
            
            // Notify room
            io.to(`impostor:${roomId}`).emit('impostor:player-left', { roomId, username: user.username });
            const playersList = Array.from(room.players.entries()).map(([id, p]) => ({ id, username: p.username }));
            io.to(`impostor:${roomId}`).emit('impostor:room-state', {
              roomId,
              hostId: room.hostId,
              players: playersList,
              started: room.started,
              customWords: room.customWords
            });
          }
          broadcastPublicServers();
        }
      }

      // Remove from CS16 rooms
      for (const [roomId, room] of cs16Rooms.entries()) {
        if (room.players.has(user.id)) {
          room.players.delete(user.id);
          if (room.players.size === 0) {
            cs16Rooms.delete(roomId);
            publicServers.get('cs16').delete(roomId);
          } else {
            if (room.hostId === user.id) {
              const next = room.players.keys().next();
              room.hostId = next.value;
              const publicServer = publicServers.get('cs16').get(roomId);
              if (publicServer) {
                const newHost = room.players.get(room.hostId);
                if (newHost) publicServer.hostName = newHost.username;
              }
            }
            const publicServer = publicServers.get('cs16').get(roomId);
            if (publicServer) publicServer.playerCount = room.players.size;
            
            io.to(`cs16:${roomId}`).emit('cs16:player-left', { userId: user.id });
          }
          broadcastPublicServers();
        }
      }

      io.emit('user:offline', { userId: user.id });
      
      // Update list for everyone
      const onlineUsers = Array.from(connectedUsers.values()).map(db.sanitizeUserOutput);
      io.emit('users:list', onlineUsers);
    }
  });
});

// ===============================================
// Inicialización y Configuración
// ===============================================

// Mostrar configuración cargada (sin secretos)
logger.info('Configuración del servidor:', {
  env: process.env.NODE_ENV || 'development',
  port: process.env.PORT || 3000,
  logLevel: process.env.LOG_LEVEL || 'info',
  dbConnected: db.isConnected() ? 'sí' : 'no',
  adminDiscordId: ADMIN_DISCORD_ID.slice(0, 6) + '...', // Mostrar solo parte del ID
});

// Iniciar servidor HTTP
server.listen(process.env.PORT || 3000, () => {
  logger.info(`Servidor escuchando en puerto ${process.env.PORT || 3000}`);
});

// Tareas de mantenimiento periódicas
setInterval(() => {
  try {
    // Limpiar usuarios desconectados de connectedUsers (timeout de 5 minutos)
    const now = Date.now();
    for (const [sid, user] of connectedUsers.entries()) {
      if (!user.id.startsWith('guest-') && now - user.lastActivity > 5 * 60 * 1000) {
        // Desconectar socket inactivo
        const s = io.sockets.sockets.get(sid);
        if (s) {
          s.disconnect(true);
        }
      }
    }
  } catch (e) {
    logger.error('Error en tarea de mantenimiento', e);
  }
}, 60 * 1000); // Cada minuto

// ===============================================
// Cierre limpio del servidor
// ===============================================

process.on('SIGTERM', () => {
  logger.info('SIGTERM recibido: cerrando servidor...');
  server.close(err => {
    if (err) {
      logger.error('Error cerrando servidor:', err);
      process.exit(1);
    }
    logger.info('Servidor cerrado limpiamente');
    process.exit(0);
  });
});

process.on('uncaughtException', (err) => {
  logger.error('Excepción no controlada:', err);
  // Opcional: cerrar el servidor en caso de errores críticos no manejados
  // server.close(() => process.exit(1));
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Promesa rechazada sin manejar:', promise, 'razón:', reason);
  // Opcional: cerrar el servidor en caso de rechazos de promesas no manejados
  // server.close(() => process.exit(1));
});
