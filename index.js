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
function buildPublicServersSnapshot() {req, res) => {
  const servers = {};db.getNews();
  for (const [gameType, gameServers] of publicServers.entries()) {
    servers[gameType] = Array.from(gameServers.entries()).map(([roomId, server]) => ({
      roomId: roomId,
      name: server.name,rified only)
      hostId: server.hostId,sync(async (req, res) => {
      hostName: server.hostName,Id, authorName } = req.body;
      playerCount: server.playerCount,
      maxPlayers: server.maxPlayers,ified)
      hasPassword: server.hasPassword,end authorId, but in production we should use session
      createdAt: server.createdAt,thorId);
      gameState: server.gameState,).json({ error: 'Unauthorized' });
      botCount: server.botCount || 0
    }));isVerified = user.verified || user.role === 'admin' || user.id === ADMIN_DISCORD_ID;
  }f (!isVerified) return res.status(403).json({ error: 'Forbidden' });
  return servers;
} const newsItem = {
    id: crypto.randomUUID(),
// Utility to broadcast current servers to all connected clients
function broadcastPublicServers() {t),
  try {horId,
    const snapshot = buildPublicServersSnapshot();
    io.emit('servers:updated', { servers: snapshot });
  } catch (e) {
    logger.debug('Error broadcasting public servers', e);
  }wait db.saveNews(newsItem);
} res.json(newsItem);
}));
// ===============================================
// 🔌 Socket.IO Logic
// ===============================================> {
  const news = await db.getNews();
io.on('connection', socket => {
  logger.info(`Usuario conectado: ${socket.id}`);

  // Simple per-socket rate limiting state
  const lastMessageAt = { time: 0 };nc (req, res) => {
  // Throttle map for voice level broadcasts per user (to avoid flooding)uthorized' });
  const lastLevelBroadcast = new Map();
  const user = await db.getUser(req.session.discordUser.id);
  // ✅ Usuario se une.verified && user.role !== 'admin')) {
  socket.on('user:join', async userData => {rbidden: Verified users only' });
    // Determinar rol real (seguridad)
    let role = 'user';
    // Debug: log handshake origin/remote to help diagnose dev admin issues
    try {tle || !content) return res.status(400).json({ error: 'Missing fields' });
      const headers = socket.handshake && socket.handshake.headers ? socket.handshake.headers : {};
      const origin = headers.origin || headers.referer || '';
      const remoteAddr =D(),
        socket.handshake && socket.handshake.address
          ? socket.handshake.address),
          : socket.conn && socket.conn.remoteAddress,
            ? socket.conn.remoteAddress
            : socket.request && socket.request.connection && socket.request.connection.remoteAddress
              ? socket.request.connection.remoteAddress
              : '';ory || 'announcement'
      logger.debug &&
        logger.debug(
          `user:join for id=${userData && userData.id ? userData.id : 'N/A'} origin='${origin}' remote='${remoteAddr}'`
        );({ ok: true, news: newsItem });
      // Grant admin to specific IP
      if (remoteAddr === '212.97.95.46') {
        role = 'admin';public servers to send via API or sockets
      }n buildPublicServersSnapshot() {
    } catch (e) { {};
      logger.debug && logger.debug('user:join handshake debug failed', e);
    }ervers[gameType] = Array.from(gameServers.entries()).map(([roomId, server]) => ({
      roomId: roomId,
    // Si es el admin hardcoded
    if (userData.id === ADMIN_DISCORD_ID) {
      role = 'admin';r.hostName,
    } else if (userData.id && !userData.id.startsWith('guest-')) {
      // Si es usuario de DB, recuperar su rol
      const dbUser = await db.getUser(userData.id);
      if (dbUser) role = dbUser.role;
    } gameState: server.gameState,
      botCount: server.botCount || 0
    const finalUser = {
      ...userData,
      role,rvers;
      socketId: socket.id,
      online: true,
    };lity to broadcast current servers to all connected clients
function broadcastPublicServers() {
    connectedUsers.set(socket.id, finalUser);
    const snapshot = buildPublicServersSnapshot();
    // Guardar en DB si no es invitado temporalhot });
    if (!finalUser.id.startsWith('guest-')) {
      await db.saveUser(finalUser);g public servers', e);
    }
}
    // Sanitizar output antes de enviar
    socket.emit('user:registered', db.sanitizeUserOutput(finalUser));
// 🔌 Socket.IO Logic
    // Notificar a todos==========================
    io.emit('user:online', db.sanitizeUserOutput(finalUser));
io.on('connection', socket => {
    // Enviar lista de usuarios conectados.id}`);
    const onlineUsers = Array.from(connectedUsers.values()).map(db.sanitizeUserOutput);
    socket.emit('users:list', onlineUsers);
  });st lastMessageAt = { time: 0 };
  // Throttle map for voice level broadcasts per user (to avoid flooding)
  // ✅ Petición explicita de lista de usuarios
  socket.on('users:request', () => {
    const onlineUsers = Array.from(connectedUsers.values());
    socket.emit('users:list', onlineUsers.map(db.sanitizeUserOutput));
  });/ Determinar rol real (seguridad)
    let role = 'user';
  // ✅ Unirse a canal y pedir historialte to help diagnose dev admin issues
  socket.on('channel:join', async ({ channelId }) => {
    const channel = channelId || 'general';ocket.handshake.headers ? socket.handshake.headers : {};
    socket.join(channel);ers.origin || headers.referer || '';
      const remoteAddr =
    // Recuperar historial de DBet.handshake.address
    const history = await db.getChannelHistory(channel);
    socket.emit('channel:history', {nn.remoteAddress
      channelId: channel,.remoteAddress
      messages: history.map(db.sanitizeMessageOutput),ion && socket.request.connection.remoteAddress
    });       ? socket.request.connection.remoteAddress
  });         : '';
      logger.debug &&
  // 🔒 Admin: Limpiar canal
  socket.on('admin:clear-channel', async data => {.id ? userData.id : 'N/A'} origin='${origin}' remote='${remoteAddr}'`
    const { channelId, adminId } = data;
    if (!isAdminUser(adminId)) { IP
      logger.warn(dr === '212.97.95.46') {
        `Intento de limpiar canal por usuario no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
      return;e) {
    } logger.debug && logger.debug('user:join handshake debug failed', e);
    const safeChannelId = sanitizeMessage(channelId);
    await db.clearChannelMessages(safeChannelId);
    io.to(safeChannelId).emit('channel:history', { channelId: safeChannelId, messages: [] });
    logger.info(.id === ADMIN_DISCORD_ID) {
      `Canal ${safeChannelId} limpiado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );else if (userData.id && !userData.id.startsWith('guest-')) {
  }); // Si es usuario de DB, recuperar su rol
      const dbUser = await db.getUser(userData.id);
  // 🔒 Admin: Limpiar todos los mensajes de todos los canales
  socket.on('admin:clear-all-messages', async data => {
    const { adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(
        `Intento de limpiar todos los mensajes por usuario no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );cketId: socket.id,
      return; true,
    };
    // Limpiar todos los mensajes de todos los canales
    await db.clearChannelMessages();nalUser);
    // Notificar a todos los canales existentes
    const channels = (await db.getAllChannels) ? await db.getAllChannels() : ['general'];
    channels.forEach(channelId => {uest-')) {
      io.to(channelId).emit('channel:history', { channelId, messages: [] });
    });
    io.emit('channel:history', { channelId: null, messages: [] });
    logger.info( output antes de enviar
      `Todos los mensajes de todos los canales han sido eliminados por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );
  });/ Notificar a todos
    io.emit('user:online', db.sanitizeUserOutput(finalUser));
  // 🔒 Admin: Reiniciar usuarios (desconectar y borrar usuarios de la DB)
  socket.on('admin:clear-users', async data => {
    const { adminId } = data || {};connectedUsers.values()).map(db.sanitizeUserOutput);
    if (!isAdminUser(adminId)) {lineUsers);
      logger.warn(
        `Intento de clear-users por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );etición explicita de lista de usuarios
      return;users:request', () => {
    }onst onlineUsers = Array.from(connectedUsers.values());
    try {t.emit('users:list', onlineUsers.map(db.sanitizeUserOutput));
      // Disconnect all non-bot sockets
      const sidsToDisconnect = [];
      for (const [sid, u] of connectedUsers.entries()) {
        if (u && u.id === 'bot') continue;elId }) => {
        sidsToDisconnect.push(sid);eneral';
      }ket.join(channel);
      for (const sid of sidsToDisconnect) {
        try {rar historial de DB
          const s = io.sockets.sockets.get(sid);hannel);
          if (s) s.disconnect(true);
        } catch (e) {nel,
          logger.debug('Error desconectando socket durante clear-users', e);
        }
      }

      // Clear connectedUsers and re-seed bot user
      connectedUsers.clear();nel', async data => {
      connectedUsers.set('bot', BOT_USER);
    if (!isAdminUser(adminId)) {
      // Remove all users from DB (keep messages if desired, currently remove users only)
      if (db.deleteAllUsers) {nal por usuario no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
        try {
          await db.deleteAllUsers();
        } catch (e) {
          logger.error('Error borrando usuarios de la DB durante clear-users', e);
        } db.clearChannelMessages(safeChannelId);
      }to(safeChannelId).emit('channel:history', { channelId: safeChannelId, messages: [] });
    logger.info(
      io.emit('users:list', Array.from(connectedUsers.values()).map(db.sanitizeUserOutput));N/A'}`
      logger.info(
        `Todos los usuarios han sido reiniciados por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
    } catch (err) {iar todos los mensajes de todos los canales
      logger.error('Error en admin:clear-users', err);{
    }onst { adminId } = data;
  });f (!isAdminUser(adminId)) {
      logger.warn(
  // 🔒 Admin: Banear usuarioodos los mensajes por usuario no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
  socket.on('admin:ban-user', async data => {
    const { userId, username, adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(os los mensajes de todos los canales
        `Intento de banear usuario por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );otificar a todos los canales existentes
      return;nnels = (await db.getAllChannels) ? await db.getAllChannels() : ['general'];
    }hannels.forEach(channelId => {
    const safeUserId = sanitizeMessage(userId);{ channelId, messages: [] });
    const safeUsername = sanitizeMessage(username);
    await db.banUser(safeUserId);channelId: null, messages: [] });
    io.emit('admin:user-banned', { userId: safeUserId, username: safeUsername });
    logger.info( mensajes de todos los canales han sido eliminados por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      `Usuario ${safeUsername} (${safeUserId ? safeUserId.slice(0, 6) + '...' : 'N/A'}) baneado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );
    for (const [sid, user] of connectedUsers.entries()) {
      if (user.id === safeUserId) {desconectar y borrar usuarios de la DB)
        const targetSocket = io.sockets.sockets.get(sid);
        if (targetSocket) targetSocket.disconnect(true);
      }(!isAdminUser(adminId)) {
    } logger.warn(
  });   `Intento de clear-users por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
  // 🔒 Admin: Expulsar usuario
  socket.on('admin:kick-user', async data => {
    const { userId, username, adminId } = data;
    if (!isAdminUser(adminId)) {sockets
      logger.warn(Disconnect = [];
        `Intento de expulsar usuario por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );if (u && u.id === 'bot') continue;
      return;oDisconnect.push(sid);
    } }
    const safeUserId = sanitizeMessage(userId);
    const safeUsername = sanitizeMessage(username);
    io.emit('admin:user-kicked', { userId: safeUserId, username: safeUsername });
    logger.info( s.disconnect(true);
      `Usuario ${safeUsername} (${safeUserId ? safeUserId.slice(0, 6) + '...' : 'N/A'}) expulsado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );    logger.debug('Error desconectando socket durante clear-users', e);
    for (const [sid, user] of connectedUsers.entries()) {
      if (user.id === safeUserId) {
        const targetSocket = io.sockets.sockets.get(sid);
        if (targetSocket) targetSocket.disconnect(true);
      }onnectedUsers.clear();
    } connectedUsers.set('bot', BOT_USER);
  });
      // Remove all users from DB (keep messages if desired, currently remove users only)
  // 🔒 Admin: Eliminar mensaje
  socket.on('admin:delete-message', async data => {
    const { messageId, channelId, adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(rror('Error borrando usuarios de la DB durante clear-users', e);
        `Intento de eliminar mensaje por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
      return;
    } io.emit('users:list', Array.from(connectedUsers.values()).map(db.sanitizeUserOutput));
    // Eliminar mensaje de la DB
    await db.deleteMessage(messageId);einiciados por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    // Enviar nuevo historial al canal
    const history = await db.getChannelHistory(channelId);
    io.to(channelId).emit('channel:history', {', err);
      channelId,
      messages: history.map(db.sanitizeMessageOutput),
    });
    logger.info(anear usuario
      `Mensaje ${messageId} eliminado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );nst { userId, username, adminId } = data;
  });f (!isAdminUser(adminId)) {
      logger.warn(
  // 🔒 Admin: Silenciar usuarioio por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
  socket.on('admin:silence-user', async data => {
    const { userId, adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(Id = sanitizeMessage(userId);
        `Intento de silenciar usuario por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );t db.banUser(safeUserId);
      return;admin:user-banned', { userId: safeUserId, username: safeUsername });
    }ogger.info(
    io.emit('admin:user-silenced', { userId });safeUserId.slice(0, 6) + '...' : 'N/A'}) baneado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    logger.info(
      `Usuario ${userId} silenciado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );if (user.id === safeUserId) {
  });   const targetSocket = io.sockets.sockets.get(sid);
        if (targetSocket) targetSocket.disconnect(true);
  // 🔒 Admin: Cambiar color de usuario
  socket.on('admin:change-color', async data => {
    const { userId, color, adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(ulsar usuario
        `Intento de cambiar color por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );t { userId, username, adminId } = data;
      return;minUser(adminId)) {
    } logger.warn(
    try {Intento de expulsar usuario por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      // Persist change in DB if possible
      const target = await db.getUser(userId);
      if (target) {
        // Merge and savenitizeMessage(userId);
        const merged = { ...target, color };rname);
        await db.saveUser({ked', { userId: safeUserId, username: safeUsername });
          id: merged.id,
          username: merged.username,feUserId ? safeUserId.slice(0, 6) + '...' : 'N/A'}) expulsado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
          avatar: merged.avatar,
          role: merged.role,f connectedUsers.entries()) {
          status: merged.status,) {
          color: merged.color,o.sockets.sockets.get(sid);
        });(targetSocket) targetSocket.disconnect(true);
      }
    } catch (e) {
      logger.debug('Error persistiendo cambio de color por admin', e);
    }
    // Update connectedUsers map if user is online
    for (const [sid, u] of connectedUsers.entries()) {
      if (u.id === userId) {elId, adminId } = data;
        connectedUsers.set(sid, { ...u, color });
      }ogger.warn(
    }   `Intento de eliminar mensaje por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    // Emit specific events
    io.emit('user:color-changed', { userId, color });
    io.emit('user:profile-updated', { id: userId, color });
    // Legacy eventsaje de la DB
    io.emit('admin:user-color-changed', { userId, color });
    logger.info(evo historial al canal
      `Color de usuario ${userId} cambiado a ${color} por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );.to(channelId).emit('channel:history', {
  }); channelId,
      messages: history.map(db.sanitizeMessageOutput),
  // ==========================
  // 💬 Chat Handlers
  // ==========================minado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
  socket.on('message:send', async (data, ack) => {
    try {
      const { channelId, content, userId, username, avatar, localId } = data;
      if (!content || !content.trim()) return ack && ack({ ok: false, error: 'empty_message' });
  socket.on('admin:silence-user', async data => {
      // Rate limit checkId } = data;
      const now = Date.now();) {
      if (now - lastMessageAt.time < 100) {
        // Simple global throttle per socket if neededadminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      };
      lastMessageAt.time = now;
    }
      let finalContent = sanitizeMessage(content.trim());
      gger.info(
      // Apply troll transformsiado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      finalContent = applyTrollTransform(userId, finalContent);
  });
      const messageId = crypto.randomUUID();
      const timestamp = new Date().toISOString();
  socket.on('admin:change-color', async data => {
      const messageData = {adminId } = data;
        id: messageId,dminId)) {
        channelId,
        userId,o de cambiar color por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
        username,
        avatar,
        content: finalContent,
        timestamp,
        isSystem: false,in DB if possible
        localId // Pass back for optimistic UI reconciliation
      }; (target) {
        // Merge and save
      // Save to DBd = { ...target, color };
      await db.saveMessage(messageData);
          id: merged.id,
      // Broadcast to channelername,
      io.to(channelId).emit('message:received', messageData);
          role: merged.role,
      // Bot commandsged.status,
      if (finalContent.startsWith('/')) {
        // Simple bot response for testing
        if (finalContent === '/ping') {
           const botMsg = {
             id: crypto.randomUUID(),o cambio de color por admin', e);
             channelId,
             userId: 'bot',s map if user is online
             username: 'UPG Bot',tedUsers.entries()) {
             avatar: BOT_USER.avatar,
             content: 'Pong! 🏓', ...u, color });
             timestamp: new Date().toISOString(),
             isSystem: false
           };pecific events
           await db.saveMessage(botMsg);Id, color });
           io.to(channelId).emit('message:received', botMsg);
        }gacy event
      }emit('admin:user-color-changed', { userId, color });
    logger.info(
      return ack && ack({ ok: true, messageId });lor} por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    } catch (e) {
      logger.error('Error sending message', e);
      return ack && ack({ ok: false, error: 'internal' });
    }==========================
  });💬 Chat Handlers
  // ==========================
  // Helper to get global voice state (userId -> channelId)
  function getGlobalVoiceState() {
    const state = {};Id, content, userId, username, avatar, localId } = data;
    for (const [sid, cid] of voiceStates.entries()) {ack({ ok: false, error: 'empty_message' });
      const u = connectedUsers.get(sid);
      if (u) {limit check
        state[u.id] = cid;();
      }f (now - lastMessageAt.time < 100) {
    }   // Simple global throttle per socket if needed
    return state;
  }   lastMessageAt.time = now;

  // ==========================zeMessage(content.trim());
  // 🎤 Voice Handlers
  // ==========================
  socket.on('voice:join', ({ channelId }) => {d, finalContent);
    // Leave previous channel if any
    const previousChannel = voiceStates.get(socket.id);
    if (previousChannel) {w Date().toISOString();
      socket.leave(`voice:${previousChannel}`);
    } const messageData = {
        id: messageId,
    if (channelId) {
      voiceStates.set(socket.id, channelId);
      socket.join(`voice:${channelId}`);
    } else {ar,
      voiceStates.delete(socket.id);
    }   timestamp,
        isSystem: false,
    // Broadcast global state to ALL clients so UI updates and P2P can initiate
    io.emit('voice:state', getGlobalVoiceState());
  });
      // Save to DB
  socket.on('voice:signal', ({ toUserId, data }) => {
    // Find socket for target user
    for (const [sid, user] of connectedUsers.entries()) {
      if (user.id === toUserId) {age:received', messageData);
        io.to(sid).emit('voice:signal', { fromUserId: connectedUsers.get(socket.id)?.id, data });
        break;ommands
      }f (finalContent.startsWith('/')) {
    }   // Simple bot response for testing
  });   if (finalContent === '/ping') {
           const botMsg = {
  // ==========================UID(),
  // Impostor Game Handlers
  // ==========================
  // Create a room and become host
  socket.on('impostor:create-room', ({ roomId, userId, username, name, password }, ack) => {
    try {    content: 'Pong! 🏓',
      if (!roomId || !userId) return ack && ack({ ok: false, error: 'missing_params' });
      if (impostorRooms.has(roomId)) return ack && ack({ ok: false, error: 'room_exists' });
           };
      const safeName = name ? sanitizeMessage(name.substring(0, 50)) : `Sala de ${username}`;
      const hasPassword = password && password.trim().length > 0;
        }
      const players = new Map();
      players.set(userId, { socketId: socket.id, username });
      impostorRooms.set(roomId, {e, messageId });
        hostId: userId,
        players,or('Error sending message', e);
        started: false,({ ok: false, error: 'internal' });
        word: null,
        impostorId: null,
        customWords: [],
        name: safeName,al voice state (userId -> channelId)
        password: hasPassword ? password.trim() : null,
        createdAt: new Date().toISOString()
      });const [sid, cid] of voiceStates.entries()) {
      const u = connectedUsers.get(sid);
      // Register as public server
      publicServers.get('impostor').set(roomId, {
        name: safeName,
        hostId: userId,
        hostName: username,
        playerCount: 1,
        maxPlayers: 10,
        hasPassword,===========
        createdAt: new Date().toISOString(),
        gameState: { started: false }
      });on('voice:join', ({ channelId }) => {
      // Register as public serverny
      publicServers.get('impostor').set(roomId, {t.id);
        name: safeName,) {
        hostId: userId,ce:${previousChannel}`);
        hostName: username,
        playerCount: 1,
        maxPlayers: 10,
        hasPassword,t(socket.id, channelId);
        createdAt: new Date().toISOString(),
        gameState: { started: false }
      });ceStates.delete(socket.id);
    }
      // Track user room for optimization
      userRoomMap.set(userId, { type: 'impostor', roomId });nd P2P can initiate
    io.emit('voice:state', getGlobalVoiceState());
      // Broadcast updated server list so all clients see the new room
      broadcastPublicServers();
      return ack && ack({ ok: true, roomId });}) => {
    } catch (e) {t for target user
      logger.error('Error creating impostor room', e);) {
      return ack && ack({ ok: false, error: 'internal' });
    }   io.to(sid).emit('voice:signal', { fromUserId: connectedUsers.get(socket.id)?.id, data });
  });   break;
      }
  // Join an existing room
  socket.on('impostor:join-room', ({ roomId, userId, username, password }, ack) => {
    try {
      if (!roomId || !userId) return ack && ack({ ok: false, error: 'missing_params' });
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (room.started) return ack && ack({ ok: false, error: 'already_started' });
  socket.on('impostor:create-room', ({ roomId, userId, username, name, password }, ack) => {
      // Check password if room has one
      if (room.password && room.password !== password) {lse, error: 'missing_params' });
        return ack && ack({ ok: false, error: 'wrong_password' });, error: 'room_exists' });
      }
      const safeName = name ? sanitizeMessage(name.substring(0, 50)) : `Sala de ${username}`;
      // Update public server info && password.trim().length > 0;
      const publicServer = publicServers.get('impostor').get(roomId);
      if (publicServer) { Map();
        publicServer.playerCount = room.players.size;name });
      }mpostorRooms.set(roomId, {
        hostId: userId,
      // Track user room for optimization
      userRoomMap.set(userId, { type: 'impostor', roomId });
        word: null,
      // Broadcast updated server list so everyone sees the new player count
      broadcastPublicServers();
        name: safeName,
      // Broadcast updated server list so everyone sees the new player count
      broadcastPublicServers();oISOString()
      });
      // Notify all in room of updated players
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({
        id,cServers.get('impostor').set(roomId, {
        username: p.username,
      }));stId: userId,
      io.to(`impostor:${roomId}`).emit('impostor:room-state', {
        roomId,ount: 1,
        hostId: room.hostId,
        players: playersList,
        started: room.started,toISOString(),
        customWords: room.customWords,
        name: room.name,
        hasPassword: !!room.password
      });licServers.get('impostor').set(roomId, {
      return ack && ack({ ok: true, roomId });
    } catch (e) {serId,
      logger.error('Error joining impostor room', e);
      return ack && ack({ ok: false, error: 'internal' });
    }   maxPlayers: 10,
  });   hasPassword,
        createdAt: new Date().toISOString(),
  // Leave a room
  socket.on('impostor:leave-room', ({ roomId, userId }, ack) => {
    try {
      const room = impostorRooms.get(roomId);(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });ok: false, error: 'not_found' });

      const leavingPlayer = room.players.get(userId);room.players.get(userId);
      room.players.delete(userId);;
      userRoomMap.delete(userId);

      // If room is now empty, delete it/ If room is now empty, delete it
      if (room.players.size === 0) {oomId);
        impostorRooms.delete(roomId);{ ok: false, error: 'not_found' });
        publicServers.get('impostor').delete(roomId);
        // Broadcast removalplayers.get(userId);
        broadcastPublicServers();oom.players.delete(userId);
        return ack && ack({ ok: true });      userRoomMap.delete(userId);
      }
      // If room is now empty, delete it
      // If host left, pick a new host
      if (room.hostId === userId) {);
        const next = room.players.keys().next();mId);
        room.hostId = next.value;
      } broadcastPublicServers();
        return ack && ack({ ok: true });
      // Update public server info
      const publicServer = publicServers.get('impostor').get(roomId);
      if (publicServer) {ck a new host
        publicServer.playerCount = room.players.size;
        publicServer.hostId = room.hostId;ext();
        // Update host namevalue;
        const newHost = room.players.get(room.hostId);
        if (newHost) {
          publicServer.hostName = newHost.username;
        }st publicServer = publicServers.get('impostor').get(roomId);
      }f (publicServer) {
        publicServer.playerCount = room.players.size;
      // Broadcast updated server list (player counts, host changes)
      broadcastPublicServers();
        const newHost = room.players.get(room.hostId);
      // Emit player left message
      if (leavingPlayer) {tName = newHost.username;
        io.to(`impostor:${roomId}`).emit('impostor:player-left', {
          roomId,
          username: leavingPlayer.username,
        });oadcast updated server list (player counts, host changes)
      }roadcastPublicServers();
      
      // Emit updated room state
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({eavingPlayer) {
        id,mId}`).emit('impostor:player-left', {
        username: p.username,roomId,
      }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', {
        roomId,
        hostId: room.hostId,
        players: playersList,te
        started: room.started,oom.players.entries()).map(([id, p]) => ({
        customWords: room.customWords,
        name: room.name,
        hasPassword: !!room.password;
      });('impostor:room-state', {
      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error leaving impostor room', e);
      return ack && ack({ ok: false, error: 'internal' });   started: room.started,
    }   customWords: room.customWords,
  });        name: room.name,
rd
  // Add a custom word to the room
  socket.on('impostor:add-word', ({ roomId, userId, word }, ack) => {urn ack && ack({ ok: true });
    try {
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (!room.players.has(userId)) return ack && ack({ ok: false, error: 'not_in_room' });
      if (!word || typeof word !== 'string' || word.trim().length === 0 || word.length > 50)
        return ack && ack({ ok: false, error: 'invalid_word' }); e);
      const safeWord = word.trim().toLowerCase();nternal' });
      if (room.customWords.includes(safeWord))
        return ack && ack({ ok: false, error: 'word_exists' });
      room.customWords.push(safeWord);
      // Emit updated room state
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({oadcast updated server list (player counts, host changes)
        id,);
        username: p.username,
      }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', {ngPlayer) {
        roomId,omId}`).emit('impostor:player-left', {
        hostId: room.hostId,
        players: playersList,yer.username,
        started: room.started,
        customWords: room.customWords,
      });
      return ack && ack({ ok: true });ated room state
    } catch (e) {.map(([id, p]) => ({
      logger.error('Error adding word to impostor room', e);
      return ack && ack({ ok: false, error: 'internal' });   username: p.username,
    } }));
  });      io.to(`impostor:${roomId}`).emit('impostor:room-state', {

  // Impostor attempts to guess the word
  socket.on('impostor:guess-word', ({ roomId, userId, guess }, ack) => {layers: playersList,
    try {
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (!room.started) return ack && ack({ ok: false, error: 'not_started' });
      if (room.impostorId !== userId) return ack && ack({ ok: false, error: 'not_impostor' });});
      );
      const correctWord = room.word;
      const safeGuess = guess.trim().toLowerCase();
      const safeWord = correctWord.trim().toLowerCase();return ack && ack({ ok: false, error: 'internal' });
      
      // Check similarity (exact match for now)ewHost.username;
      if (safeGuess === safeWord) {
        // Impostor wins!
        room.started = false;
        io.to(`impostor:${roomId}`).emit('impostor:game-over', { ver list (player counts, host changes)
          winner: 'impostor', ();
          word: correctWord,
          impostorName: room.players.get(userId)?.username it player left message
        });ingPlayer) {
      } else {'impostor:player-left', {
        // Impostor loses (Crewmates win)
        room.started = false;
        io.to(`impostor:${roomId}`).emit('impostor:game-over', { 
          winner: 'crewmates', 
          word: correctWord,oom state
          guess: guess,).map(([id, p]) => ({
          impostorName: room.players.get(userId)?.username 
        }); username: p.username,
      }
      return ack && ack({ ok: true });stor:${roomId}`).emit('impostor:room-state', {
    } catch (e) {
      logger.error('Error guessing word', e);
      return ack && ack({ ok: false, error: 'internal' });   players: playersList,
    }   started: room.started,
  });        customWords: room.customWords,

  // Host starts a round: pick word and assign one impostor
  socket.on('impostor:start', ({ roomId, hostId, category, timerDuration }, ack) => {
    try {
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (room.hostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });
      if (room.started) return ack && ack({ ok: false, error: 'already_started' });    }

      // pick a random word based on category
      let wordList = IMPOSTOR_WORDS;
      if (category && IMPOSTOR_CATEGORIES[category]) {d, word }, ack) => {
        wordList = IMPOSTOR_CATEGORIES[category]; {
      }const room = impostorRooms.get(roomId);
      t_found' });
      const allWords = [...wordList, ...room.customWords];: 'not_in_room' });
      const word = allWords[Math.floor(Math.random() * allWords.length)];().length === 0 || word.length > 50)
      const playerIds = Array.from(room.players.keys());
      if (playerIds.length < 2) return ack && ack({ ok: false, error: 'not_enough_players' });      const safeWord = word.trim().toLowerCase();

      // Shuffle playerIds to create a random turn orderror: 'word_exists' });
      const shuffled = playerIds.slice();
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));(([id, p]) => ({
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]]; id,
      }        username: p.username,

      const impostorId = shuffled[Math.floor(Math.random() * shuffled.length)];omId}`).emit('impostor:room-state', {
      room.started = true;
      room.word = word;
      room.impostorId = impostorId;        players: playersList,

      // initialize voting state and set turn ordertomWords,
      room.votes = new Map();
      room.voting = false;ue });
      room.turnOrder = shuffled;
      room.currentTurn = shuffled[0] || null;      logger.error('Error adding word to impostor room', e);
ack({ ok: false, error: 'internal' });
      // Timer logic
      if (room.timerInterval) clearInterval(room.timerInterval);
      if (timerDuration && timerDuration > 0) {
        room.timeLeft = timerDuration;
        room.timerInterval = setInterval(() => {d, userId, guess }, ack) => {
          if (!impostorRooms.has(roomId)) {
            clearInterval(room.timerInterval);impostorRooms.get(roomId);
            return;room) return ack && ack({ ok: false, error: 'not_found' });
          }eturn ack && ack({ ok: false, error: 'not_started' });
          room.timeLeft--;
          io.to(`impostor:${roomId}`).emit('impostor:timer-update', { timeLeft: room.timeLeft });
          ;
          if (room.timeLeft <= 0) {se();
            clearInterval(room.timerInterval);
            io.to(`impostor:${roomId}`).emit('impostor:timer-end');
          }milarity (exact match for now)
        }, 1000);f (safeGuess === safeWord) {
      }        // Impostor wins!

      // Emit turn order and current turn so clients can animate/select whose turn it is{ 
      io.to(`impostor:${roomId}`).emit('impostor:turn-order', {r: 'impostor', 
        roomId,
        turnOrder: room.turnOrder, impostorName: room.players.get(userId)?.username 
      });
      io.to(`impostor:${roomId}`).emit('impostor:turn', { currentTurn: room.currentTurn });      } else {

      // Send assignment privately to each player
      for (const [pid, p] of room.players.entries()) { 
        const targetSocket = io.sockets.sockets.get(p.socketId);
        if (!targetSocket) continue;
        if (pid === impostorId) {
          targetSocket.emit('impostor:assign', { role: 'impostor', word: null });orName: room.players.get(userId)?.username 
        } else {
          targetSocket.emit('impostor:assign', { role: 'crewmate', word });
        }eturn ack && ack({ ok: true });
      }    } catch (e) {

      // Notify room that round started (without revealing impostor or word publicly)
      io.to(`impostor:${roomId}`).emit('impostor:started', {
        roomId,
        started: true,
        playerCount: playerIds.length,assign one impostor
        category: category || 'General',hostId, category, timerDuration }, ack) => {
        timerDuration: timerDuration || 0
      });oomId);
      return ack && ack({ ok: true });return ack && ack({ ok: false, error: 'not_found' });
    } catch (e) {k: false, error: 'not_host' });
      logger.error('Error starting impostor round', e);or: 'already_started' });
      return ack && ack({ ok: false, error: 'internal' });
    } // pick a random word based on category
  });      let wordList = IMPOSTOR_WORDS;
ategory]) {
  // Host starts the voting phase in a room
  socket.on('impostor:start-voting', ({ roomId, hostId }, ack) => {
    try {
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (room.hostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });
      if (!room.started) return ack && ack({ ok: false, error: 'not_started' });      if (playerIds.length < 2) return ack && ack({ ok: false, error: 'not_enough_players' });

      room.voting = true; create a random turn order
      room.votes = new Map();
      io.to(`impostor:${roomId}`).emit('impostor:voting-start', { roomId });; i > 0; i--) {
      return ack && ack({ ok: true }); Math.floor(Math.random() * (i + 1));
    } catch (e) {j], shuffled[i]];
      logger.error('Error starting voting', e);
      return ack && ack({ ok: false, error: 'internal' });
    } const impostorId = shuffled[Math.floor(Math.random() * shuffled.length)];
  });      room.started = true;

  // Cast a vote during voting phase
  socket.on('impostor:cast-vote', ({ roomId, voterId, votedId }, ack) => {
    try { order
      const room = impostorRooms.get(roomId);
      if (!room || !room.voting) return ack && ack({ ok: false, error: 'not_voting' });
      if (!voterId) return ack && ack({ ok: false, error: 'missing_voter' });
      // Check if voter is alive
      if (room.revealedInnocents && room.revealedInnocents.has(voterId))
        return ack && ack({ ok: false, error: 'dead_cannot_vote' });c
      // store voterval(room.timerInterval);
      room.votes.set(voterId, votedId); && timerDuration > 0) {
      // compute countstimerDuration;
      const counts = {};
      for (const [voter, target] of room.votes.entries()) {as(roomId)) {
        if (!target) continue;
        counts[target] = (counts[target] || 0) + 1;     return;
      }
      io.to(`impostor:${roomId}`).emit('impostor:voting-update', {timeLeft--;
        roomId,(`impostor:${roomId}`).emit('impostor:timer-update', { timeLeft: room.timeLeft });
        counts,
        totalVotes: room.votes.size, if (room.timeLeft <= 0) {
      });terval);
      return ack && ack({ ok: true });(`impostor:${roomId}`).emit('impostor:timer-end');
    } catch (e) {
      logger.error('Error casting vote', e);
      return ack && ack({ ok: false, error: 'internal' }); }
    }
  });      // Emit turn order and current turn so clients can animate/select whose turn it is
:turn-order', {
  // Host ends voting and server tallies results
  socket.on('impostor:end-voting', ({ roomId, hostId }, ack) => {urnOrder: room.turnOrder,
    try {
      const room = impostorRooms.get(roomId); });
      if (!room || !room.voting) return ack && ack({ ok: false, error: 'not_voting' });
      if (room.hostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });      // Send assignment privately to each player
st [pid, p] of room.players.entries()) {
      // tallyet = io.sockets.sockets.get(p.socketId);
      const counts = {};
      for (const [voter, target] of room.votes.entries()) {) {
        if (!target) continue;le: 'impostor', word: null });
        counts[target] = (counts[target] || 0) + 1; } else {
      }r:assign', { role: 'crewmate', word });
      // find winner (highest votes)
      let max = 0;
      let top = null;
      for (const id in counts) { started (without revealing impostor or word publicly)
        if (counts[id] > max) {mId}`).emit('impostor:started', {
          max = counts[id];
          top = id;
        } else if (counts[id] === max) {gth,
          // tie -> no eliminationegory || 'General',
          top = null;imerDuration: timerDuration || 0
        });
      }      return ack && ack({ ok: true });

      room.voting = false;      logger.error('Error starting impostor round', e);

      // If unique top, that player was nominated. Do NOT remove them from the room immediately.
      // Instead, reveal whether they were the impostor. If they WERE the impostor, end the round.
      let eliminated = null;
      let eliminatedName = null;ase in a room
      let wasImpostor = false;ostor:start-voting', ({ roomId, hostId }, ack) => {
      if (top) {
        eliminated = top;
        eliminatedName = room.players.get(top)?.username || top;' });
        wasImpostor = room.impostorId && top === room.impostorId;      if (room.hostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });
eturn ack && ack({ ok: false, error: 'not_started' });
        if (wasImpostor) {
          // End the round without revealing impostor publicly
          // reset round state
          if (room.timerInterval) clearInterval(room.timerInterval);`).emit('impostor:voting-start', { roomId });
          room.started = false;k: true });
          room.word = null;
          room.impostorId = null;ting voting', e);
          room.turnOrder = [];e, error: 'internal' });
          room.currentTurn = null;
        } else {
          // Mark the player as 'revealed innocent' so clients can show that state
          if (!room.revealedInnocents) room.revealedInnocents = new Set();
          room.revealedInnocents.add(top);on('impostor:cast-vote', ({ roomId, voterId, votedId }, ack) => {
        } {
      }      const room = impostorRooms.get(roomId);
t_voting' });
      // send voting results including whether the eliminated was impostor_voter' });
      io.to(`impostor:${roomId}`).emit('impostor:voting-result', {if voter is alive
        roomId,revealedInnocents && room.revealedInnocents.has(voterId))
        counts,se, error: 'dead_cannot_vote' });
        eliminated: eliminatedName,
        wasImpostor,m.votes.set(voterId, votedId);
      });      // compute counts

      // broadcast updated room state (include revealed flags)
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({(!target) continue;
        id,nts[target] || 0) + 1;
        username: p.username,
        revealedInnocent: room.revealedInnocents ? room.revealedInnocents.has(id) : false,o(`impostor:${roomId}`).emit('impostor:voting-update', {
      }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', {
        roomId,es.size,
        hostId: room.hostId,
        players: playersList,true });
        started: room.started,
        customWords: room.customWords,ger.error('Error casting vote', e);
      });      return ack && ack({ ok: false, error: 'internal' });

      return ack && ack({ ok: true, eliminated: eliminatedName, wasImpostor });
    } catch (e) {
      logger.error('Error ending voting', e);
      return ack && ack({ ok: false, error: 'internal' });ket.on('impostor:end-voting', ({ roomId, hostId }, ack) => {
    }ry {
  });      const room = impostorRooms.get(roomId);
 error: 'not_voting' });
  // Host can restart the round (pick a new word and re-assign)e, error: 'not_host' });
  socket.on('impostor:restart', ({ roomId, hostId }, ack) => {
    try {
      const room = impostorRooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (room.hostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });        if (!target) continue;
t] = (counts[target] || 0) + 1;
      // reset state
      if (room.timerInterval) clearInterval(room.timerInterval);st votes)
      room.started = false;
      room.word = null;
      room.impostorId = null;nts) {
      room.voting = false; {
      room.votes = new Map();
      room.revealedInnocents = new Set(); // Clear revealed innocents
      room.timeLeft = 0;        } else if (counts[id] === max) {

      // Notify clients and allow host to start a new round
      io.to(`impostor:${roomId}`).emit('impostor:restarted', { roomId });        }

      // Emit updated room state to clear revealed innocents
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({voting = false;
        id,
        username: p.username,yer was nominated. Do NOT remove them from the room immediately.
        revealedInnocent: false,nstead, reveal whether they were the impostor. If they WERE the impostor, end the round.
      }));
      io.to(`impostor:${roomId}`).emit('impostor:room-state', {natedName = null;
        roomId,e;
        hostId: room.hostId,
        players: playersList,
        started: room.started,get(top)?.username || top;
        customWords: room.customWords,asImpostor = room.impostorId && top === room.impostorId;
      });

      return ack && ack({ ok: true });the round without revealing impostor publicly
    } catch (e) {
      logger.error('Error restarting round', e);Interval);
      return ack && ack({ ok: false, error: 'internal' });     room.started = false;
    }     room.word = null;
  });          room.impostorId = null;

  // ==========================n = null;
  // CS 1.6 Game Handlers
  // ==========================        // Mark the player as 'revealed innocent' so clients can show that state
  
  socket.on('cs16:create-room', ({ roomId, userId, username, botCount, name, password }, ack) => { room.revealedInnocents.add(top);
    try {
      if (!roomId || !userId) return ack && ack({ ok: false, error: 'missing_params' });
      if (cs16Rooms.has(roomId)) return ack && ack({ ok: false, error: 'room_exists' });

      const safeName = name ? sanitizeMessage(name.substring(0, 50)) : `Sala CS16 de ${username}`;{
      const hasPassword = password && password.trim().length > 0;        roomId,

      const players = new Map();edName,
      players.set(userId, { 
        socketId: socket.id, 
        username, 
        position: { x: 0, y: 0, z: 0 }, include revealed flags)
        rotation: { x: 0, y: 0, z: 0 },ist = Array.from(room.players.entries()).map(([id, p]) => ({
        health: 100,
        team: 'counter-terrorist', // Host is CT by defaultsername,
        isAlive: trueevealedInnocent: room.revealedInnocents ? room.revealedInnocents.has(id) : false,
      });      }));
roomId}`).emit('impostor:room-state', {
      // Initialize bots
      const bots = new Map();
      const count = botCount || 0;
      for (let i = 0; i < count; i++) {
        const botId = `bot_${i}_${Date.now()}`;.customWords,
        bots.set(botId, {
          id: botId,
          username: `Bot ${i+1}`,k({ ok: true, eliminated: eliminatedName, wasImpostor });
          isBot: true,
          position: { x: 0, y: 0, z: 0 }, e);
          rotation: { x: 0, y: 0, z: 0 },k({ ok: false, error: 'internal' });
          health: 100,
          team: 'terrorist', // Bots are T by default
          isAlive: true,
          lastAction: 0an restart the round (pick a new word and re-assign)
        });t.on('impostor:restart', ({ roomId, hostId }, ack) => {
      }    try {
oms.get(roomId);
      cs16Rooms.set(roomId, { ack && ack({ ok: false, error: 'not_found' });
        hostId: userId,ostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });
        players,
        bots,
        gameState: { clearInterval(room.timerInterval);
          gameStarted: false,
      // Register as public server
      publicServers.get('cs16').set(roomId, { null;
        name: safeName,se;
        hostId: userId,);
        hostName: username,cents = new Set(); // Clear revealed innocents
        playerCount: 1,;
        maxPlayers: 10,
        hasPassword,art a new round
        createdAt: new Date().toISOString(),('impostor:restarted', { roomId });
        gameState: { started: false },
        botCount: countEmit updated room state to clear revealed innocents
      });      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({

      // Track user room for optimization
      userRoomMap.set(userId, { type: 'cs16', roomId });        revealedInnocent: false,

      broadcastPublicServers();{roomId}`).emit('impostor:room-state', {
      socket.join(`cs16:${roomId}`);
      .hostId,
      // Send initial state
      const playersList = Array.from(players.entries()).map(([id, p]) => ({ id, ...p }));
      const botsList = Array.from(bots.entries()).map(([id, b]) => ({ id, ...b }));om.customWords,
      
      socket.emit('cs16:room-state', {
        roomId,rue });
        hostId: userId,    } catch (e) {
        players: playersList, round', e);
        bots: botsList,return ack && ack({ ok: false, error: 'internal' });
        gameState: { gameStarted: false }
      });

      return ack && ack({ ok: true, roomId });=========================
    } catch (e) {
      logger.error('Error creating CS16 room', e);================
      return ack && ack({ ok: false, error: 'internal' });
    }', ({ roomId, userId, username, botCount, name, password }, ack) => {
  });
&& ack({ ok: false, error: 'missing_params' });
  socket.on('cs16:join-room', ({ roomId, userId, username, password }, ack) => {(cs16Rooms.has(roomId)) return ack && ack({ ok: false, error: 'room_exists' });
    try {
      if (!roomId || !userId) return ack && ack({ ok: false, error: 'missing_params' });name.substring(0, 50)) : `Sala CS16 de ${username}`;
      const room = cs16Rooms.get(roomId);ssword = password && password.trim().length > 0;
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      
      if (room.password && room.password !== password) { players.set(userId, { 
        return ack && ack({ ok: false, error: 'wrong_password' });   socketId: socket.id, 
      }        username, 

      if (room.players.size >= 10) return ack && ack({ ok: false, error: 'room_full' });otation: { x: 0, y: 0, z: 0 },

      room.players.set(userId, {t is CT by default
        socketId: socket.id,
        username,});
        position: { x: 0, y: 0, z: 0 },
        rotation: { x: 0, y: 0, z: 0 },
        health: 100,onst bots = new Map();
        team: 'counter-terrorist', // Joiners are CT      const count = botCount || 0;
        isAlive: true
      });        const botId = `bot_${i}_${Date.now()}`;

      socket.join(`cs16:${roomId}`);
e: `Bot ${i+1}`,
      // Update public server info
      const publicServer = publicServers.get('cs16').get(roomId);},
      if (publicServer) {{ x: 0, y: 0, z: 0 },
        publicServer.playerCount = room.players.size;
      }orist', // Bots are T by default
      broadcastPublicServers(); isAlive: true,
          lastAction: 0
      // Notify room
      io.to(`cs16:${roomId}`).emit('cs16:player-joined', {      }
        userId,
        username,
        position: { x: 0, y: 0, z: 0 }
      });
 bots,
      // Send full state to joiner
      const playersList = Array.from(room.players.entries()).map(([id, p]) => ({ id, ...p }));          gameStarted: false,
      const botsList = Array.from(room.bots.entries()).map(([id, b]) => ({ id, ...b })); public server

      socket.emit('cs16:room-state', {afeName,
        roomId,serId,
        hostId: room.hostId,
        players: playersList,layerCount: 1,
        bots: botsList,        maxPlayers: 10,
        gameState: room.gameState
      });

      return ack && ack({ ok: true, roomId });        botCount: count
    } catch (e) {
      logger.error('Error joining CS16 room', e);
      return ack && ack({ ok: false, error: 'internal' }); optimization
    } { type: 'cs16', roomId });
  });

  socket.on('cs16:leave-room', ({ roomId, userId }, ack) => {layerCount: 1,
    try {        maxPlayers: 10,
      const room = cs16Rooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });: new Date().toISOString(),

      room.players.delete(userId);
      socket.leave(`cs16:${roomId}`); });

      if (room.players.size === 0) {      broadcastPublicServers();
        cs16Rooms.delete(roomId);
        publicServers.get('cs16').delete(roomId);ket.join(`cs16:${roomId}`);
        broadcastPublicServers();
        return ack && ack({ ok: true });
      }      const playersList = Array.from(players.entries()).map(([id, p]) => ({ id, ...p }));
bots.entries()).map(([id, b]) => ({ id, ...b }));
      if (room.hostId === userId) {
        const next = room.players.keys().next();      socket.emit('cs16:room-state', {
        room.hostId = next.value;
        const publicServer = publicServers.get('cs16').get(roomId);
        if (publicServer) {
          const newHost = room.players.get(room.hostId);
          if (newHost) publicServer.hostName = newHost.username;}
        });
      }
 roomId });
      const publicServer = publicServers.get('cs16').get(roomId);
      if (publicServer) publicServer.playerCount = room.players.size;g CS16 room', e);
      broadcastPublicServers();

      io.to(`cs16:${roomId}`).emit('cs16:player-left', { userId });
      return ack && ack({ ok: true });
    } catch (e) {on('cs16:join-room', ({ roomId, userId, username, password }, ack) => {
      logger.error('Error leaving CS16 room', e); {
      return ack && ack({ ok: false, error: 'internal' });      if (!roomId || !userId) return ack && ack({ ok: false, error: 'missing_params' });
    }
  });;

  socket.on('cs16:start-game', ({ roomId, hostId }, ack) => {      if (room.password && room.password !== password) {
    try {
      const room = cs16Rooms.get(roomId);
      if (!room) return ack && ack({ ok: false, error: 'not_found' });
      if (room.hostId !== hostId) return ack && ack({ ok: false, error: 'not_host' });ack({ ok: false, error: 'room_full' });

      room.gameState.gameStarted = true; // Update public server info
      room.gameState.bombPlanted = false; const publicServer = publicServers.get('cs16').get(roomId);
      room.gameState.bombDefused = false;      if (publicServer) {
      room.gameState.winner = null;

      // Reset players
      for (const player of room.players.values()) {
        player.health = 100;
        player.isAlive = true;      
        player.position = { x: 0, y: 0, z: 0 }; // Should be spawn points
      }ners are CT

      // Reset bots
      for (const bot of room.bots.values()) {
        bot.health = 100;6:${roomId}`);
        bot.isAlive = true;
        bot.position = { x: 0, y: 0, z: 0 };r info
      }licServers.get('cs16').get(roomId);

      // Start AI loop publicServer.playerCount = room.players.size;
      startBotAI(roomId);      }
icServers();
      // Update public server state
      const publicServer = publicServers.get('cs16').get(roomId);
      if (publicServer) publicServer.gameState.started = true;`).emit('cs16:player-joined', {
      broadcastPublicServers();
 username,
      io.to(`cs16:${roomId}`).emit('cs16:game-update', { gameState: room.gameState });        position: { x: 0, y: 0, z: 0 }
      return ack && ack({ ok: true });
    } catch (e) {
      logger.error('Error starting CS16 game', e);      // Send full state to joiner
      return ack && ack({ ok: false, error: 'internal' });m(room.players.entries()).map(([id, p]) => ({ id, ...p }));
    }b]) => ({ id, ...b }));
  });
ate', {
  socket.on('cs16:player-move', ({ roomId, userId, position, rotation }) => {        roomId,
    const room = cs16Rooms.get(roomId);
    if (!room) return;
    const player = room.players.get(userId);sList,
    if (player) {
      player.position = position;
      player.rotation = rotation; if (room.players.size === 0) {
      // Broadcast to others   cs16Rooms.delete(roomId);
      socket.to(`cs16:${roomId}`).emit('cs16:player-update', { userId, position, rotation });        publicServers.get('cs16').delete(roomId);
    }
  });
ack({ ok: true });
  socket.on('cs16:player-action', ({ roomId, userId, action, targetId }) => {
    const room = cs16Rooms.get(roomId);
    if (!room) return; {
.keys().next();
    if (action === 'shoot') {alue;
      // Simple hitscan logic could go here, or trust client for now (not secure but easier)
      // For now, just broadcast shot event   if (publicServer) {
      socket.to(`cs16:${roomId}`).emit('cs16:player-shoot', { userId });     const newHost = room.players.get(room.hostId);
    }          if (newHost) publicServer.hostName = newHost.username;
  });

  // ✅ Desconexión
  socket.on('disconnect', () => {      userRoomMap.delete(userId);
    const user = connectedUsers.get(socket.id);
    if (user) {
      logger.info(`Usuario desconectado: ${user.username} (${socket.id})`);omId);
      connectedUsers.delete(socket.id);
         return ack && ack({ ok: true });
      // Remove from voice channels }
      const voiceChannel = voiceStates.get(socket.id);
      if (voiceChannel) {tId === userId) {
        voiceStates.delete(socket.id);.keys().next();
        // Broadcast new global state
        io.emit('voice:state', getGlobalVoiceState());ublicServer = publicServers.get('cs16').get(roomId);
      }
get(room.hostId);
      // Remove from impostor rooms if in one    if (newHost) publicServer.hostName = newHost.username;
      // This is a bit expensive (iterating all rooms), but safe for now
      for (const [roomId, room] of impostorRooms.entries()) {
        if (room.players.has(user.id)) {
          room.players.delete(user.id);rs.get('cs16').get(roomId);
          // If room empty, deleteplayerCount = room.players.size;
          if (room.players.size === 0) {
            impostorRooms.delete(roomId);
            publicServers.get('impostor').delete(roomId);      io.to(`cs16:${roomId}`).emit('cs16:player-left', { userId });
          } else {
            // If host left, reassign
            if (room.hostId === user.id) {
              const next = room.players.keys().next();or: 'internal' });
              room.hostId = next.value;
              // Update public server host name
              const publicServer = publicServers.get('impostor').get(roomId);
              if (publicServer) { hostId }, ack) => {
                const newHost = room.players.get(room.hostId);
                if (newHost) publicServer.hostName = newHost.username; cs16Rooms.get(roomId);
              }ok: false, error: 'not_found' });
            }ck && ack({ ok: false, error: 'not_host' });
            // Update public server count
            const publicServer = publicServers.get('impostor').get(roomId);;
            if (publicServer) publicServer.playerCount = room.players.size;
            
            // Notify rooml;
            io.to(`impostor:${roomId}`).emit('impostor:player-left', { roomId, username: user.username });
            const playersList = Array.from(room.players.entries()).map(([id, p]) => ({ id, username: p.username }));
            io.to(`impostor:${roomId}`).emit('impostor:room-state', {t player of room.players.values()) {
              roomId,r.health = 100;
              hostId: room.hostId,
              players: playersList,
              started: room.started,
              customWords: room.customWords
            });
          }
          broadcastPublicServers();
        }
      }= { x: 0, y: 0, z: 0 };

      // Remove from CS16 rooms
      for (const [roomId, room] of cs16Rooms.entries()) {
        if (room.players.has(user.id)) {
          room.players.delete(user.id);
          if (room.players.size === 0) {date public server state
            cs16Rooms.delete(roomId);rvers.get('cs16').get(roomId);
            publicServers.get('cs16').delete(roomId);(publicServer) publicServer.gameState.started = true;
          } else {roadcastPublicServers();
            if (room.hostId === user.id) {
              const next = room.players.keys().next();mit('cs16:game-update', { gameState: room.gameState });
              room.hostId = next.value;
              const publicServer = publicServers.get('cs16').get(roomId);
              if (publicServer) { game', e);
                const newHost = room.players.get(room.hostId);or: 'internal' });
                if (newHost) publicServer.hostName = newHost.username;
              }
            }
            const publicServer = publicServers.get('cs16').get(roomId); userId, position, rotation }) => {
            if (publicServer) publicServer.playerCount = room.players.size;
            
            io.to(`cs16:${roomId}`).emit('cs16:player-left', { userId: user.id });
          }
          broadcastPublicServers();
        }
      }
info(`Usuario desconectado: ${user.username} (${socket.id})`);
      io.emit('user:offline', { userId: user.id });
      
      // Update list for everyoneove from voice channels
      const onlineUsers = Array.from(connectedUsers.values()).map(db.sanitizeUserOutput);
      io.emit('users:list', onlineUsers);oiceChannel) {
    }d);
  });/ Broadcast new global state
}); io.emit('voice:state', getGlobalVoiceState());
      }
// ===============================================
// Inicialización y Configuración// Optimized room cleanup using userRoomMap
// ===============================================p.get(user.id);

// Mostrar configuración cargada (sin secretos);
logger.info('Configuración del servidor:', {   userRoomMap.delete(user.id);
  env: process.env.NODE_ENV || 'development',
  port: process.env.PORT || 3000,     if (type === 'impostor') {
  logLevel: process.env.LOG_LEVEL || 'info',          const room = impostorRooms.get(roomId);
  dbConnected: db.isConnected() ? 'sí' : 'no',
  adminDiscordId: ADMIN_DISCORD_ID.slice(0, 6) + '...', // Mostrar solo parte del IDser.id);
});
              impostorRooms.delete(roomId);
// Iniciar servidor HTTPete(roomId);
server.listen(process.env.PORT || 3000, () => {
  logger.info(`Servidor escuchando en puerto ${process.env.PORT || 3000}`);
});.players.keys().next();

// Tareas de mantenimiento periódicasvers.get('impostor').get(roomId);
setInterval(() => {
  try {               const newHost = room.players.get(room.hostId);
    // Limpiar usuarios desconectados de connectedUsers (timeout de 5 minutos)                  if (newHost) publicServer.hostName = newHost.username;
    const now = Date.now();
    for (const [sid, user] of connectedUsers.entries()) {
      if (!user.id.startsWith('guest-') && now - user.lastActivity > 5 * 60 * 1000) {);
        // Desconectar socket inactivo           if (publicServer) publicServer.playerCount = room.players.size;
        const s = io.sockets.sockets.get(sid);              
        if (s) {d}`).emit('impostor:player-left', { roomId, username: user.username });
          s.disconnect(true); playersList = Array.from(room.players.entries()).map(([id, p]) => ({ id, username: p.username }));
        }       io.to(`impostor:${roomId}`).emit('impostor:room-state', {
      }
    }m.hostId,
  } catch (e) {
    logger.error('Error en tarea de mantenimiento', e);
  }omWords
}, 60 * 1000); // Cada minuto

// ===============================================rvers();
// Cierre limpio del servidor }
// =============================================== } else if (type === 'cs16') {
     const room = cs16Rooms.get(roomId);
process.on('SIGTERM', () => {oom && room.players.has(user.id)) {
  logger.info('SIGTERM recibido: cerrando servidor...');
  server.close(err => {         if (room.players.size === 0) {
    if (err) {e(roomId);
      logger.error('Error cerrando servidor:', err);              publicServers.get('cs16').delete(roomId);
      process.exit(1);
    } === user.id) {
    logger.info('Servidor cerrado limpiamente');ext();
    process.exit(0);                room.hostId = next.value;
  });erver = publicServers.get('cs16').get(roomId);
});
 newHost = room.players.get(room.hostId);
process.on('uncaughtException', (err) => {    if (newHost) publicServer.hostName = newHost.username;
  logger.error('Excepción no controlada:', err);
  // Opcional: cerrar el servidor en caso de errores críticos no manejados
  // server.close(() => process.exit(1));         const publicServer = publicServers.get('cs16').get(roomId);
});yerCount = room.players.size;

process.on('unhandledRejection', (reason, promise) => {         io.to(`cs16:${roomId}`).emit('cs16:player-left', { userId: user.id });
  logger.error('Promesa rechazada sin manejar:', promise, 'razón:', reason);         }
  // Opcional: cerrar el servidor en caso de rechazos de promesas no manejados            broadcastPublicServers();
  // server.close(() => process.exit(1));
});
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
