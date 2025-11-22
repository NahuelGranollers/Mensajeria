function isAdminUser(userId) {
  return userId === ADMIN_DISCORD_ID;
}
function sanitizeMessage(msg) {
  return xss(msg);
}
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xss = require('xss');
const winston = require('winston');
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

// Estado de canales de voz: userId -> channelId
const voiceStates = new Map();

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

  // ✅ Usuario se une
  socket.on('user:join', async userData => {
    // Determinar rol real (seguridad)
    let role = 'user';

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
    io.emit('admin:user-color-changed', { userId, color });
    logger.info(
      `Color de usuario ${userId} cambiado a ${color} por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );
  });

  // 🔒 Admin: Mensaje global
  socket.on('admin:global-message', async data => {
    const { content, adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(
        `Intento de mensaje global por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
      return;
    }
    // Emitir a todos los canales
    io.emit('admin:global-message', { content });
    logger.info(
      `Mensaje global enviado por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );
  });

  // 🔒 Admin: Modo troll
  socket.on('admin:troll-mode', async data => {
    const { userId, adminId } = data;
    if (!isAdminUser(adminId)) {
      logger.warn(
        `Intento de modo troll por no admin: ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
      );
      return;
    }
    io.emit('admin:user-troll', { userId });
    logger.info(
      `Modo troll activado para usuario ${userId} por admin ${adminId ? adminId.slice(0, 6) + '...' : 'N/A'}`
    );
  });

  // ✅ Enviar mensaje
  socket.on('message:send', async msgData => {
    if (!msgData.content || !msgData.content.trim()) return;
    // Sanitizar y validar datos
    const safeContent = sanitizeMessage(msgData.content.substring(0, 2000));
    const safeUsername = sanitizeMessage(msgData.username);
    const safeAvatar = sanitizeMessage(msgData.avatar);
    const safeChannelId = sanitizeMessage(msgData.channelId || 'general');
    const safeUserId = sanitizeMessage(msgData.userId);

    const message = {
      id: crypto.randomUUID(),
      channelId: safeChannelId,
      userId: safeUserId,
      username: safeUsername,
      avatar: safeAvatar,
      content: safeContent,
      timestamp: new Date().toISOString(),
      isSystem: false,
    };

    // Guardar en DB
    await db.saveMessage(message);

    // Emitir a todos en el canal
    io.to(message.channelId).emit('message:received', db.sanitizeMessageOutput(message));

    // 🤖 Lógica del Bot (Respuestas Agresivas)
    if (message.content.toLowerCase().includes('@upg')) {
      const text = message.content.toLowerCase();
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
          logger.info(`Enviando respuesta del bot: ${botResponse}`);
          io.to(message.channelId).emit('message:received', db.sanitizeMessageOutput(botMessage));
          logger.info(`Mensaje del bot enviado al canal ${message.channelId}`);
        } catch (err) {
          logger.error('Error guardando mensaje del bot:', err);
        }
      }, 1500);
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
    } else {
      // Unirse al nuevo canal
      voiceStates.set(user.id, channelId);
      logger.info(`Usuario ${user.username} se unió al canal de voz: ${channelId}`);
    }

    // Emitir estado actualizado a TODOS
    io.emit('voice:state', Object.fromEntries(voiceStates));
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
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.info(`Servidor corriendo en puerto ${PORT}`);
  logger.info(`Admin ID configurado: ${ADMIN_DISCORD_ID}`);
});
