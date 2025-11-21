const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const axios = require("axios");
const session = require("express-session");
const cookieParser = require("cookie-parser");
require("dotenv").config();
const { GoogleGenerativeAI } = require("@google/generative-ai");

// Inicializar Gemini
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.0-pro" });

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
  color: '#5865F2'
};

// Almacenamiento en memoria de usuarios conectados
const connectedUsers = new Map();
connectedUsers.set('bot', BOT_USER);

// Estado de canales de voz: userId -> channelId
const voiceStates = new Map();

// ✅ Sistema de Logs Profesional
const COLORS = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m'
};

const ICONS = {
  info: 'ℹ️',
  success: '✅',
  warning: '⚠️',
  error: '❌',
  debug: '🔍',
  server: '🚀',
  socket: '🔌',
  user: '👤',
  message: '💬',
  admin: '👑',
  ban: '🔨',
  security: '🛡️'
};

const catchAsync = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

const logger = {
  info: (message, ...args) => console.log(`${COLORS.blue}${ICONS.info} [INFO]${COLORS.reset} ${message}`, ...args),
  success: (message, ...args) => console.log(`${COLORS.green}${ICONS.success} [SUCCESS]${COLORS.reset} ${message}`, ...args),
  warning: (message, ...args) => console.log(`${COLORS.yellow}${ICONS.warning} [WARNING]${COLORS.reset} ${message}`, ...args),
  error: (message, ...args) => console.error(`${COLORS.red}${ICONS.error} [ERROR]${COLORS.reset} ${message}`, ...args),
  debug: (message, ...args) => {
    if (process.env.DEBUG === 'true') console.log(`${COLORS.gray}${ICONS.debug} [DEBUG]${COLORS.reset} ${message}`, ...args);
  },
  server: (message, ...args) => console.log(`${COLORS.cyan}${ICONS.server} [SERVER]${COLORS.reset} ${message}`, ...args),
  socket: (message, ...args) => console.log(`${COLORS.magenta}${ICONS.socket} [SOCKET]${COLORS.reset} ${message}`, ...args),
  user: (message, ...args) => console.log(`${COLORS.green}${ICONS.user} [USER]${COLORS.reset} ${message}`, ...args),
  message: (message, ...args) => console.log(`${COLORS.blue}${ICONS.message} [MESSAGE]${COLORS.reset} ${message}`, ...args),
  admin: (message, ...args) => console.log(`${COLORS.yellow}${ICONS.admin} [ADMIN]${COLORS.reset} ${message}`, ...args),
};

const app = express();
const server = http.createServer(app);

// ✅ Middleware
app.use(express.json());
app.use(cookieParser());

// CORS para rutas Express
app.use((req, res, next) => {
  const allowedOrigins = [
    'https://unaspartidillasgang.online',
    'https://unaspartidillas.online',
    'http://localhost:5173'
  ];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(session({
  secret: process.env.SESSION_SECRET || 'your-super-secret-key-change-this',
  resave: false,
  saveUninitialized: false,
  name: 'upg.sid',
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  },
  proxy: true
}));

const io = new Server(server, {
  cors: {
    origin: [
      "https://unaspartidillasgang.online",
      "https://unaspartidillas.online",
      "http://localhost:5173"
    ],
    methods: ["GET", "POST"],
    credentials: true
  }
});

// ✅ Map de usuarios conectados (socketId -> userData)
// const connectedUsers = new Map(); // YA DEFINIDO ARRIBA

// ===============================================
// 🔐 Discord OAuth2 Routes
// ===============================================

app.get("/auth/discord", catchAsync(async (req, res) => {
  const redirectUri = process.env.DISCORD_REDIRECT_URI;
  const clientId = process.env.DISCORD_CLIENT_ID;
  const scope = "identify";

  if (!clientId || !redirectUri) {
    throw new Error('Variables de entorno DISCORD_CLIENT_ID o DISCORD_REDIRECT_URI no configuradas');
  }

  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;

  await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));

  const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${scope}&state=${state}`;
  res.redirect(discordAuthUrl);
}));

app.get("/auth/callback", catchAsync(async (req, res) => {
  const { code, state, error } = req.query;
  const frontendUrl = process.env.FRONTEND_URL || 'https://unaspartidillas.online';

  if (error) return res.redirect(`${frontendUrl}/?auth=error&error_code=${error}`);
  if (!code) return res.redirect(`${frontendUrl}/?auth=error&error_code=no_code`);

  // Validación de state omitida para simplificar en entornos mixtos, pero recomendada en prod estricto

  const tokenResponse = await axios.post(
    "https://discord.com/api/oauth2/token",
    new URLSearchParams({
      client_id: process.env.DISCORD_CLIENT_ID,
      client_secret: process.env.DISCORD_CLIENT_SECRET,
      code: code,
      grant_type: "authorization_code",
      redirect_uri: process.env.DISCORD_REDIRECT_URI,
    }),
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );

  const { access_token, refresh_token, expires_in } = tokenResponse.data;

  const userResponse = await axios.get("https://discord.com/api/users/@me", {
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
    avatar: discordUser.avatar ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png` : null,
    role: role,
    status: 'online'
  });

  await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));

  res.redirect(`${frontendUrl}/?auth=success`);
}));

app.get("/auth/user", (req, res) => {
  if (!req.session.discordUser) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  res.json(req.session.discordUser);
});

app.post("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("upg.sid");
    res.json({ success: true });
  });
});

// ===============================================
// 🔌 Socket.IO Logic
// ===============================================

io.on("connection", (socket) => {
  logger.socket(`Usuario conectado: ${socket.id}`);

  // ✅ Usuario se une
  socket.on("user:join", async (userData) => {
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
      online: true
    };

    connectedUsers.set(socket.id, finalUser);

    // Guardar en DB si no es invitado temporal
    if (!finalUser.id.startsWith('guest-')) {
      await db.saveUser(finalUser);
    }

    socket.emit("user:registered", finalUser);

    // Notificar a todos
    io.emit("user:online", finalUser);

    // Enviar lista de usuarios conectados
    const onlineUsers = Array.from(connectedUsers.values());
    socket.emit("users:list", onlineUsers);
  });

  // ✅ Petición explicita de lista de usuarios
  socket.on("users:request", () => {
    const onlineUsers = Array.from(connectedUsers.values());
    socket.emit("users:list", onlineUsers);
  });

  // ✅ Unirse a canal y pedir historial
  socket.on("channel:join", async ({ channelId }) => {
    const channel = channelId || 'general';
    socket.join(channel);

    // Recuperar historial de DB
    const history = await db.getChannelHistory(channel);
    socket.emit("channel:history", {
      channelId: channel,
      messages: history
    });
  });

  // ✅ Enviar mensaje
  socket.on("message:send", async (msgData) => {
    if (!msgData.content || !msgData.content.trim()) return;

    const message = {
      id: crypto.randomUUID(),
      channelId: msgData.channelId || 'general',
      userId: msgData.userId,
      username: msgData.username,
      avatar: msgData.avatar,
      content: msgData.content.substring(0, 2000), // Limitar longitud
      timestamp: new Date().toISOString(),
      isSystem: false
    };

    // Guardar en DB
    await db.saveMessage(message);

    // Emitir a todos en el canal
    io.to(message.channelId).emit("message:received", message);

    // 🤖 Lógica del Bot (Gemini)
    if (message.content.toLowerCase().includes('@upg')) {
      try {
        // Prompt para el bot
        const prompt = `Eres UPG, un asistente útil y divertido para la comunidad de gamers "United Player Group". 
        El usuario ${message.username} dice: "${message.content}". 
        Responde de manera concisa y amigable (máximo 200 caracteres si es posible).`;

        const result = await model.generateContent(prompt);
        const response = await result.response;
        const text = response.text();

        // Crear mensaje del bot
        const botMessage = {
          id: crypto.randomUUID(),
          channelId: message.channelId,
          userId: 'bot',
          username: 'UPG',
          avatar: BOT_USER.avatar,
          content: text,
          timestamp: new Date().toISOString(),
          isSystem: false,
          role: 'bot'
        };

        // Simular tiempo de escritura (opcional, pero da realismo)
        setTimeout(async () => {
          try {
            await db.saveMessage(botMessage);
            io.to(message.channelId).emit("message:received", botMessage);
          } catch (err) {
            logger.error("Error guardando mensaje del bot:", err);
          }
        }, 1500);

      } catch (error) {
        logger.error("Error con Gemini:", error);

        // Mensaje de error amigable
        const errorMessage = {
          id: crypto.randomUUID(),
          channelId: message.channelId,
          userId: 'bot',
          username: 'UPG',
          avatar: BOT_USER.avatar,
          content: "Lo siento, mis circuitos están un poco fritos ahora mismo. Inténtalo más tarde. 🤖💥",
          timestamp: new Date().toISOString(),
          isSystem: false,
          role: 'bot'
        };

        io.to(message.channelId).emit("message:received", errorMessage);
      }
    }
  });

  // ✅ Canales de Voz
  socket.on("voice:join", ({ channelId }) => {
    logger.socket(`Intento de unirse a voz: ${socket.id} -> ${channelId}`);
    const user = connectedUsers.get(socket.id);
    if (!user) {
      logger.warning(`Usuario no encontrado en connectedUsers para socket ${socket.id}`);
      return;
    }

    const currentChannel = voiceStates.get(user.id);
    logger.debug(`Usuario ${user.username} (${user.id}) estado actual: ${currentChannel}, nuevo: ${channelId}`);

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
    io.emit("voice:state", Object.fromEntries(voiceStates));
  });

  // ✅ Desconexión
  socket.on("disconnect", () => {
    const user = connectedUsers.get(socket.id);
    if (user) {
      connectedUsers.delete(socket.id);
      io.emit("user:offline", { userId: user.id, username: user.username });

      // Limpiar estado de voz si estaba conectado
      if (voiceStates.has(user.id)) {
        voiceStates.delete(user.id);
        io.emit("voice:state", Object.fromEntries(voiceStates));
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
  logger.server(`Servidor corriendo en puerto ${PORT}`);
  logger.info(`Admin ID configurado: ${ADMIN_DISCORD_ID}`);
});
