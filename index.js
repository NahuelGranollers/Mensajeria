const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const axios = require("axios");
const session = require("express-session");
const cookieParser = require("cookie-parser");
require("dotenv").config(); // Carga .env en la carpeta server

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

// ✅ Async Error Wrapper (OAuth2 Best Practice)
const catchAsync = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

const logger = {
  info: (message, ...args) => {
    console.log(`${COLORS.blue}${ICONS.info} [INFO]${COLORS.reset} ${message}`, ...args);
  },
  success: (message, ...args) => {
    console.log(`${COLORS.green}${ICONS.success} [SUCCESS]${COLORS.reset} ${message}`, ...args);
  },
  warning: (message, ...args) => {
    console.log(`${COLORS.yellow}${ICONS.warning} [WARNING]${COLORS.reset} ${message}`, ...args);
  },
  error: (message, ...args) => {
    console.error(`${COLORS.red}${ICONS.error} [ERROR]${COLORS.reset} ${message}`, ...args);
  },
  debug: (message, ...args) => {
    if (process.env.DEBUG === 'true') {
      console.log(`${COLORS.gray}${ICONS.debug} [DEBUG]${COLORS.reset} ${message}`, ...args);
    }
  },
  server: (message, ...args) => {
    console.log(`${COLORS.cyan}${ICONS.server} [SERVER]${COLORS.reset} ${message}`, ...args);
  },
  socket: (message, ...args) => {
    console.log(`${COLORS.magenta}${ICONS.socket} [SOCKET]${COLORS.reset} ${message}`, ...args);
  },
  user: (message, ...args) => {
    console.log(`${COLORS.green}${ICONS.user} [USER]${COLORS.reset} ${message}`, ...args);
  },
  message: (message, ...args) => {
    console.log(`${COLORS.blue}${ICONS.message} [MESSAGE]${COLORS.reset} ${message}`, ...args);
  },
  admin: (message, ...args) => {
    console.log(`${COLORS.yellow}${ICONS.admin} [ADMIN]${COLORS.reset} ${message}`, ...args);
  },
  ban: (message, ...args) => {
    console.log(`${COLORS.red}${ICONS.ban} [BAN]${COLORS.reset} ${message}`, ...args);
  },
  security: (message, ...args) => {
    console.log(`${COLORS.cyan}${ICONS.security} [SECURITY]${COLORS.reset} ${message}`, ...args);
  }
};

const app = express();
const server = http.createServer(app);

// ✅ Middleware
app.use(express.json());
app.use(cookieParser());

// CORS para rutas Express (OAuth)
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
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

app.use(session({
  secret: process.env.SESSION_SECRET || 'your-super-secret-key-change-this',
  resave: false,
  saveUninitialized: false,
  name: 'upg.sid', // Custom name for better debugging
  cookie: {
    secure: process.env.NODE_ENV === 'production', // true en producción (HTTPS)
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // 'none' para cross-domain
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 días
    // No establecer domain para permitir cookies cross-domain con diferentes dominios
  },
  proxy: true // Trust proxy headers (Render uses proxies)
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

// Historial en memoria por canal
const CHANNELS = { general: [] };

// ✅ Map de usuarios conectados (socketId -> userData)
const connectedUsers = new Map();

// ✅ Set de usernames en uso (para evitar duplicados)
const usedUsernames = new Set();

// El servidor detecta la IP del cliente, la hashea y la compara con este valor
// Si coincide, automáticamente se asignan permisos de administrador
const ADMIN_IP_HASH = '44273c5917d79833c51420afd84a77cef89743c63a44b3c07742ee59d9cde94a';

function hashIP(ip) {
  if (!ip) return null;
  // Si viene una lista de IPs separadas por comas (proxy/CDN), tomar solo la primera
  const firstIp = ip.split(',')[0].trim();
  const cleanIp = firstIp.replace('::ffff:', '').trim();
  return crypto.createHash('sha256').update(cleanIp).digest('hex');
}

// Verificar si una IP es admin
function isAdminIP(ip) {
  const ipHash = hashIP(ip);
  return ipHash === ADMIN_IP_HASH;
}

// ✅ Sistema de usuarios registrados permanentemente
const USERS_FILE = path.join(__dirname, 'users.json');
let registeredUsers = {}; // ipHash -> userData

// Cargar usuarios registrados
function loadRegisteredUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const data = fs.readFileSync(USERS_FILE, 'utf8');
      registeredUsers = JSON.parse(data);
      logger.success(`Usuarios registrados cargados: ${Object.keys(registeredUsers).length} usuarios`);
    }
  } catch (error) {
    logger.error('Error cargando usuarios registrados:', error);
  }
}

// Guardar usuarios registrados
function saveRegisteredUsers() {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(registeredUsers, null, 2));
  } catch (error) {
    logger.error('Error guardando usuarios registrados:', error);
  }
}

// Obtener o crear usuario por IP
function getUserByIP(ipHash) {
  return registeredUsers[ipHash] || null;
}

// Registrar/actualizar usuario por IP
function registerUser(ipHash, userData) {
  registeredUsers[ipHash] = {
    ...userData,
    ipHash,
    lastSeen: new Date().toISOString(),
    registeredAt: registeredUsers[ipHash]?.registeredAt || new Date().toISOString()
  };
  saveRegisteredUsers();
}

// Obtener lista completa de usuarios (online + offline)
function getAllUsers() {
  const allUsers = [];
  
  // Agregar todos los usuarios registrados
  for (const ipHash in registeredUsers) {
    const registeredUser = registeredUsers[ipHash];
    
    // Buscar si está conectado
    let isOnline = false;
    let socketId = null;
    
    for (const [sid, connectedUser] of connectedUsers.entries()) {
      if (connectedUser.id === registeredUser.id) {
        isOnline = true;
        socketId = sid;
        break;
      }
    }
    
    allUsers.push({
      id: registeredUser.id,
      username: registeredUser.username,
      avatar: registeredUser.avatar,
      role: registeredUser.role,
      online: isOnline,
      status: isOnline ? 'online' : 'offline',
      socketId: socketId,
      lastSeen: registeredUser.lastSeen,
      registeredAt: registeredUser.registeredAt
    });
  }
  
  return allUsers;
}

// ✅ Sistema de baneos
const BANNED_FILE = path.join(__dirname, 'banned.json');
let bannedList = { ips: [], userIds: [] };

// Cargar lista de baneados
function loadBannedList() {
  try {
    if (fs.existsSync(BANNED_FILE)) {
      const data = fs.readFileSync(BANNED_FILE, 'utf8');
      bannedList = JSON.parse(data);
    }
  } catch (error) {
    logger.error('Error cargando lista de baneados:', error);
  }
}

// Guardar lista de baneados
function saveBannedList() {
  try {
    fs.writeFileSync(BANNED_FILE, JSON.stringify(bannedList, null, 2));
  } catch (error) {
    logger.error('Error guardando lista de baneados:', error);
  }
}

// Verificar si usuario/IP está baneado
function isBanned(userId, ip) {
  return bannedList.userIds.includes(userId) || bannedList.ips.includes(ip);
}

// Banear usuario y su IP
function banUser(userId, ip) {
  if (!bannedList.userIds.includes(userId)) {
    bannedList.userIds.push(userId);
  }
  if (ip && !bannedList.ips.includes(ip)) {
    bannedList.ips.push(ip);
  }
  saveBannedList();
}

// Cargar datos al iniciar
loadRegisteredUsers();
loadBannedList();

// ✅ Rate Limiting - Prevenir spam
const rateLimits = new Map(); // socketId -> { messages: [], lastCheck: timestamp }

function checkRateLimit(socketId, action = 'message') {
  const now = Date.now();
  const limit = action === 'message' ? 5 : 10; // 5 mensajes o 10 acciones por ventana
  const window = 10000; // 10 segundos
  
  if (!rateLimits.has(socketId)) {
    rateLimits.set(socketId, { actions: [now], lastCheck: now });
    return true;
  }
  
  const userData = rateLimits.get(socketId);
  // Limpiar acciones antiguas fuera de la ventana
  userData.actions = userData.actions.filter(timestamp => now - timestamp < window);
  
  if (userData.actions.length >= limit) {
    return false; // Rate limit excedido
  }
  
  userData.actions.push(now);
  userData.lastCheck = now;
  return true;
}

// Limpiar rate limits de usuarios desconectados cada 5 minutos
setInterval(() => {
  const now = Date.now();
  for (const [socketId, data] of rateLimits.entries()) {
    if (now - data.lastCheck > 300000) { // 5 minutos sin actividad
      rateLimits.delete(socketId);
    }
  }
}, 300000);

// ===============================================
// 🔐 Discord OAuth2 Routes (Authorization Code Flow)
// ===============================================

// Ruta 0: Debug - Verificar configuración (ELIMINAR EN PRODUCCIÓN)
app.get("/auth/debug", (req, res) => {
  res.json({
    clientId: process.env.DISCORD_CLIENT_ID ? '✅ Configurado' : '❌ Faltante',
    clientSecret: process.env.DISCORD_CLIENT_SECRET ? '✅ Configurado' : '❌ Faltante',
    redirectUri: process.env.DISCORD_REDIRECT_URI || '❌ Faltante',
    frontendUrl: process.env.FRONTEND_URL || '❌ Faltante',
    nodeEnv: process.env.NODE_ENV || 'development'
  });
});

// Ruta 1: Iniciar OAuth - Redirige al usuario a Discord
app.get("/auth/discord", catchAsync(async (req, res) => {
  const redirectUri = process.env.DISCORD_REDIRECT_URI;
  const clientId = process.env.DISCORD_CLIENT_ID;
  const scope = "identify";
  
  // Debug: Verificar que las variables están cargadas
  if (!clientId || !redirectUri) {
    logger.error("❌ Variables de entorno faltantes!");
    logger.error(`CLIENT_ID: ${clientId ? 'OK' : 'UNDEFINED'}`);
    logger.error(`REDIRECT_URI: ${redirectUri ? 'OK' : 'UNDEFINED'}`);
    const error = new Error('server_error');
    error.statusCode = 500;
    error.description = 'Error de configuración del servidor. Variables de entorno no configuradas.';
    throw error;
  }
  
  // Generate state parameter for CSRF protection (best practice)
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  
  // Save session before redirect to ensure it persists
  await new Promise((resolve, reject) => {
    req.session.save((err) => {
      if (err) {
        logger.error("❌ Error saving session state:", err);
        reject(err);
      } else {
        logger.debug(`✅ Session state saved: ${state}`);
        resolve();
      }
    });
  });
  
  const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${scope}&state=${state}`;
  
  logger.info(`🔐 Redirecting to Discord OAuth`);
  logger.debug(`State generated: ${state}`);
  res.redirect(discordAuthUrl);
}));

// Ruta 2: Callback de Discord - Intercambia el code por el token
app.get("/auth/callback", catchAsync(async (req, res) => {
  const { code, state, error } = req.query;
  
  // Check for OAuth errors from Discord
  if (error) {
    logger.error(`❌ Discord OAuth error: ${error}`);
    const frontendUrl = process.env.FRONTEND_URL || 'https://unaspartidillas.online';
    return res.redirect(`${frontendUrl}/?auth=error&error_code=${error}`);
  }
  
  if (!code) {
    logger.error("❌ No authorization code received from Discord");
    const authError = new Error('invalid_request');
    authError.statusCode = 400;
    authError.description = 'Authorization failed: No code provided';
    throw authError;
  }
  
  // Validate state parameter (CSRF protection)
  // In cross-domain scenarios, session might not persist, so we validate if it exists
  logger.debug(`Received state: ${state}`);
  logger.debug(`Session state: ${req.session.oauthState}`);
  
  if (req.session.oauthState && state !== req.session.oauthState) {
    logger.error(`❌ OAuth state mismatch - Expected: ${req.session.oauthState}, Got: ${state}`);
    const authError = new Error('invalid_request');
    authError.statusCode = 400;
    authError.description = 'State parameter mismatch';
    throw authError;
  }
  
  if (!req.session.oauthState) {
    logger.warning("⚠️ Session state not found - this may happen in cross-domain scenarios");
    logger.warning("State validation skipped - consider using alternative CSRF protection");
  }
  
  // Clear state after validation
  delete req.session.oauthState;

  logger.info("🔄 Exchanging authorization code for access token...");
  
  // Intercambiar code por access_token
  const tokenResponse = await axios.post(
    "https://discord.com/api/oauth2/token",
    new URLSearchParams({
      client_id: process.env.DISCORD_CLIENT_ID,
      client_secret: process.env.DISCORD_CLIENT_SECRET,
      code: code,
      grant_type: "authorization_code",
      redirect_uri: process.env.DISCORD_REDIRECT_URI,
    }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );

  const { access_token, refresh_token, expires_in } = tokenResponse.data;
  logger.success("✅ Access token obtained successfully");

  // Obtener información del usuario de Discord
  const userResponse = await axios.get("https://discord.com/api/users/@me", {
    headers: {
      Authorization: `Bearer ${access_token}`,
    },
  });

  const discordUser = userResponse.data;
  logger.user(`👤 Discord user authenticated: ${discordUser.username}#${discordUser.discriminator} (ID: ${discordUser.id})`);

  // Guardar usuario en sesión (con refresh_token para futura implementación)
  req.session.discordUser = {
    id: discordUser.id,
    username: discordUser.username,
    discriminator: discordUser.discriminator,
    avatar: discordUser.avatar,
    accessToken: access_token,
    refreshToken: refresh_token, // Save for token refresh
    tokenExpiry: Date.now() + (expires_in * 1000), // Calculate expiry timestamp
  };

  // Guardar la sesión antes de redirigir
  await new Promise((resolve, reject) => {
    req.session.save((err) => {
      if (err) {
        logger.error("❌ Error saving session:", err);
        const sessionError = new Error('server_error');
        sessionError.statusCode = 500;
        sessionError.description = 'Error al guardar sesión';
        reject(sessionError);
      } else {
        resolve();
      }
    });
  });

  // Redirigir al frontend con éxito
  const frontendUrl = process.env.FRONTEND_URL || 'https://unaspartidillas.online';
  const redirectUrl = `${frontendUrl}/?auth=success`;
  
  logger.info(`🔄 Redirecting to frontend: ${redirectUrl}`);
  logger.success(`✅ Session saved for user: ${discordUser.username}`);
  
  // Redirección con HTML meta refresh como fallback
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta http-equiv="refresh" content="0;url=${redirectUrl}">
      <title>Redirigiendo...</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          margin: 0;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
        }
        .container {
          text-align: center;
        }
        .spinner {
          border: 4px solid rgba(255, 255, 255, 0.3);
          border-top: 4px solid white;
          border-radius: 50%;
          width: 40px;
          height: 40px;
          animation: spin 1s linear infinite;
          margin: 20px auto;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>✅ Autenticación exitosa</h1>
        <div class="spinner"></div>
        <p>Redirigiendo a UPG...</p>
        <p><small>Si no se redirige automáticamente, <a href="${redirectUrl}" style="color: white;">haz clic aquí</a></small></p>
      </div>
      <script>
        setTimeout(() => {
          window.location.href = "${redirectUrl}";
        }, 500);
      </script>
    </body>
    </html>
  `);
}));

// Ruta 3: Obtener usuario autenticado
app.get("/auth/user", (req, res) => {
  logger.debug(`Auth check - Session ID: ${req.sessionID}`);
  logger.debug(`Auth check - Cookies: ${JSON.stringify(req.cookies)}`);
  logger.debug(`Auth check - Session exists: ${!!req.session}`);
  logger.debug(`Auth check - Discord user in session: ${!!req.session?.discordUser}`);
  
  if (!req.session.discordUser) {
    logger.warning(`❌ No Discord user in session for session ID: ${req.sessionID}`);
    return res.status(401).json({ error: "Not authenticated" });
  }
  
  logger.info(`✅ Discord user session found (ID: ${req.session.discordUser.id}, username: ${req.session.discordUser.username})`);
  res.json(req.session.discordUser);
});

// Ruta 4: Logout
app.post("/auth/logout", (req, res) => {
  const username = req.session?.discordUser?.username || 'Unknown';
  
  req.session.destroy((err) => {
    if (err) {
      logger.error("❌ Error destroying session:", err);
      return res.status(500).json({ error: "Logout failed" });
    }
    
    // Clear both possible cookie names
    res.clearCookie("upg.sid");
    res.clearCookie("connect.sid");
    
    logger.info(`👋 User ${username} logged out successfully`);
    res.json({ success: true });
  });
});

io.on("connection", (socket) => {
  const clientIp = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
  const ipHash = hashIP(clientIp);
  logger.socket(`Usuario conectado: ${socket.id}`);

  // ✅ Sistema de Heartbeat - Mantener conexión activa (sin timeout/desconexión)
  let heartbeatInterval;
  const HEARTBEAT_INTERVAL = 10000; // Enviar ping cada 10 segundos

  // Iniciar heartbeat después de que el usuario se registre
  const startHeartbeat = () => {
    heartbeatInterval = setInterval(() => {
      socket.emit('heartbeat:ping');
    }, HEARTBEAT_INTERVAL);
  };

  // Respuesta del cliente al ping (solo para monitoreo)
  socket.on('heartbeat:pong', () => {
    logger.debug(`Heartbeat recibido de ${socket.id}`);
  });

  // ✅ Verificar disponibilidad de username
  socket.on("username:check", ({ username }) => {
    const normalizedUsername = username.toLowerCase().trim();
    const isAvailable = !Array.from(usedUsernames).some(
      name => name.toLowerCase() === normalizedUsername
    );

    if (!isAvailable) {
      socket.emit("username:check-result", { 
        available: false, 
        message: "Este nombre de usuario ya está en uso. Por favor, elige otro." 
      });
    } else {
      socket.emit("username:check-result", { available: true });
    }
  });

  // ✅ Usuario se registra
  socket.on("user:join", (userData) => {
    logger.debug(`user:join: ${userData.username} (${socket.id})`);
    
    // Verificar si está baneado
    if (isBanned(userData.id, clientIp)) {
      const ipHashShort = ipHash?.substring(0, 16) + "...";
      logger.ban(`Usuario baneado intentó conectarse: ${userData.username} - IP Hash: ${ipHashShort}`);
      socket.emit("banned", { reason: "Tu usuario o IP ha sido baneado del servidor." });
      socket.disconnect(true);
      return;
    }

    let finalUserData;
    let isNewUser = false;

    // 🔐 NUEVO: Si el usuario viene con ID de Discord (no es guest-XXXX), usar directamente
    const isDiscordUser = userData.id && !userData.id.startsWith('guest-') && !userData.username.startsWith('Invitado');
    
    if (isDiscordUser) {
      // Usuario de Discord - usar sus datos directamente, no buscar por IP
      logger.user(`🔐 Usuario Discord conectando: ${userData.username} (ID: ${userData.id})`);
      
      const isAdmin = isAdminIP(clientIp);
      const userRole = isAdmin ? 'admin' : 'user';

      finalUserData = {
        ...userData,
        role: userRole,
        socketId: socket.id,
        ip: clientIp,
        ipHash,
        online: true,
        connectedAt: new Date().toISOString()
      };

      // No registrar por IP, registrar por ID de Discord
      logger.user(`Usuario Discord: ${userData.username} - ${userRole}`);
    } else {
      // Usuario invitado - usar sistema de IP como antes
      const existingUser = getUserByIP(ipHash);

      if (existingUser) {
        finalUserData = {
          id: existingUser.id,
          username: existingUser.username,
          avatar: existingUser.avatar,
          role: existingUser.role,
          socketId: socket.id,
          ip: clientIp,
          ipHash,
          online: true,
          connectedAt: new Date().toISOString()
        };
        logger.user(`Usuario invitado reconectado: ${existingUser.username}`);
      } else {
      // Usuario nuevo - verificar que el username no esté en uso
      const normalizedUsername = userData.username.toLowerCase().trim();
      const alreadyExists = Array.from(usedUsernames).some(
        name => name.toLowerCase() === normalizedUsername
      );

      if (alreadyExists) {
        logger.warning(`Username duplicado: ${userData.username}`);
        socket.emit("username:taken", { 
          message: "Este nombre de usuario ya está en uso." 
        });
        socket.disconnect(true);
        return;
      }

      const isAdmin = isAdminIP(clientIp);
      const userRole = isAdmin ? 'admin' : 'user';

      finalUserData = {
        ...userData,
        role: userRole,
        socketId: socket.id,
        ip: clientIp,
        ipHash,
        online: true,
        connectedAt: new Date().toISOString()
      };

        isNewUser = true;
        logger.user(`Nuevo usuario invitado: ${userData.username} - ${userRole}`);
      }
    }

    usedUsernames.add(finalUserData.username);
    connectedUsers.set(socket.id, finalUserData);
    
    // Solo registrar por IP si es usuario invitado (no Discord)
    if (!isDiscordUser) {
      registerUser(ipHash, {
        id: finalUserData.id,
        username: finalUserData.username,
        avatar: finalUserData.avatar,
        role: finalUserData.role
      });
    }

    startHeartbeat();

    if (finalUserData.role === 'admin') {
      socket.emit("role:updated", { role: 'admin' });
      logger.admin(`Admin conectado: ${finalUserData.username}`);
    }

    socket.emit("user:registered", finalUserData);

    const allUsers = getAllUsers();
    socket.emit("users:list", allUsers);

    io.emit("user:online", { 
      userId: finalUserData.id, 
      username: finalUserData.username,
      avatar: finalUserData.avatar,
      role: finalUserData.role
    });

    io.emit("users:update", allUsers);
  });

  // ✅ Solicitud de lista de usuarios (incluye online + offline)
  socket.on("users:request", () => {
    const allUsers = getAllUsers();
    socket.emit("users:list", allUsers);
    logger.debug(`Lista completa de usuarios enviada: ${allUsers.length} usuarios (${connectedUsers.size} online)`);
  });

  // User joins channel
  socket.on("channel:join", ({ channelId, userId }) => {
    const channel = channelId || 'general';
    socket.join(channel);
    
    // Envía el historial solo a este usuario
    socket.emit("channel:history", {
      channelId: channel,
      messages: CHANNELS[channel] || []
    });
    
    logger.debug(`Usuario ${userId} se unió al canal ${channel}`);
  });

  // Recibe nuevo mensaje desde el frontend
  socket.on("message:send", async (msgData) => {
    // ✅ Verificar rate limit
    if (!checkRateLimit(socket.id, 'message')) {
      socket.emit('rate-limit-exceeded', { 
        message: 'Estás enviando mensajes demasiado rápido. Por favor, espera unos segundos.' 
      });
      logger.warning(`Rate limit excedido: ${msgData.username}`);
      return;
    }

    const channelId = msgData.channelId || 'general';
    
    // Validar contenido del mensaje
    if (!msgData.content || msgData.content.trim().length === 0) {
      return;
    }
    
    // Limitar longitud del mensaje
    if (msgData.content.length > 2000) {
      socket.emit('message-error', { 
        message: 'El mensaje es demasiado largo (máximo 2000 caracteres).' 
      });
      return;
    }
    
    // Asigna un id si no viene
    msgData.id = Date.now().toString() + Math.random().toString(36).substring(2, 5);
    
    // Guarda en historial en memoria
    if (!CHANNELS[channelId]) CHANNELS[channelId] = [];
    CHANNELS[channelId].push(msgData);

    // Envía a todos los DEL canal ese mensaje
    io.to(channelId).emit("message:received", msgData);
    logger.message(`${channelId}/${msgData.username}: ${msgData.content.substring(0, 50)}${msgData.content.length > 50 ? '...' : ''}`);

    // 🤖 BOT: Responder cuando se menciona @upg (API gratuita de Hugging Face)
    if (msgData.content.toLowerCase().includes('@upg') || msgData.content.toLowerCase().includes('@upgbot')) {
      try {
        // Extraer la pregunta (remover la mención)
        const question = msgData.content
          .replace(/@upg/gi, '')
          .replace(/@upgbot/gi, '')
          .trim();

        if (question.length > 0) {
          // Generar respuesta agresiva directamente (más confiable que API externa)
          let botResponse = '';
          
          // Respuestas basadas en palabras clave (con y sin acentos)
          const lowerQuestion = question.toLowerCase();
          
          // Saludos
          if (lowerQuestion.match(/\b(hola|hey|buenas|ey|wenas|sup|saludos|hi|hello|que tal|que pasa|que hay)\b/)) {
            const greetings = [
              '¿Qué coño quieres, tío? 🙄',
              'Buenas mis cojones, gilipollas. ¿Qué pasa?',
              'Hola, retrasado. ¿En qué mierda te ayudo ahora?',
              '¿Hola? Menuda originalidad, pringao.',
              'Eh, ¿qué quieres, maricón? Suelta ya.',
              'Venga, habla de una vez, capullo. No tengo todo el día.',
              '¿Saludos? Qué educado el subnormal... ¿Qué coño quieres?'
            ];
            botResponse = greetings[Math.floor(Math.random() * greetings.length)];
          
          // Cómo estás / Qué tal
          } else if (lowerQuestion.match(/\b(como|como estas|que tal|como andas|como va|como te va|como te encuentras|como lo llevas)\b/)) {
            const howResponses = [
              'Fatal, gracias por preguntar, capullo. 😤',
              'Como el puto culo, ¿y tú qué tal, subnormal?',
              'De puta madre hasta que llegaste tú, maricón.',
              'Mejor que tú seguro, gilipollas. Joder...',
              'Mal, gracias a retrasados como tú. 😒',
              'Genial hasta que me empezaste a tocar los cojones.',
              'Harto de responder gilipolleces, la verdad.'
            ];
            botResponse = howResponses[Math.floor(Math.random() * howResponses.length)];
          
          // Ayuda
          } else if (lowerQuestion.match(/\b(ayuda|help|ayudame|ayudar|socorro|auxilio|necesito ayuda)\b/)) {
            const helpResponses = [
              '¿Ayuda? Ayúdate tú solo, retrasado. Google existe. 🤦',
              'Joder, ¿en serio necesitas ayuda para eso? Qué inútil...',
              'Ayuda dice... Menudo pringao. Búscalo en Google, tío.',
              'No pienso ayudarte una mierda, capullo. Siguiente.',
              '¿Ayuda con qué, gilipollas? Sé más específico.',
              'Búscate la vida, maricón. Yo no estoy para esto.',
              'Ayuda mis cojones. Apáñatelas tú solo, subnormal.'
            ];
            botResponse = helpResponses[Math.floor(Math.random() * helpResponses.length)];
          
          // Gracias
          } else if (lowerQuestion.match(/\b(gracias|thanks|thank you|thx|grax|graciass)\b/)) {
            const thanksResponses = [
              'De nada, gilipollas. Ahora lárgate. 👋',
              'Ya, ya... Lo que tú digas, pringao.',
              'Gracias mis cojones. Venga, fuera.',
              'Sí, sí... Lo que sea, maricón.',
              'Vale, vale. Ahora déjame en paz, retrasado.',
              'De nada, capullo. La próxima cobra, eh.'
            ];
            botResponse = thanksResponses[Math.floor(Math.random() * thanksResponses.length)];
          
          // Quién eres / Qué eres
          } else if (lowerQuestion.match(/\b(quien|quie eres|que eres|eres un bot|eres bot|quien eres tu|presentate)\b/)) {
            const whoResponses = [
              'Soy el puto amo, eso es lo que soy. Y tú un don nadie. 😎',
              '¿Quién soy? Tu peor pesadilla, retrasado. Bot UPG.',
              'El bot más maleducado que vas a conocer, gilipollas.',
              'Soy UPG, el bot que no aguanta subnormales como tú.',
              'Un bot que se cansa de responder mierdas todo el día. Eso soy.',
              '¿Quién soy? El bot que te va a mandar a la mierda, pringao.'
            ];
            botResponse = whoResponses[Math.floor(Math.random() * whoResponses.length)];
          
          // Preguntas (qué, cuál, cuándo, dónde, por qué, etc.)
          } else if (lowerQuestion.match(/\b(que es|que significa|cual|cuando|donde|por que|porque|para que|cuanto|cuantos)\b/)) {
            const questionResponses = [
              '¿Y yo qué coño sé, tío? No soy Wikipedia. 🙄',
              'Ni puta idea, macho. Pregúntale a Google.',
              'Búscalo tú mismo, retrasado. Tengo cosas mejores que hacer.',
              'Joder, ¿en serio me preguntas eso? Usa el cerebro.',
              'Qué pereza me das, tío. Google -> Buscar -> Enter. Fácil.',
              'No tengo ni idea ni me importa, gilipollas.',
              'Me la suda completamente esa pregunta, capullo.'
            ];
            botResponse = questionResponses[Math.floor(Math.random() * questionResponses.length)];
          
          // Insultos o agresiones al bot
          } else if (lowerQuestion.match(/\b(tonto|idiota|estupido|imbecil|gilipollas|puto|mierda|malo|pesado|inutil|basura)\b/)) {
            const insultResponses = [
              '¿A quién llamas tú gilipollas, subnormal? 😤',
              'Cuidadito con lo que dices, pringao. Puedo ser mucho peor.',
              'Tú sí que eres un puto imbécil, maricón.',
              'Mira quién habla, el rey de los retrasados. 🤡',
              '¿Insultos? Venga, sorpréndeme, capullo. He oído cosas peores.',
              'Qué original, otro subnormal insultando. Qué nivel...'
            ];
            botResponse = insultResponses[Math.floor(Math.random() * insultResponses.length)];
          
          // Juegos o entretenimiento
          } else if (lowerQuestion.match(/\b(juego|jugar|juega|partida|game|divertido|aburrido|entretenme)\b/)) {
            const gameResponses = [
              'Juega a hacerte una paja, retrasado. Yo no estoy para juegos. 🎮',
              '¿Juegos? Joder, búscate una vida, pringao.',
              'Vete a jugar con tu madre, gilipollas. Aquí no hay juegos.',
              'El único juego es ver cuánto tardas en largarte, capullo.',
              'No soy tu puto entretenimiento, maricón. Next.'
            ];
            botResponse = gameResponses[Math.floor(Math.random() * gameResponses.length)];
          
          // Bromas o humor
          } else if (lowerQuestion.match(/\b(chiste|broma|gracioso|risa|jaja|jeje|lol|xd|humor)\b/)) {
            const jokeResponses = [
              'El chiste aquí eres tú, subnormal. 😂',
              '¿Chiste? Tu vida es el mejor chiste, pringao.',
              'Jajaja... No. Lárgate, gilipollas.',
              'El único chiste es que pienses que soy gracioso, retrasado.',
              'Tu cara es suficiente comedia, capullo. No necesitas más.'
            ];
            botResponse = jokeResponses[Math.floor(Math.random() * jokeResponses.length)];
          
          } else {
            // Respuesta genérica agresiva
            const genericResponses = [
              '¿Y yo qué coño sé, tío? No soy tu madre. 🙄',
              'Menuda pregunta de mierda, macho. Piensa un poco.',
              'Joder, ¿en serio me preguntas eso? Qué nivel, pringao...',
              'No tengo ni puta idea. Siguiente pregunta, gilipollas.',
              'Búscalo en Google, retrasado. Yo no estoy para tus gilipolleces.',
              'Vaya tontería me acabas de preguntar, capullo. En fin...',
              'Me importa una mierda tu pregunta, la verdad. 💩',
              '¿Eso es todo lo que tienes? Qué decepción, maricón.',
              'Paso de contestar esa gilipollez. Siguiente.',
              'No sé ni por qué me molestas con eso, subnormal.',
              'Uff, qué pereza... No pienso responder eso.',
              'Pregunta mejor o no preguntes, pringao.'
            ];
            botResponse = genericResponses[Math.floor(Math.random() * genericResponses.length)];
          }

          if (botResponse) {
            // Añadir insulto aleatorio ocasionalmente (40% de probabilidad)
            if (Math.random() < 0.4) {
              const insults = [
                ' Gilipollas.',
                ' Retrasado. 🤡',
                ' Maricón.',
                ' Subnormal.',
                ' Menudo pringao.',
                ' Imbécil.',
                ' Pedazo de capullo.',
                ' Hijo de puta.'
              ];
              botResponse += insults[Math.floor(Math.random() * insults.length)];
            }

            // Enviar respuesta del bot
            const botMessage = {
              id: Date.now().toString() + Math.random().toString(36).substring(2, 5),
              channelId: channelId,
              userId: 'bot',
              username: 'UPG',
              avatar: '/upg.png',
              content: botResponse,
              timestamp: new Date().toISOString()
            };

            // Guardar en historial
            CHANNELS[channelId].push(botMessage);

            // Enviar a todos
            setTimeout(() => {
              io.to(channelId).emit("message:received", botMessage);
              logger.message(`${channelId}/UPG Bot: ${botResponse.substring(0, 50)}${botResponse.length > 50 ? '...' : ''}`);
            }, 1000); // Pequeño delay para simular "typing"
          }
        } else {
          // Si no hay pregunta después de @upg
          const noQuestionResponses = [
            '¿Me mencionas y no dices nada? Menudo retrasado... 🤦',
            '¿Qué coño quieres, tío? Habla claro. 😤',
            'Me mencionas para nada, gilipollas. Increíble.',
            '¿Hola? ¿Alguien en casa? Di algo, subnormal.'
          ];
          const noQuestionMessage = {
            id: Date.now().toString() + Math.random().toString(36).substring(2, 5),
            channelId: channelId,
            userId: 'bot',
            username: 'UPG',
            avatar: '/upg.png',
            content: noQuestionResponses[Math.floor(Math.random() * noQuestionResponses.length)],
            timestamp: new Date().toISOString()
          };
          
          CHANNELS[channelId].push(noQuestionMessage);
          setTimeout(() => {
            io.to(channelId).emit("message:received", noQuestionMessage);
          }, 1000);
        }
      } catch (error) {
        logger.error('Error en bot:', error);
        // Enviar respuesta de error agresiva
        const aggressiveErrors = [
          '😤 Uff, me hiciste petar con tu pregunta de mierda, retrasado. Bien hecho.',
          '🤦 Error fatal causado por tu mensaje, gilipollas. ¿Contento ahora?',
          '💢 Mi cerebro acaba de explotar intentando entender tu lógica de subnormal. GG.',
          '😒 Hubo un error, tío. Probablemente culpa tuya por preguntar gilipolleces.',
          '🙄 Sistema caído, joder. Es lo que pasa cuando me molestas con mierdas, capullo.'
        ];
        const errorMessage = {
          id: Date.now().toString() + Math.random().toString(36).substring(2, 5),
          channelId: channelId,
          userId: 'bot',
          username: 'UPG',
          avatar: '/upg.png',
          content: aggressiveErrors[Math.floor(Math.random() * aggressiveErrors.length)],
          timestamp: new Date().toISOString()
        };
        
        CHANNELS[channelId].push(errorMessage);
        setTimeout(() => {
          io.to(channelId).emit("message:received", errorMessage);
        }, 1000);
      }
    }
  });

  // ✅ ADMIN: Eliminar mensaje
  socket.on("admin:delete-message", ({ messageId, channelId, adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    // Verificar que es admin
    if (!admin || admin.role !== 'admin') {
      logger.warning(`Usuario ${admin?.username} intentó eliminar mensaje sin permisos`);
      return;
    }

    // Eliminar mensaje del historial
    if (CHANNELS[channelId]) {
      const index = CHANNELS[channelId].findIndex(msg => msg.id === messageId);
      if (index !== -1) {
        const deletedMsg = CHANNELS[channelId][index];
        CHANNELS[channelId].splice(index, 1);
        
        // Notificar a todos
        io.to(channelId).emit("message:deleted", { messageId, channelId });
        
        // Reenviar historial actualizado
        io.to(channelId).emit("channel:history", {
          channelId,
          messages: CHANNELS[channelId]
        });
        
        logger.admin(`${admin.username} eliminó mensaje de ${deletedMsg.username}`);
      }
    }
  });

  // ✅ ADMIN: Limpiar canal
  socket.on("admin:clear-channel", ({ channelId, adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    // Verificar que es admin
    if (!admin || admin.role !== 'admin') {
      logger.warning(`Usuario ${admin?.username} intentó limpiar canal sin permisos`);
      return;
    }

    // Limpiar canal
    CHANNELS[channelId] = [];
    
    // Notificar a todos
    io.to(channelId).emit("channel:cleared", { channelId });
    io.to(channelId).emit("channel:history", {
      channelId,
      messages: []
    });
    
    logger.admin(`${admin.username} limpió el canal ${channelId}`);
  });

  // ✅ ADMIN: Banear usuario
  socket.on("admin:ban-user", ({ userId, username, adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    // Verificar que es admin
    if (!admin || admin.role !== 'admin') {
      logger.warning(`Usuario ${admin?.username} intentó banear sin permisos`);
      return;
    }

    // Buscar usuario a banear
    let targetSocket = null;
    let targetIp = null;
    
    for (const [socketId, userData] of connectedUsers.entries()) {
      if (userData.id === userId) {
        targetSocket = socketId;
        targetIp = userData.ip;
        break;
      }
    }

    if (targetSocket && targetIp) {
      // Banear usuario y su IP
      banUser(userId, targetIp);
      
      // Desconectar usuario
      const targetSocketObj = io.sockets.sockets.get(targetSocket);
      if (targetSocketObj) {
        targetSocketObj.emit("banned", { 
          reason: `Has sido baneado por el administrador ${admin.username}.` 
        });
        targetSocketObj.disconnect(true);
      }
      
      // Notificar a todos
      io.emit("user:banned", { userId, username });
      
      const targetIpHash = hashIP(targetIp)?.substring(0, 16) + "...";
      logger.ban(`Admin ${admin.username} baneó a ${username} - IP Hash: ${targetIpHash}`);
    }
  });

  // ✅ Voice channel join
  socket.on("voice:join", ({ channelName, userId }) => {
    logger.debug(`Usuario ${userId} se unió a voz: ${channelName}`);
    io.emit("voice:update", { userId, channelName, action: "join" });
  });

  // ✅ Voice channel leave
  socket.on("voice:leave", ({ channelName, userId }) => {
    logger.debug(`Usuario ${userId} salió de voz: ${channelName}`);
    io.emit("voice:update", { userId, channelName, action: "leave" });
  });

  // ✅ ADMIN: Kick/Eliminar usuario (sin ban)
  socket.on("admin:kick-user", ({ userId, username, adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    // Verificar que es admin
    if (!admin || admin.role !== 'admin') {
      logger.warning(`Usuario ${admin?.username} intentó kickear sin permisos`);
      return;
    }

    // Buscar usuario a kickear
    let targetSocket = null;
    
    for (const [socketId, userData] of connectedUsers.entries()) {
      if (userData.id === userId) {
        targetSocket = socketId;
        break;
      }
    }

    if (targetSocket) {
      // Eliminar de usuarios conectados
      connectedUsers.delete(targetSocket);
      usedUsernames.delete(username);
      
      // Desconectar usuario
      const targetSocketObj = io.sockets.sockets.get(targetSocket);
      if (targetSocketObj) {
        targetSocketObj.emit("kicked", { 
          reason: `Has sido expulsado por el administrador ${admin.username}.` 
        });
        targetSocketObj.disconnect(true);
      }
      
      // Notificar a todos
      io.emit("user:kicked", { userId, username });
      
      logger.admin(`Admin ${admin.username} expulsó a ${username}`);
      
      // Actualizar lista de usuarios
      const allUsers = Array.from(connectedUsers.values());
      io.emit("users:update", allUsers);
    }
  });

  // ✅ ADMIN: Eliminar todos los usuarios registrados
  socket.on("admin:clear-users", ({ adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    if (!admin || admin.role !== 'admin') {
      logger.warning(`Usuario ${admin?.username} intentó limpiar usuarios sin permisos`);
      return;
    }

    const adminIpHash = admin.ipHash;
    
    // Limpiar todos los usuarios excepto el admin
    registeredUsers = {};
    if (adminIpHash && admin) {
      registeredUsers[adminIpHash] = {
        id: admin.id,
        username: admin.username,
        avatar: admin.avatar,
        role: admin.role,
        ipHash: adminIpHash,
        lastSeen: new Date().toISOString(),
        registeredAt: new Date().toISOString()
      };
    }
    saveRegisteredUsers();

    // Desconectar a todos los usuarios excepto el admin
    for (const [socketId, userData] of connectedUsers.entries()) {
      if (userData.role !== 'admin') {
        const targetSocket = io.sockets.sockets.get(socketId);
        if (targetSocket) {
          targetSocket.emit("kicked", { 
            reason: "El administrador ha limpiado la base de usuarios." 
          });
          targetSocket.disconnect(true);
        }
      }
    }

    logger.admin(`${admin.username} eliminó todos los usuarios registrados`);
    socket.emit("admin:action-success", { action: "clear-users", message: "Usuarios eliminados correctamente" });
  });

  // ✅ ADMIN: Limpiar todos los mensajes
  socket.on("admin:clear-all-messages", ({ adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    if (!admin || admin.role !== 'admin') {
      logger.warning(`Usuario ${admin?.username} intentó limpiar mensajes sin permisos`);
      return;
    }

    // Limpiar todos los canales
    for (const channelId in CHANNELS) {
      CHANNELS[channelId] = [];
      io.to(channelId).emit("channel:history", {
        channelId,
        messages: []
      });
    }

    logger.admin(`${admin.username} eliminó todos los mensajes del servidor`);
    io.emit("admin:notification", { message: "Todos los mensajes han sido eliminados por un administrador" });
    socket.emit("admin:action-success", { action: "clear-messages", message: "Mensajes eliminados correctamente" });
  });

  // ✅ ADMIN: Limpiar lista de baneados
  socket.on("admin:clear-banned", ({ adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    if (!admin || admin.role !== 'admin') {
      logger.warning(`Usuario ${admin?.username} intentó limpiar baneos sin permisos`);
      return;
    }

    bannedList = { ips: [], userIds: [] };
    saveBannedList();

    logger.admin(`${admin.username} limpió la lista de baneados`);
    socket.emit("admin:action-success", { action: "clear-banned", message: "Lista de baneos limpiada correctamente" });
  });

  // ✅ ADMIN: Limpiar caché del servidor
  socket.on("admin:clear-cache", ({ adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    if (!admin || admin.role !== 'admin') {
      logger.warning(`Usuario ${admin?.username} intentó limpiar caché sin permisos`);
      return;
    }

    // Limpiar rate limits
    rateLimits.clear();

    logger.admin(`${admin.username} limpió el caché del servidor`);
    socket.emit("admin:action-success", { action: "clear-cache", message: "Caché limpiado correctamente" });
  });

  // ✅ ADMIN: Expulsar todos los usuarios
  socket.on("admin:kick-all-users", ({ adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    if (!admin || admin.role !== 'admin') {
      logger.warning(`Usuario ${admin?.username} intentó expulsar usuarios sin permisos`);
      return;
    }

    let kickedCount = 0;
    for (const [socketId, userData] of connectedUsers.entries()) {
      if (userData.role !== 'admin' && socketId !== socket.id) {
        const targetSocket = io.sockets.sockets.get(socketId);
        if (targetSocket) {
          targetSocket.emit("kicked", { 
            reason: `Has sido expulsado por el administrador ${admin.username}.` 
          });
          targetSocket.disconnect(true);
          kickedCount++;
        }
      }
    }

    logger.admin(`${admin.username} expulsó a ${kickedCount} usuarios`);
    socket.emit("admin:action-success", { 
      action: "kick-all", 
      message: `${kickedCount} usuarios expulsados correctamente` 
    });
  });

  // ✅ ADMIN: Exportar datos del servidor
  socket.on("admin:export-data", ({ adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    if (!admin || admin.role !== 'admin') {
      logger.warning(`Usuario ${admin?.username} intentó exportar datos sin permisos`);
      return;
    }

    const exportData = {
      timestamp: new Date().toISOString(),
      users: registeredUsers,
      bannedList: bannedList,
      channels: Object.keys(CHANNELS).map(channelId => ({
        id: channelId,
        messageCount: CHANNELS[channelId].length
      })),
      connectedUsers: connectedUsers.size,
      totalUsers: Object.keys(registeredUsers).length
    };

    logger.admin(`${admin.username} exportó los datos del servidor`);
    socket.emit("admin:export-data-result", { data: exportData });
  });

  // ✅ ADMIN: Reiniciar servidor Socket.IO
  socket.on("admin:restart-server", ({ adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    if (!admin || admin.role !== 'admin') {
      logger.warning(`Usuario ${admin?.username} intentó reiniciar servidor sin permisos`);
      return;
    }

    logger.admin(`${admin.username} está reiniciando el servidor Socket.IO`);
    
    // Notificar a todos
    io.emit("server:restarting", { 
      message: "El servidor se está reiniciando. Serás reconectado en breve." 
    });

    // Desconectar a todos después de 2 segundos
    setTimeout(() => {
      io.disconnectSockets();
      logger.server("Todas las conexiones cerradas para reinicio");
    }, 2000);

    socket.emit("admin:action-success", { 
      action: "restart-server", 
      message: "Servidor reiniciando..." 
    });
  });

  // ✅ Desconexión
  socket.on("disconnect", () => {
    // Limpiar heartbeat interval
    if (heartbeatInterval) {
      clearInterval(heartbeatInterval);
    }

    const user = connectedUsers.get(socket.id);
    
    if (user) {
      logger.user(`Desconectado: ${user.username} (${socket.id})`);
      
      // 🔐 Detectar si es usuario Discord o invitado
      const isDiscordUser = user.id && !user.id.startsWith('guest-') && !user.username.startsWith('Invitado');
      
      if (isDiscordUser) {
        // Usuario Discord - mantener en lista como offline
        logger.user(`👤 Usuario Discord desconectado (se mantiene como offline): ${user.username}`);
        
        // Actualizar lastSeen del usuario registrado
        if (user.ipHash) {
          const registeredUser = registeredUsers[user.ipHash];
          if (registeredUser) {
            registeredUser.lastSeen = new Date().toISOString();
            saveRegisteredUsers();
          }
        }
        
        // Eliminar de usuarios conectados
        connectedUsers.delete(socket.id);

        // Liberar username
        usedUsernames.delete(user.username);

        // Notificar que está offline (se mantiene en lista)
        io.emit("user:offline", { 
          userId: user.id, 
          username: user.username 
        });
      } else {
        // Usuario invitado - eliminar completamente
        logger.user(`👥 Usuario invitado desconectado (eliminado): ${user.username}`);
        
        // Eliminar de usuarios conectados
        connectedUsers.delete(socket.id);

        // Liberar username
        usedUsernames.delete(user.username);
        
        // Eliminar de usuarios registrados por IP
        if (user.ipHash && registeredUsers[user.ipHash]) {
          delete registeredUsers[user.ipHash];
          saveRegisteredUsers();
        }

        // Notificar eliminación completa (no aparecerá en offline)
        io.emit("user:removed", { 
          userId: user.id, 
          username: user.username 
        });
      }

      // Enviar lista actualizada con todos los usuarios (online + offline)
      const allUsers = getAllUsers();
      io.emit("users:update", allUsers);
      
      logger.debug(`Usuario offline, total usuarios registrados: ${Object.keys(registeredUsers).length}`);
    } else {
      logger.debug(`Usuario desconectado (no registrado): ${socket.id}`);
    }
  });
});

// ✅ Global Error Handler for OAuth2 (Best Practice)
app.use((err, req, res, next) => {
  // Map of OAuth2 error codes to user-friendly messages
  const errorMessages = {
    'invalid_request': 'La solicitud de autorización no es válida',
    'unauthorized_client': 'El cliente no está autorizado',
    'access_denied': 'Acceso denegado por el usuario',
    'unsupported_response_type': 'Tipo de respuesta no soportado',
    'invalid_scope': 'Alcance no válido',
    'server_error': 'Error del servidor',
    'temporarily_unavailable': 'Servicio temporalmente no disponible',
  };

  const statusCode = err.statusCode || 500;
  const errorCode = err.message || 'server_error';
  const description = err.description || errorMessages[errorCode] || 'Error desconocido';

  logger.error(`OAuth Error [${errorCode}]: ${description}`);

  // Redirect to frontend with error for OAuth errors
  if (req.path.startsWith('/auth/')) {
    const frontendUrl = process.env.FRONTEND_URL || 'https://unaspartidillas.online';
    return res.redirect(`${frontendUrl}/?auth=error&error_code=${errorCode}&error_description=${encodeURIComponent(description)}`);
  }

  // JSON response for API errors
  res.status(statusCode).json({
    error: errorCode,
    error_description: description
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.server(`Servidor corriendo en puerto ${PORT}`);
  logger.socket(`Socket.IO escuchando en puerto ${PORT}`);
  logger.security(`Sistema de baneos activado`);
  logger.security(`Rate limiting activado (5 msg/10s)`);
  logger.info(`Heartbeat system ready`);
  logger.security(`OAuth2 with CSRF protection (state parameter) enabled`);
});
