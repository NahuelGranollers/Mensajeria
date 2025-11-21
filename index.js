const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const axios = require("axios");
const session = require("express-session");
const cookieParser = require("cookie-parser");
require("dotenv").config({ path: ".env.server" });

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
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-super-secret-key-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // true en producción (HTTPS)
    httpOnly: true,
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 días
  }
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

// Ruta 1: Iniciar OAuth - Redirige al usuario a Discord
app.get("/auth/discord", (req, res) => {
  const redirectUri = process.env.DISCORD_REDIRECT_URI;
  const clientId = process.env.DISCORD_CLIENT_ID;
  const scope = "identify rpc.voice.read";
  
  const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent(scope)}`;
  
  logger.info(`🔐 Redirecting to Discord OAuth: ${discordAuthUrl}`);
  res.redirect(discordAuthUrl);
});

// Ruta 2: Callback de Discord - Intercambia el code por el token
app.get("/auth/callback", async (req, res) => {
  const { code } = req.query;
  
  if (!code) {
    logger.error("❌ No authorization code received from Discord");
    return res.status(400).send("Authorization failed: No code provided");
  }

  try {
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

    const { access_token } = tokenResponse.data;
    logger.success("✅ Access token obtained successfully");

    // Obtener información del usuario de Discord
    const userResponse = await axios.get("https://discord.com/api/users/@me", {
      headers: {
        Authorization: `Bearer ${access_token}`,
      },
    });

    const discordUser = userResponse.data;
    logger.user(`👤 Discord user authenticated: ${discordUser.username}#${discordUser.discriminator} (ID: ${discordUser.id})`);

    // Guardar usuario en sesión
    req.session.discordUser = {
      id: discordUser.id,
      username: discordUser.username,
      discriminator: discordUser.discriminator,
      avatar: discordUser.avatar,
      accessToken: access_token,
    };

    // Redirigir al frontend con éxito
    res.redirect(`/?auth=success`);
  } catch (error) {
    logger.error("❌ Discord OAuth error:", error.response?.data || error.message);
    res.status(500).send("Authentication failed");
  }
});

// Ruta 3: Obtener usuario autenticado
app.get("/auth/user", (req, res) => {
  if (!req.session.discordUser) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  res.json(req.session.discordUser);
});

// Ruta 4: Logout
app.post("/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      logger.error("❌ Error destroying session:", err);
      return res.status(500).json({ error: "Logout failed" });
    }
    
    res.clearCookie("connect.sid");
    logger.info("👋 User logged out successfully");
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
    // Verificar si está baneado
    if (isBanned(userData.id, clientIp)) {
      const ipHashShort = ipHash?.substring(0, 16) + "...";
      logger.ban(`Usuario baneado intentó conectarse: ${userData.username} - IP Hash: ${ipHashShort}`);
      socket.emit("banned", { reason: "Tu usuario o IP ha sido baneado del servidor." });
      socket.disconnect(true);
      return;
    }

    // ✅ Verificar si este IP ya tiene usuario registrado
    const existingUser = getUserByIP(ipHash);
    
    let finalUserData;
    let isNewUser = false;

    if (existingUser) {
      // Usuario existente - recuperar datos guardados (nombre y avatar)
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
      
      logger.user(`Usuario existente reconectado: ${existingUser.username} (${socket.id})`);
    } else {
      // Usuario nuevo - verificar que el username no esté en uso
      const normalizedUsername = userData.username.toLowerCase().trim();
      const alreadyExists = Array.from(usedUsernames).some(
        name => name.toLowerCase() === normalizedUsername
      );

      if (alreadyExists) {
        logger.warning(`Intento de registro con username duplicado: ${userData.username}`);
        socket.emit("username:taken", { 
          message: "Este nombre de usuario ya está en uso." 
        });
        socket.disconnect(true);
        return;
      }

      // Detectar si es admin por IP
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
      logger.user(`Usuario nuevo registrado: ${userData.username} (${socket.id}) - Rol: ${userRole}`);
    }

    // Agregar username al set de usados
    usedUsernames.add(finalUserData.username);

    // Guardar en connectedUsers
    connectedUsers.set(socket.id, finalUserData);

    // Guardar permanentemente en users.json
    registerUser(ipHash, {
      id: finalUserData.id,
      username: finalUserData.username,
      avatar: finalUserData.avatar,
      role: finalUserData.role
    });

    // Iniciar heartbeat para este usuario
    startHeartbeat();

    // Enviar rol actualizado al usuario si es admin
    if (finalUserData.role === 'admin') {
      socket.emit("role:updated", { role: 'admin' });
      logger.admin(`ADMIN DETECTADO - ${finalUserData.username}`);
    }

    // Enviar confirmación al usuario con sus datos finales
    socket.emit("user:registered", finalUserData);

    // Enviar lista completa de TODOS los usuarios (online + offline)
    const allUsers = getAllUsers();
    socket.emit("users:list", allUsers);

    // Notificar a todos que este usuario se conectó
    io.emit("user:online", { 
      userId: finalUserData.id, 
      username: finalUserData.username,
      avatar: finalUserData.avatar,
      role: finalUserData.role
    });

    // Enviar lista actualizada a todos
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
  socket.on("message:send", (msgData) => {
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

      // Liberar username (ya no es necesario mantenerlo bloqueado)
      usedUsernames.delete(user.username);

      // Notificar a todos que el usuario se desconectó (pero sigue existiendo offline)
      io.emit("user:offline", { 
        userId: user.id, 
        username: user.username 
      });

      // Enviar lista actualizada con todos los usuarios (online + offline)
      const allUsers = getAllUsers();
      io.emit("users:update", allUsers);
      
      logger.debug(`Usuario offline, total usuarios registrados: ${Object.keys(registeredUsers).length}`);
    } else {
      logger.debug(`Usuario desconectado (no registrado): ${socket.id}`);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.server(`Servidor corriendo en puerto ${PORT}`);
  logger.socket(`Socket.IO escuchando en puerto ${PORT}`);
  logger.security(`Sistema de baneos activado`);
  logger.security(`Rate limiting activado (5 msg/10s)`);
  logger.info(`Heartbeat system ready`);
});
