const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const fs = require("fs");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: [
      "https://unaspartidillasgang.online",
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
    console.error('Error cargando lista de baneados:', error);
  }
}

// Guardar lista de baneados
function saveBannedList() {
  try {
    fs.writeFileSync(BANNED_FILE, JSON.stringify(bannedList, null, 2));
  } catch (error) {
    console.error('Error guardando lista de baneados:', error);
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

// Cargar baneos al iniciar
loadBannedList();

io.on("connection", (socket) => {
  const clientIp = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
  console.log("🔌 Usuario conectado:", socket.id, "IP:", clientIp);

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
      console.log(`⛔ Usuario baneado intentó conectarse: ${userData.username} (${clientIp})`);
      socket.emit("banned", { reason: "Tu usuario o IP ha sido baneado del servidor." });
      socket.disconnect(true);
      return;
    }

    // Verificar nuevamente que el username no esté en uso (por si acaso)
    const normalizedUsername = userData.username.toLowerCase().trim();
    const alreadyExists = Array.from(usedUsernames).some(
      name => name.toLowerCase() === normalizedUsername
    );

    if (alreadyExists) {
      console.log(`⚠️ Intento de registro con username duplicado: ${userData.username}`);
      socket.emit("username:taken", { 
        message: "Este nombre de usuario ya está en uso." 
      });
      socket.disconnect(true);
      return;
    }

    // Agregar username al set de usados
    usedUsernames.add(userData.username);

    // Guardar usuario con su socketId e IP
    connectedUsers.set(socket.id, {
      ...userData,
      socketId: socket.id,
      ip: clientIp,
      connectedAt: new Date().toISOString()
    });

    console.log(`👤 Usuario registrado: ${userData.username} (${socket.id})`);

    // Enviar usuario nuevo a todos
    io.emit("user:joined", userData);

    // Enviar lista completa de usuarios al nuevo usuario
    const usersList = Array.from(connectedUsers.values());
    socket.emit("users:list", usersList);

    // Enviar lista actualizada a todos
    io.emit("users:update", usersList);
  });

  // ✅ Solicitud de lista de usuarios
  socket.on("users:request", () => {
    const usersList = Array.from(connectedUsers.values());
    socket.emit("users:list", usersList);
    console.log(`📋 Lista de usuarios enviada: ${usersList.length} usuarios`);
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
    
    console.log(`📢 Usuario ${userId} se unió al canal ${channel}`);
  });

  // Recibe nuevo mensaje desde el frontend
  socket.on("message:send", (msgData) => {
    const channelId = msgData.channelId || 'general';
    
    // Asigna un id si no viene
    msgData.id = Date.now().toString() + Math.random().toString(36).substring(2, 5);
    
    // Guarda en historial en memoria
    if (!CHANNELS[channelId]) CHANNELS[channelId] = [];
    CHANNELS[channelId].push(msgData);

    // Envía a todos los DEL canal ese mensaje
    io.to(channelId).emit("message:received", msgData);
    console.log(`💬 Mensaje en ${channelId} de ${msgData.username}:`, msgData.content);
  });

  // ✅ ADMIN: Eliminar mensaje
  socket.on("admin:delete-message", ({ messageId, channelId, adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    // Verificar que es admin
    if (!admin || admin.role !== 'admin') {
      console.log(`⚠️ Usuario ${admin?.username} intentó eliminar mensaje sin permisos`);
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
        
        console.log(`🗑️ Admin ${admin.username} eliminó mensaje de ${deletedMsg.username}`);
      }
    }
  });

  // ✅ ADMIN: Limpiar canal
  socket.on("admin:clear-channel", ({ channelId, adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    // Verificar que es admin
    if (!admin || admin.role !== 'admin') {
      console.log(`⚠️ Usuario ${admin?.username} intentó limpiar canal sin permisos`);
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
    
    console.log(`🧹 Admin ${admin.username} limpió el canal ${channelId}`);
  });

  // ✅ ADMIN: Banear usuario
  socket.on("admin:ban-user", ({ userId, username, adminId }) => {
    const admin = connectedUsers.get(socket.id);
    
    // Verificar que es admin
    if (!admin || admin.role !== 'admin') {
      console.log(`⚠️ Usuario ${admin?.username} intentó banear sin permisos`);
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
      
      console.log(`🔨 Admin ${admin.username} baneó a ${username} (IP: ${targetIp})`);
    }
  });

  // ✅ Voice channel join
  socket.on("voice:join", ({ channelName, userId }) => {
    console.log(`🎤 Usuario ${userId} se unió a voz: ${channelName}`);
    io.emit("voice:update", { userId, channelName, action: "join" });
  });

  // ✅ Voice channel leave
  socket.on("voice:leave", ({ channelName, userId }) => {
    console.log(`🔇 Usuario ${userId} salió de voz: ${channelName}`);
    io.emit("voice:update", { userId, channelName, action: "leave" });
  });

  // ✅ Desconexión
  socket.on("disconnect", () => {
    const user = connectedUsers.get(socket.id);
    
    if (user) {
      console.log(`⛔ Usuario desconectado: ${user.username} (${socket.id})`);
      
      // Eliminar usuario
      connectedUsers.delete(socket.id);

      // Liberar username
      usedUsernames.delete(user.username);

      // Notificar a todos
      io.emit("user:left", { 
        userId: user.id, 
        username: user.username 
      });

      // Enviar lista actualizada
      const usersList = Array.from(connectedUsers.values());
      io.emit("users:update", usersList);
      
      console.log(`👥 Usuarios restantes: ${usersList.length}`);
    } else {
      console.log("⛔ Usuario desconectado (no registrado):", socket.id);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`📡 Socket.IO escuchando en puerto ${PORT}`);
  console.log(`🛡️ Sistema de baneos activado`);
});
