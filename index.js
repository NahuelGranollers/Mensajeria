const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

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

io.on("connection", (socket) => {
  console.log("🔌 Usuario conectado:", socket.id);

  // ✅ Usuario se registra
  socket.on("user:join", (userData) => {
    // Guardar usuario con su socketId
    connectedUsers.set(socket.id, {
      ...userData,
      socketId: socket.id,
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
});