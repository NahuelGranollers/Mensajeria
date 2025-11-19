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

io.on("connection", (socket) => {
  console.log("Usuario conectado");

  // User joins channel
  socket.on("channel:join", ({ channelId, userId }) => {
    socket.join(channelId || 'general');
    // Envía el historial solo a este usuario
    socket.emit("channel:history", {
      channelId: channelId || 'general',
      messages: CHANNELS[channelId || 'general'] || []
    });
    console.log(`Usuario ${userId} se unió al canal ${channelId || 'general'}`);
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
    console.log(`Mensaje en ${channelId}:`, msgData.content);
  });

  socket.on("disconnect", () => {
    console.log("Usuario desconectado");
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
