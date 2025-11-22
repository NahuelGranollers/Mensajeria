# UPG Backend Server

Backend server para UPG Community Hub con Socket.IO y Discord OAuth2.

## 🚀 Deployment en Render

### 1. Configuración Inicial

1. Conecta este repositorio a Render
2. Selecciona "Web Service"
3. Configuración:
   - **Root Directory**: `server`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Environment**: Node

### 2. Variables de Entorno en Render

Configura estas variables en el dashboard de Render:

```
DISCORD_CLIENT_ID=1432386430855938189
DISCORD_CLIENT_SECRET=uPLiqGZfG898lDrt1vTqtovni2iEv_Hq
DISCORD_REDIRECT_URI=https://mensajeria-ksc7.onrender.com/auth/callback
FRONTEND_URL=https://unaspartidillas.online
SESSION_SECRET=upg_secret_key_change_in_production_2025
NODE_ENV=production
PORT=3000
```

### 3. Discord Developer Portal

Asegúrate de que el redirect URI esté configurado en Discord:

1. Ve a: https://discord.com/developers/applications
2. Selecciona tu aplicación (ID: 1432386430855938189)
3. OAuth2 → Redirects
4. Añade: `https://mensajeria-ksc7.onrender.com/auth/callback`
5. Scope: `identify`

## 📦 Instalación Local

```bash
cd server
npm install
npm start
```

Para desarrollo local, modifica `.env`:

```
DISCORD_REDIRECT_URI=http://localhost:3000/auth/callback
FRONTEND_URL=http://localhost:5173
NODE_ENV=development
```

## 🔒 Seguridad

- ✅ Variables sensibles en `.env` (nunca commitear)
- ✅ CSRF protection con state parameter
- ✅ Session con httpOnly cookies
- ✅ CORS configurado para dominios específicos
- ✅ Rate limiting en mensajes
- ✅ IP-based admin detection

## 🛠️ Características

- **Socket.IO**: Chat en tiempo real
- **Discord OAuth2**: Autenticación segura
- **Express Sessions**: Gestión de sesiones
- **Rate Limiting**: Prevención de spam
- **Admin System**: Panel de administración
- **Persistent Storage**: users.json y banned.json

## 📡 Endpoints

### OAuth Routes

- `GET /auth/discord` - Inicia OAuth
- `GET /auth/callback` - Callback de Discord
- `GET /auth/user` - Obtener usuario actual
- `POST /auth/logout` - Cerrar sesión
- `GET /auth/debug` - Debug de configuración (eliminar en prod)

### Socket.IO Events

Ver `index.js` para lista completa de eventos Socket.IO

## 🔄 Updates

Para actualizar el servidor en Render:

1. Haz commit de tus cambios
2. Push a GitHub
3. Render detectará los cambios automáticamente
4. Reiniciará el servidor

## 📊 Logs

El servidor usa un sistema de logs con colores:

- 🚀 Server events
- 🔌 Socket connections
- 👤 User actions
- 💬 Messages
- 👑 Admin actions
- 🔨 Bans
- 🛡️ Security events

## 🆘 Troubleshooting

### Error: State parameter mismatch

- Verifica que las cookies funcionen en HTTPS
- Comprueba `sameSite: 'none'` y `secure: true`

### Error: Cannot find module

- Ejecuta `npm install` en la carpeta server

### Usuario no persiste después de login

- Revisa los logs de Render
- Verifica que SESSION_SECRET esté configurado
- Comprueba que las cookies se estén enviando

## 📝 Notas

- Los usuarios se guardan en `users.json`
- Los baneados se guardan en `banned.json`
- Estos archivos se crean automáticamente
- No se incluyen en el repositorio (ver .gitignore)
