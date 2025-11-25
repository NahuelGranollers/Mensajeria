# UPG Backend Server

Backend server para UPG Community Hub con Socket.IO y Discord OAuth2.

## 📁 Estructura del Servidor

```
server/
├── index.js              # Archivo principal del servidor
├── db.js                 # Gestión de base de datos (SQLite/PostgreSQL)
├── package.json          # Dependencias del proyecto
├── .env.example          # Plantilla de variables de entorno
├── .gitignore            # Archivos a ignorar en git
├── README.md             # Este archivo
├── admin-secret.json     # Contraseña hasheada del admin (generada automáticamente)
├── database.sqlite       # Base de datos SQLite (desarrollo)
├── database.sqlite-shm   # Shared memory (SQLite)
└── database.sqlite-wal   # Write-ahead log (SQLite)
```

**Nota:** Los archivos `.env`, `database.sqlite*`, `admin-secret.json`, `users.json` y `banned.json` se generan automáticamente y NO deben incluirse en el control de versiones.

## 🚀 Deployment en Render

### 1. Configuración Inicial

1. Conecta este repositorio a Render
2. Selecciona "Web Service"
3. Configuración:
   - **Root Directory**: `server`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Environment**: Node
   - **Node Version**: 18.x o superior

**Importante:** Render debe apuntar a la carpeta `/server` del repositorio, donde están todos los archivos del backend.

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
```

### Configurar Variables de Entorno

1. Copia el archivo de ejemplo:
```bash
cp .env.example .env
```

2. Edita `.env` con tus valores reales:
```env
DISCORD_CLIENT_ID=tu_client_id
DISCORD_CLIENT_SECRET=tu_client_secret
DISCORD_REDIRECT_URI=http://localhost:3000/auth/callback
FRONTEND_URL=http://localhost:5173
SESSION_SECRET=tu_clave_secreta_aqui
NODE_ENV=development
PORT=3000
GEMINI_API_KEY=tu_api_key_de_gemini
```

3. Verifica que todo esté configurado:
```bash
npm run check
```

4. Inicia el servidor:
```bash
npm start
```

Para desarrollo con auto-reload:
```bash
npm run dev
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
