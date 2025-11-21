const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, 'database.sqlite');
const db = new Database(dbPath);

// Obtener lista de tablas
const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all();

console.log('\nTABLAS CREADAS:');
tables.forEach((table) => {
    console.log(`- ${table.name}`);
});

console.log(`\nTOTAL: ${tables.length} tablas`);

// Verificar tabla users
console.log('\n=== TABLA USERS ===');
const usersInfo = db.prepare(`PRAGMA table_info(users)`).all();
usersInfo.forEach(col => {
    console.log(`  ${col.name} (${col.type})`);
});

// Verificar tabla messages
console.log('\n=== TABLA MESSAGES ===');
const messagesInfo = db.prepare(`PRAGMA table_info(messages)`).all();
messagesInfo.forEach(col => {
    console.log(`  ${col.name} (${col.type})`);
});

db.close();
console.log('\n✅ Verificación completa!');
