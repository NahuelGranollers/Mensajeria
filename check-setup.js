#!/usr/bin/env node

/**
 * Script de verificación de dependencias del servidor
 * Verifica que todas las dependencias necesarias estén instaladas
 */

const fs = require('fs');
const path = require('path');

console.log('🔍 Verificando dependencias del servidor...\n');

// Verificar que estamos en la carpeta correcta
const packageJsonPath = path.join(__dirname, 'package.json');
if (!fs.existsSync(packageJsonPath)) {
  console.error('❌ Error: No se encontró package.json');
  console.error('   Asegúrate de ejecutar este script desde la carpeta /server');
  process.exit(1);
}

// Verificar node_modules
const nodeModulesPath = path.join(__dirname, 'node_modules');
if (!fs.existsSync(nodeModulesPath)) {
  console.error('❌ Error: No se encontró la carpeta node_modules');
  console.error('   Ejecuta: npm install');
  process.exit(1);
}

// Lista de dependencias críticas
const criticalDeps = [
  'express',
  'socket.io',
  'dotenv',
  'better-sqlite3',
  'winston',
  'xss'
];

let allInstalled = true;

criticalDeps.forEach(dep => {
  const depPath = path.join(nodeModulesPath, dep);
  if (fs.existsSync(depPath)) {
    console.log(`✅ ${dep}`);
  } else {
    console.log(`❌ ${dep} - NO INSTALADO`);
    allInstalled = false;
  }
});

// Verificar archivos de configuración
console.log('\n🔍 Verificando archivos de configuración...\n');

const configFiles = [
  { file: '.env', required: false, message: 'Archivo de variables de entorno (copia .env.example)' },
  { file: '.env.example', required: true, message: 'Plantilla de variables de entorno' },
  { file: 'db.js', required: true, message: 'Módulo de base de datos' },
  { file: 'index.js', required: true, message: 'Archivo principal del servidor' },
];

configFiles.forEach(({ file, required, message }) => {
  const filePath = path.join(__dirname, file);
  if (fs.existsSync(filePath)) {
    console.log(`✅ ${file} - ${message}`);
  } else {
    if (required) {
      console.log(`❌ ${file} - FALTANTE (${message})`);
      allInstalled = false;
    } else {
      console.log(`⚠️  ${file} - NO CONFIGURADO (${message})`);
    }
  }
});

// Verificar variables de entorno
console.log('\n🔍 Verificando variables de entorno...\n');

require('dotenv').config();

const requiredEnvVars = [
  'DISCORD_CLIENT_ID',
  'DISCORD_CLIENT_SECRET',
  'SESSION_SECRET',
  'FRONTEND_URL'
];

const optionalEnvVars = [
  'GEMINI_API_KEY',
  'DATABASE_URL',
  'NODE_ENV',
  'PORT'
];

requiredEnvVars.forEach(varName => {
  if (process.env[varName]) {
    console.log(`✅ ${varName} - Configurado`);
  } else {
    console.log(`❌ ${varName} - NO CONFIGURADO`);
    allInstalled = false;
  }
});

console.log('\nVariables opcionales:');
optionalEnvVars.forEach(varName => {
  if (process.env[varName]) {
    console.log(`✅ ${varName} - Configurado`);
  } else {
    console.log(`⚠️  ${varName} - No configurado (opcional)`);
  }
});

// Resultado final
console.log('\n' + '='.repeat(50));
if (allInstalled) {
  console.log('✅ Todas las dependencias críticas están instaladas');
  console.log('✅ El servidor está listo para ejecutarse');
  console.log('\nPara iniciar el servidor, ejecuta: npm start');
  process.exit(0);
} else {
  console.log('❌ Faltan dependencias o configuración');
  console.log('\nPasos para solucionar:');
  console.log('1. Ejecuta: npm install');
  console.log('2. Copia .env.example a .env');
  console.log('3. Configura las variables en .env');
  process.exit(1);
}
