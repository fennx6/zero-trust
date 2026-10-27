// ============================================================
// shared/database.js
// Koneksi SQLite tunggal yang dipakai gateway, kedua service,
// dan seed. Satu proses = satu koneksi (better-sqlite3 sync).
// ============================================================

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

let _db = null;

/**
 * Buka (sekali) dan kembalikan koneksi database bersama.
 * Path database berasal dari env DB_PATH (default data/database.sqlite)
 * dan selalu diresolusi relatif ke root proyek.
 */
function getDb() {
  if (_db) return _db;

  const rawPath = process.env.DB_PATH || 'data/database.sqlite';
  const dbPath = path.isAbsolute(rawPath) ? rawPath : path.join(__dirname, '..', rawPath);

  fs.mkdirSync(path.dirname(dbPath), { recursive: true });

  _db = new Database(dbPath);
  _db.pragma('journal_mode = WAL');   // aman untuk 3 proses sekaligus
  _db.pragma('foreign_keys = ON');
  _db.pragma('busy_timeout = 5000');  // tunggu kunci tulisan antar proses

  return _db;
}

/** Terapkan schema.sql (semua CREATE TABLE IF NOT EXISTS). */
function applySchema() {
  const schemaPath = path.join(__dirname, '..', 'database', 'schema.sql');
  const schema = fs.readFileSync(schemaPath, 'utf8');
  getDb().exec(schema);
}

module.exports = { getDb, applySchema };
