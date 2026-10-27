-- ============================================================
-- Schema SQLite — Zero Trust Sistem Nilai
-- Satu database bersama untuk gateway dan kedua service.
-- Semua tabel memakai IF NOT EXISTS agar aman dijalankan ulang.
-- ============================================================

PRAGMA foreign_keys = ON;

-- Pengguna: admin, dosen, mahasiswa.
-- (Akun service tidak disimpan di sini; client ID/secret service
--  diambil dari environment variable.)
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT    NOT NULL UNIQUE,
  nama          TEXT    NOT NULL,
  role          TEXT    NOT NULL CHECK (role IN ('admin', 'dosen', 'mahasiswa')),
  nim           TEXT    UNIQUE,              -- hanya diisi untuk mahasiswa
  password_hash TEXT    NOT NULL,           -- bcrypt, tidak pernah plaintext
  created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Device terdaftar per user. Satu device ID hanya boleh dipakai
-- satu user, sehingga device milik user lain selalu ditolak.
CREATE TABLE IF NOT EXISTS devices (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT    NOT NULL,
  label     TEXT,
  UNIQUE (device_id)
);

-- Refresh token. Yang disimpan adalah hash SHA-256 token,
-- sehingga kebocoran database tidak langsung membocorkan token.
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT    NOT NULL UNIQUE,
  expires_at TEXT    NOT NULL,              -- ISO 8601 UTC
  revoked    INTEGER NOT NULL DEFAULT 0,    -- 1 = sudah dicabut (logout)
  created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Kelas dan dosen pengampu (relasi dibaca Policy Engine).
CREATE TABLE IF NOT EXISTS kelas (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  kode     TEXT    NOT NULL UNIQUE,
  nama     TEXT    NOT NULL,
  dosen_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT  NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Peserta kelas (mahasiswa yang mengambil kelas).
CREATE TABLE IF NOT EXISTS enrollments (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  kelas_id  INTEGER NOT NULL REFERENCES kelas(id) ON DELETE CASCADE,
  user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE (kelas_id, user_id)
);

-- Nilai beserta status final. Belum final = masih bisa diubah dosen.
CREATE TABLE IF NOT EXISTS nilai (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  kelas_id   INTEGER NOT NULL REFERENCES kelas(id) ON DELETE CASCADE,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  nilai      INTEGER NOT NULL CHECK (nilai BETWEEN 0 AND 100),
  final      INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (kelas_id, user_id)
);

-- Transkrip tujuan sinkronisasi nilai final (diisi Service Nilai
-- melalui endpoint /transkrip/sinkron dengan token service).
CREATE TABLE IF NOT EXISTS transkrip (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kelas_id  INTEGER NOT NULL REFERENCES kelas(id) ON DELETE CASCADE,
  nilai     INTEGER NOT NULL,
  synced_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (user_id, kelas_id)
);

-- Audit log keputusan akses (allow/deny) yang dicatat gateway.
-- Dilarang menyimpan password/token/secret di tabel ini.
CREATE TABLE IF NOT EXISTS audit_logs (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  subject_type TEXT    NOT NULL CHECK (subject_type IN ('user', 'service')),
  subject_id   TEXT    NOT NULL,
  endpoint     TEXT    NOT NULL,
  device_id    TEXT,
  result       TEXT    NOT NULL CHECK (result IN ('allow', 'deny')),
  reason       TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_refresh_user    ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_transaksi_user  ON transkrip (user_id);
