// ============================================================
// gateway/auth.js
// Autentikasi di gateway (satu-satunya pintu masuk pengguna):
//   POST /auth/login    -> kredensial valid + X-Device-ID terdaftar
//   POST /auth/refresh  -> refresh token valid, belum kedaluwarsa,
//                          belum dicabut; token lama di-revoke (rotasi)
//   POST /auth/logout   -> mencabut refresh token yang dipakai
//   POST /auth/service  -> kredensial client Service Nilai
//
// Menghasilkan juga middleware authenticate() yang dipakai semua
// route non-auth: verifikasi JWT + X-Device-ID terdaftar.
// Identitas SELALU berasal dari token terverifikasi.
// ============================================================

const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { getDb } = require('../shared/database');
const { signAccessToken, signServiceToken, verifyToken } = require('../shared/token');
const { audit } = require('./audit');

const router = express.Router();

router.use(express.json({ limit: '64kb' }));

// ---------- helper ----------

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

/** Hash buffer khusus untuk perbandingan timing-safe. */
const sha256Buf = (s) => crypto.createHash('sha256').update(String(s)).digest();

/** Bandingkan nilai sensitif tanpa timing leak (hash dulu agar panjang sama). */
function safeEqual(a, b) {
  try {
    return crypto.timingSafeEqual(sha256Buf(a), sha256Buf(b));
  } catch {
    return false;
  }
}

function accessTokenExpiresIn() {
  return Number(process.env.ACCESS_TOKEN_TTL || 600); // 10 menit
}

function refreshTokenTtlMs() {
  return Number(process.env.REFRESH_TOKEN_TTL || 86400) * 1000; // 1 hari
}

/** Buat refresh token acak, simpan HASH-nya (bukan nilai token). */
function issueRefreshToken(db, userId) {
  const refreshToken = crypto.randomBytes(48).toString('hex');
  const expiresAt = new Date(Date.now() + refreshTokenTtlMs()).toISOString();
  db.prepare(
    'INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked) VALUES (?, ?, ?, 0)'
  ).run(userId, sha256(refreshToken), expiresAt);
  return { refreshToken, expiresAt };
}

/** Endpoint device terdaftar untuk user tertentu. */
function deviceBelongsTo(deviceId, userId) {
  if (!deviceId || typeof deviceId !== 'string' || deviceId.length > 128) return false;
  const row = getDb().prepare(
    'SELECT user_id FROM devices WHERE device_id = ?'
  ).get(deviceId);
  return !!row && row.user_id === userId;
}

function userRow(username) {
  return getDb().prepare(
    'SELECT id, username, nama, role, nim, password_hash FROM users WHERE username = ?'
  ).get(username) || null;
}

// ---------- POST /auth/login ----------

router.post('/login', (req, res) => {
  const endpoint = 'POST /auth/login';
  const deviceId = req.get('x-device-id') || null;
  const body = req.body || {};
  const { username, password } = body;

  const deny = (status, code, message, subject) => {
    audit({
      subjectType: 'user', subjectId: subject || username || '(tanpa-username)',
      endpoint, deviceId, result: 'deny', reason: message,
    });
    return res.status(status).json({ error: { code, message } });
  };

  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return deny(400, 'VALIDATION', 'Field "username" dan "password" wajib diisi.');
  }
  if (!deviceId) {
    return deny(401, 'DEVICE_MISSING', 'Header X-Device-ID wajib ada.');
  }

  const user = userRow(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    // Pesan seragam untuk user tidak ada / password salah (anti-enumeration).
    return deny(401, 'CREDENTIALS_INVALID', 'Username atau password salah.');
  }
  if (!deviceBelongsTo(deviceId, user.id)) {
    return deny(403, 'DEVICE_NOT_REGISTERED', 'Device tidak terdaftar untuk user ini.');
  }

  const accessToken = signAccessToken({ sub: user.username, role: user.role });
  const { refreshToken } = issueRefreshToken(getDb(), user.id);

  audit({
    subjectType: 'user', subjectId: user.username, endpoint, deviceId,
    result: 'allow', reason: 'Kredensial valid dan device terdaftar.',
  });

  return res.status(200).json({
    tokenType: 'Bearer',
    accessToken,
    refreshToken,
    expiresIn: accessTokenExpiresIn(),
    user: { username: user.username, nama: user.nama, role: user.role },
  });
});

// ---------- POST /auth/refresh ----------

router.post('/refresh', (req, res) => {
  const endpoint = 'POST /auth/refresh';
  const deviceId = req.get('x-device-id') || null;
  const body = req.body || {};
  const { refreshToken } = body;

  const deny = (status, code, message, subject) => {
    audit({
      subjectType: 'user', subjectId: subject || '(tidak-dikenal)',
      endpoint, deviceId, result: 'deny', reason: message,
    });
    return res.status(status).json({ error: { code, message } });
  };

  if (!refreshToken || typeof refreshToken !== 'string') {
    return deny(400, 'VALIDATION', 'Field "refreshToken" wajib diisi.');
  }
  if (!deviceId) {
    return deny(401, 'DEVICE_MISSING', 'Header X-Device-ID wajib ada.');
  }

  const row = getDb().prepare(`
    SELECT rt.id, rt.user_id, rt.expires_at, rt.revoked,
           u.username, u.role
    FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id
    WHERE rt.token_hash = ?
  `).get(sha256(refreshToken)) || null;

  if (!row) {
    return deny(401, 'REFRESH_TOKEN_INVALID', 'Refresh token tidak dikenal.');
  }
  if (row.revoked === 1) {
    return deny(401, 'REFRESH_TOKEN_REVOKED', 'Refresh token sudah dicabut.');
  }
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    return deny(401, 'REFRESH_TOKEN_EXPIRED', 'Refresh token kedaluwarsa.');
  }
  if (!deviceBelongsTo(deviceId, row.user_id)) {
    return deny(403, 'DEVICE_NOT_REGISTERED', 'Device tidak terdaftar untuk user token ini.');
  }

  const db = getDb();

  // Rotasi: refresh token lama dicabut, token baru diterbitkan.
  // Maksudnya refresh token sekali pakai, mengecilkan jendela replay.
  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?').run(row.id);
  const accessToken = signAccessToken({ sub: row.username, role: row.role });
  const neue = issueRefreshToken(db, row.user_id);

  audit({
    subjectType: 'user', subjectId: row.username, endpoint, deviceId,
    result: 'allow', reason: 'Refresh token valid; token lama dicabut (rotasi).',
  });

  return res.status(200).json({
    tokenType: 'Bearer',
    accessToken,
    refreshToken: neue.refreshToken,
    expiresIn: accessTokenExpiresIn(),
  });
});

// ---------- POST /auth/logout ----------

router.post('/logout', (req, res) => {
  const endpoint = 'POST /auth/logout';
  const deviceId = req.get('x-device-id') || null;
  const body = req.body || {};
  const { refreshToken } = body;

  if (!refreshToken || typeof refreshToken !== 'string') {
    audit({
      subjectType: 'user', subjectId: '(tidak-dikenal)', endpoint, deviceId,
      result: 'deny', reason: 'Field "refreshToken" wajib diisi.',
    });
    return res.status(400).json({ error: { code: 'VALIDATION', message: 'Field "refreshToken" wajib diisi.' } });
  }

  const row = getDb().prepare(
    'SELECT id, user_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = ?'
  ).get(sha256(refreshToken)) || null;

  if (!row || row.revoked === 1 || new Date(row.expires_at).getTime() <= Date.now()) {
    // Jangan bedakan penyebab; token seperti itu memang tidak layak logout.
    const subject = row && row.user_id
      ? (userRow(String(row.user_id))?.username || '(tidak-dikenal)')
      : '(tidak-dikenal)';
    audit({
      subjectType: 'user', subjectId: subject, endpoint, deviceId,
      result: 'deny', reason: 'Refresh token tidak valid / dicabut / kedaluwarsa.',
    });
    return res.status(401).json({ error: { code: 'REFRESH_TOKEN_INVALID', message: 'Refresh token tidak valid.' } });
  }

  const username = userRow(String(row.user_id))?.username || '(tidak-dikenal)';
  getDb().prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?').run(row.id);

  audit({
    subjectType: 'user', subjectId: username, endpoint, deviceId,
    result: 'allow', reason: 'Logout: refresh token dicabut.',
  });
  return res.status(200).json({ message: 'Logout berhasil; refresh token dicabut.' });
});

// ---------- POST /auth/service ----------

router.post('/service', (req, res) => {
  const endpoint = 'POST /auth/service';
  const body = req.body || {};
  const { clientId, clientSecret } = body;

  if (!safeEqual(clientId, process.env.SERVICE_CLIENT_ID) ||
      !safeEqual(clientSecret, process.env.SERVICE_CLIENT_SECRET)) {
    audit({
      subjectType: 'service', subjectId: clientId || '(tanpa-client-id)', endpoint, deviceId: null,
      result: 'deny', reason: 'Kredensial client tidak valid.',
    });
    return res.status(401).json({ error: { code: 'CLIENT_INVALID', message: 'Client credentials tidak valid.' } });
  }

  audit({
    subjectType: 'service', subjectId: clientId, endpoint, deviceId: null,
    result: 'allow', reason: 'Kredensial client service valid; access token service (5 menit) diterbitkan.',
  });

  return res.status(200).json({
    tokenType: 'Bearer',
    accessToken: signServiceToken(clientId),
    expiresIn: Number(process.env.SERVICE_TOKEN_TTL || 300),
  });
});

// ---------- middleware authenticate() untuk route non-auth ----------

/**
 * Verifikasi ingress pengguna pada gateway:
 *  - JWT Bearer valid (tanda tangan + masa berlaku + claim)
 *  - X-Device-ID wajib ada & terdaftar untuk user token (role user)
 *  - token service tanpa device (dipakai antar-layanan oleh Service Nilai)
 * Hasil: req.auth / req.user / req.deviceId.
 */
function authenticate(req, res, next) {
  const path = req.originalUrl.split('?')[0];
  const endpoint = `${req.method} ${path}`;
  const deviceId = req.get('x-device-id') || null;

  const deny = (status, code, message, extra = {}) => {
    audit({
      subjectType: 'user', subjectId: extra.subjectId || '(tidak-terverifikasi)',
      endpoint, deviceId, result: 'deny', reason: message,
    });
    return res.status(status).json({ error: { code, message } });
  };

  const header = req.get('authorization') || '';
  const match = header.match(/^Bearer\s+(\S+)$/i);
  if (!match) return deny(401, 'TOKEN_MISSING', 'Header Authorization: Bearer <token> wajib ada.');

  const v = verifyToken(match[1]);
  if (!v.ok) return deny(401, v.code, v.message);

  // Token service: tanpa device check (komunikasi antar-layanan).
  if (v.payload.role === 'service') {
    req.auth = { sub: v.payload.sub, role: v.payload.role };
    req.user = null;
    req.deviceId = null;
    return next();
  }

  const user = userRow(v.payload.sub);
  if (!user) return deny(401, 'UNKNOWN_SUBJECT', 'User pada token tidak dikenal.', { subjectId: v.payload.sub });
  if (!deviceId) return deny(401, 'DEVICE_MISSING', 'Header X-Device-ID wajib ada.', { subjectId: user.username });
  if (!deviceBelongsTo(deviceId, user.id)) {
    return deny(403, 'DEVICE_NOT_REGISTERED', 'Device tidak terdaftar untuk user token ini.', { subjectId: user.username });
  }

  req.auth = { sub: user.username, role: user.role };
  req.user = user;
  req.deviceId = deviceId;
  return next();
}

module.exports = { router, authenticate };
