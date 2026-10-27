// ============================================================
// shared/middleware.js
// Lapisan pertahanan yang dipakai KEDUA service:
//  1. requireGatewaySecret — tolak request tanpa X-Gateway-Secret
//     yang benar (gateway otentik; request langsung ke service ditolak).
//  2. requireJwt — verifikasi JWT Bearer yang diteruskan gateway,
//     hasil ditempel di req.auth.
//  3. requireRole — otorisasi minimal berdasarkan role dari token.
// Gateway secret saja TIDAK cukup: keduanya wajib lulus.
// ============================================================

const crypto = require('crypto');
const { verifyToken } = require('./token');
const { getDb } = require('./database');

/** Bandingkan secret tanpa "timing leak". Hash dulu agar panjang selalu sama. */
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

/** Penolakan error JSON yang konsisten untuk semua service. */
function deny(res, status, code, message) {
  return res.status(status).json({ error: { code, message } });
}

function getGatewaySecret() {
  return process.env.GATEWAY_SECRET;
}

/** (1) Verifikasi X-Gateway-Secret. */
function requireGatewaySecret(req, res, next) {
  const headerName = 'x-gateway-secret';
  const received = req.get(headerName);
  const expected = getGatewaySecret();

  if (expected && received && safeEqual(received, expected)) {
    return next();
  }
  // Alasan spesifik disertakan agar audit/demo mudah dibedakan.
  if (!received) {
    return deny(res, 401, 'GATEWAY_SECRET_MISSING', 'Header X-Gateway-Secret wajib ada.');
  }
  return deny(res, 401, 'GATEWAY_SECRET_WRONG', 'X-Gateway-Secret salah.');
}

/** (2) Verifikasi JWT Bearer. Hasil: req.auth = { sub, role }. */
function requireJwt(req, res, next) {
  const header = req.get('authorization') || '';
  const match = header.match(/^Bearer\s+(\S+)$/i);
  if (!match) {
    return deny(res, 401, 'TOKEN_MISSING', 'Header Authorization: Bearer <token> wajib ada.');
  }

  const result = verifyToken(match[1]);
  if (!result.ok) {
    const status = result.code === 'TOKEN_EXPIRED' ? 401 : 401;
    return deny(res, status, result.code, result.message);
  }

  req.auth = { sub: result.payload.sub, role: result.payload.role, exp: result.payload.exp };
  return next();
}

/** (3a) Batasi role yang boleh lewat. */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.auth || !roles.includes(req.auth.role)) {
      return deny(res, 403, 'FORBIDDEN_ROLE', `Endpoint ini hanya untuk role: ${roles.join(', ')}.`);
    }
    return next();
  };
}

/**
 * (3b) Verifikasi konteks tambahan di sisi service:
 * mahasiswa hanya boleh data miliknya sendiri. Identitas selalu
 * diambil dari token yang telah diverifikasi — bukan dari header client.
 * @param {(auth: {sub:string, role:string}, req:import('express').Request) => boolean} check
 */
function requireOwnership(check) {
  return (req, res, next) => {
    if (check(req.auth, req)) return next();
    return deny(res, 403, 'FORBIDDEN_OWNERSHIP', 'Anda tidak berhak mengakses data ini.');
  };
}

/** Ambil user by username (untuk pemetaan NIM dkk). Prepared statement. */
function findUserByUsername(username) {
  if (!username || typeof username !== 'string' || username.length > 64) return null;
  return getDb().prepare('SELECT id, username, nama, role, nim FROM users WHERE username = ?').get(username) || null;
}

module.exports = {
  deny,
  requireGatewaySecret,
  requireJwt,
  requireRole,
  requireOwnership,
  findUserByUsername,
};
