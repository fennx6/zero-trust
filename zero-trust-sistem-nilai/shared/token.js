// ============================================================
// shared/token.js
// Penerbitan dan verifikasi JWT:
//  - Access token user : TTL 10 menit (env ACCESS_TOKEN_TTL)
//  - Token service      : TTL 5 menit  (env SERVICE_TOKEN_TTL), role "service"
// Verifikasi memeriksa tanda tangan, masa berlaku, dan claim wajib.
// ============================================================

const jwt = require('jsonwebtoken');

const JWT_SECRET = () => process.env.JWT_SECRET;

const ACCESS_TOKEN_TTL = () => Number(process.env.ACCESS_TOKEN_TTL || 600);   // 10 menit
const SERVICE_TOKEN_TTL = () => Number(process.env.SERVICE_TOKEN_TTL || 300); // 5 menit

/**
 * Sign token user. Claim minimal: sub (username/NIM) dan role.
 * @param {{sub: string, role: string}} payload
 * @param {{expiresIn?: (string|number)}} [opts] - override TTL, dipakai untuk pengujian token kedaluwarsa.
 */
function signAccessToken(payload, opts = {}) {
  return jwt.sign(
    { sub: payload.sub, role: payload.role },
    JWT_SECRET(),
    { expiresIn: opts.expiresIn || ACCESS_TOKEN_TTL() }
  );
}

/**
 * Sign token service (antarservice). Role selalu "service",
 * TTL 5 menit — pendek demi least privilege.
 */
function signServiceToken(clientId) {
  return jwt.sign(
    { sub: clientId, role: 'service' },
    JWT_SECRET(),
    { expiresIn: SERVICE_TOKEN_TTL() }
  );
}

/**
 * Verifikasi token: tanda tangan, masa berlaku, dan claim wajib.
 * Tidak melempar error; selalu mengembalikan hasil:
 *   { ok: true, payload }                                  atau
 *   { ok: false, code, message } dengan code salah satu dari:
 *   TOKEN_MALFORMED | TOKEN_EXPIRED | TOKEN_INVALID | CLAIM_MISSING
 */
function verifyToken(token) {
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET());
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return fail('TOKEN_EXPIRED', 'Access token kedaluwarsa.');
    }
    if (err.name === 'JsonWebTokenError') {
      return fail('TOKEN_MALFORMED', 'Access token tidak valid.');
    }
    return fail('TOKEN_INVALID', 'Verifikasi token gagal.');
  }

  if (!payload || typeof payload.sub !== 'string' || typeof payload.role !== 'string') {
    return fail('CLAIM_MISSING', 'Claim wajib (sub/role) tidak ada.');
  }

  return { ok: true, payload: { sub: payload.sub, role: payload.role, iat: payload.iat, exp: payload.exp } };

  function fail(code, message) {
    return { ok: false, code, message };
  }
}

module.exports = { signAccessToken, signServiceToken, verifyToken };
