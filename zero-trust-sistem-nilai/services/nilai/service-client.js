// ============================================================
// services/nilai/service-client.js
// Komunikasi Service Nilai -> Service Transkrip TIDAK langsung
// ke port 3002, tapi lewat gateway:
//   1. POST {GATEWAY_URL}/auth/service      -> token service (5 menit)
//   2. POST {GATEWAY_URL}/transkrip/sinkron (Bearer token service)
// Token service di-cache sampai mendekati kedaluwarsa (margin 30 detik).
// ============================================================

const GATEWAY_URL = process.env.GATEWAY_URL || 'http://localhost:3000';

let cached = null; // { token, exp } — v getAddress dalam epoch detik.

function clientId() { return process.env.SERVICE_CLIENT_ID; }
function clientSecret() { return process.env.SERVICE_CLIENT_SECRET; }

/** Ambil token service; pakai cache jika masih berlaku. */
async function getServiceToken() {
  if (cached && cached.exp - 30 > Math.floor(Date.now() / 1000)) {
    return cached.token;
  }

  const res = await fetch(`${GATEWAY_URL}/auth/service`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ clientId: clientId(), clientSecret: clientSecret() }),
  });

  if (!res.ok) {
    let detail = '';
    try { detail = (await res.json())?.error?.message || ''; } catch { /* abaikan */ }
    throw new Error(`Gagal memperoleh token service (HTTP ${res.status}) ${detail}`.trim());
  }

  const body = await res.json();
  if (!body.accessToken) {
    throw new Error('Respons /auth/service tidak memuat accessToken.');
  }

  // Decode exp tanpa verifikasi (JWT baru saja dibuat by gateway,
  // dan diterima via HTTPS/local transport tertutup dev).
  const part = String(body.accessToken).split('.')[1];
  const payload = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  cached = { token: body.accessToken, exp: payload.exp || 0 };
  return cached.token;
}

/**
 * Sinkronkan satu nilai final ke Service Transkrip melalui gateway.
 * @param {{nim:string, kelasCode:string, nilai:number}} payload
 * @returns {Promise<{sent:boolean, status?:number, message?:string}>}
 */
async function sinkronKeTranskrip(payload) {
  try {
    const token = await getServiceToken();
    const res = await fetch(`${GATEWAY_URL}/transkrip/sinkron`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    return { sent: true, status: res.status, message: body?.message || body?.error?.message || '' };
  } catch (err) {
    // Gateway tidak terjangkau / jaringan gagal: status dilaporkan caller.
    return { sent: false, status: 0, message: err.message };
  }
}

module.exports = { getServiceToken, sinkronKeTranskrip, GATEWAY_URL };
