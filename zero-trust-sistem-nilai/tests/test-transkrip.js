// ============================================================
// tests/test-transkrip.js
// Uji Service Transkrip (port 3002) — skenario negatif & positif.
// Token dibuat langsung dengan shared/token.js (JWT_SECRET sama
// dengan yang dipakai service, mensimulasikan token yang
// diteruskan gateway).
//
// Jalankan: node tests/test-transkrip.js   (server harus sudah jalan)
// ============================================================

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const { signAccessToken, signServiceToken } = require('../shared/token');

const BASE = process.env.SERVICE_TRANSKRIP_URL || 'http://localhost:3002';
const SECRET = process.env.GATEWAY_SECRET;

let pass = 0;
let failCount = 0;

function log(name, ok, detail) {
  if (ok) pass++;
  else failCount++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  -> ' + detail : ''}`);
}

async function call(method, urlPath, { secret = true, token = null, body = null } = {}) {
  const headers = {};
  if (secret) headers['X-Gateway-Secret'] = SECRET;
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (body) headers['Content-Type'] = 'application/json';
  const res = await fetch(BASE + urlPath, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch { /* ignore */ }
  return { status: res.status, json };
}

async function main() {
  const tMhs = signAccessToken({ sub: '10522001', role: 'mahasiswa' });  // Andi
  const tMhs2 = signAccessToken({ sub: '10522002', role: 'mahasiswa' }); // Bela
  const tDosen = signAccessToken({ sub: 'budi.santoso', role: 'dosen' });
  const tAdmin = signAccessToken({ sub: 'admin', role: 'admin' });
  const tService = signServiceToken('nilai-service');
  const tExpired = signAccessToken({ sub: '10522001', role: 'mahasiswa' }, { expiresIn: -10 });
  const tWrongSign = require('jsonwebtoken').sign(
    { sub: '10522001', role: 'mahasiswa' }, 'secret-salah', { expiresIn: 60 }
  );

  // --- Skenario negatif: lapisan gateway secret ---
  let r = await call('GET', '/transkrip/10522001', { secret: false, token: tMhs });
  log('tanpa X-Gateway-Secret ditolak 401', r.status === 401 && r.json.error.code === 'GATEWAY_SECRET_MISSING', `status=${r.status} code=${r.json?.error?.code}`);

  r = await fetch(`${BASE}/transkrip/10522001`, { method: 'GET', headers: { 'X-Gateway-Secret': 'salah', 'Authorization': `Bearer ${tMhs}` } });
  let j = await r.json().catch(() => null);
  log('X-Gateway-Secret salah ditolak 401', r.status === 401 && j?.error?.code === 'GATEWAY_SECRET_WRONG', `status=${r.status} code=${j?.error?.code}`);

  // --- Skenario negatif: lapisan JWT ---
  r = await call('GET', '/transkrip/10522001', { token: null });
  log('token hilang ditolak 401', r.status === 401 && r.json.error.code === 'TOKEN_MISSING', `code=${r.json?.error?.code}`);

  r = await call('GET', '/transkrip/10522001', { token: 'bukan.jwt-token' });
  log('token malformed ditolak 401', r.status === 401 && r.json.error.code === 'TOKEN_MALFORMED', `code=${r.json?.error?.code}`);

  r = await call('GET', '/transkrip/10522001', { token: tWrongSign });
  log('token tanda tangan salah ditolak 401', r.status === 401, `code=${r.json?.error?.code}`);

  r = await call('GET', '/transkrip/10522001', { token: tExpired });
  log('token kedaluwarsa ditolak 401', r.status === 401 && r.json.error.code === 'TOKEN_EXPIRED', `code=${r.json?.error?.code}`);

  // --- Endpoint sinkron: hanya token service ---
  r = await call('POST', '/transkrip/sinkron', { token: tMhs, body: { nim: '10522001', kelasCode: 'KIF-101', nilai: 85 } });
  log('token USER ke /sinkron ditolak 403', r.status === 403, `status=${r.status}`);
  r = await call('POST', '/transkrip/sinkron', { token: tAdmin, body: { nim: '10522001', kelasCode: 'KIF-101', nilai: 85 } });
  log('token ADMIN ke /sinkron ditolak 403', r.status === 403, `status=${r.status}`);

  r = await call('POST', '/transkrip/sinkron', { token: tService, body: { nim: '10522001', kelasCode: 'TIDAK-ADA', nilai: 85 } });
  log('sinkron kelas tidak dikenal 404', r.status === 404, `status=${r.status}`);

  r = await call('POST', '/transkrip/sinkron', { token: tService, body: { nim: '10522001', kelasCode: 'KIF-101', nilai: 150 } });
  log('sinkron nilai diluar 0-100 ditolak 400', r.status === 400, `status=${r.status}`);

  // --- Skenario positif: sinkron token service ---
  r = await call('POST', '/transkrip/sinkron', { token: tService, body: { nim: '10522001', kelasCode: 'KIF-101', nilai: 85 } });
  log('sinkron token service 200', r.status === 200 && r.json.message === 'Transkrip tersinkron.', `status=${r.status} synced_at=${r.json?.synced_at}`);

  // Upsert kedua untuk (mahasiswa, kelas) yang sama → tidak duplikat.
  r = await call('POST', '/transkrip/sinkron', { token: tService, body: { nim: '10522001', kelasCode: 'KIF-101', nilai: 88 } });
  log('sinkron ulang 200 (upsert)', r.status === 200 && r.json.nilai === 88, `status=${r.status} nilai=${r.json?.nilai}`);

  // --- Skenario positif/negatif: baca transkrip ---
  r = await call('GET', '/transkrip/10522001', { token: tMhs });
  const upserted = r.status === 200 && r.json.transkrip?.length === 1 && r.json.transkrip[0].nilai === 88;
  log('mahasiswa baca miliknya 200 (nilai upsert=88, tidak duplikat)', upserted, `status=${r.status} rows=${r.json?.transkrip?.length}`);

  r = await call('GET', '/transkrip/10522002', { token: tMhs });
  log('mahasiswa baca NIM orang lain ditolak 403', r.status === 403 && r.json.error.code === 'FORBIDDEN_OWNERSHIP', `status=${r.status}`);

  r = await call('GET', '/transkrip/10522001', { token: tMhs2 });
  log('mahasiswa-2 baca NIM mahasiswa-1 ditolak 403', r.status === 403, `status=${r.status}`);

  r = await call('GET', '/transkrip/10522003', { token: tAdmin });
  log('admin baca NIM mana pun 200 (belum ada transkrip=tabel kosong)', r.status === 200 && Array.isArray(r.json.transkrip), `status=${r.status} rows=${r.json?.transkrip?.length}`);

  r = await call('GET', '/transkrip/10522001', { token: tDosen });
  log('dosen baca transkrip ditolak 403', r.status === 403, `status=${r.status}`);

  r = await call('GET', '/transkrip/10522001', { token: tService });
  log('token service baca transkrip ditolak 403', r.status === 403, `status=${r.status}`);

  r = await call('GET', '/transkrip/999999', { token: tAdmin });
  log('NIM tidak dikenal ditolak 404', r.status === 404, `status=${r.status}`);

  // --- Endpoint yang tidak ada ---
  r = await call('GET', '/tidak-ada', { token: tMhs });
  log('endpoint tidak dikenal 404', r.status === 404, `status=${r.status}`);

  console.log(`\nHasil: ${pass} PASS, ${failCount} FAIL`);
  process.exit(failCount === 0 ? 0 : 1);
}

main().catch((e) => { console.error('Uji gagal dijalankan:', e.message); process.exit(1); });
