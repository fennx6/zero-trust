// ============================================================
// tests/test-gateway.js
// Uji API Gateway (port 3000) secara end-to-end:
// skrip ini men-spawn ketiga service, lalu menguji seluruh alur
// login/refresh/logout/service-token, kebijakan akses (role,
// ownership, jam akses), proxy PEP, sinkronisasi via gateway,
// serta isi audit log (allow/deny, tanpa secret).
//
// Fase A: konfigurasi jam akses DI LUAR waktu sekarang (uji 403)
// Fase B: jam akses 00:00-24:00 (uji alur penuh)
// Jalankan: node tests/test-gateway.js
// ============================================================

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const { spawn, execFileSync } = require('child_process');
const { getDb } = require('../shared/database');
const { nowInZone } = require('../shared/hours');
const jwt = require('jsonwebtoken');

const G = 'http://localhost:3000';
const N = 'http://localhost:3001';
const T = 'http://localhost:3002';

let pass = 0, fail = 0;
function log(name, ok, detail) {
  if (ok) pass++; else fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  -> ' + detail : ''}`);
}

async function call(base, method, urlPath, { token = null, device = null, body = null, secretHeader = false } = {}) {
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (device) headers['X-Device-ID'] = device;
  if (body) headers['Content-Type'] = 'application/json';
  if (secretHeader) headers['X-Gateway-Secret'] = process.env.GATEWAY_SECRET;
  const res = await fetch(base + urlPath, { method, headers, body: body ? JSON.stringify(body) : undefined });
  let json = null;
  try { json = await res.json(); } catch { /* abaikan */ }
  return { status: res.status, json };
}

async function login(device, username, password) {
  return call(G, 'POST', '/auth/login', { device, body: { username, password } });
}

async function startServer(script, extraEnv = {}) {
  const child = spawn(process.execPath, [script], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, ...extraEnv },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  const url = script.includes('gateway') ? G : script.includes('transkrip') ? T : N;
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try { const r = await fetch(`${url}/health`); if (r.ok) return child; } catch { /* tunggu */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  child.kill();
  throw new Error(`Server ${script} tidak siap.`);
}

function freePorts() {
  // Di Windows, proses sisa sebelumnya harus benar-benar dibunuh sebelum spawn.
  try {
    execFileSync('powershell', ['-NoProfile', '-Command',
      'Get-NetTCPConnection -LocalPort 3000,3001,3002 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }'
    ], { stdio: 'ignore' });
  } catch { /* bersih */ }
}

async function startAll(extraEnv) {
  freePorts();
  await new Promise((r) => setTimeout(r, 500));
  const procs = [];
  procs.push(await startServer('services/transkrip/server.js', extraEnv));
  procs.push(await startServer('services/nilai/server.js', extraEnv));
  procs.push(await startServer('gateway/server.js', extraEnv));
  return procs;
}

function stopAll(procs) {
  for (const p of procs) {
    try {
      execFileSync('taskkill', ['/PID', String(p.pid), '/F', '/T'], { stdio: 'ignore' });
    } catch { /* abaikan */ }
  }
}

const db = () => getDb();
function auditCount(result, endpoint) {
  return db().prepare('SELECT COUNT(*) n FROM audit_logs WHERE result = ? AND endpoint = ?').get(result, endpoint).n;
}
function auditSecretRows() {
  // Scan dari SUDUT PEMBOCORAN NILAI, bukan kata prosa:
  // nilai JWT asli selalu diawali "eyJ..." — "Bearer eyJ" hanya
  // muncul bila token sungguhan ikut dicatat.
  return db().prepare(`
    SELECT id, subject_id, endpoint, reason FROM audit_logs
    WHERE reason LIKE '%eyJ%' OR subject_id LIKE '%eyJ%'
  `).all();
}
function auditKind(result) {
  return db().prepare('SELECT COUNT(*) n FROM audit_logs WHERE result = ?').get(result).n;
}

async function main() {
  const kelasId = Object.fromEntries(db().prepare('SELECT id, kode FROM kelas').all().map((r) => [r.kode, r.id]));
  const nilaiId = (kode, nim) => db().prepare(`
    SELECT n.id FROM nilai n JOIN kelas k ON k.id=n.kelas_id JOIN users u ON u.id=n.user_id
    WHERE k.kode = ? AND u.nim = ?
  `).get(kode, nim).id;

  const nowJakarta = nowInZone('Asia/Jakarta');
  const startA = (nowJakarta.hour + 1) % 24;
  const endA = (nowJakarta.hour + 2) % 24;

  let procs;

  // ---------------- FASE A: DI LUAR JAM AKSES ----------------
  console.log('\n=== FASE A: di luar jam akses (jendela ' + startA + ':00-' + endA + ':00) ===');
  procs = await startAll({ ACCESS_START_HOUR: startA, ACCESS_END_HOUR: endA });

  let r = await login('DEV-DOSEN-01', 'budi.santoso', 'Dosen#12345');
  log('A: login dosen sukses (login tidak dibatasi jam)', r.status === 200 && !!r.json.accessToken, `status=${r.status}`);
  const tBudiA = r.json.accessToken;

  r = await call(G, 'PUT', `/nilai/${nilaiId('KIF-101', '10522001')}`, { token: tBudiA, device: 'DEV-DOSEN-01', body: { nilai: 95 } });
  log('A: PUT nilai di luar jam ditolak gateway 403', r.status === 403 && r.json.error.code === 'OUTSIDE_ACCESS_HOURS',
    `status=${r.status} code=${r.json?.error?.code}`);

  r = await call(G, 'POST', `/kelas/${kelasId['KIF-101']}/finalisasi`, { token: tBudiA, device: 'DEV-DOSEN-01' });
  log('A: finalisasi di luar jam ditolak gateway 403', r.status === 403 && r.json.error.code === 'OUTSIDE_ACCESS_HOURS',
    `status=${r.status}`);

  stopAll(procs);
  await new Promise((r) => setTimeout(r, 400));
  auditClear();

  // ---------------- FASE B: DI DALAM JAM AKSES ----------------
  console.log('\n=== FASE B: di dalam jam akses (00:00-24:00) ===');
  procs = await startAll({ ACCESS_START_HOUR: 0, ACCESS_END_HOUR: 24 });

  // --- Login & device ---
  r = await login('DEV-DOSEN-01', 'budi.santoso', 'password-salah');
  log('B: login password salah 401', r.status === 401 && r.json.error.code === 'CREDENTIALS_INVALID', `code=${r.json?.error?.code}`);

  r = await login('DEV-MHS-01', 'budi.santoso', 'Dosen#12345');
  log('B: login dengan device milik user lain 403', r.status === 403 && r.json.error.code === 'DEVICE_NOT_REGISTERED', `code=${r.json?.error?.code}`);

  r = await login('DEV-TAK-ADA', 'budi.santoso', 'Dosen#12345');
  log('B: login dengan device tidak terdaftar 403', r.status === 403 && r.json.error.code === 'DEVICE_NOT_REGISTERED', `code=${r.json?.error?.code}`);

  r = await login('DEV-DOSEN-01', 'budi.santoso', 'Dosen#12345');
  const tBudi = r.json.accessToken;
  const rtBudi = r.json.refreshToken;
  const dur = jwt.decode(tBudi);
  log('B: login valid 200 (TTL 600 detik)', r.status === 200 && (dur.exp - dur.iat) === 600, `ttl=${dur.exp - dur.iat}`);

  const rMhs = await login('DEV-MHS-01', '10522001', 'Mhs#12345');
  const tMhs1 = rMhs.json.accessToken;
  const rtMhs1 = rMhs.json.refreshToken;
  const rAdmin = await login('DEV-ADMIN-01', 'admin', 'Admin#12345');
  const tAdmin = rAdmin.json.accessToken;

  // --- Context endpoint: header/device ---
  r = await call(G, 'GET', '/nilai', { device: 'DEV-DOSEN-01' });
  log('B: request tanpa token ditolak 401', r.status === 401 && r.json.error.code === 'TOKEN_MISSING', `code=${r.json?.error?.code}`);

  r = await call(G, 'GET', '/nilai', { token: tBudi });
  log('B: request tanpa X-Device-ID ditolak 401', r.status === 401 && r.json.error.code === 'DEVICE_MISSING', `code=${r.json?.error?.code}`);

  r = await call(G, 'GET', '/nilai', { token: tBudi, device: 'DEV-MHS-01' });
  log('B: token dosen + device mahasiswa ditolak 403', r.status === 403 && r.json.error.code === 'DEVICE_NOT_REGISTERED', `code=${r.json?.error?.code}`);

  // --- Proxy: GET /nilai ---
  r = await call(G, 'GET', '/nilai', { token: tBudi, device: 'DEV-DOSEN-01' });
  log('B: dosen GET /nilai via gateway 200', r.status === 200 && r.json.kelas?.[0]?.kelas?.kode === 'KIF-101', `status=${r.status}`);

  r = await call(G, 'GET', '/nilai', { token: tMhs1, device: 'DEV-MHS-01' });
  log('B: mahasiswa GET /nilai via gateway 200', r.status === 200 && r.json.nilai?.length === 2, `status=${r.status}`);

  // --- Transkrip: ownership via PEP + PDP ---
  r = await call(G, 'GET', '/transkrip/10522002', { token: tMhs1, device: 'DEV-MHS-01' });
  log('B: mahasiswa baca transkrip NIM lain ditolak 403 gateway', r.status === 403 && r.json.error.code === 'FORBIDDEN_OWNERSHIP', `code=${r.json?.error?.code}`);
  log('B: deny itu terekam di audit log', auditCount('deny', 'GET /transkrip/10522002') >= 1, `rows=${auditCount('deny', 'GET /transkrip/10522002')}`);

  r = await call(G, 'GET', '/transkrip/10522001', { token: tMhs1, device: 'DEV-MHS-01' });
  log('B: mahasiswa baca transkrip sendiri 200 (masih kosong)', r.status === 200 && Array.isArray(r.json.transkrip), `status=${r.status}`);

  r = await call(G, 'GET', '/transkrip/10522001', { token: tAdmin, device: 'DEV-ADMIN-01' });
  log('B: admin baca transkrip siapa pun 200', r.status === 200, `status=${r.status}`);

  // --- Sinkron: token user ditolak di gateway ---
  r = await call(G, 'POST', '/transkrip/sinkron', { token: tMhs1, device: 'DEV-MHS-01', body: { nim: '10522001', kelasCode: 'KIF-101', nilai: 1 } });
  log('B: token USER ke /sinkron ditolak 403 gateway', r.status === 403 && r.json.error.code === 'ENDPOINT_SERVICE_ONLY', `code=${r.json?.error?.code}`);
  log('B: deny /sinkron terekam di audit log', auditCount('deny', 'POST /transkrip/sinkron') >= 1, `rows=${auditCount('deny', 'POST /transkrip/sinkron')}`);

  // --- PUT nilai: ownership, final, validasi ---
  const nilaiBudi = nilaiId('KIF-101', '10522001');
  const nilaiFinalSiti = nilaiId('KIF-102', '10522001');

  r = await call(G, 'PUT', `/nilai/${nilaiBudi}`, { token: tBudi, device: 'DEV-DOSEN-01', body: { nilai: 95 } });
  log('B: dosen pengampu ubah nilai via gateway 200', r.status === 200 && r.json.nilai === 95, `status=${r.status}`);

  r = await call(G, 'PUT', `/nilai/${nilaiFinalSiti}`, { token: tBudi, device: 'DEV-DOSEN-01', body: { nilai: 1 } });
  log('B: dosen mengubah nilai kelas dosen lain ditolak 403 (ownership)', r.status === 403 && r.json.error.code === 'FORBIDDEN_OWNERSHIP', `code=${r.json?.error?.code}`);

  r = await call(G, 'PUT', `/nilai/${nilaiFinalSiti}`, { token: tAdmin, device: 'DEV-ADMIN-01', body: { nilai: 1 } });
  log('B: admin PUT nilai ditolak 403 (role)', r.status === 403 && r.json.error.code === 'FORBIDDEN_ROLE', `code=${r.json?.error?.code}`);

  r = await call(G, 'PUT', `/nilai/${nilaiBudi}`, { token: tBudi, device: 'DEV-DOSEN-01', body: { nilai: 999 } });
  log('B: nilai diluar 0-100 ditolak 400 service (via proxy)', r.status === 400, `status=${r.status}`);

  // --- Finalisasi end-to-end melalui gateway ---
  r = await call(G, 'POST', `/kelas/9999/finalisasi`, { token: tBudi, device: 'DEV-DOSEN-01' });
  log('B: finalisasi kelas tidak ada 404', r.status === 404, `status=${r.status}`);

  r = await call(G, 'POST', `/kelas/${kelasId['KIF-102']}/finalisasi`, { token: tBudi, device: 'DEV-DOSEN-01' });
  log('B: finalisasi kelas dosen lain ditolak 403', r.status === 403 && r.json.error.code === 'FORBIDDEN_OWNERSHIP', `code=${r.json?.error?.code}`);

  r = await call(G, 'POST', `/kelas/${kelasId['KIF-101']}/finalisasi`, { token: tMhs1, device: 'DEV-MHS-01' });
  log('B: mahasiswa finalisasi ditolak 403', r.status === 403 && r.json.error.code === 'FORBIDDEN_ROLE', `code=${r.json?.error?.code}`);

  r = await call(G, 'POST', `/kelas/${kelasId['KIF-101']}/finalisasi`, { token: tBudi, device: 'DEV-DOSEN-01' });
  log('B: finalisasi via gateway 200 & sinkron KE service transkrip BERHASIL',
    r.status === 200 && r.json.sinkron === true && r.json.jumlah_nilai === 3, `status=${r.status} sinkron=${r.json?.sinkron}`);

  const rowT = db().prepare("SELECT nilai FROM transkrip WHERE kelas_id = ? AND user_id = (SELECT id FROM users WHERE nim='10522001')").get(kelasId['KIF-101']);
  log('B: DB transkrip berisi nilai hasil sinkron (95)', rowT?.nilai === 95, `nilai=${rowT?.nilai}`);

  r = await call(G, 'PUT', `/nilai/${nilaiBudi}`, { token: tBudi, device: 'DEV-DOSEN-01', body: { nilai: 1 } });
  log('B: nilai setelah finalisasi tidak bisa diubah 403 ALREADY_FINAL (gateway)', r.status === 403 && r.json.error.code === 'ALREADY_FINAL', `code=${r.json?.error?.code}`);

  // --- Token service (client credentials) ---
  r = await call(G, 'POST', '/auth/service', { body: { clientId: 'nilai-service', clientSecret: 'salah' } });
  log('B: /auth/service secret salah 401', r.status === 401, `status=${r.status}`);

  r = await call(G, 'POST', '/auth/service', { body: { clientId: process.env.SERVICE_CLIENT_ID, clientSecret: process.env.SERVICE_CLIENT_SECRET } });
  const st = r.json?.accessToken ? jwt.decode(r.json.accessToken) : null;
  log('B: /auth/service valid 200, TTL 300, role service', r.status === 200 && st.role === 'service' && (st.exp - st.iat) === 300,
    `ttl=${st ? st.exp - st.iat : '-'}`);
  log('B: izinkan /auth/service terekam di audit (subject service)', auditCount('allow', 'POST /auth/service') >= 1, `rows=${auditCount('allow', 'POST /auth/service')}`);
  log('B: izinkan /transkrip/sinkron dengan token service terekam di audit', auditCount('allow', 'POST /transkrip/sinkron') >= 1, `rows=${auditCount('allow', 'POST /transkrip/sinkron')}`);

  // --- Refresh & logout ---
  r = await call(G, 'POST', '/auth/refresh', { device: 'DEV-DOSEN-01', token: rtBudi, body: { refreshToken: 'bogus' } });
  log('B: refresh token tidak dikenal 401', r.status === 401 && r.json.error.code === 'REFRESH_TOKEN_INVALID', `code=${r.json?.error?.code}`);

  r = await call(G, 'POST', '/auth/refresh', { device: 'DEV-DOSEN-01', body: { refreshToken: rtBudi } });
  const rtBaru = r.json?.refreshToken;
  log('B: refresh valid 200 & rotasi token', r.status === 200 && !!rtBaru && rtBaru !== rtBudi, `status=${r.status}`);

  r = await call(G, 'POST', '/auth/refresh', { device: 'DEV-DOSEN-01', body: { refreshToken: rtBudi } });
  log('B: refresh token lama yang diputar tidak bisa dipakai 401 REVOKED', r.status === 401 && r.json.error.code === 'REFRESH_TOKEN_REVOKED', `code=${r.json?.error?.code}`);

  r = await call(G, 'POST', '/auth/logout', { device: 'DEV-DOSEN-01', body: { refreshToken: rtBaru } });
  log('B: logout mencabut refresh token 200', r.status === 200, `status=${r.status}`);

  r = await call(G, 'POST', '/auth/refresh', { device: 'DEV-DOSEN-01', body: { refreshToken: rtBaru } });
  log('B: refresh token yang dicabut tidak bisa dipakai 401', r.status === 401 && r.json.error.code === 'REFRESH_TOKEN_REVOKED', `code=${r.json?.error?.code}`);

  // refresh token kedaluwarsa (disisipkan langsung ke DB untuk kasus ini)
  const hash = require('crypto').createHash('sha256').update('rt-expired-demo').digest('hex');
  db().prepare(`
    INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked)
    VALUES ((SELECT id FROM users WHERE username='10522002'), ?, '2000-01-01T00:00:00.000Z', 0)
  `).run(hash);
  r = await call(G, 'POST', '/auth/refresh', { device: 'DEV-MHS-02', body: { refreshToken: 'rt-expired-demo' } });
  log('B: refresh token kedaluwarsa ditolak 401 EXPIRED', r.status === 401 && r.json.error.code === 'REFRESH_TOKEN_EXPIRED', `code=${r.json?.error?.code}`);

  // --- Kebersihan audit log ---
  const dirtyRows = auditSecretRows();
  for (const r of dirtyRows) console.log('  [audit-dirty]', JSON.stringify(r));
  log('B: audit tanpa bocoran nilai token (scan eyJ/Bearer)', dirtyRows.length === 0, `rows=${dirtyRows.length}`);
  log('B: audit berisi allow & deny', auditKind('allow') > 0 && auditKind('deny') > 0,
    `allow=${auditKind('allow')} deny=${auditKind('deny')}`);

  stopAll(procs);
  await new Promise((r) => setTimeout(r, 400));

  execFileSync(process.execPath, ['database/seed.js', '--reset'], { cwd: path.join(__dirname, '..'), stdio: 'ignore' });
  console.log('\n[teardown] database di-reset ke kondisi seed bersih.');

  console.log(`\nHasil: ${pass} PASS, ${fail} FAIL`);
  process.exit(fail === 0 ? 0 : 1);
}

function auditClear() {
  db().prepare('DELETE FROM audit_logs').run();
}

main().catch((e) => { console.error('Uji gagal dijalankan:', e); process.exit(1); });
