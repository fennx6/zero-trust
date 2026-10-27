// ============================================================
// tests/test-nilai.js
// Uji Service Nilai (port 3001) — skenario negatif & positif.
// Skrip INI sendiri men-spawn server dua kali:
//   Fase A: konfigurasi jam akses DI LUAR waktu sekarang (uji 403 jam akses)
//   Fase B: jam akses 00:00-24:00 (uji alur penuh, termasuk finalisasi yang
//           mencoba sinkron ke GATEWAY — belum ada, jadi sinkron=false)
// Setelah selesai, seed di-reset agar data demo kembali bersih.
// Jalankan: node tests/test-nilai.js
// ============================================================

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const { spawn } = require('child_process');
const { execFileSync } = require('child_process');
const { getDb } = require('../shared/database');
const { nowInZone } = require('../shared/hours');
const { signAccessToken } = require('../shared/token');
const jwt = require('jsonwebtoken');

const PORT = Number(process.env.SERVICE_NILAI_PORT || 3001);
const BASE = `http://localhost:${PORT}`;
const CHILD_ENV_EXTRA = {};

let pass = 0, fail = 0;
function log(name, ok, detail) {
  if (ok) pass++; else fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  -> ' + detail : ''}`);
}

async function call(method, urlPath, { secret = true, token = null, body = null } = {}) {
  const headers = {};
  if (secret) headers['X-Gateway-Secret'] = process.env.GATEWAY_SECRET;
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (body) headers['Content-Type'] = 'application/json';
  const res = await fetch(BASE + urlPath, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch { /* abaikan */ }
  return { status: res.status, json };
}

/** Spawn server service nilai dengan env tertentu; tunggu /health siap. */
async function startServer(extraEnv) {
  const child = spawn(process.execPath, ['services/nilai/server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (d) => (out += d));
  child.stderr.on('data', (d) => (out += d));

  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) { child.ready = true; return child; }
    } catch { /* belum siap */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  child.kill();
  throw new Error('Server tidak siap dalam 10 detik. Log:\n' + out.slice(-2000));
}

async function main() {
  const db = getDb();
  const kodesKelas = Object.fromEntries(
    db.prepare('SELECT id, kode FROM kelas').all().map((r) => [r.kode, r.id])
  );
  const nilaiBudi = db.prepare(`
    SELECT n.id FROM nilai n JOIN kelas k ON k.id = n.kelas_id JOIN users u ON u.id = n.user_id
    WHERE k.kode = 'KIF-101' AND u.nim = '10522001'
  `).get().id;
  const nilaiSitiFinal = db.prepare(`
    SELECT n.id FROM nilai n JOIN kelas k ON k.id = n.kelas_id JOIN users u ON u.id = n.user_id
    WHERE k.kode = 'KIF-102' AND u.nim = '10522001'
  `).get().id;
  const enrollCahyoKIF102 = db.prepare(`
    SELECT e.id FROM enrollments e JOIN users u ON u.id = e.user_id JOIN kelas k ON k.id = e.kelas_id
    WHERE k.kode = 'KIF-102' AND u.nim = '10522003'
  `).get().id;

  const tMhs1 = signAccessToken({ sub: '10522001', role: 'mahasiswa' });
  const tMhs2 = signAccessToken({ sub: '10522002', role: 'mahasiswa' });
  const tDosenBudi = signAccessToken({ sub: 'budi.santoso', role: 'dosen' });
  const tDosenSiti = signAccessToken({ sub: 'siti.rahayu', role: 'dosen' });
  const tAdmin = signAccessToken({ sub: 'admin', role: 'admin' });
  const tService = jwt.sign({ sub: 'nilai-service', role: 'service' }, process.env.JWT_SECRET, { expiresIn: 60 });

  // ---------------- FASE A: DI LUAR JAM AKSES ----------------
  console.log('\n=== FASE A: di luar jam akses ===');
  const nowJakarta = nowInZone('Asia/Jakarta');
  const startA = (nowJakarta.hour + 1) % 24;
  const endA = (nowJakarta.hour + 2) % 24;
  let child = await startServer({ ACCESS_START_HOUR: startA, ACCESS_END_HOUR: endA });

  let r = await call('PUT', `/nilai/${nilaiBudi}`, { token: tDosenBudi, body: { nilai: 95 } });
  log('A: PUT di luar jam ditolak 403', r.status === 403 && r.json.error.code === 'OUTSIDE_ACCESS_HOURS',
    `status=${r.status} code=${r.json?.error?.code} (jam=${nowJakarta.hour})`);
  r = await call('POST', `/kelas/${kodesKelas['KIF-101']}/finalisasi`, { token: tDosenBudi });
  log('A: finalisasi di luar jam ditolak 403', r.status === 403 && r.json.error.code === 'OUTSIDE_ACCESS_HOURS',
    `status=${r.status}`);

  // Uji lapisan secret/JWT juga (sekali cukup, karena bersifat lintas service).
  r = await call('GET', '/nilai', { secret: false, token: tMhs1 });
  log('A: tanpa X-Gateway-Secret ditolak 401', r.status === 401, `code=${r.json?.error?.code}`);
  r = await call('GET', '/nilai', { token: null });
  log('A: token hilang ditolak 401', r.status === 401 && r.json.error.code === 'TOKEN_MISSING', `code=${r.json?.error?.code}`);
  r = await call('GET', '/nilai', { token: jwt.sign({ sub: '10522001', role: 'mahasiswa' }, 'secret-salah', { expiresIn: 60 }) });
  log('A: token tanda tangan salah ditolak 401', r.status === 401, `code=${r.json?.error?.code}`);

  child.kill();
  await new Promise((r) => setTimeout(r, 300));

  // ---------------- FASE B: DI DALAM JAM AKSES ----------------
  console.log('\n=== FASE B: di dalam jam akses (00-24) ===');
  child = await startServer({ ACCESS_START_HOUR: 0, ACCESS_END_HOUR: 24 });

  r = await call('GET', '/nilai', { token: tAdmin });
  log('B: admin GET /nilai ditolak 403', r.status === 403, `status=${r.status}`);
  r = await call('GET', '/nilai', { token: tService });
  log('B: token service GET /nilai ditolak 403', r.status === 403, `status=${r.status}`);

  r = await call('GET', '/nilai', { token: tMhs1 });
  const nilaiMhs1 = r.json?.nilai;
  log('B: mahasiswa baca nilai miliknya 200 (2 kelas, bukan punya orang lain)',
    r.status === 200 && Array.isArray(nilaiMhs1) && nilaiMhs1.length === 2 &&
    nilaiMhs1.every((n) => n.kode === 'KIF-101' || n.kode === 'KIF-102'),
    `status=${r.status} rows=${nilaiMhs1?.length}`);

  r = await call('GET', '/nilai', { token: tMhs2 });
  log('B: mahasiswa-2 lihat baris miliknya (berbeda dari mhs-1, tidak ada bocor data lain)',
    r.status === 200 && r.json.nilai.length === 2 && JSON.stringify(r.json.nilai.map((n) => n.nilai)) !== JSON.stringify(nilaiMhs1.map((n) => n.nilai)),
    `rows=${r.json?.nilai?.length}`);

  r = await call('GET', '/nilai', { token: tDosenBudi });
  const kelasBudi = r.json?.kelas;
  log('B: dosen budi hanya lihat KIF-101 (3 peserta)',
    r.status === 200 && kelasBudi?.length === 1 && kelasBudi[0].kelas.kode === 'KIF-101' && kelasBudi[0].peserta.length === 3,
    `kelas=${kelasBudi?.length} peserta=${kelasBudi?.[0]?.peserta?.length}`);

  r = await call('GET', '/nilai', { token: tDosenSiti });
  const pesertaSiti = r.json?.kelas?.[0];
  log('B: dosen siti hanya lihat KIF-102, peserta tanpa nilai tampil (nilai null)',
    r.status === 200 && pesertaSiti?.kelas.kode === 'KIF-102' &&
    pesertaSiti.peserta.length === 3 &&
    pesertaSiti.peserta.find((p) => p.nim === '10522003')?.nilai === null,
    `kode=${pesertaSiti?.kelas?.kode} peserta=${pesertaSiti?.peserta?.length}`);

  r = await call('PUT', `/nilai/${nilaiBudi}`, { token: tMhs1, body: { nilai: 1 } });
  log('B: mahasiswa PUT nilai ditolak 403', r.status === 403, `status=${r.status}`);

  r = await call('PUT', `/nilai/${nilaiSitiFinal}`, { token: tDosenBudi, body: { nilai: 1 } });
  log('B: dosen budi ubah nilai kelas siti ditolak 403 (ownership)', r.status === 403 && r.json.error.code === 'FORBIDDEN_OWNERSHIP',
    `code=${r.json?.error?.code}`);

  r = await call('PUT', `/nilai/${nilaiSitiFinal}`, { token: tDosenSiti, body: { nilai: 1 } });
  log('B: nilai sudah final tidak dapat diubah 409', r.status === 409 && r.json.error.code === 'ALREADY_FINAL',
    `code=${r.json?.error?.code}`);

  r = await call('PUT', `/nilai/${nilaiBudi}`, { token: tDosenBudi, body: { nilai: 95 } });
  log('B: dosen pengampu ubah nilai 200', r.status === 200 && r.json.nilai === 95, `status=${r.status}`);
  r = await call('GET', '/nilai', { token: tMhs1 });
  log('B: perubahan terverifikasi dibaca mahasiswa (95)', r.json?.nilai?.find((n) => n.kode === 'KIF-101')?.nilai === 95,
    `nilai=${r.json?.nilai?.find((n) => n.kode === 'KIF-101')?.nilai}`);

  r = await call('PUT', `/nilai/${nilaiBudi}`, { token: tDosenBudi, body: { nilai: 999 } });
  log('B: nilai diluar 0-100 ditolak 400', r.status === 400, `status=${r.status}`);

  // Insert nilai baru via PUT id enrollment (asumsi terdokumentasi).
  r = await call('PUT', `/nilai/${enrollCahyoKIF102}`, { token: tDosenSiti, body: { nilai: 77 } });
  log('B: siswa belum dinilai mendapat nilai baru 200', r.status === 200 && r.json.nilai === 77, `status=${r.status}`);

  r = await call('POST', `/kelas/99999/finalisasi`, { token: tDosenBudi });
  log('B: finalisasi kelas tidak ada 404', r.status === 404, `status=${r.status}`);
  r = await call('POST', `/kelas/${kodesKelas['KIF-102']}/finalisasi`, { token: tDosenBudi });
  log('B: finalisasi kelas dosen lain ditolak 403', r.status === 403 && r.json.error.code === 'FORBIDDEN_OWNERSHIP',
    `code=${r.json?.error?.code}`);
  r = await call('POST', `/kelas/${kodesKelas['KIF-101']}/finalisasi`, { token: tMhs1 });
  log('B: mahasiswa finalisasi ditolak 403', r.status === 403, `status=${r.status}`);

  r = await call('POST', `/kelas/${kodesKelas['KIF-101']}/finalisasi`, { token: tDosenBudi });
  const fOk = r.status === 200 && r.json.message === 'Kelas difinalisasi.' && r.json.jumlah_nilai === 3 && r.json.sinkron === false;
  log('B: finalisasi saat gateway belum aktif: 200, final, sinkron=false', fOk,
    `status=${r.status} jumlah=${r.json?.jumlah_nilai} sinkron=${r.json?.sinkron}`);

  // Verifikasi DB langsung: semua nilai kelas 1 final=1.
  const finals = db.prepare('SELECT COUNT(*) n FROM nilai WHERE kelas_id = ? AND final = 1').get(kodesKelas['KIF-101']).n;
  log('B: DB memverifikasi 3 nilai final=1', finals === 3, `final=${finals}`);

  r = await call('PUT', `/nilai/${nilaiBudi}`, { token: tDosenBudi, body: { nilai: 5 } });
  log('B: setelah finalisasi, nilai kelas tidak bisa diubah 409', r.status === 409 && r.json.error.code === 'ALREADY_FINAL',
    `code=${r.json?.error?.code}`);

  child.kill();
  await new Promise((r) => setTimeout(r, 300));

  // Kembalikan database ke kondisi seed bersih.
  execFileSync(process.execPath, ['database/seed.js', '--reset'], { cwd: path.join(__dirname, '..'), stdio: 'ignore' });
  console.log('\n[teardown] database di-reset ke kondisi seed bersih.');

  console.log(`\nHasil: ${pass} PASS, ${fail} FAIL`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error('Uji gagal dijalankan:', e); process.exit(1); });
