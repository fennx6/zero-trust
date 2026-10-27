// ============================================================
// services/nilai/routes.js
// Resource data nilai dan kelas.
// Semua route dipasang SETELAH requireGatewaySecret + requireJwt,
// jadi identitas selalu dari token terverifikasi.
// Policy kepemilikan (kelas yang diampu / nilai mahasiswa sendiri)
// dicek dari relasi database — bukan hanya role.
// ============================================================

const express = require('express');
const { getDb } = require('../../shared/database');
const { deny, requireRole, findUserByUsername } = require('../../shared/middleware');
const { isWithinAccessHours } = require('../../shared/hours');
const { sinkronKeTranskrip } = require('./service-client');

const router = express.Router();

const sqlNilaiMahasiswa = `
  SELECT k.id AS kelas_id, k.kode, k.nama AS nama_kelas, n.id AS nilai_id,
         n.nilai, n.final, n.updated_at
  FROM nilai n
  JOIN kelas k ON k.id = n.kelas_id
  WHERE n.user_id = ?
  ORDER BY k.kode
`;

const sqlNilaiDosenPerKelas = `
  SELECT k.id AS kelas_id, k.kode, k.nama AS nama_kelas,
         u.nim, u.nama AS nama_mahasiswa, n.id AS nilai_id,
         n.nilai, n.final, n.updated_at
  FROM kelas k
  JOIN enrollments e ON e.kelas_id = k.id
  JOIN users u       ON u.id = e.user_id
  LEFT JOIN nilai n  ON n.kelas_id = k.id AND n.user_id = u.id
  WHERE k.dosen_id = ?
  ORDER BY k.kode, u.nim
`;

/**
 * GET /nilai
 *  - mahasiswa: nilai miliknya saja (nilai n.user_id = user token).
 *  - dosen    : nilai pada kelas yang diampu (kelas k.dosen_id = user token).
 *  - admin/service: ditolak.
 */
router.get('/nilai', requireRole('mahasiswa', 'dosen'), (req, res) => {
  const user = findUserByUsername(req.auth.sub);
  if (!user) return deny(res, 401, 'UNKNOWN_SUBJECT', 'User pada token tidak dikenal.');
  const db = getDb();

  if (user.role === 'mahasiswa') {
    const rows = db.prepare(sqlNilaiMahasiswa).all(user.id);
    return res.status(200).json({
      peran: 'mahasiswa',
      nilai: rows.map((r) => ({
        kode: r.kode,
        nama_kelas: r.nama_kelas,
        nilai: r.nilai,
        final: !!r.final,
        updated_at: r.updated_at,
      })),
    });
  }

  // dosen: grup per kelas (LEFT JOIN agar peserta tanpa nilai tetap tampil).
  const rows = db.prepare(sqlNilaiDosenPerKelas).all(user.id);
  const byKelas = new Map();
  for (const r of rows) {
    if (!byKelas.has(r.kode)) {
      byKelas.set(r.kode, { kelas: { id: r.kelas_id, kode: r.kode, nama: r.nama_kelas }, peserta: [] });
    }
    byKelas.get(r.kode).peserta.push({
      nim: r.nim,
      nama: r.nama_mahasiswa,
      nilai_id: r.nilai_id,
      nilai: r.nilai,
      final: r.final ? true : false,
      updated_at: r.updated_at,
    });
  }
  return res.status(200).json({ peran: 'dosen', kelas: [...byKelas.values()] });
});

/**
 * Cari target nilai PUT: baris nilai eksisting (update) atau
 * enrollment tanpa nilai (insert pertama kali). Return {kelas, nilai}
 */
function findPutTarget(db, id) {
  const nilaiRow = db.prepare(`
    SELECT n.id AS nilai_id, n.nilai, n.final, n.user_id, k.id AS kelas_id, k.kode, k.dosen_id
    FROM nilai n JOIN kelas k ON k.id = n.kelas_id
    WHERE n.id = ?
  `).get(id);
  if (nilaiRow) return { kelas: nilaiRow, nilai: nilaiRow };

  // Belum ada baris nilai? Interprestasikan :id sebagai enrollment id
  // (asumsi terdokumentasi di README): PUT pertama kali menciptakan nilai.
  const enroll = db.prepare(`
    SELECT e.id, e.kelas_id, e.user_id, k.kode, k.dosen_id
    FROM enrollments e JOIN kelas k ON k.id = e.kelas_id
    WHERE e.id = ?
  `).get(id);
  if (enroll) return { kelas: enroll, nilai: null };
  return null;
}

/**
 * PUT /nilai/:id
 *  - hanya dosen pengampu kelas nilai itu (ownership dari DB).
 *  - nilai yang sudah final tidak boleh diubah (409).
 *  - harus dalam jam akses (403 OUTSIDE_ACCESS_HOURS).
 *  - body: { nilai: 0..100 }
 */
router.put('/nilai/:id', requireRole('dosen'), (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return deny(res, 400, 'VALIDATION', 'Parameter :id tidak valid.');
  }
  const body = req.body || {};
  const nilaiBaru = body.nilai;
  if (!Number.isInteger(nilaiBaru) || nilaiBaru < 0 || nilaiBaru > 100) {
    return deny(res, 400, 'VALIDATION', 'Field "nilai" wajib integer 0-100.');
  }

  const db = getDb();
  const dosen = findUserByUsername(req.auth.sub);
  if (!dosen || dosen.role !== 'dosen') {
    return deny(res, 403, 'FORBIDDEN_ROLE', 'Hanya dosen yang boleh mengubah nilai.');
  }

  const target = findPutTarget(db, id);
  if (!target) return deny(res, 404, 'NOT_FOUND', 'Nilai/enrollment tidak ditemukan.');

  // Ownership: kelas harus diampu dosen dari token.
  if (target.kelas.dosen_id !== dosen.id) {
    return deny(res, 403, 'FORBIDDEN_OWNERSHIP', 'Kelas ini bukan kelas yang Anda ampu.');
  }

  if (target.nilai && target.nilai.final === 1) {
    return deny(res, 409, 'ALREADY_FINAL', 'Nilai sudah final dan tidak dapat diubah.');
  }

  // Jam akses ditolak setelah ownership agar pesan rapi; policy final.
  const hours = isWithinAccessHours();
  if (!hours.allowed) return deny(res, 403, 'OUTSIDE_ACCESS_HOURS', hours.reason);

  if (target.nilai) {
    db.prepare('UPDATE nilai SET nilai = ?, updated_at = ? WHERE id = ?')
      .run(nilaiBaru, new Date().toISOString(), target.nilai.nilai_id);
  } else {
    db.prepare('INSERT INTO nilai (kelas_id, user_id, nilai, final) VALUES (?, ?, ?, 0)')
      .run(target.kelas.kelas_id, target.kelas.user_id, nilaiBaru);
  }

  return res.status(200).json({
    message: 'Nilai diperbarui.',
    kelas: target.kelas.kode,
    nilai: nilaiBaru,
    final: false,
  });
});

/**
 * POST /kelas/:id/finalisasi
 *  - hanya dosen pengampu; harus dalam jam akses.
 *  - menandai semua nilai kelas final=1, lalu sinkron ke Service
 *    Transkrip MELALUI GATEWAY pakai token service (bukan langsung 3002).
 *  - jika gateway/gateway-sync gagal, finalisasi tetap kedudukan final
 *    dan respons menyatakan sinkron=false agar bisa dipanggil ulang.
 */
router.post('/kelas/:id/finalisasi', requireRole('dosen'), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return deny(res, 400, 'VALIDATION', 'Parameter :id tidak valid.');
  }

  const db = getDb();
  const dosen = findUserByUsername(req.auth.sub);
  const kelas = db.prepare('SELECT id, kode, nama, dosen_id FROM kelas WHERE id = ?').get(id);
  if (!kelas) return deny(res, 404, 'NOT_FOUND', 'Kelas tidak ditemukan.');
  if (kelas.dosen_id !== dosen.id) {
    return deny(res, 403, 'FORBIDDEN_OWNERSHIP', 'Kelas ini bukan kelas yang Anda ampu.');
  }

  const hours = isWithinAccessHours();
  if (!hours.allowed) return deny(res, 403, 'OUTSIDE_ACCESS_HOURS', hours.reason);

  const nilaiRows = db.prepare(`
    SELECT n.id, n.nilai, u.nim, u.nama
    FROM nilai n JOIN users u ON u.id = n.user_id
    WHERE n.kelas_id = ?
  `).all(kelas.id);

  // Finalisasi: tandai final=1 untuk semua nilai kelas ini (transaksional).
  const finalizeStmt = db.prepare('UPDATE nilai SET final = 1, updated_at = ? WHERE kelas_id = ?');
  db.transaction(() => { finalizeStmt.run(new Date().toISOString(), kelas.id); })();

  // Sinkronisasi lewat gateway (mohon sekuensial, per nilai). Jika gagal,
  // lapor sinkron=false agar pemanggil bisa retry tanpa merusak status final.
  const hasil = [];
  let sinkronOk = true;
  for (const r of nilaiRows) {
    const out = await sinkronKeTranskrip({ nim: r.nim, kelasCode: kelas.kode, nilai: r.nilai });
    const ok = out.sent && out.status === 200;
    sinkronOk = sinkronOk && ok;
    hasil.push({ nim: r.nim, nilai: r.nilai, sinkron: ok, status: out.status });
    if (!ok) {
      console.error(`[nilai] sinkron gagal utk ${r.nim} ${kelas.kode}: HTTP ${out.status} ${out.message}`);
    }
  }

  return res.status(200).json({
    message: 'Kelas difinalisasi.',
    kelas: kelas.kode,
    jumlah_nilai: nilaiRows.length,
    sinkron: sinkronOk,
    detail_sinkron: hasil,
  });
});

module.exports = router;
