// ============================================================
// services/transkrip/routes.js
// Resource data transkrip mahasiswa.
// Semua endpoint DI BAWAH ini dipasang SETELAH middleware
// requireGatewaySecret + requireJwt, jadi identitas selalu berasal
// dari token yang sudah diverifikasi — bukan dari header client.
// ============================================================

const express = require('express');
const { getDb } = require('../../shared/database');
const { deny, requireRole, findUserByUsername } = require('../../shared/middleware');

const router = express.Router();

/** Bentuk transkrip yang dikirim ke client tanpa data internal. */
function shapeRow(r) {
  return {
    nim: r.nim,
    kode: r.kode,
    nama_kelas: r.nama_kelas,
    nilai: r.nilai,
    synced_at: r.synced_at,
  };
}

const sqlTranskripByNim = `
  SELECT u.nim, u.nama AS nama_mahasiswa, k.kode, k.nama AS nama_kelas,
         t.nilai, t.synced_at
  FROM transkrip t
  JOIN users u ON u.id = t.user_id
  JOIN kelas k ON k.id = t.kelas_id
  WHERE u.nim = ?
  ORDER BY k.kode
`;

/**
 * POST /transkrip/sinkron — hanya token dengan role "service".
 * Token user (mahasiswa/dosen/admin) ditolak: 403.
 */
router.post('/transkrip/sinkron', requireRole('service'), (req, res) => {
  const body = req.body || {};
  const { nim, kelasCode, nilai } = body;

  // Validasi input (konsisten, tanpa gabungkan input ke SQL).
  if (typeof nim !== 'string' || nim.trim() === '') {
    return deny(res, 400, 'VALIDATION', 'Field "nim" wajib berupa string.');
  }
  if (typeof kelasCode !== 'string' || kelasCode.trim() === '') {
    return deny(res, 400, 'VALIDATION', 'Field "kelasCode" wajib berupa string.');
  }
  if (!Number.isInteger(nilai) || nilai < 0 || nilai > 100) {
    return deny(res, 400, 'VALIDATION', 'Field "nilai" wajib integer 0-100.');
  }

  const db = getDb();

  const mahasiswa = db.prepare("SELECT id, username, nama FROM users WHERE nim = ? AND role = 'mahasiswa'").get(nim);
  if (!mahasiswa) {
    return deny(res, 404, 'NOT_FOUND', `Mahasiswa NIM ${nim} tidak ditemukan.`);
  }
  const kelas = db.prepare('SELECT id, kode, nama FROM kelas WHERE kode = ?').get(kelasCode);
  if (!kelas) {
    return deny(res, 404, 'NOT_FOUND', `Kelas ${kelasCode} tidak ditemukan.`);
  }

  // Upsert transkrip: nilai final dari Service Nilai menimpa nilai lama
  // untuk pasangan (mahasiswa, kelas) yang sama.
  const syncedAt = new Date().toISOString();
  const upsert = db.prepare(`
    INSERT INTO transkrip (user_id, kelas_id, nilai, synced_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT (user_id, kelas_id)
    DO UPDATE SET nilai = excluded.nilai, synced_at = excluded.synced_at
  `);

  let result;
  db.transaction(() => {
    result = upsert.run(mahasiswa.id, kelas.id, nilai, syncedAt);
  })();

  return res.status(200).json({
    message: 'Transkrip tersinkron.',
    nim,
    kelas: kelas.kode,
    nilai,
    synced_at: syncedAt,
  });
});

/**
 * GET /transkrip/:nim
 *  - mahasiswa: hanya NIM miliknya sendiri (dari token -> user.nim).
 *  - admin    : boleh NIM mana pun.
 *  - role lain (dosen/service): ditolak.
 */
router.get('/transkrip/:nim', requireRole('mahasiswa', 'admin'), (req, res) => {
  const nimParam = String(req.params.nim || '').trim();
  if (!/^\d{6,12}$/.test(nimParam)) {
    return deny(res, 400, 'VALIDATION', 'Format NIM tidak valid.');
  }

  const requester = findUserByUsername(req.auth.sub);
  if (!requester) {
    // Token valid tapi user sudah tidak ada di database.
    return deny(res, 401, 'UNKNOWN_SUBJECT', 'User pada token tidak dikenal.');
  }

  // Policy kepemilikan ditegakkan DI SINI juga (pertahanan berlapis —
  // gateway sudah menegakkan hal yang sama):
  if (requester.role === 'mahasiswa' && requester.nim !== nimParam) {
    return deny(res, 403, 'FORBIDDEN_OWNERSHIP', 'Mahasiswa hanya boleh melihat transkrip miliknya.');
  }

  const rows = getDb().prepare(sqlTranskripByNim).all(nimParam);
  if (rows.length === 0) {
    // Bedakan: nim tidak ada vs transkrip kosong.
    const mhs = getDb().prepare("SELECT nim, nama FROM users WHERE nim = ? AND role = 'mahasiswa'").get(nimParam);
    if (!mhs) {
      return deny(res, 404, 'NOT_FOUND', `Mahasiswa NIM ${nimParam} tidak ditemukan.`);
    }
    return res.status(200).json({ nim: mhs.nim, nama: mhs.nama, transkrip: [] });
  }

  return res.status(200).json({
    nim: rows[0].nim,
    nama: rows[0].nama_mahasiswa,
    transkrip: rows.map(shapeRow),
  });
});

module.exports = router;
