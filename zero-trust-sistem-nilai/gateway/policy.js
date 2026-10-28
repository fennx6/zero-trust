// ============================================================
// gateway/policy.js
// Policy Engine (PDP). Fungsi murni yang mengevaluasi kebijakan:
//  - role yang berhak (least privilege)
//  - kepemilikan data diambil dari RELASI database
//    (kelas yang diampu dosen, NIM mahasiswa, nilai)
//  - jam akses (dari shared/hours.js, configurable)
// Gateway TIDAK mempercayai asumsi client — semuanya dari DB.
//
// Keputusan: { allow, target?, status?, code?, reason }
// ============================================================

const { getDb } = require('../shared/database');
const { isWithinAccessHours } = require('../shared/hours');

function allow(target, reason) {
  return { allow: true, target, reason };
}
function deny(status, code, reason) {
  return { allow: false, status, code, reason };
}

/**
 * Evaluasi satu request.
 * @param {{method:string, path:string, auth:{sub,role}, user:object|null, deviceId:string|null}} ctx
 */
function decide({ method, path, auth, user, deviceId }) {
  const db = getDb();
  const role = auth.role;

  // Token service (dari Service Nilai melalui POST /auth/service):
  // hanya boleh untuk operational antar-service yang diizinkan.
  if (role === 'service') {
    if (method === 'POST' && path === '/transkrip/sinkron') {
      return allow('transkrip', 'Token service valid untuk sinkronisasi transkrip.');
    }
    return deny(403, 'SERVICE_SCOPE_LIMITED', 'Token service hanya boleh digunakan untuk sinkronisasi transkrip.');
  }

  // GET /nilai — mahasiswa: miliknya; dosen: kelas yang diampu.
  if (method === 'GET' && path === '/nilai') {
    if (role === 'mahasiswa') return allow('nilai', 'Mahasiswa membaca nilai miliknya sendiri.');
    if (role === 'dosen') return allow('nilai', 'Dosen membaca nilai kelas yang diampu.');
    return deny(403, 'FORBIDDEN_ROLE', `Role ${role} tidak berhak membaca nilai.`);
  }

  // PUT /nilai/:id — hanya dosen pengampu, belum final, jam akses.
  const mPut = method === 'PUT' ? /^\/nilai\/(\d+)$/.exec(path) : null;
  if (mPut) {
    if (role !== 'dosen') return deny(403, 'FORBIDDEN_ROLE', 'Hanya dosen yang boleh mengubah nilai.');
    const id = Number(mPut[1]);

    // Objek yang dituju bisa berupa baris nilai EKSISTING atau
    // enrollment tanpa nilai (PUT pertama kali menciptakan nilai).
    const nilaiRow = db.prepare(`
      SELECT n.id, n.final, k.dosen_id, k.kode
      FROM nilai n JOIN kelas k ON k.id = n.kelas_id
      WHERE n.id = ?
    `).get(id);
    const enrollRow = nilaiRow ? null : db.prepare(`
      SELECT e.id, k.dosen_id, k.kode
      FROM enrollments e JOIN kelas k ON k.id = e.kelas_id
      WHERE e.id = ?
    `).get(id);

    const target = nilaiRow || enrollRow;
    if (!target) return deny(404, 'NOT_FOUND', 'Nilai / enrollment tidak ditemukan.');
    if (target.dosen_id !== user.id) {
      return deny(403, 'FORBIDDEN_OWNERSHIP', 'Kelas nilai itu bukan kelas yang Anda ampu.');
    }
    if (nilaiRow && nilaiRow.final === 1) {
      return deny(403, 'ALREADY_FINAL', 'Nilai sudah final dan tidak dapat diubah.');
    }
    const hours = isWithinAccessHours();
    if (!hours.allowed) return deny(403, 'OUTSIDE_ACCESS_HOURS', hours.reason);
    return allow('nilai', 'Dosen pengampu mengubah nilai yang belum final pada jam akses.');
  }

  // POST /kelas/:id/finalisasi — hanya dosen pengampu, jam akses.
  const mFin = method === 'POST' ? /^\/kelas\/(\d+)\/finalisasi$/.exec(path) : null;
  if (mFin) {
    if (role !== 'dosen') return deny(403, 'FORBIDDEN_ROLE', 'Hanya dosen yang boleh memfinalisasi kelas.');
    const kelas = db.prepare('SELECT id, kode, dosen_id FROM kelas WHERE id = ?').get(Number(mFin[1]));
    if (!kelas) return deny(404, 'NOT_FOUND', 'Kelas tidak ditemukan.');
    if (kelas.dosen_id !== user.id) {
      return deny(403, 'FORBIDDEN_OWNERSHIP', 'Kelas ini bukan kelas yang Anda ampu.');
    }
    const hours = isWithinAccessHours();
    if (!hours.allowed) return deny(403, 'OUTSIDE_ACCESS_HOURS', hours.reason);
    return allow('nilai', 'Dosen pengampu memfinalisasi kelas pada jam akses.');
  }

  // GET /transkrip/:nim — mahasiswa: NIM sendiri; admin: semua NIM.
  const mTr = method === 'GET' ? /^\/transkrip\/([A-Za-z0-9]+)$/.exec(path) : null;
  if (mTr) {
    const nim = mTr[1];
    if (role === 'mahasiswa') {
      if (user.nim !== nim) {
        return deny(403, 'FORBIDDEN_OWNERSHIP', 'Mahasiswa hanya boleh melihat transkrip miliknya.');
      }
      return allow('transkrip', 'Mahasiswa membaca transkrip miliknya sendiri.');
    }
    if (role === 'admin') return allow('transkrip', 'Admin melihat transkrip mahasiswa mana pun.');
    return deny(403, 'FORBIDDEN_ROLE', `Role ${role} tidak berhak membaca transkrip.`);
  }

  // POST /transkrip/sinkron — LARANG token user; hanya service (dicek di atas).
  if (method === 'POST' && path === '/transkrip/sinkron') {
    return deny(403, 'ENDPOINT_SERVICE_ONLY', 'Endpoint ini hanya untuk token service; token user ditolak.');
  }

  return deny(404, 'NO_ROUTE', 'Endpoint tidak dikenal oleh gateway.');
}

module.exports = { decide };
