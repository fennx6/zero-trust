// ============================================================
// database/seed.js
// Seed data demo: 1 admin, 2 dosen, 3 mahasiswa, 2 kelas
// (dosen pengampu berbeda), 1 device per user, dan beberapa
// nilai (termasuk yang sudah final untuk skenario pengujian).
//
// Rerun yang aman:
//   node database/seed.js            -> seed hanya jika belum ter-seed
//   node database/seed.js --reset    -> hapus data demo lalu seed ulang
// ============================================================

const path = require('path');
const bcrypt = require('bcryptjs');
const { getDb, applySchema } = require('../shared/database');

const BcryptRounds = 10;

// Data akun demo. Password demo sengaja sederhana dan
// didokumentasikan di README; di database hanya tersimpan hash.
const USERS = [
  { username: 'admin',        nama: 'Admin Prodi',    role: 'admin',     nim: null,      password: 'Admin#12345' },
  { username: 'budi.santoso', nama: 'Budi Santoso',   role: 'dosen',     nim: null,      password: 'Dosen#12345' },
  { username: 'siti.rahayu',  nama: 'Siti Rahayu',    role: 'dosen',     nim: null,      password: 'Dosen#12345' },
  { username: '10522001',     nama: 'Andi Praputra',  role: 'mahasiswa', nim: '10522001', password: 'Mhs#12345' },
  { username: '10522002',     nama: 'Bela Sari',      role: 'mahasiswa', nim: '10522002', password: 'Mhs#12345' },
  { username: '10522003',     nama: 'Cahyo Wibowo',   role: 'mahasiswa', nim: '10522003', password: 'Mhs#12345' },
];

const DEVICES = [
  { username: 'admin',    deviceId: 'DEV-ADMIN-01', label: 'Laptop Admin' },
  { username: 'budi.santoso', deviceId: 'DEV-DOSEN-01', label: 'Laptop Budi' },
  { username: 'siti.rahayu',  deviceId: 'DEV-DOSEN-02', label: 'Laptop Siti' },
  { username: '10522001', deviceId: 'DEV-MHS-01',   label: 'Laptop Andi' },
  { username: '10522002', deviceId: 'DEV-MHS-02',   label: 'Laptop Bela' },
  { username: '10522003', deviceId: 'DEV-MHS-03',   label: 'Laptop Cahyo' },
];

// Kelas: kode, nama, dan username dosen pengampu (berbeda).
const KELAS = [
  { kode: 'KIF-101', nama: 'Pemrograman Web',   dosen: 'budi.santoso' },
  { kode: 'KIF-102', nama: 'Basis Data',        dosen: 'siti.rahayu' },
];

// Semua mahasiswa mengambil kedua kelas.
function enrollUsernames() {
  return USERS.filter((u) => u.role === 'mahasiswa').map((u) => u.username);
}

function isSeeded(db) {
  return db.prepare('SELECT COUNT(*) AS n FROM users').get().n > 0;
}

function wipeDemoData(db) {
  // Urutan menghormati foreign key (tanpa OFF pragma).
  db.prepare('DELETE FROM nilai').run();
  db.prepare('DELETE FROM transkrip').run();
  db.prepare('DELETE FROM enrollments').run();
  db.prepare('DELETE FROM kelas').run();
  db.prepare('DELETE FROM refresh_tokens').run();
  db.prepare('DELETE FROM devices').run();
  db.prepare('DELETE FROM users').run();
  db.prepare('DELETE FROM audit_logs').run();
}

function seed() {
  const db = getDb();
  applySchema();

  if (isSeeded(db) && !process.argv.includes('--reset')) {
    console.log('[seed] Database sudah berisi data. Gunakan "--reset" untuk seed ulang dari awal.');
    return;
  }
  if (process.argv.includes('--reset')) {
    wipeDemoData(db);
    console.log('[seed] Data demo lama dihapus (audit log termasuk).');
  }

  const seededAt = new Date().toISOString();

  // Semua operasi seed dalam satu transaksi agar tidak setengah jalan.
  const run = db.transaction(() => {
    const insUser = db.prepare(
      'INSERT INTO users (username, nama, role, nim, password_hash) VALUES (?, ?, ?, ?, ?)'
    );
    const idByUsername = {};
    for (const u of USERS) {
      const info = insUser.run(
        u.username, u.nama, u.role, u.nim, bcrypt.hashSync(u.password, BcryptRounds)
      );
      idByUsername[u.username] = info.lastInsertRowid;
    }

    const insDevice = db.prepare(
      'INSERT INTO devices (user_id, device_id, label) VALUES (?, ?, ?)'
    );
    for (const d of DEVICES) {
      insDevice.run(idByUsername[d.username], d.deviceId, d.label);
    }

    const insKelas = db.prepare('INSERT INTO kelas (kode, nama, dosen_id) VALUES (?, ?, ?)');
    const idKelas = {};
    for (const k of KELAS) {
      const info = insKelas.run(k.kode, k.nama, idByUsername[k.dosen]);
      idKelas[k.kode] = info.lastInsertRowid;
    }

    const insEnroll = db.prepare(
      'INSERT INTO enrollments (kelas_id, user_id) VALUES (?, ?)'
    );
    for (const kodeKelas of Object.keys(idKelas)) {
      for (const mhs of enrollUsernames()) {
        insEnroll.run(idKelas[kodeKelas], idByUsername[mhs]);
      }
    }

    // Nilai awal untuk skenario uji:
    //  - KIF-101 (Budi)  : nilai ada, semua belum final  -> bisa diubah/finalisasi
    //  - KIF-102 (Siti)  : 2 nilai sudah final           -> uji "nilai final tak bisa diubah"
    //                      1 mahasiswa belum ada nilai   -> uji insert nilai baru
    const insNilai = db.prepare(
      'INSERT INTO nilai (kelas_id, user_id, nilai, final, updated_at) VALUES (?, ?, ?, ?, ?)'
    );
    for (const mhs of enrollUsernames()) {
      insNilai.run(idKelas['KIF-101'], idByUsername[mhs], 80, 0, seededAt);
    }
    insNilai.run(idKelas['KIF-102'], idByUsername['10522001'], 90, 1, seededAt);
    insNilai.run(idKelas['KIF-102'], idByUsername['10522002'], 75, 1, seededAt);
  });
  run();

  // Ringkasan akun demo (password demo juga didokumentasikan di README).
  console.log('[seed] Seed selesai. Ringkasan akun demo:');
  for (const u of USERS) {
    const dev = DEVICES.find((d) => d.username === u.username);
    console.log(
      `  - ${u.username.padEnd(14)} role=${u.role.padEnd(9)} password=${u.password.padEnd(12)} device=${dev.deviceId}`
    );
  }
  console.log('[seed] Kelas: KIF-101 (dosen budi.santoso), KIF-102 (dosen siti.rahayu).');
}

seed();
