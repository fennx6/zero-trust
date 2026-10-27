// Skrip verifikasi cepat isi database setelah seed (bukan bagian aplikasi).
const { getDb } = require('../shared/database');
const bcrypt = require('bcryptjs');

const db = getDb();
const count = (sql) => db.prepare(sql).get().n;

console.log('--- Jumlah baris ---');
console.log('users           :', count('SELECT COUNT(*) n FROM users'));
console.log('devices         :', count('SELECT COUNT(*) n FROM devices'));
console.log('kelas           :', count('SELECT COUNT(*) n FROM kelas'));
console.log('enrollments     :', count('SELECT COUNT(*) n FROM enrollments'));
console.log('nilai           :', count('SELECT COUNT(*) n FROM nilai'));
console.log('nilai final     :', count('SELECT COUNT(*) n FROM nilai WHERE final = 1'));
console.log('transkrip       :', count('SELECT COUNT(*) n FROM transkrip'));
console.log('audit_logs      :', count('SELECT COUNT(*) n FROM audit_logs'));
console.log('refresh_tokens  :', count('SELECT COUNT(*) n FROM refresh_tokens'));

console.log('\n--- Relasi kelas -> dosen ---');
for (const r of db.prepare(
  'SELECT k.kode, k.nama, u.username AS dosen FROM kelas k JOIN users u ON u.id = k.dosen_id'
).all()) {
  console.log(` ${r.kode} ${r.nama} -> ${r.dosen}`);
}

console.log('\n--- Cek hash password admin ---');
const admin = db.prepare("SELECT username, password_hash FROM users WHERE username = 'admin'").get();
console.log(' hash  :', admin.password_hash.slice(0, 29) + '...');
console.log(' hash ok:', admin.password_hash.startsWith('$2'), '| bcrypt matches:', bcrypt.compareSync('Admin#12345', admin.password_hash));
