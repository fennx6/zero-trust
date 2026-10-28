/**
 * Utilitas verifikasi skenario AGENTS §12 poin 20:
 * "Setiap keputusan allow/deny yang relevan tercatat dalam audit log".
 *
 * Pemakaian:  node tests/audit-check.js [jumlah_baris]
 *
 * Membaca tabel audit_logs langsung dari database bersama, mencetak
 * statistik allow/deny + N baris terakhir, dan memindai agar TIDAK ADA
 * token JWT (string berawalan "eyJ") bocor ke kolom audit.
 */
const { getDb } = require('../shared/database');

const jumlah = Number.parseInt(process.argv[2] || '15', 10);
const db = getDb();

const stats = db.prepare(`
  SELECT SUM(CASE WHEN result = 'allow' THEN 1 ELSE 0 END) AS allow,
         SUM(CASE WHEN result = 'deny'  THEN 1 ELSE 0 END) AS deny,
         COUNT(*) AS total
  FROM audit_logs
`).get();

const rows = db.prepare(`
  SELECT id, timestamp, subject_type, subject_id, endpoint, device_id, result, reason
  FROM audit_logs
  ORDER BY id DESC
  LIMIT ?
`).all(jumlah);

console.log(`Statistik audit_logs: total=${stats.total}, allow=${stats.allow ?? 0}, deny=${stats.deny ?? 0}`);
console.log(`${rows.length} baris terakhir:`);
for (const r of rows) {
  console.log(
    `#${r.id} ${r.timestamp} | ${r.result} | ${r.subject_type}:${r.subject_id} | ` +
    `${r.endpoint} | device=${r.device_id ?? '-'} | ${r.reason}`
  );
}

// Anti-bocor: tidak boleh ada token JWT (awalan "eyJ") di kolom mana pun.
const bocor = db.prepare(`
  SELECT COUNT(*) AS n FROM audit_logs
  WHERE subject_id LIKE 'eyJ%' OR endpoint LIKE 'eyJ%'
     OR device_id LIKE 'eyJ%'  OR reason LIKE 'eyJ%'
`).get();

if (bocor.n > 0) {
  console.error(`PERINGATAN: ${bocor.n} baris audit_logs mengandung token JWT (awalan "eyJ")!`);
  process.exitCode = 1;
} else {
  console.log('Scan anti-bocor: TIDAK ada token JWT di audit_logs. OK.');
}
