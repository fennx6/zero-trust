/**
 * Membuat file environment Newman dari .env AKTIF (isi secret, TIDAK di-commit;
 * lihat .gitignore: newman-env.tmp.json).
 *
 * Pemakaian:  node postman/make-newman-env.js
 * Hasil    :  newman-env.tmp.json di root proyek.
 */
const fs = require('fs');
const path = require('path');

const envPath = path.join(__dirname, '..', '.env');
const outPath = path.join(__dirname, '..', 'newman-env.tmp.json');

if (!fs.existsSync(envPath)) {
  console.error('[newman-env] .env tidak ditemukan. Salin .env.example menjadi .env lalu isi.');
  process.exit(1);
}

const map = {};
for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
  const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
  if (m && !m[1].startsWith('#')) map[m[1]] = m[2].trim();
}

const values = [
  ['serviceClientId', map.SERVICE_CLIENT_ID],
  ['serviceClientSecret', map.SERVICE_CLIENT_SECRET],
  ['gatewaySecret', map.GATEWAY_SECRET],
].map(([key, value]) => ({ key, value, enabled: true }));

fs.writeFileSync(outPath, JSON.stringify({ name: 'newman-local', values }, null, 2));
console.log('[newman-env] Ditulis:', outPath, '(jangan di-commit)');
