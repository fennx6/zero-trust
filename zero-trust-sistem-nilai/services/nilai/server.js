// ============================================================
// services/nilai/server.js
// Service Nilai — port 3001.
// Resource data nilai & kelas. Ketika finalisasi, memanggil
// sinkronisasi Service Transkrip MELALUI GATEWAY (bukan langsung
// ke port 3002) dengan token service dari POST /auth/service.
// Jalankan: npm run service:nilai
// ============================================================

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

const express = require('express');
const { validateCommon } = require('../../shared/config');
const { requireGatewaySecret, requireJwt, deny } = require('../../shared/middleware');
const { accessHoursConfig } = require('../../shared/hours');
const routes = require('./routes');

validateCommon('Service Nilai');

// Info jam akses dibaca saat start supaya salah konfigurasi langsung terlihat.
const hours = accessHoursConfig();
if (!Number.isInteger(hours.start) || !Number.isInteger(hours.end) || hours.end <= hours.start) {
  console.error(`[nilai] Konfigurasi jam akses tidak valid: start=${hours.start} end=${hours.end} (end harus > start).`);
  process.exit(1);
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));

app.get('/health', (req, res) => {
  res.json({ service: 'nilai', status: 'ok', jam_akses: `${hours.start}:00-${hours.end}:00 ${hours.timezone}` });
});

// Lapisan pertahanan: gateway secret + JWT.
app.use(requireGatewaySecret);
app.use(requireJwt);

app.use('/', routes);

app.use((req, res) => deny(res, 404, 'NOT_FOUND', `Endpoint ${req.method} ${req.originalUrl} tidak ada.`));

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return deny(res, 400, 'BAD_JSON', 'Body JSON tidak valid.');
  }
  console.error('[nilai] error tidak terduga:', err.message);
  return deny(res, 500, 'INTERNAL', 'Terjadi kesalahan internal.');
});

const PORT = Number(process.env.SERVICE_NILAI_PORT || 3001);
app.listen(PORT, () => {
  console.log(
    `[nilai] Service Nilai berjalan di http://localhost:${PORT} ` +
    `(jam akses ${hours.start}:00-${hours.end}:00 ${hours.timezone})`
  );
});
