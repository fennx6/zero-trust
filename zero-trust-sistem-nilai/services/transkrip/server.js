// ============================================================
// services/transkrip/server.js
// Service Transkrip — port 3002.
// Resource data transkrip mahasiswa. Dihubungi HANYA lewat
// gateway; request langsung ditolak karena tidak membawa
// X-Gateway-Secret + JWT yang dikonfirmasi gateway.
// Jalankan: npm run service:transkrip
// ============================================================

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

const express = require('express');
const { validateCommon } = require('../../shared/config');
const { requireGatewaySecret, requireJwt, deny } = require('../../shared/middleware');
const routes = require('./routes');

validateCommon('Service Transkrip');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));

// Health check tanpa auth — untuk keperluan operasional/demo saja.
app.get('/health', (req, res) => {
  res.json({ service: 'transkrip', status: 'ok' });
});

// Lapisan pertahanan: gateway secret + JWT. Berlaku untuk semua route berikutnya.
app.use(requireGatewaySecret);
app.use(requireJwt);

// Endpoint transkrip.
app.use('/', routes);

// 404 dengan bentuk error konsisten.
app.use((req, res) => deny(res, 404, 'NOT_FOUND', `Endpoint ${req.method} ${req.originalUrl} tidak ada.`));

// Error handler terakhir — jangan bocorkan stack trace ke client.
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return deny(res, 400, 'BAD_JSON', 'Body JSON tidak valid.');
  }
  console.error('[transkrip] error tidak terduga:', err.message);
  return deny(res, 500, 'INTERNAL', 'Terjadi kesalahan internal.');
});

const PORT = Number(process.env.SERVICE_TRANSKRIP_PORT || 3002);
app.listen(PORT, () => {
  console.log(`[transkrip] Service Transkrip berjalan di http://localhost:${PORT}`);
});
