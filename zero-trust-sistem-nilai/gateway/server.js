// ============================================================
// gateway/server.js
// API Gateway — port 3000. Satu-satunya pintu masuk pengguna
// dan komunikasi antar-service (Zero Trust).
//
// Aliran setiap request:
//   /auth/*     -> auth.js (kredensial, device, token)
//   lainnya     -> authenticate() -> PDP (policy.decide)
//                  -> audit allow/deny -> PEP (proxy ke service)
// Jalankan: npm run gateway
// ============================================================

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const express = require('express');
const { validateGateway } = require('../shared/config');
const { audit } = require('./audit');
const { router: authRouter, authenticate } = require('./auth');
const { decide } = require('./policy');
const { mountProxies } = require('./proxy');

validateGateway('API Gateway');

const app = express();
app.disable('x-powered-by');

// Health check tanpa auth (untuk operasional/demo).
app.get('/health', (req, res) => {
  res.json({ service: 'gateway', status: 'ok' });
});

// ---- Endpoint autentikasi (mengelola kredensial/device sendiri) ----
app.use('/auth', authRouter);

// ---- Middleware autentikasi & kebijakan (PEP + audit) ----
//
// 1. authenticate(): JWT + X-Device-ID terdaftar -> req.auth/user/deviceId
app.use(authenticate);

// 2. Policy Engine: PDP membaca relasi database (owner, role, jam akses).
//    Setiap keputusan di-audit. Jika jejak audit gagal ditulis, akses
//    ditolak — keputusan tidak boleh hilang jejaknya.
app.use((req, res, next) => {
  const pathNoQuery = req.originalUrl.split('?')[0];
  const endpoint = `${req.method} ${pathNoQuery}`;
  const isService = req.auth.role === 'service';

  const decision = decide({
    method: req.method,
    path: pathNoQuery,
    auth: req.auth,
    user: req.user || null,
    deviceId: req.deviceId || null,
  });

  const written = audit({
    subjectType: isService ? 'service' : 'user',
    subjectId: req.auth.sub,
    endpoint,
    deviceId: req.deviceId || null,
    result: decision.allow ? 'allow' : 'deny',
    reason: decision.reason,
  });

  if (!written) {
    return res.status(500).json({
      error: { code: 'AUDIT_WRITE_FAILED', message: 'Gagal menulis audit log; akses ditolak.' },
    });
  }
  if (!decision.allow) {
    return res.status(decision.status).json({
      error: { code: decision.code, message: decision.reason },
    });
  }
  return next();
});

// 3. PEP: hanya request yang diizinkan yang diteruskan ke service.
mountProxies(app);

// ---- Fallback ----
app.use((req, res) => {
  const pathNoQuery = req.originalUrl.split('?')[0];
  audit({
    subjectType: req.auth?.role === 'service' ? 'service' : 'user',
    subjectId: req.auth?.sub || '(tidak-dikenal)',
    endpoint: `${req.method} ${pathNoQuery}`,
    deviceId: req.deviceId || null,
    result: 'deny',
    reason: 'Fallback: endpoint tidak dikonfigurasi di gateway.',
  });
  return res.status(404).json({
    error: { code: 'NO_ROUTE', message: `Endpoint ${req.method} ${pathNoQuery} tidak dikonfigurasi.` },
  });
});

// Handler error global (JSON body rusak di route /auth, dll).
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: { code: 'BAD_JSON', message: 'Body JSON tidak valid.' } });
  }
  console.error('[gateway] error tidak terduga:', err.message);
  return res.status(500).json({ error: { code: 'INTERNAL', message: 'Terjadi kesalahan internal.' } });
});

const PORT = Number(process.env.GATEWAY_PORT || 3000);
app.listen(PORT, () => {
  console.log(`[gateway] API Gateway berjalan di http://localhost:${PORT}`);
  console.log('[gateway] Semua request pengguna dan antar-service wajib melewati pintu ini.');
});
