// ============================================================
// gateway/proxy.js
// Policy Enforcement Point (PEP) — request yang sudah LEWAT
// kebijakan diteruskan ke service yang tepat.
//
// Tugas penting di sini:
//  1. Sisipkan X-Gateway-Secret (ditimpa selalu — client tidak
//     bisa menyelipkan secret miliknya, dan service menolak
//     request yang tidak lewat gateway).
//  2. Hapus header palsu yang bisa dipakai client memalsukan
//     identitas (x-user-role, x-user-id, dst). Identitas resmi
//     diwakili JWT asli yang berada di header Authorization.
// ============================================================

const { createProxyMiddleware } = require('http-proxy-middleware');
const { audit } = require('./audit');

const FAKE_IDENTITY_HEADERS = ['x-user-id', 'x-user-role', 'x-user-nim', 'x-auth-sub', 'x-auth-role'];

/** Middleware sanitasi header sebelum request diteruskan ke service. */
function sanitizeForwardedRequest(req, res, next) {
  for (const h of FAKE_IDENTITY_HEADERS) {
    delete req.headers[h];
  }
  // Timpa selalu: gateway adalah satu-satunya yang tahu secret ini.
  req.headers['x-gateway-secret'] = process.env.GATEWAY_SECRET;
  next();
}

/** Buat proxy untuk satu service dengan pelapor error 502 + audit. */
function makeProxy(target, name) {
  return createProxyMiddleware({
    target,
    changeOrigin: false,
    on: {
      error: (err, req, res) => {
        console.error(`[proxy:${name}] error:`, err.message);
        try {
          audit({
            subjectType: req.auth?.role === 'service' ? 'service' : 'user',
            subjectId: req.auth?.sub || '(tidak-dikenal)',
            endpoint: `${req.method} ${req.originalUrl}`.split('?')[0],
            deviceId: req.deviceId || null,
            result: 'deny',
            reason: `Service ${name} tidak terjangkau (${err.code || err.message}).`,
          });
        } catch { /* audit gagal tidak boleh mematikan respons */ }
        if (res && res.writeHead) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: { code: 'SERVICE_UNAVAILABLE', message: `Service ${name} tidak terjangkau.` },
          }));
        }
      },
    },
  });
}

/**
 * Pasang seluruh lapisan PEP pada app.
 * PENTING: mounting berpredicate path (bukan mount-prefix),
 * karena app.use('/nilai', mw) akan membuang prefix '/nilai' dari path —
 * sehingga service menerima path '/'. Dengan predicate, originalUrl
 * diteruskan utuh seperti yang diminta service.
 */
function mountProxies(app) {
  const proxyNilai = makeProxy(process.env.SERVICE_NILAI_URL || 'http://localhost:3001', 'nilai');
  const proxyTranskrip = makeProxy(process.env.SERVICE_TRANSKRIP_URL || 'http://localhost:3002', 'transkrip');

  const forward = (handler, re) => (req, res, next) =>
    re.test(req.originalUrl.split('?')[0]) ? handler(req, res, next) : next();

  app.use(sanitizeForwardedRequest);                                  // header sanitasi
  app.use(forward(proxyNilai, /^\/(nilai|kelas)(\/|$)/));             // Service Nilai
  app.use(forward(proxyTranskrip, /^\/transkrip(\/|$)/));             // Service Transkrip
}

module.exports = { mountProxies };
