// ============================================================
// shared/config.js
// Validasi konfigurasi wajib saat aplikasi mulai.
// Fail fast: kalau secret penting hilang, aplikasi menolak jalan
// dengan pesan yang jelas (bukan melanjutkan tanpa sekuriti).
// ============================================================

const REQUIRED_Common = ['GATEWAY_SECRET', 'JWT_SECRET'];

// Gateway tambahan: kredensial client service.
const REQUIRED_GATEWAY = ['SERVICE_CLIENT_ID', 'SERVICE_CLIENT_SECRET'];

/**
 * Validasi daftar environment variable wajib.
 * @param {string[]} names - kunci env yang wajib ada dan tidak boleh kosong.
 * @param {string} appName - nama aplikasi untuk pesan error.
 */
function validateConfig(names, appName) {
  const missing = names.filter((n) => {
    const v = process.env[n];
    return v === undefined || String(v).trim() === '';
  });

  if (missing.length > 0) {
    console.error(`[config] ${appName}: environment variable wajib tidak ada: ${missing.join(', ')}`);
    console.error('[config] Salin .env.example menjadi .env, isi semua nilai, lalu jalankan ulang.');
    process.exit(1);
  }
}

/** Validasi yang umum untuk semua aplikasi (gateway & service). */
function validateCommon(appName) {
  validateConfig(REQUIRED_Common, appName);
}

/** Validasi tambahan khusus gateway. */
function validateGateway(appName) {
  validateCommon(appName);
  validateConfig(REQUIRED_GATEWAY, appName);
}

module.exports = { validateConfig, validateCommon, validateGateway };
