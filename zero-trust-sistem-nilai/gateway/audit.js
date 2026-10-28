// ============================================================
// gateway/audit.js
// Audit log: setiap keputusan akses (allow/deny) yang dibuat
// gateway dicatat ke tabel audit_logs. Dilarang menulis
// password, token, client secret, atau gateway secret.
//
// Kegagalan menulis TIDAK boleh dibiarkan diam-diam (AGENTS §8):
// audit() mengembalikan false, dan caller (gatewayShield) wajib
// menolak akses bila jejak gagal ditulis.
// ============================================================

const { getDb } = require('../shared/database');

/**
 * Catat satu keputusan akses.
 * @param {{subjectType:'user'|'service', subjectId:string, endpoint:string,
 *          deviceId?:string|null, result:'allow'|'deny', reason:string}} entry
 * @returns {boolean} true jika berhasil ditulis.
 */
function audit(entry) {
  try {
    getDb()
      .prepare(`
        INSERT INTO audit_logs (subject_type, subject_id, endpoint, device_id, result, reason)
        VALUES (?, ?, ?, ?, ?, ?)
      `)
      .run(
        entry.subjectType,
        entry.subjectId,
        entry.endpoint,
        entry.deviceId ?? null,
        entry.result,
        entry.reason
      );
    return true;
  } catch (err) {
    console.error('[audit] GAGAL menulis audit log:', err.message);
    return false;
  }
}

module.exports = { audit };
