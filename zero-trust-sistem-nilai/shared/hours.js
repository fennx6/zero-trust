// ============================================================
// shared/hours.js
// Verifikasi jam akses 07:00–21:00 (SEBELUM perubahan nilai dan
// finalisasi, bukan untuk endpoint baca). Tidak bergantung pada
// zona waktu mesin: zona waktu diambil dari env TIMEZONE
// (default Asia/Jakarta), rentang jam dari env ACCESS_START_HOUR
// dan ACCESS_END_HOUR agar demo mudah diatur.
// ============================================================

/**
 * Pecah waktu "sekarang" di zona waktu tertentu menjadi jam & menit.
 * Returns {hour, minute} integer, dan (jarang) error jika tz tidak dikenal.
 */
function nowInZone(timeZone, date = new Date()) {
  try {
    const parts = new Intl.DateTimeFormat('en-GB', {
      timeZone,
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
    }).formatToParts(date);
    const get = (type) => Number(parts.find((p) => p.type === type)?.value);
    return { hour: get('hour'), minute: get('minute'), error: null };
  } catch (e) {
    return { hour: null, minute: null, error: e };
  }
}

function accessHoursConfig() {
  return {
    start: Number(process.env.ACCESS_START_HOUR ?? 7),
    end: Number(process.env.ACCESS_END_HOUR ?? 21),
    timezone: process.env.TIMEZONE || 'Asia/Jakarta',
  };
}

/**
 * Apakah sekarang berada dalam rentang jam akses?
 * Rentang inklusif di awal, eksklusif di akhir: start <= jam < end.
 */
function isWithinAccessHours(date = new Date()) {
  const cfg = accessHoursConfig();
  const { hour, minute, error } = nowInZone(cfg.timezone, date);
  if (error) return { allowed: false, reason: `Zona waktu "${cfg.timezone}" tidak dikenal.` };

  const t = hour + minute / 60;
  if (t < cfg.start || t >= cfg.end) {
    const pad = (n) => String(n).padStart(2, '0');
    return {
      allowed: false,
      reason: `Di luar jam akses. Rentang diizinkan: ${pad(cfg.start)}:00-${pad(cfg.end)}:00 (${cfg.timezone}).`,
    };
  }
  return { allowed: true, reason: null };
}

module.exports = { nowInZone, isWithinAccessHours, accessHoursConfig };
