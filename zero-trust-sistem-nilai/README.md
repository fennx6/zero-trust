# Zero Trust Sistem Nilai Informatika

Praktikum individu mata kuliah **Keamanan Informasi** — implementasi prinsip
Zero Trust (**never trust, always verify**, *least privilege*, *assume breach*)
pada level aplikasi, tanpa frontend. Semua request pengguna **dan** komunikasi
antar-service wajib melewati API Gateway.

## 1. Arsitektur dan Port

```
                    ┌───────────────────────────────┐
   Postman/client ──►  API Gateway  :3000           │
                    │  - Auth (login/refresh/       │
                    │    logout/service token)      │
                    │  - PEP: proxy + sanitasi      │
                    │  - PDP: policy dari DB        │
                    │  - Audit log (allow/deny)     │
                    └──────┬────────────────┬───────┘
              X-Gateway-Secret │                │ X-Gateway-Secret
              + JWT diverifikasi│                │ + JWT diverifikasi
                    ┌──────────▼──────┐  ┌──────▼────────────┐
                    │ Service Nilai   │  │ Service Transkrip │
                    │ :3001           │  │ :3002             │
                    │ GET /nilai      │  │ GET /transkrip/:nim│
                    │ PUT /nilai/:id  │  │ POST /transkrip/  │
                    │ POST /kelas/:id/│  │      sinkron      │
                    │   finalisasi    │  │  (role service)   │
                    └──────────┬──────┘  └──────▲────────────┘
                               │   POST /transkrip/sinkron
                               │   (lewat gateway, token service)
                    ┌──────────▼───────────────────┴───────┐
                    │  SQLite bersama: data/database.sqlite│
                    │  (WAL, busy_timeout 5000)            │
                    └──────────────────────────────────────┘
```

- **API Gateway (3000)** — satu-satunya pintu masuk. Autentikasi, *Policy
  Enforcement Point* (PEP), *Policy Engine/PDP* sebagai modul `gateway/policy.js`,
  audit log `gateway/audit.js`.
- **Service Nilai (3001)** — resource nilai & kelas. Memverifikasi
  `X-Gateway-Secret` **dan** JWT. Saat finalisasi, meminta token service lewat
  `POST /auth/service` lalu sinkron ke Service Transkrip **melalui gateway**
  (`services/nilai/service-client.js`), bukan langsung ke 3002.
- **Service Transkrip (3002)** — resource transkrip. Verifikasi berlapis yang
  sama; `POST /transkrip/sinkron` hanya menerima token role `service`.
- **Database** — satu file SQLite bersama (`data/database.sqlite`). Keberadaan
  DB bersama **tidak** dipakai untuk melewati gateway: komunikasi antarlayanan
  tetap HTTP via 3000.

## 2. Prasyarat

| Komponen | Versi |
|---|---|
| Node.js | **18+** (wajib untuk `fetch` antar-service). Dites di Node v26.12.0 |
| npm | versi bawaan Node |
| Postman *(opsional)* | desktop client, atau cukup Newman (sudah jadi devDependency) |

## 3. Instalasi dan Konfigurasi

```powershell
cd zero-trust-sistem-nilai
npm install
Copy-Item .env.example .env      # lalu isi nilainya (lihat tabel di bawah)
```

Isi `.env` (nilai contoh pada `.env.example` adalah placeholder, **bukan secret
asli** — secret asli tidak pernah di-commit):

| Variabel | Wajib? | Keterangan |
|---|---|---|
| `GATEWAY_SECRET` | ✅ semua app | Secret gateway→service (header `X-Gateway-Secret`) |
| `JWT_SECRET` | ✅ semua app | Secret tanda tangan JWT user & service |
| `SERVICE_CLIENT_ID` | ✅ gateway | Client ID untuk `POST /auth/service` (default `nilai-service`) |
| `SERVICE_CLIENT_SECRET` | ✅ gateway | Secret client service |
| `GATEWAY_PORT` / `SERVICE_NILAI_PORT` / `SERVICE_TRANSKRIP_PORT` | — | 3000 / 3001 / 3002 |
| `SERVICE_NILAI_URL` / `SERVICE_TRANSKRIP_URL` | — | Dipakai gateway & service-client |
| `ACCESS_TOKEN_TTL` | — | Detik; default `600` (10 menit) |
| `REFRESH_TOKEN_TTL` | — | Detik; default `86400` (1 hari) |
| `SERVICE_TOKEN_TTL` | — | Detik; default `300` (5 menit) |
| `ACCESS_START_HOUR` / `ACCESS_END_HOUR` | — | Jendela jam akses; default `7` / `21`, rentang `start ≤ jam < end` |
| `TIMEZONE` | — | IANA, default `Asia/Jakarta` (jam akses tidak bergantung zona mesin) |
| `DB_PATH` | — | Default `data/database.sqlite` |

Aplikasi *fail fast*: bila `GATEWAY_SECRET`/`JWT_SECRET` (dan kredensial client
service pada gateway) kosong, proses menolak jalan dengan pesan jelas
(`shared/config.js`).

Membuat secret acak:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## 4. Database: Schema dan Seed

Schema dibuat idempoten oleh `database/schema.sql` (users, devices,
refresh_tokens, kelas, enrollments, nilai, transkrip, audit_logs).

```powershell
npm run setup                    # seed idempoten (aman diulang)
node database/seed.js --reset    # hapus data demo + audit, lalu seed ulang bersih
```

Seed minimal sesuai ketentuan: 1 admin, 2 dosen, 3 mahasiswa, 2 kelas dengan
pengampu berbeda, 1 device terdaftar per user. Password demo disimpan sebagai
**hash bcrypt** (bcryptjs), bukan plaintext. Nilai awal untuk skenario uji:
KIF-101 (3 mahasiswa, semua belum final), KIF-102 (2 nilai final, 1 mahasiswa
belum dinilai).

## 5. Menjalankan Aplikasi

Tiga terminal terpisah (disarankan untuk demo, log terlihat per aplikasi):

```powershell
npm run gateway            # :3000
npm run service:nilai      # :3001
npm run service:transkrip  # :3002
```

atau satu perintah (concurrently):

```powershell
npm run start:all
```

> Ubah `.env` → **restart** aplikasi agar konfigurasi baru terbaca.

## 6. Akun Demo dan Device

| Username | Role | Password | Device ID | Catatan |
|---|---|---|---|---|
| `admin` | admin | `Admin#12345` | `DEV-ADMIN-01` | lihat transkrip NIM mana pun |
| `budi.santoso` | dosen | `Dosen#12345` | `DEV-DOSEN-01` | pengampu **KIF-101** |
| `siti.rahayu` | dosen | `Dosen#12345` | `DEV-DOSEN-02` | pengampu **KIF-102** |
| `10522001` (Andi) | mahasiswa | `Mhs#12345` | `DEV-MHS-01` | terdaftar KIF-101 & KIF-102 |
| `10522002` (Bela) | mahasiswa | `Mhs#12345` | `DEV-MHS-02` | terdaftar KIF-101 & KIF-102 |
| `10522003` (Cahyo) | mahasiswa | `Mhs#12345` | `DEV-MHS-03` | terdaftar KIF-101 & KIF-102 |

Device terikat ke user: login/request dengan `X-Device-ID` milik user lain
ditolak `403 DEVICE_NOT_REGISTERED`.

## 7. Endpoint dan Header

Semua endpoint user diakses **melalui gateway** `http://localhost:3000` dengan
header `Authorization: Bearer <access-token>` dan `X-Device-ID: <device>`.

| Endpoint | Kebijakan | Penolakan khas |
|---|---|---|
| `POST /auth/login` | kredensial valid + device terdaftar | `401 CREDENTIALS_INVALID`, `403 DEVICE_NOT_REGISTERED` |
| `POST /auth/refresh` | refresh token valid, belum kedaluwarsa/cabut; **rotasi single-use** | `401 REFRESH_TOKEN_REVOKED` |
| `POST /auth/logout` | mencabut refresh token yang dipakai | `401 REFRESH_TOKEN_REVOKED` |
| `POST /auth/service` | hanya client service (client ID + secret) | `401 CLIENT_INVALID` |
| `GET /nilai` | mahasiswa: miliknya; dosen: kelas yang diampu | `403 FORBIDDEN_*` |
| `PUT /nilai/:id` | dosen pengampu; belum final; dalam jam akses | `403 FORBIDDEN_OWNERSHIP/ROLE`, `403 ALREADY_FINAL` (via gateway), `403 OUTSIDE_ACCESS_HOURS`, `400 VALIDATION` |
| `POST /kelas/:id/finalisasi` | dosen pengampu; dalam jam akses; memicu sinkron via gateway | sama seperti PUT |
| `GET /transkrip/:nim` | mahasiswa: NIM sendiri; admin: semua | `403 FORBIDDEN_OWNERSHIP` |
| `POST /transkrip/sinkron` | **hanya token service**; token user apa pun ditolak | `403 ENDPOINT_SERVICE_ONLY` (gateway) / `403` (service) |

Akses **langsung ke service** (3001/3002) tanpa `X-Gateway-Secret` → `401
GATEWAY_SECRET_MISSING`; secret salah → `401 GATEWAY_SECRET_WRONG`; secret benar
tanpa token → `401 TOKEN_MISSING`. Token JWT selalu diverifikasi tanda tangan +
masa berlaku (`TOKEN_MALFORMED`, `TOKEN_EXPIRED`, `TOKEN_INVALID`,
`CLAIM_MISSING`). Identitas/role **tidak** dibaca dari header client — hanya
dari token terverifikasi.

**Catatan `PUT /nilai/:id`** (asumsi terdokumentasi): bila `:id` adalah id baris
`nilai` → update; bila `:id` adalah id baris `enrollments` yang belum punya
nilai → dibuat baris nilai baru (dipakai untuk mahasiswa yang belum dinilai;
lihat `enroll_id` pada `GET /nilai` versi dosen).

## 8. Alur Finalisasi → Sinkronisasi Transkrip

1. Dosen mengubah nilai: `PUT /nilai/:id` `{ "nilai": 95 }` (jam akses 07–21).
2. Dosen memfinalisasi: `POST /kelas/:id/finalisasi` → semua nilai kelas
   `final=1` secara transaksional.
3. Service Nilai memanggil `POST /auth/service` **via gateway** memakai
   `SERVICE_CLIENT_ID`/`SECRET` → token service (5 menit, role `service`).
4. Untuk setiap nilai, Service Nilai memanggil `POST /transkrip/sinkron`
   **via gateway** dengan token service → upsert tabel `transkrip`.
5. Respons finalisasi: `{ jumlah_nilai, sinkron: true, detail_sinkron: [...] }`.
   Bila sinkron gagal, `sinkron=false` — nilai tetap final dan finalisasi bisa
   diulang untuk retry.
6. Mahasiswa membaca hasilnya: `GET /transkrip/:nim`.

## 9. Pengujian dengan Postman / Newman

### 9.1 Impor koleksi

Impor dua file di folder `postman/`:

- `zero-trust-sistem-nilai.postman_collection.json` — alur utama:
  **A. Autentikasi** (12), **B. Nilai & Kelas via gateway** (16),
  **C. Sinkron & anti-lompat-pintu** (5).
- `zero-trust-sistem-nilai-luar-jam.postman_collection.json` — skenario negatif
  jam akses (4), dijalankan **terpisah** (lihat 9.3).

Sebelum run, isi *collection variable* (tab **Variables**):

- `serviceClientSecret` ← nilai `SERVICE_CLIENT_SECRET` dari `.env` aktif.
- `gatewaySecret` ← nilai `GATEWAY_SECRET` dari `.env` aktif.

Token access/refresh dan id `nilai`/`kelas`/`enrollment` diisi **otomatis**
oleh test script — jalankan request **berurutan** dari atas.

> Koleksi mengasumsikan **seed bersih**: jalankan `node database/seed.js
> --reset` dan matikan-nyalakan ulang server sebelum run, karena beberapa
> asersi bergantung state awal (mis. "Cahyo belum dinilai").

### 9.2 Menjalankan via Newman (CLI)

```powershell
node postman/make-newman-env.js   # baca .env -> newman-env.tmp.json (di-gitignore)
npx newman run postman/zero-trust-sistem-nilai.postman_collection.json --environment newman-env.tmp.json
Remove-Item newman-env.tmp.json   # bereskan: file ini berisi secret dari .env
```

### 9.3 Skenario "di luar jam akses"

Pembatasan jam bersifat konfiguratif, jadi pengujian negatifnya dilakukan dengan
jendela sempit:

1. Ubah `.env`: `ACCESS_START_HOUR=1`, `ACCESS_END_HOUR=2` (pastikan waktu demo
   berada di luar 01–02).
2. Restart ketiga aplikasi.
3. Jalankan koleksi `...luar-jam...` → semua harus `403 OUTSIDE_ACCESS_HOURS`.
4. Kembalikan `.env` ke `7`/`21` dan restart.

### 9.4 Pemetaan skenario §12 → request koleksi

| # | Skenario AGENTS §12 | Item koleksi |
|---|---|---|
| 1 | Login valid + device terdaftar | A1, A2, A3, A3b |
| 2 | Kredensial salah ditolak | A4 |
| 3 | Device tidak terdaftar / milik user lain | A5 |
| 4 | Token hilang/invalid/kedaluwarsa | C2, C3, C5 (+ test otomatis) |
| 5 | Refresh valid; refresh dicabut/kedaluwarsa ditolak | A6, A7 |
| 6 | Logout mencabut refresh; tak bisa dipakai lagi | A8, A9 |
| 7 | Mahasiswa baca nilai & transkrip miliknya | B3, B4 |
| 8 | Mahasiswa baca data mahasiswa lain | B5 |
| 9 | Dosen baca nilai kelas yang diampu | B1, B2 |
| 10 | Dosen ubah nilai kelas dosen lain | B9 |
| 11 | Nilai final tidak bisa diubah | B10, B16 |
| 12 | Perubahan/finalisasi di luar jam | D3, D4 (koleksi luar jam) |
| 13 | Finalisasi kelas oleh pengampu pada jam izin | B14 |
| 14 | Finalisasi memicu sinkron via gateway | B14, B15 |
| 15 | Token user ke endpoint sinkron ditolak | C1, C4 |
| 16 | Langsung ke service tanpa gateway secret | C2, C3 |
| 17 | Secret benar tapi tanpa token valid | C5 |
| 18 | Token service valid bisa sinkron | A10 + B14 (internal) |
| 19 | Admin baca transkrip NIM mana pun | B6 |
| 20 | Audit allow/deny tercatat | `node tests/audit-check.js` |

## 10. Uji Otomatis (Node)

```powershell
node tests/test-gateway.js    # spawn ketiga service sendiri; 40 assertion alur gateway
node tests/test-nilai.js      # spawn sendiri; jam akses di-toggling; 24 assertion
node tests/test-transkrip.js  # butuh ketiga server SUDAH hidup; 20 assertion
node tests/check-seed.js      # verifikasi seed, tanpa server
node tests/audit-check.js 15  # statistik audit + scan anti-bocor token, tanpa server
```

Hasil terakhir (state tahap 6): test-gateway **40/40**, test-nilai **24/24**,
test-transkrip **20/20**, Newman utama **33 request / 61 asersi / 0 gagal**,
Newman luar jam **4 request / 6 asersi / 0 gagal**, audit-check tanpa kebocoran
token. Test otomatis memakai `.env` aktif; skenario "di luar jam" pada
`test-nilai.js` men-spawn server dengan jendela jam sendiri sehingga tidak
tergantung waktu demo.

## 11. Struktur Proyek

```
zero-trust-sistem-nilai/
├── gateway/            # server.js, auth.js, policy.js, proxy.js, audit.js
├── services/
│   ├── nilai/          # server.js, routes.js, service-client.js
│   └── transkrip/      # server.js, routes.js
├── shared/             # config.js, database.js, token.js, middleware.js, hours.js
├── database/           # schema.sql, seed.js
├── tests/              # test-*.js, check-seed.js, audit-check.js
├── postman/            # 2 koleksi + make-newman-env.js (tanpa secret)
├── data/               # database.sqlite (di-gitignore)
├── .env.example
└── package.json
```

## 12. Batasan yang Diketahui

1. **`PUT /nilai/:id` interpretasi ganda** — id baris nilai atau id enrollment
   (untuk nilai pertama kali). Dipilih agar tetap satu endpoint sesuai daftar
   wajib; sudah didokumentasikan di §7.
2. **Id database berubah tiap `--reset`** (AUTOINCREMENT tidak di-reset).
   Koleksi Postman mengambil id secara dinamis — jangan hardcode id.
3. **Uji "di luar jam" butuh konfigurasi** — jendela jam dibaca saat startup;
   pengujian negatifnya memerlukan ubah `.env` + restart (§9.3), atau pakai
   `tests/test-nilai.js` yang men-spawn server dengan jendela sendiri.
4. **Audit log dibaca lewat DB**, bukan endpoint khusus (tidak diwajibkan);
   gunakan `tests/audit-check.js` atau klien SQLite.
5. **Koleksi Postman bergantung seed bersih** (§9.1).
6. Token kedaluwarsa saat demo → login ulang (TTL memang pendek sesuai spek).
7. Tanpa frontend (sesuai ketentuan tugas); seluruh uji via API.
