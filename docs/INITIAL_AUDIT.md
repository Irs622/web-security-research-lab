# Initial Audit Report: WAF Security Testing Lab

> **Catatan:** Dokumen ini adalah arsip kondisi awal repository sebelum pengembangan. Kondisi terkini dijelaskan di [README](../README.md), [ARCHITECTURE.md](ARCHITECTURE.md), dan [PRODUCTION.md](PRODUCTION.md).

**Tanggal Audit:** 10 Oktober 2026  
**Auditor:** Agent A (Repository Auditor & AppSec/Research Engineer)  
**Tujuan Proyek:** Evaluasi Efektivitas Web Application Firewall (ModSecurity + OWASP CRS) dalam Mendeteksi dan Memitigasi Serangan terhadap Aplikasi Web (OWASP Juice Shop) untuk Skripsi Teknik Informatika.  
**Target Environment:** macOS (Apple Silicon M3, 8 GB RAM) / Linux VPS (via loopback/SSH tunnel).

---

## 1. Arsitektur Repository Saat Ini

Struktur repository saat inspeksi awal:
```text
waf-research-lab/
├── .gitignore
├── Makefile
├── README.md
├── docker-compose.yml
├── evaluation/
│   └── analyze_results.py
├── results/                  (kosong)
├── simulator/
│   ├── attack_cases.json     (8 kasus uji)
│   └── run_tests.py
└── waf/                      (kosong)
```

Komponen yang terdefinisi pada `docker-compose.yml`:
1. **`juice-shop`**: `bkimminich/juice-shop:latest`, exposing `127.0.0.1:3001:3000` (mode baseline).
2. **`waf`**: `owasp/modsecurity-crs:nginx`, reverse proxy ke `http://juice-shop:3000`, exposing `127.0.0.1:8080:8080` (mode WAF).
3. **`zap-baseline`**: `ghcr.io/zaproxy/zaproxy:stable`, profile `scan`, menjalankan `zap-baseline.py` terhadap `http://waf:8080`.
4. **Jaringan internal**: Bridge network Docker `lab`.

---

## 2. Status Runtime & Lingkungan Eksekusi

| Komponen | Status Aktual | Catatan Teknis |
|---|---|---|
| **OS Host** | macOS (Darwin ARM64 / Apple M3) | RAM 8 GB |
| **Docker CLI** | Terinstal (v29.6.2, Compose v5.3.1) | Terdeteksi pada sistem host |
| **Docker Daemon** | **Inactive / Offline** | `docker info` gagal: socket `unix:///Users/mac/.docker/run/docker.sock` tidak aktif. `/Applications/Docker.app` ada di sistem, namun daemon belum dijalankan. |
| **Python Host** | Python 3.9.6 (`/usr/bin/python3`) | `README.md` menyatakan butuh Python 3.10+, namun host menjalankan 3.9.6 (Xcode CLT). Perlu dukungan kompatibilitas 3.9 (e.g. `typing.Optional` / `from __future__ import annotations`). |
| **Python Libraries** | `pandas` (v2.3.3) terinstal, `matplotlib` & `pytest` **belum terinstal** | Modul `matplotlib` tidak ditemukan (`ModuleNotFoundError`). `pytest` tidak ditemukan. |
| **Validasi Statis Docker** | **Pass** | `docker compose config` berhasil memvalidasi sintaks Compose tanpa daemon aktif. |

---

## 3. Daftar Temuan Berdasarkan Kategori Prioritas

### Kategori 1: CRITICAL (Integritas Metodologi & Kebocoran Logika Penelitian)

#### [AUDIT-CRIT-01] Conflation Status HTTP 403 dengan Mitigasi & Deteksi Serangan
- **Lokasi:** `simulator/run_tests.py` (baris 84–85, 96), `evaluation/analyze_results.py` (baris 42, 48).
- **Deskripsi:** Skrip saat ini menganggap HTTP status 403/406 sebagai "WAF block signal", lalu dihitung langsung sebagai `Attack block-signal rate`.
- **Dampak Ilmiah:** 
  1. Status 403 dapat terjadi karena error otorisasi bawaan Juice Shop, routing Nginx, rate-limiting, atau konfigurasi proxy, bukan karena rule CRS terpicu.
  2. Deteksi (WAF mengenali pola dan membangkitkan alert dengan Rule ID) dipersamakan dengan Pemblokiran (WAF memutus request dan mencegah sampai ke backend). Padahal dalam mode deteksi/anomaly scoring, sebuah request bisa terdeteksi tapi tidak diblokir, atau sebaliknya.
  3. Ground truth pada backend tidak diuji: status HTTP 200 pada baseline tidak membuktikan kerentanan tereksploitasi, dan 403 pada WAF tidak membuktikan mitigasi berhasil.
- **Rekomendasi:** Pisahkan evaluasi Detection (berdasarkan ModSecurity Audit Log & CRS Rule ID) dan Blocking (berdasarkan intervensi HTTP 403 saat enforcement mode). Ground truth harus dinyatakan eksplisit per test case.

---

### Kategori 2: HIGH (Keamanan Jaringan, Containment, & Reproducibility)

#### [AUDIT-HIGH-01] Kerentanan Redirect Mengikuti Host Eksternal (Out-of-Scope Leakage)
- **Lokasi:** `simulator/run_tests.py` (baris 72: `urllib.request.urlopen`).
- **Deskripsi:** `urllib.request.urlopen` secara default mengikuti HTTP 301/302 Redirect secara otomatis. Jika payload atau respon Juice Shop menghasilkan header `Location` yang mengarah ke IP publik atau LAN, simulator akan mengirim HTTP request ke luar containment loopback.
- **Pelanggaran Batasan:** Melanggar aturan Section 3: *"Python simulator wajib menolak URL publik, hostname yang tidak diizinkan, redirect ke host lain... Jangan mengikuti redirect secara otomatis ke host lain."*
- **Rekomendasi:** Implementasikan custom `HTTPRedirectHandler` pada urllib yang menolak (raise error) atau memvalidasi target redirect agar tetap pada allowlist loopback lokal.

#### [AUDIT-HIGH-02] Penggunaan Tag Docker Image Tidak Terpin (`:latest`, `:nginx`, `:stable`)
- **Lokasi:** `docker-compose.yml` (baris 5, 15, 34).
- **Deskripsi:** 
  - `bkimminich/juice-shop:latest`
  - `owasp/modsecurity-crs:nginx`
  - `ghcr.io/zaproxy/zaproxy:stable`
- **Dampak Ilmiah:** Penarikan ulang image di masa mendatang (atau di VPS) berisiko mengunduh versi mayor/minor berbeda (misal CRS v3 vs v4, atau ModSecurity v3 vs v2), sehingga aturan deteksi, signature ID, dan ambang batas anomali berubah secara diam-diam.
- **Rekomendasi:** Pin versi secara eksplisit (misal: `bkimminich/juice-shop:v17.1.1`, `owasp/modsecurity-crs:4.9.0-nginx-alpine-202411030703` atau tag rilis CRS v4 yang stabil, `ghcr.io/zaproxy/zaproxy:2.15.0`).

#### [AUDIT-HIGH-03] Dataset Uji Terlalu Kecil & Bias (N=8)
- **Lokasi:** `simulator/attack_cases.json`.
- **Deskripsi:** Dataset hanya memiliki 8 entri: 3 normal, 2 SQLi, 2 XSS, 1 Path Traversal. Semua request menggunakan HTTP GET.
- **Dampak Ilmiah:** Menghitung metrik akademis seperti Precision, Recall, FPR, dan F1-Score dari 8 sampel menghasilkan variansi ekstrem (1 salah klasifikasi mengubah metrik sebesar 12.5% hingga 50%). Ini tidak representatif dan tidak dapat dipertanggungjawabkan dalam skripsi.
- **Rekomendasi:** Perluas dataset kasus uji terkontrol ke ukuran yang memadai (misal 30–50+ kasus berlabel dengan variasi GET query, POST JSON body, URL encoding, dan variasi benign request realistis), dengan skema data lengkap: `test_id`, `category`, `expected_class`, `method`, `path`, `description`, `expected_waf_behavior`.

---

### Kategori 3: MEDIUM (Konfigurasi Container, Observabilitas, & Evaluasi)

#### [AUDIT-MED-01] Direktori `waf/` Kosong & Log WAF Tidak Dimount ke Host
- **Lokasi:** `./waf/` (kosong), `docker-compose.yml` service `waf`.
- **Deskripsi:** Container WAF berjalan menggunakan konfigurasi default image tanpa volume mount untuk file konfigurasi kustom (`modsecurity.conf`, tuning rules) maupun mount log audit (`/var/log/modsec_audit.log`).
- **Dampak:** Simulator atau script analisis tidak dapat membaca file log ModSecurity secara langsung dari host untuk mengekstrak Rule ID, Anomaly Score Inbound/Outbound, dan URI yang terpicu. Peneliti terpaksa bergantung pada output `docker logs` mentah yang sulit dikorelasikan secara terstruktur per request.
- **Rekomendasi:** Mount direktori `waf/` untuk konfigurasi kustom dan direktori log audit WAF ke host (`./logs/waf/`).

#### [AUDIT-MED-02] Ketiadaan Docker Healthcheck & Dependency Ordering
- **Lokasi:** `docker-compose.yml` service `juice-shop` dan `waf`.
- **Deskripsi:** Service `waf` hanya memiliki `depends_on: [juice-shop]` tanpa `condition: service_healthy`. Container Juice Shop membutuhkan waktu inisialisasi Node.js (5–15 detik).
- **Dampak:** Jika WAF dimulai sebelum Juice Shop siap menerima koneksi, request proxy pertama akan mengembalikan HTTP 502 Bad Gateway yang dapat memicu false result pada pengujian.
- **Rekomendasi:** Tambahkan health check HTTP (`GET /`) pada `juice-shop` dan konfigurasikan `condition: service_healthy` pada `waf`.

#### [AUDIT-MED-03] Hilangnya Skrip Visualisasi & Metrik Penelitian Lengkap
- **Lokasi:** `evaluation/` (hanya ada `analyze_results.py`).
- **Deskripsi:** Berdasarkan spesifikasi Phase 5, diperlukan:
  - `evaluation/generate_charts.py`
  - Perhitungan metrik: Recall/Detection Rate (`TP / (TP + FN)`), False Positive Rate (`FP / (FP + TN)`), Precision (`TP / (TP + FP)`), Blocking Rate, Latensi p50 & p95.
- **Status:** `generate_charts.py` belum dibuat. `analyze_results.py` hanya menghitung mean dan p95 latensi serta rasio kasar, belum memiliki matriks konfusi (Confusion Matrix) dan penanganan edge case (pembagian dengan nol, dataset kosong).

#### [AUDIT-MED-04] Ketiadaan Unit Tests (`tests/`)
- **Lokasi:** Root repository.
- **Deskripsi:** Tidak ada unit tests untuk memverifikasi parser URL validator, penolakan redirect, kalkulasi metrik, skema dataset, atau penanganan error.
- **Rekomendasi:** Buat modul test (`tests/test_simulator.py`, `tests/test_evaluation.py`) yang dapat dijalankan secara lokal (menggunakan `unittest` bawaan Python 3.9 jika `pytest` belum terinstal).

---

### Kategori 4: LOW (Dokumentasi & Limitasi Sumber Daya)

#### [AUDIT-LOW-01] Struktur Dokumentasi Akademik Belum Lengkap
- **Lokasi:** `docs/`.
- **Deskripsi:** Dokumentasi standar penelitian yang dipersyaratkan (`ARCHITECTURE.md`, `METHODOLOGY.md`, `METRICS.md`, `EXPERIMENT_RUNBOOK.md`, `SECURITY_SCOPE.md`, `RESULTS_INTERPRETATION.md`) belum ada.
- **Rekomendasi:** Buat dokumen-dokumen tersebut secara bertahap pada fase yang sesuai.

#### [AUDIT-LOW-02] Ketiadaan Batasan Resource Container untuk RAM 8 GB
- **Lokasi:** `docker-compose.yml`.
- **Deskripsi:** Lingkungan MacBook M3 memiliki RAM 8 GB. Node.js (Juice Shop), ModSecurity (Nginx), dan OWASP ZAP (Java) dapat mengonsumsi memori besar jika dijalankan bersamaan.
- **Rekomendasi:** Terapkan `mem_limit` pada service container untuk mencegah system thrashing.

---

### Kategori 5: INFORMATIONAL

#### [AUDIT-INFO-01] Status Docker Daemon Host
- Docker Desktop terpasang pada path `/Applications/Docker.app`, namun saat ini servicenya belum berjalan.
- Sebelum Phase 1 dan 2 dieksekusi secara runtime, Docker daemon harus dinyalakan oleh sistem/user.
- Pengujian saat ini pada Phase 0 dibatasi pada validasi statis dan audit kode/arsitektur.

---

## 4. Daftar Masalah yang Dapat Direproduksi (Reproducible Issues)

1. **Docker Daemon Unreachable:**
   ```bash
   $ docker info
   failed to connect to the docker API at unix:///Users/mac/.docker/run/docker.sock
   ```
   *Konsekuensi:* Perintah `docker compose up` tidak dapat dijalankan saat ini.

2. **Redirect Bypassing Containment:**
   Penggunaan `urllib.request.urlopen` standar tanpa custom redirect handler terbukti mengikuti response 302 ke sembarang URL eksternal secara default.

3. **Missing Modules in Host Python:**
   ```bash
   $ python3 -c "import matplotlib"
   ModuleNotFoundError: No module named 'matplotlib'
   $ python3 -m pytest --version
   No module named pytest
   ```

4. **Missing Ground Truth & Schema Mismatch:**
   Field `test_id`, `description`, `expected_class`, `response_size_bytes`, `waf_rule_ids` tidak ada pada dataset dan log saat ini.

---

## 5. Daftar Asumsi yang Belum Terverifikasi

1. **Asumsi Versi Image:** Diasumsikan image `owasp/modsecurity-crs:nginx` membawa Core Rule Set versi 4.x dengan Anomaly Scoring aktif. Ini belum dapat dikonfirmasi sampai container dapat dijalankan dan log diperiksa.
2. **Asumsi Respon Juice Shop pada Baseline:** Diasumsikan semua payload pada `attack_cases.json` mengembalikan respons yang mencerminkan kerentanan (misal SQLi mengembalikan data ekstra atau error SQLite). Hal ini belum divalidasi karena runtime belum aktif.
3. **Asumsi Aksesibilitas Audit Log ModSecurity:** Diasumsikan audit log dapat diarahkan ke file volume bersama yang dapat diparsing langsung oleh Python runner.

---

## 6. Prioritas Perbaikan (Action Plan)

| Prioritas | Item Tindakan | Phase Terkait |
|---|---|---|
| **P0** | Perbaiki containment simulator: tambahkan no-redirect policy dan validasi skema URL ketat. | Phase 3 |
| **P1** | Perbaiki `docker-compose.yml`: pinning image tags, tambahkan health check, volume mount config & log WAF, batasan RAM. | Phase 1 |
| **P2** | Siapkan struktur konfigurasi `waf/` dan direktori log untuk korelasi Rule ID. | Phase 1 & 2 |
| **P3** | Perluas dataset uji `attack_cases.json` dengan skema lengkap dan ground truth terdefinisi. | Phase 3 |
| **P4** | Implementasikan pipeline evaluasi `analyze_results.py` dan `generate_charts.py` dengan kalkulasi Confusion Matrix lengkap (TP, FP, TN, FN, Recall, Precision, FPR, Latency p50/p95). | Phase 5 |
| **P5** | Siapkan modul unit test menggunakan `unittest` (standar Python) untuk memvalidasi simulator dan modul evaluasi tanpa ketergantungan external package. | Phase 3 & 5 |
| **P6** | Lengkapi dokumentasi penelitian di `docs/`. | Phase 6 |

---
*Laporan dibuat sesuai kaidah metodologi penelitian akademik dan prinsip security containment.*
