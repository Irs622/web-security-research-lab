# WAF Security Testing Lab

[![CI](https://github.com/Irs622/web-security-research-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Irs622/web-security-research-lab/actions/workflows/ci.yml)

Repository penelitian eksperimental skripsi Teknik Informatika berjudul:  
**"Evaluasi Efektivitas Web Application Firewall dalam Mendeteksi dan Memitigasi Serangan terhadap Aplikasi Web"**

Repository ini memiliki **dua mode penggunaan**:

| Mode | Tujuan | File Compose | Paparan Jaringan |
|---|---|---|---|
| **Lab Riset** | Eksperimen skripsi terhadap OWASP Juice Shop | [`docker-compose.yml`](docker-compose.yml) | Loopback saja (`127.0.0.1`) |
| **Produksi** | Melindungi website nyata milik sendiri | [`deploy/prod/docker-compose.prod.yml`](deploy/prod/docker-compose.prod.yml) | Publik via HTTPS (80/443) |

---

## 1. Ikhtisar Arsitektur

Laboratorium ini menguji kemampuan **ModSecurity v3** yang diperkuat oleh **OWASP Core Rule Set (CRS) v4.25 LTS** dalam mendeteksi dan memitigasi serangan terhadap aplikasi sengaja rentan **OWASP Juice Shop v17.1.1**.

```
                +------------------------------------------+
                |    Python Test Simulator (Controlled)    |
                +------------------------------------------+
                       |                             |
             [Mode: baseline]                   [Mode: waf]
             (Direct Access)                (Inspected Access)
                       |                             |
                       v                             v
               127.0.0.1:3001                 127.0.0.1:8080
                       |                             |
                       |                 +-----------------------+
                       |                 |   waflab-modsecurity  |
                       |                 | (Nginx + ModSec v3    |
                       |                 |  + OWASP CRS v4.25)   |
                       |                 +-----------------------+
                       |                             |
                       v                             v (Proxy Pass)
             +---------------------------------------------------+
             |       waflab-juice-shop (Port 3000 Internal)      |
             +---------------------------------------------------+
```

### Komponen Utama & Versi Image
- **Target Aplikasi:** `bkimminich/juice-shop:v17.1.1` (Distroless Node.js)
- **WAF Engine & Ruleset:** `owasp/modsecurity-crs:4.25.2-nginx-alpine-lts` (Nginx 1.30, ModSecurity 3.0.17, CRS 4.25.2, Anomaly Inbound: 5, Paranoia Level: 1)
- **Passive Scanner:** `ghcr.io/zaproxy/zaproxy:2.16.0` (OWASP ZAP Baseline)
- **Controlled Simulator:** Python 3 (urllib dengan strict no-redirect policy & ModSecurity audit log correlator)
- **Evaluation & Visualizer:** Python (Pandas & Matplotlib)

### Struktur Repository
```text
.
├── docker-compose.yml          # Lab riset: Juice Shop + WAF + ZAP (loopback only)
├── Makefile                    # Shortcut perintah lab & produksi
├── requirements.txt            # Dependensi Python (pandas, matplotlib, pytest)
├── simulator/                  # Simulator uji terkontrol + korelator audit log
│   ├── attack_cases.json       # Dataset 40 kasus berlabel
│   ├── run_tests.py            # CLI eksekusi eksperimen
│   ├── runner.py               # Eksekutor request & pencatatan hasil
│   ├── log_correlator.py       # Korelasi request ↔ audit log ModSecurity
│   └── target_validator.py     # Allowlist loopback & anti-redirect
├── evaluation/                 # Kalkulasi metrik & pembuatan grafik
├── results/                    # CSV hasil, ringkasan metrik, grafik, laporan ZAP
├── tests/                      # Unit test (pytest)
├── deploy/prod/                # Profil deployment produksi
│   ├── docker-compose.prod.yml # Caddy (TLS) + ModSecurity/CRS
│   ├── .env.example            # Template konfigurasi
│   ├── caddy/Caddyfile         # TLS otomatis & security headers
│   └── waf/                    # Rule exclusion CRS (tuning false positive)
├── docs/                       # Dokumentasi penelitian & operasional
└── .github/workflows/ci.yml    # CI: unit test, validasi compose, smoke test WAF
```

---

## 2. Batasan Keamanan & Containment

- Seluruh service aplikasi hanya di-bind ke loopback host (`127.0.0.1:3001` dan `127.0.0.1:8080`).
- Dilarang keras mengekspos port ke `0.0.0.0` atau jaringan publik.
- Simulator Python dilengkapi dengan handler anti-redirect untuk mencegah kebocoran request di luar containment lokal (SSRF protection).
- Jika diuji pada VPS, akses wajib dilakukan secara aman melalui SSH loopback tunnel:
  ```bash
  ssh -N -L 8080:127.0.0.1:8080 -L 3001:127.0.0.1:3001 user@vps-ip
  ```

---

## 3. Prasyarat & Instalasi

### Prasyarat
- macOS (Apple Silicon M-Series atau Intel) atau Linux VPS dengan RAM minimal 4 GB.
- Docker Engine & Docker Compose v2+.
- Python 3.9+.

### Setup Lingkungan Lokal
```bash
# Clone repository
git clone https://github.com/Irs622/web-security-research-lab.git
cd web-security-research-lab

# Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# atau cukup: make install
```

---

## 4. Panduan Menjalankan Eksperimen

### Langkah 1: Jalankan Lab Container
```bash
make up
# atau: docker compose up -d juice-shop waf
```
Periksa kesiapan dan healthcheck:
```bash
make ps
# Pastikan kedua container berstatus "healthy"
```

### Langkah 2: Jalankan Unit Test Validasi
```bash
make test-unit
# Memverifikasi URL validator, redirect handler, kalkulator metrik, dan skema dataset
```

### Langkah 3: Eksekusi Eksperimen Dua Jalur
```bash
# 1. Jalur Kontrol (Baseline Langsung)
make test-baseline

# 2. Jalur Perlakuan (WAF ModSecurity)
make test-waf
```

### Langkah 4: Analisis Metrik & Pembuatan Grafik
```bash
# Menampilkan ringkasan metrik Confusion Matrix, Recall, Precision, FPR, Latensi
make analyze

# Menghasilkan grafik ilmiah (PNG) untuk skripsi
make charts
```

### Langkah 5: OWASP ZAP Passive Scan
```bash
make zap
```

### Opsi Lanjutan Simulator
```bash
python3 simulator/run_tests.py --target http://127.0.0.1:8080 --mode waf \
  --delay 0.25 --timeout 5.0 --cases simulator/attack_cases.json --output results/waf.csv
```
| Opsi | Default | Keterangan |
|---|---|---|
| `--target` | (wajib) | URL loopback: `:3001` baseline, `:8080` WAF |
| `--mode` | (wajib) | `baseline` atau `waf` |
| `--delay` | `0.25` | Jeda antar request (detik, minimum 0.1) |
| `--timeout` | `5.0` | Timeout HTTP (detik) |
| `--cases` | `simulator/attack_cases.json` | Dataset kasus uji |
| `--output` | `results/{mode}.csv` | Lokasi CSV hasil |
| `--no-docker-logs` | nonaktif | Matikan korelasi audit log via Docker CLI |

### Daftar Perintah Make
| Perintah | Fungsi |
|---|---|
| `make install` | Buat `.venv` dan instal `requirements.txt` |
| `make up` / `make down` / `make ps` / `make logs` | Kelola container lab |
| `make test-unit` | Jalankan pytest |
| `make test-baseline` / `make test-waf` | Eksekusi eksperimen dua jalur |
| `make analyze` / `make charts` | Hitung metrik & buat grafik |
| `make zap` | OWASP ZAP passive baseline scan |
| `make prod-up` / `make prod-down` | Jalankan / hentikan stack produksi |
| `make prod-restart` | Restart WAF setelah mengubah rule exclusion |
| `make prod-logs` | Ikuti log WAF produksi |
| `make prod-fp` | Ringkasan 20 rule ID CRS yang paling sering terpicu |

---

## 5. Ringkasan Hasil Eksperimen Aktual (N=40 Kasus Uji)

| Metrik Evaluasi | Nilai | Keterangan |
|---|---|---|
| **True Positives (TP)** | 27 | Serangan berhasil dideteksi oleh aturan CRS |
| **False Positives (FP)** | 0 | Request normal tidak ada yang salah diblokir |
| **True Negatives (TN)** | 12 | Seluruh request benign diizinkan WAF (pass-through tanpa pemblokiran) |
| **False Negatives (FN)** | 1 | 1 probe traversal null-byte lolos pada PL 1 |
| **Detection Rate (Recall)** | **96.43%** | Tingkat keberhasilan deteksi ancaman |
| **Precision** | **100.00%** | Tingkat ketepatan peringatan deteksi |
| **False Positive Rate (FPR)** | **0.00%** | Tingkat kesalahan deteksi terhadap user sah |
| **Enforcement Blocking Rate** | **96.43%** | 27 dari 28 serangan diputus (HTTP 403) |
| **Baseline Latency (Mean)** | 18.47 ms | Latensi langsung ke OWASP Juice Shop |
| **WAF Latency (Mean)** | 21.55 ms | Latensi melalui Nginx + ModSecurity |
| **Inspection Overhead** | **+3.07 ms** | Overhead komputasi inspeksi WAF |

Grafik visualisasi tersimpan di:
- `results/confusion_matrix.png`
- `results/latency_comparison.png`
- `results/category_breakdown.png`

---

## 6. Dokumentasi Lengkap

- [Arsitektur Sistem](docs/ARCHITECTURE.md)
- [Batasan Keamanan & Containment](docs/SECURITY_SCOPE.md)
- [Metodologi Penelitian](docs/METHODOLOGY.md)
- [Formulasi Metrik Evaluasi](docs/METRICS.md)
- [Experiment Runbook](docs/EXPERIMENT_RUNBOOK.md)
- [Panduan Interpretasi Hasil](docs/RESULTS_INTERPRETATION.md)
- [Initial Audit Report](docs/INITIAL_AUDIT.md)

---
*Dikembangkan untuk keperluan penelitian skripsi akademik Teknik Informatika.*
