# WAF Security Testing Lab

Repository penelitian eksperimental skripsi Teknik Informatika berjudul:  
**"Evaluasi Efektivitas Web Application Firewall dalam Mendeteksi dan Memitigasi Serangan terhadap Aplikasi Web"**

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
pip install pytest matplotlib pandas
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
