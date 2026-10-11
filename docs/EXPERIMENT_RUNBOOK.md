# Experiment Runbook: Panduan Eksekusi Penelitian

Panduan langkah-demi-langkah bagi peneliti untuk mereproduksi seluruh eksperimen pengujian keamanan WAF di macOS maupun VPS Linux.

---

## 1. Prasyarat Sistem

- **Docker Desktop / Docker Engine:** Compose v2 aktif.
- **Python 3.9+:** (Atau Python 3.10+).
- **RAM Minimum:** 4 GB disarankan 8 GB.
- **Port Tersedia:** `127.0.0.1:3001` (Baseline) dan `127.0.0.1:8080` (WAF).

---

## 2. Inisialisasi Environment

```bash
# Masuk ke direktori proyek
cd waf-research-lab

# Buat virtual environment lokal dan aktifkan
python3 -m venv .venv
source .venv/bin/activate

# Instal dependensi pengujian dan grafik
pip install -r requirements.txt
# atau: make install
```

---

## 3. Menjalankan Lab Container

```bash
# Tarik image container resmi yang ter-pin (tag + digest sha256, lihat docker-compose.yml)
docker compose pull

# Jalankan service target Juice Shop dan ModSecurity CRS
docker compose up -d juice-shop waf

# Pastikan kedua container berada dalam status "healthy"
docker compose ps
```

Verifikasi endpoint aktif:
```bash
curl -I http://127.0.0.1:3001/
curl -I http://127.0.0.1:8080/
```
Keduanya harus merespon dengan status HTTP 200.

---

## 4. Menjalankan Unit Tests

Sebelum pengujian dimulai, validasi bahwa modul validator URL, redirect handling, dan kalkulator metrik bekerja dengan benar:
```bash
.venv/bin/pytest -v
```
Seluruh tes harus berstatus `PASSED`.

---

## 5. Eksekusi Pengujian Terkontrol

> ⚠️ **Jangan menjalankan dua eksperimen bersamaan.** Semua skenario memakai container `waflab-modsecurity` yang sama; `experiment-matrix` dan `experiment-tuned` me-*recreate* container itu dengan Paranoia Level berbeda. Eksekusi paralel (mis. dua terminal) memutus koneksi di tengah run (`transport_error`) dan mencampur data antar-level. Bila terjadi, hapus hasil run tersebut dan ulangi.

### Tahap A: Pengujian Jalur Kontrol (Baseline)
```bash
python3 simulator/run_tests.py --target http://127.0.0.1:3001 --mode baseline --repeat 3
# atau: make test-baseline   (REPEAT=3 default)
```
*Hasil akan tersimpan ke `results/baseline.csv`, metadata run ke `results/baseline.meta.json`.*

### Tahap B: Pengujian Jalur WAF
```bash
python3 simulator/run_tests.py --target http://127.0.0.1:8080 --mode waf --repeat 3
# atau: make test-waf
```
*Hasil akan tersimpan ke `results/waf.csv` lengkap dengan Rule ID CRS yang terpicu.*

Opsi penting simulator:

| Opsi | Default | Fungsi |
|---|---|---|
| `--repeat N` | 1 (`make`: 3) | Ulangi seluruh suite N kali; deteksi dihitung sekali, latensi dari semua pengulangan |
| `--warmup N` | 5 | Request pemanasan yang tidak dicatat |
| `--delay S` | 0.25 | Jeda antar-request (minimum 0.1 s) |
| `--output PATH` | `results/<mode>.csv` | Lokasi CSV hasil |

Pastikan kolom `transport_error` kosong dan `log_match` bernilai `trace_id` untuk hampir semua baris WAF. Baris `rejected_by_proxy` (HTTP 400 dari Nginx tanpa audit log) adalah perilaku yang diharapkan untuk URI `../`.

### Tahap C: Matriks Paranoia Level 1–4
```bash
make experiment-matrix          # ±10 menit; hasil di results/paranoia/pl<N>/
```

### Tahap D: Skenario PL2 Tuned
```bash
make experiment-tuned           # PL2 + exclusion sempit dari lab/tuning/; hasil di results/paranoia/pl2-tuned/
```
### Tahap E: Validasi Hold-out
```bash
make experiment-holdout         # 20 benign baru vs PL1, PL2, PL2 tuned; hasil di results/holdout/<skenario>/
```

Ketiga target mengembalikan WAF ke PL1 setelah selesai. `experiment-matrix` dan `experiment-tuned` juga memperbarui `results/paranoia/paranoia_comparison.json` serta `paranoia_tradeoff.png`.

---

## 6. Analisis Hasil & Pembuatan Grafik

```bash
# Tampilkan ringkasan matriks konfusi, recall, precision, FPR, dan latensi
python3 evaluation/analyze_results.py
# opsional untuk file lain: --waf X.csv --baseline Y.csv --output Z.json

# Hasilkan grafik visualisasi ilmiah untuk skripsi
.venv/bin/python evaluation/generate_charts.py
```

Grafik akan tersimpan di:
- `results/confusion_matrix.png`
- `results/latency_comparison.png`
- `results/category_breakdown.png`

---

## 7. Eksekusi Passive Baseline Scan (OWASP ZAP)

```bash
docker compose --profile scan run --rm zap-baseline
```
Laporan passive scan akan tersimpan di direktori `results/`.

---

## 8. Penghentian Lab

```bash
# Menghentikan container
docker compose down

# Reset menyeluruh
docker compose down -v
```
