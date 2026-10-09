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
pip install pytest matplotlib pandas
```

---

## 3. Menjalankan Lab Container

```bash
# Tarik image container resmi yang ter-pin
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

### Tahap A: Pengujian Jalur Kontrol (Baseline)
```bash
python3 simulator/run_tests.py --target http://127.0.0.1:3001 --mode baseline
```
*Hasil akan tersimpan ke `results/baseline.csv`.*

### Tahap B: Pengujian Jalur WAF
```bash
python3 simulator/run_tests.py --target http://127.0.0.1:8080 --mode waf
```
*Hasil akan tersimpan ke `results/waf.csv` lengkap dengan Rule ID CRS yang terpicu.*

---

## 6. Analisis Hasil & Pembuatan Grafik

```bash
# Tampilkan ringkasan matriks konfusi, recall, precision, FPR, dan latensi
python3 evaluation/analyze_results.py

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
