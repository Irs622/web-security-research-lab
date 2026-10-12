# Changelog

Perubahan penting pada lab ini, terbaru di atas.

## 2026-10-13
- **Metrik:** rasio dengan penyebut nol (recall/F1/blocking pada set hold-out benign) kini `null`, bukan 0%; ringkasan hold-out dihitung ulang.
- **Korelasi:** tidak lagi fallback ke pencocokan URI bila audit log mencatat trace header, mencegah pengambilan transaksi lama.
- **CLI:** `load_cases()` menolak `test_id` ganda; `--delay` < 0.1 ditolak; `generate_charts.py` menerima `--summary` dan `--output-dir`.
- **Tooling:** target `make check`, interpreter seragam `$(PY)`; CI dengan matrix Python 3.9/3.12, cache pip, permission read-only.
- **Test:** coverage naik dari 55% ke 82%.
- **Dokumentasi:** DATASET.md, OUTPUT_FORMAT.md, DEVELOPMENT.md, CHANGELOG.md.

## 2026-10-11
- Set hold-out benign (20 kasus) dan target `experiment-holdout`; kategori CRS tambahan pada skema dataset.
- Image di-pin dengan digest; skenario PL2 tuned dengan exclusion CRS sempit.
- Header `Accept` dikirim simulator; HTTP 400 dari Nginx diklasifikasikan `rejected_by_proxy`; hasil N=70 (3×) dan matriks Paranoia Level 1–4.
- 30 kasus benign realistis ditambahkan.
- Integration test, metadata run, lint ruff, coverage, dan simulator penuh di CI.
- Pengulangan dengan warm-up, IQR latensi, uji Mann-Whitney U, matriks Paranoia Level.
- Interval kepercayaan Wilson, daftar FN/FP, kolom kategori, polling audit log.
- Korelasi audit log berbasis trace-id dan atribusi blokir yang akurat.
- Profil deployment produksi (Caddy + ModSecurity) dan workflow CI.

## 2026-10-10
- Rilis awal: baseline, simulator, korelasi CRS, metrik, dan dokumentasi.
