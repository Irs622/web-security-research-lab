# Panduan Pengembangan

Untuk kontributor yang mengubah kode simulator, evaluasi, dataset, atau konfigurasi.

---

## 1. Setup

```bash
make install        # membuat .venv dan menginstal requirements.txt
make check          # ruff + pytest dengan coverage
```

Kode mendukung Python **3.9** (Python bawaan macOS) hingga versi terbaru; CI menguji 3.9 dan 3.12. Semua target Make memakai interpreter `.venv` bila tersedia (variabel `PY`).

---

## 2. Struktur Modul

| Modul | Tanggung jawab |
|---|---|
| `simulator/target_validator.py` | Allowlist host/port loopback, penolakan redirect |
| `simulator/runner.py` | Eksekusi request, pengukuran latensi, penentuan `observed_outcome`, penulisan CSV & metadata |
| `simulator/log_correlator.py` | Membaca audit log JSON ModSecurity via `docker logs` dan mencocokkannya per `X-Lab-Trace-Id` |
| `simulator/run_tests.py` | CLI dan validasi dataset (`load_cases`) |
| `evaluation/analyze_results.py` | Confusion matrix, rasio, Wilson CI, Mann-Whitney U |
| `evaluation/compare_paranoia.py` | Agregasi skenario Paranoia Level |
| `evaluation/generate_charts.py` | Grafik PNG |

Alur data: dataset JSON → `runner` → CSV + `meta.json` → `analyze_results` → `summary_metrics.json` → grafik.

---

## 3. Test

| Berkas | Cakupan |
|---|---|
| `tests/test_target_validator.py` | Containment URL dan redirect |
| `tests/test_runner_integration.py` | Runner terhadap server HTTP lokal (tanpa Docker) |
| `tests/test_correlation.py` | Korelasi audit log dan atribusi blokir |
| `tests/test_evaluation.py` | Rumus metrik dan edge case |
| `tests/test_paranoia_compare.py`, `tests/test_cli.py` | CLI, grafik, perbandingan Paranoia Level |
| `tests/test_dataset.py` | Skema kedua dataset, independensi hold-out, keunikan request, identitas kasus asli di dataset diperluas, well-formedness JSON/XML, host payload dalam lingkup lab |

Unit test tidak membutuhkan Docker. Pengujian end-to-end terhadap container dijalankan oleh job `waf-smoke` di CI.

---

## 4. CI ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml))

| Job | Isi |
|---|---|
| `lint` | `ruff check .` |
| `unit-tests` | pytest + coverage pada Python 3.9 dan 3.12 |
| `compose-validate` | `docker compose config` untuk profil lab dan produksi |
| `waf-smoke` | Menyalakan lab, memastikan request benign lolos dan SQLi/XSS diblokir, menjalankan simulator penuh, analisis, dan grafik; hasil diunggah sebagai artifact `experiment-results` |

---

## 5. Konvensi

- Gaya kode mengikuti [`ruff.toml`](../ruff.toml); jalankan `make check` sebelum commit.
- Perubahan pada logika metrik atau korelasi wajib disertai test dan pembaruan [METRICS.md](METRICS.md) / [METHODOLOGY.md](METHODOLOGY.md).
- Bila perubahan memengaruhi angka di `results/`, jalankan ulang eksperimen terkait dan perbarui tabel di README serta [RESULTS_INTERPRETATION.md](RESULTS_INTERPRETATION.md).
- Image Docker di-pin dengan tag + digest; perbarui keduanya bersamaan.
- Catat perubahan penting di [CHANGELOG.md](../CHANGELOG.md).
