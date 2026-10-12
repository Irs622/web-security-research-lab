# Format Berkas Hasil

Referensi kolom dan field untuk seluruh berkas yang dihasilkan di `results/`.

---

## 1. CSV Hasil Eksperimen (`results/{mode}.csv`)

Ditulis oleh [`simulator/runner.py`](../simulator/runner.py), satu baris per request (termasuk pengulangan).

| Kolom | Keterangan |
|---|---|
| `run_id` | `run_{mode}_{YYYYmmdd_HHMMSS}` (UTC) |
| `test_id`, `category`, `expected_class` | Disalin dari dataset |
| `repeat_index` | 0 untuk pengulangan pertama. **Hanya baris `0` yang dihitung untuk metrik deteksi**; semua baris dipakai untuk statistik latensi |
| `mode` | `baseline` atau `waf` |
| `timestamp_utc` | Waktu ISO-8601 setelah respons diterima |
| `method`, `path` | Method dan path lengkap beserta query string yang dikirim |
| `http_status` | Kode status HTTP; kosong bila terjadi error transport |
| `latency_ms` | Waktu request–respons (ms), diukur dengan `perf_counter` |
| `response_size_bytes` | Ukuran body yang dibaca (maks. 64 KiB) |
| `transport_error` | Pesan error koneksi/timeout; baris dengan nilai ini dikeluarkan dari metrik |
| `waf_rule_ids` | Rule ID CRS yang terpicu, dipisah `;` (mode `waf`) |
| `waf_intervention` | `True` bila ModSecurity memutus transaksi (`is_interrupted` di audit log) |
| `trace_id` | Nilai header `X-Lab-Trace-Id` yang dikirim |
| `log_match` | Cara korelasi audit log: `trace_id`, `uri`, `none`, atau `disabled` |
| `observed_outcome` | Lihat tabel di bawah |

Nilai `observed_outcome`:

| Nilai | Arti |
|---|---|
| `allowed_baseline` | Request mode baseline (tanpa WAF) |
| `blocked_by_waf` | ModSecurity memblokir request |
| `detected_alert_only` | Rule serangan terpicu tetapi skor anomali di bawah ambang blokir |
| `rejected_by_proxy` | Nginx menolak (HTTP 400) sebelum ModSecurity berjalan; tidak ada record audit |
| `passed_clean` | Tidak ada rule serangan yang terpicu |
| `transport_error` | Request gagal di level jaringan |

---

## 2. Metadata Run (`results/{mode}.meta.json`)

Ditulis di samping setiap CSV untuk reproducibility: `run_id`, `mode`, `started_utc`, `finished_utc`, `git_sha`, `dataset_sha256`, `case_count`, `repeat`, `warmup`, `paranoia_level`, `anomaly_inbound`, `tuned_exclusions`, `images` (referensi image beserta digest), `python`, `platform`, `transport_errors`.

---

## 3. Ringkasan Metrik (`summary_metrics.json`)

Ditulis oleh [`evaluation/analyze_results.py`](../evaluation/analyze_results.py). Definisi rumus ada di [METRICS.md](METRICS.md).

| Field | Keterangan |
|---|---|
| `sample_count` | Jumlah kasus yang dievaluasi (pengulangan pertama, tanpa error transport) |
| `confusion_matrix` | `TP`, `FP`, `TN`, `FN` |
| `detection_rate_recall`, `precision`, `false_positive_rate`, `f1_score`, `blocking_rate`, `overall_mitigation_rate` | Rasio 0–1, dibulatkan 4 desimal. **`null` bila penyebutnya nol** (mis. set hold-out tanpa kasus malicious) |
| `malicious_blocked`, `malicious_rejected_by_proxy`, `total_malicious` | Hitungan mentah |
| `latency_waf`, `latency_baseline` | `mean_ms`, `p50_ms`, `p95_ms` |
| `latency_overhead_mean_ms` | Selisih rata-rata WAF − baseline |
| `latency_stats` | `n`, `mean_ms`, `p50_ms`, `p95_ms`, `iqr_ms` per mode, serta `mann_whitney_u` (`u`, `z`, `p_value`) |
| `confidence_intervals_95` | Interval Wilson `[bawah, atas]` untuk recall, precision, FPR, blocking rate |
| `category_breakdown` | Per kategori: `total`, `detected`, `blocked` |
| `misclassified` | Daftar kasus FN/FP beserta rule yang terpicu |

---

## 4. Perbandingan Paranoia Level (`results/paranoia/`)

- `pl{N}/` dan `pl2-tuned/` — masing-masing berisi `waf.csv`, `waf.meta.json`, `summary_metrics.json`.
- `paranoia_comparison.json` — satu baris per skenario: `scenario`, `paranoia_level`, `tuned`, `recall`, `recall_ci95`, `false_positive_rate`, `fpr_ci95`, `precision`, `f1_score`, `blocking_rate`, `waf_p50_ms`, `confusion_matrix`.
- `paranoia_tradeoff.png` — grafik recall/FPR/F1 per level.

Hasil hold-out disimpan dengan struktur yang sama di `results/holdout/{pl1,pl2,pl2-tuned}/`.

---

## 5. Grafik

`make charts` (atau `python evaluation/generate_charts.py --summary <json> --output-dir <dir>`) menghasilkan `confusion_matrix.png`, `latency_comparison.png`, dan `category_breakdown.png` pada 300 dpi.
