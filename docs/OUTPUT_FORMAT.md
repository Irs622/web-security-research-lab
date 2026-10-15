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
| `waf_alert` | `True` bila ada rule serangan (selain `920350`/`949110`) di audit log; kosong pada baseline |
| `intervention_evidence` | `audit_log` (keputusan blokir dari record audit) atau `status_heuristic` (tidak ada record; status 403/406 dipakai sebagai perkiraan); kosong pada baseline |
| `block_source` | `waf`, `proxy` (Nginx 400 sebelum ModSecurity), `application` (401/403 dari Juice Shop tanpa intervensi WAF), `none`; kosong bila error transport |
| `backend_outcome` | `not_reached` (diputus WAF/proxy di fase request), `reached_response_blocked` (WAF hanya memblokir respons lewat rule `95xxxx`; aplikasi sudah memproses request), `2xx`/`3xx`/`4xx`/`5xx`, atau `transport_error`. Hanya kelas status; bukan bukti eksploitasi |
| `scenario_applicability` | Disalin dari dataset (`sink_present`, `pattern_only`, `benign_control`); `unspecified` bila dataset tidak memuatnya |

Lima kolom terakhir ditambahkan di akhir header (skema v2). CSV lama tanpa kolom tersebut tetap dapat dianalisis: `intervention_evidence` diturunkan dari `log_match`, dan applicability menjadi `unspecified`.

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

Ditulis di samping setiap CSV untuk reproducibility:

| Field | Keterangan |
|---|---|
| `run_id`, `mode`, `target`, `started_utc`, `finished_utc` | Identitas dan waktu run |
| `git_sha`, `git_dirty` | Commit kode; `git_dirty: true` berarti ada perubahan file ter-track di luar `results/` yang belum di-commit saat run |
| `dataset_path`, `dataset_file_sha256` | Berkas dataset dan hash byte-nya |
| `dataset_sha256`, `case_count` | Hash kanonik isi dataset (dipakai untuk mencegah pencampuran hasil) dan jumlah kasus |
| `repeat`, `warmup` | Parameter pengulangan |
| `paranoia_level`, `anomaly_inbound`, `tuned_exclusions` | Konfigurasi yang *dimaksudkan* (dari environment variable shell) |
| `exclusions_file`, `exclusions_sha256` | File exclusion dan hash-nya bila `TUNED=1` |
| `waf_runtime` | (mode `waf`) `env` container WAF yang *benar-benar berjalan* (`PARANOIA`, `ANOMALY_INBOUND`, …) dan `mounts` (mis. file exclusion yang di-mount) |
| `waf_producer` | (mode `waf`) Field `producer` audit log ModSecurity: versi engine, connector, dan komponen CRS |
| `audit_log_correlation` | (mode `waf`) Jumlah baris per nilai `log_match` |
| `requests_attempted`, `requests_completed`, `transport_errors` | Jumlah request terjadwal, yang mendapat respons HTTP, dan yang gagal di level jaringan |
| `images` | Referensi image beserta digest |
| `python`, `platform`, `cpu_count` | Lingkungan eksekusi |
| `host_load_avg_start`, `host_load_avg_end` | Load average host 1/5/15 menit di awal dan akhir run |

---

## 3. Ringkasan Metrik (`summary_metrics.json`)

Ditulis oleh [`evaluation/analyze_results.py`](../evaluation/analyze_results.py). Definisi rumus ada di [METRICS.md](METRICS.md).

| Field | Keterangan |
|---|---|
| `sample_count` | Jumlah kasus yang dievaluasi (pengulangan pertama, tanpa error transport) |
| `confusion_matrix` | `TP`, `FP`, `TN`, `FN` |
| `detection_rate_recall`, `precision`, `false_positive_rate`, `specificity`, `f1_score`, `blocking_rate`, `overall_mitigation_rate` | Rasio 0–1, dibulatkan 4 desimal. **`null` bila penyebutnya nol** (mis. set hold-out tanpa kasus malicious). `blocking_rate` hanya menghitung intervensi terkonfirmasi audit log |
| `malicious_blocked`, `malicious_blocked_unverified`, `malicious_rejected_by_proxy`, `total_malicious` | Hitungan mentah; `unverified` = 403/406 tanpa record audit |
| `alerts_outbound_only` | Kasus yang rule serangannya hanya rule fase respons (`95xxxx`), diblokir atau tidak |
| `request_phase` | `confusion_matrix`, `detection_rate_recall`, `false_positive_rate`, `recall_ci95`, `fpr_ci95` tanpa menghitung deteksi yang hanya berasal dari rule `95xxxx` |
| `latency_waf`, `latency_baseline` | `mean_ms`, `p50_ms`, `p95_ms` |
| `latency_overhead_mean_ms`, `latency_overhead_p50_ms` | Selisih rata-rata dan median WAF − baseline |
| `latency_stats` | `n`, `mean_ms`, `p50_ms`, `p95_ms`, `iqr_ms` per mode, serta `mann_whitney_u` (`u`, `z`, `p_value`) |
| `confidence_intervals_95` | Interval Wilson `[bawah, atas]` untuk recall, precision, FPR, specificity, blocking rate |
| `category_breakdown`, `applicability_breakdown` | Per kelompok: `total`, `detected`, `blocked`, `malicious`, `benign`, `tp`, `fn`, `fp`, `tn`, `blocked_confirmed`, `recall`, `recall_ci95`, `blocking_rate`, `false_positive_rate`, `small_sample` (lihat [METRICS.md](METRICS.md)) |
| `misclassified` | Daftar kasus FN/FP beserta rule yang terpicu, `outcome`, dan (FN) `scenario_applicability` |

---

## 4. Perbandingan Paranoia Level (`results/paranoia/`)

- `pl{N}/` dan `pl2-tuned/` — masing-masing berisi `waf.csv`, `waf.meta.json`, `summary_metrics.json`.
- `paranoia_comparison.json` — satu baris per skenario: `scenario`, `paranoia_level`, `tuned`, `recall`, `recall_ci95`, `false_positive_rate`, `fpr_ci95`, `precision`, `f1_score`, `blocking_rate`, `waf_p50_ms`, `confusion_matrix`.
- `paranoia_tradeoff.png` — grafik recall/FPR/F1 per level.

Hasil hold-out disimpan dengan struktur yang sama di `results/holdout/{pl1,pl2,pl2-tuned}/`.

Eksperimen latensi menulis `results/extended/latency/round<N>/{baseline,waf}.csv` (+ `.meta.json`) dan `latency_summary.json`: `rounds`, `per_round` (urutan mode, load average, statistik per mode dan Δp50 untuk `benign` dan `all`), serta untuk `benign` dan `all`: `overhead_p50_ms_per_round`, `overhead_p50_ms_median_of_rounds`, `overhead_p50_ms_range`, `pooled`, `pooled_overhead_p50_ms`, `pooled_overhead_p50_ci95_bootstrap`. Run ini memakai `--no-docker-logs`, jadi kolom deteksinya tidak boleh dipakai untuk metrik deteksi.

Hasil dataset diperluas memakai struktur yang sama di bawah `results/extended/` (`baseline.csv`, `waf.csv`, `summary_metrics.json`, grafik, `paranoia/`, `holdout/`). Jangan menyalin atau membandingkan CSV antar-direktori tanpa memeriksa `dataset_sha256` di `*.meta.json`.

---

## 5. Grafik

`make charts` (atau `python evaluation/generate_charts.py --summary <json> --output-dir <dir>`) menghasilkan `confusion_matrix.png`, `latency_comparison.png`, dan `category_breakdown.png` pada 300 dpi.
