# Changelog

Perubahan penting pada lab ini, terbaru di atas.

## 2026-10-16
- **Hold-out diperbesar** dari 20 menjadi 80 kasus benign (`HOLDOUT-021…080`), di-commit sebelum tuning baru. Batas atas Wilson FPR saat 0 FP turun dari 16,1% ke 4,6%.
- **Tuning v2** (`lab/tuning/`, id 1103–1104): `932236` dikecualikan pada `q` pencarian dan `931130` pada `json.comment` feedback. Diturunkan hanya dari FP PL2 dataset diperluas. FPR PL2 tuned dataset diperluas 12.31% → 4.62% (in-sample), recall tetap 88.16%; FPR hold-out PL2 tuned 15% (12/80) vs PL1 2.5%.
- **Latensi multi-ronde:** `make experiment-latency` dan `evaluation/latency_rounds.py` (median antar-ronde Δp50, rentang, bootstrap CI; populasi benign saja vs semua). Hasil: overhead benign median +7.69 ms; mencampur request yang diblokir menyembunyikan sebagian besar overhead (+2.08 ms).
- **Metadata:** load average host dan jumlah CPU; `git_dirty` kini mengabaikan `results/`, sehingga tahap pipeline berikutnya tidak lagi tercatat "dirty" hanya karena berkas hasil ditulis ulang.
- **Hasil:** `results/paranoia/pl2-tuned`, `results/holdout/`, `results/extended/paranoia/pl2-tuned`, `results/extended/holdout/`, dan `results/extended/latency/` dijalankan ulang pada commit `dc2bbe7`.

## 2026-10-15
- **Dataset diperluas** `simulator/attack_cases_extended.json`: 217 kasus (65 benign, 152 malicious, 13 keluarga), superset dari dataset asli. Paket skenario eksternal diaudit lebih dulu: ID yang bertabrakan dengan dataset asli, kebocoran hold-out, label keliru, dan request duplikat lintas kategori dikoreksi ([SCENARIO_MATRIX.md](docs/SCENARIO_MATRIX.md)).
- **Ground truth vs observasi:** field `scenario_applicability` (`sink_present`/`pattern_only`/`benign_control`); kolom CSV baru `waf_alert`, `intervention_evidence`, `block_source`, `backend_outcome`, `scenario_applicability`.
- **Metrik:** blocking rate hanya dari intervensi terkonfirmasi audit log; specificity; overhead p50; recall/blocking/FPR + Wilson CI per kategori dan per applicability dengan penanda sampel kecil; `alerts_outbound_only`. Hasil lama dihitung ulang dan identik.
- **Reproducibility:** metadata run mencatat path dan hash berkas dataset, `git_dirty`, environment dan mount container WAF yang berjalan, versi ModSecurity/CRS dari audit log, serta jumlah request dicoba/berhasil. Analyzer menolak pasangan CSV WAF/baseline dari dataset berbeda.
- **Tooling:** variabel `CASES`/`OUT` di semua target eksperimen, `make experiment-extended`, `make compose-check`, `compare_paranoia.py --matrix-dir`.
- **Perbaikan lab:** `PARANOIA` kini juga menyetel `BLOCKING_PARANOIA` dan `DETECTION_PARANOIA`. Sebelumnya image CRS memakai blocking PL1 untuk semua skenario, sehingga hasil PL2–PL4 dataset asli hanya mengukur rule yang terpicu, bukan blokir (lihat koreksi di RESULTS_INTERPRETATION.md §2c).
- **Atribusi:** blokir yang hanya berasal dari rule outbound (`950100` + `959100`) dicatat `backend_outcome = reached_response_blocked`; `959100` diperlakukan sebagai meta-rule seperti `949110`; metrik `request_phase` (recall/FPR tanpa rule `95xxxx`).
- **Eksperimen (dataset asli, dijalankan ulang):** `results/paranoia/` (PL1–PL4, PL2 tuned) dan `results/holdout/` dijalankan ulang dengan blocking PL = detection PL. Klasifikasi identik dengan run awal. Blocking rate kini sama dengan recall (PL2 82.14%, PL3/PL4 85.71%; sebelumnya 78.57% di semua PL). FP PL2+ kini benar-benar diblokir.
- **Eksperimen:** hasil dataset diperluas di `results/extended/` (baseline, PL1–PL4, PL2 tuned, hold-out), 3× pengulangan, 0 error transport.
- **Test:** validasi dataset diperluas (keunikan request, identitas kasus asli, independensi hold-out ter-normalisasi, well-formedness JSON/XML, host payload dalam lingkup lab).

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
