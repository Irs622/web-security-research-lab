# Formulasi dan Definisi Metrik Evaluasi

Dokumen ini mendokumentasikan seluruh rumus matematika, indikator kinerja, dan metrik latensi yang dihitung dalam pipeline evaluasi laboratorium WAF.

---

## 1. Metrik Akurasi Deteksi

### A. Detection Rate / Recall (True Positive Rate / TPR)
Kemampuan WAF dalam mendeteksi request berbahaya dari keseluruhan request serangan yang diajukan.
$$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$

### B. Precision (Positive Predictive Value / PPV)
Proporsi deteksi WAF yang benar-benar merupakan serangan nyata terhadap total request yang ditandai sebagai serangan.
$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$$

### C. False Positive Rate (Fall-out / FPR)
Tingkat kesalahan WAF dalam menandai lalu lintas pengguna yang sah sebagai serangan.
$$\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$

### C2. Specificity (True Negative Rate)
Proporsi request benign yang dibiarkan lewat tanpa alert.
$$\text{Specificity} = \frac{\text{TN}}{\text{TN} + \text{FP}} = 1 - \text{FPR}$$

### D. F1-Score (Harmonic Mean)
Rata-rata harmonik antara Precision dan Recall untuk mengukur keseimbangan efektivitas.
$$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

---

## 2. Metrik Mitigasi & Pemblokiran

### Enforcement / Blocking Rate
Persentase request malicious yang diputus ModSecurity sebelum mencapai aplikasi.
$$\text{Blocking Rate} = \frac{\text{Malicious, intervensi terkonfirmasi audit log}}{\text{Total Malicious}}$$

"Terkonfirmasi" berarti transaksi audit log yang dikorelasikan dengan request (`log_match` = `trace_id`/`uri`) memiliki `is_interrupted: true`. HTTP 403 tanpa record audit (`intervention_evidence = status_heuristic`) **tidak** dihitung; jumlahnya dilaporkan terpisah sebagai `malicious_blocked_unverified`. HTTP 401/403 yang dikirim Juice Shop sendiri tercatat `block_source = application` dan juga tidak dihitung. Request yang ditolak Nginx (HTTP 400) sebelum ModSecurity dilaporkan sebagai `malicious_rejected_by_proxy` dan masuk `overall_mitigation_rate`, bukan blocking rate.

---

## 3. Metrik Kinerja dan Latensi

1. **Mean Latency ($\bar{L}$):** Rata-rata waktu round-trip HTTP dalam milidetik.
2. **Median Latency ($p_{50}$):** Persentil ke-50 respon latensi.
3. **Tail Latency ($p_{95}$):** Persentil ke-95 respon latensi untuk mendeteksi lonjakan komputasi inspeksi regex ModSecurity.
4. **Inspection Overhead ($\Delta L$):** Selisih latensi tambahan yang diperkenalkan oleh lapisan reverse proxy dan evaluasi CRS:
$$\Delta L = \bar{L}_{\text{WAF}} - \bar{L}_{\text{Baseline}}$$
   Dilaporkan juga selisih median: $\Delta L_{p50} = p_{50,\text{WAF}} - p_{50,\text{Baseline}}$ (`latency_overhead_p50_ms`), yang lebih tahan terhadap outlier.

Overhead hanya dihitung bila CSV WAF dan baseline berasal dari dataset yang sama; `analyze_results.py` menolak pasangan yang `dataset_sha256`-nya berbeda.

---

## 4. Penanganan Edge Cases & Keamanan Matematis

Pada skrip [`evaluation/analyze_results.py`](../evaluation/analyze_results.py), seluruh kalkulasi diproteksi dari pembagian dengan nol (*Division-by-Zero Guard*):
- Jika $\text{TP} + \text{FN} = 0$, Recall dan Blocking Rate bernilai `null` (tidak terdefinisi).
- Jika $\text{TP} + \text{FP} = 0$, Precision bernilai `null`.
- Jika $\text{FP} + \text{TN} = 0$, FPR dan Specificity bernilai `null`.
- Jika Recall atau Precision `null`, F1-Score juga `null`; jika keduanya 0, F1-Score bernilai `0.0`.

Nilai `null` ditampilkan sebagai `n/a` pada laporan teks. Ini disengaja: melaporkan 0% untuk metrik yang tidak dapat dihitung akan terbaca sebagai hasil pengukuran.

---

## 5. Ekslusi Rule ID dalam Kalkulasi Deteksi

Dua kelompok Rule ID dikecualikan dari variabel `attack_rules` (penentu `has_attack_detection`) sebelum klasifikasi TP/FP/TN/FN dilakukan:

### LAB_ENVIRONMENT_PROTOCOL_RULES: `{920350}`

Rule **920350** ("Request Header Host Is Numeric IP Address") terpicu pada **setiap** request dalam lab karena Host header berisi `127.0.0.1`. Rule ini memberikan anomaly score 3 poin — di bawah blocking threshold 5. Tidak ada kaitannya dengan deteksi pola serangan aplikasi. Jika tidak dikecualikan, seluruh 12 request benign akan salah diklasifikasikan sebagai FP.

### SCORING_META_RULES: `{949110}`

Rule **949110** ("Inbound Anomaly Score Exceeded") adalah meta-rule CRS yang terpicu ketika akumulasi skor dari rule-rule serangan lain melewati threshold. Rule ini **tidak mendeteksi pola serangan secara independen** — ia hanya mencerminkan hasil rule-rule yang sudah dihitung di atas. Menyertakannya dalam `has_attack_detection` akan menyebabkan double-counting pada setiap TP yang diblokir. Dikecualikan untuk menjaga keabsahan perhitungan confusion matrix.

## Interval Kepercayaan & Uji Statistik

- **Metrik tak terdefinisi bernilai `null`**: bila penyebut nol (mis. set hold-out yang seluruhnya benign tidak punya kasus malicious), `detection_rate_recall`, `blocking_rate`, `f1_score`, dan `overall_mitigation_rate` ditulis `null` di JSON dan `n/a` di laporan — bukan 0%, yang akan terbaca sebagai "tidak mendeteksi apa pun".
- **Wilson 95% CI** dilaporkan untuk Recall, Precision, FPR, dan Blocking Rate (`confidence_intervals_95` di `summary_metrics.json`). Dengan sampel kecil (mis. 0/12 benign), FPR 0% masih kompatibel dengan FPR sebenarnya hingga ±24% — selalu sertakan interval saat menulis kesimpulan.
- **Pengulangan (`--repeat N`)**: deteksi dihitung sekali per kasus (`repeat_index = 0`), sedangkan seluruh pengulangan menjadi sampel latensi. Request warm-up (`--warmup`, default 5) tidak dicatat.
- **Latensi**: dilaporkan mean, p50, p95, dan IQR; perbedaan baseline vs WAF diuji dengan **Mann-Whitney U** dua sisi (aproksimasi normal, koreksi ties) karena distribusi latensi tidak normal.
- **Daftar FN/FP** (`misclassified`) mencantumkan path dan rule yang muncul untuk analisis kegagalan.

## Perbandingan Paranoia Level

`make experiment-matrix` menjalankan suite WAF pada Paranoia Level 1–4 (`REPEAT=3` default), menyimpan hasil di `results/paranoia/pl<N>/`, lalu `evaluation/compare_paranoia.py` membuat `paranoia_comparison.json` dan grafik `paranoia_tradeoff.png` (Recall vs FPR vs F1).

## Metadata Reproducibility

Setiap run menulis `<output>.meta.json` di samping CSV: `run_id`, git SHA, SHA-256 dataset, jumlah kasus, `repeat`/`warmup`, Paranoia Level & threshold, digest image container yang sedang berjalan (`docker inspect`), serta versi Python/platform. Lampirkan file ini bersama hasil saat menulis laporan.

## Latensi Multi-ronde

`evaluation/latency_rounds.py` (dipanggil `make experiment-latency`) membaca `round<N>/{baseline,waf}.csv` dan melaporkan:

- **Δp50 per ronde** = $p_{50,\text{WAF}} - p_{50,\text{Baseline}}$ dalam ronde yang sama, serta median dan rentangnya antar-ronde. Median antar-ronde adalah angka utama karena tahan terhadap satu ronde yang terganggu beban host.
- **Δp50 gabungan** dengan interval kepercayaan 95% *percentile bootstrap* (2000 resample, seed tetap sehingga laporan dapat direproduksi).
- Dua populasi: **benign saja** (angka utama, mewakili biaya bagi pengguna sah) dan **semua request**. Request malicious yang diblokir dijawab WAF tanpa menyentuh backend, sehingga mencampurnya membuat WAF tampak lebih cepat.
- Load average host di awal setiap run (`host_load_avg_start`), sebagai indikator gangguan.

Ronde yang datasetnya berbeda antara baseline dan WAF ditolak.

## Metrik per Kategori dan per Applicability

`category_breakdown` dan `applicability_breakdown` di `summary_metrics.json` memuat, per kelompok: `total`, `malicious`, `benign`, `tp`, `fn`, `fp`, `tn`, `detected`, `blocked` (semua intervensi), `blocked_confirmed`, `recall` + `recall_ci95`, `blocking_rate` (terkonfirmasi), `false_positive_rate`, dan `small_sample` (`true` bila 0 < malicious < 10). Rumus sama dengan metrik keseluruhan, dibatasi ke baris kelompok tersebut; rasio dengan penyebut nol bernilai `null`.

Recall kelompok `pattern_only` adalah tingkat deteksi signature, bukan tingkat pencegahan eksploitasi (lihat [SCENARIO_MATRIX.md §4](SCENARIO_MATRIX.md#4-tiga-klaim-yang-berbeda)).

## Alert Fase Respons

Rule `95xxxx` (RESPONSE-95x, mis. `950100` "aplikasi mengembalikan 5xx") bereaksi terhadap respons aplikasi, bukan payload request. Rule ini tetap dihitung sebagai deteksi (sesuai desain awal dan hasil yang sudah dilaporkan), tetapi jumlah kasus yang **hanya** memicu rule fase respons dilaporkan sebagai `alerts_outbound_only` agar pembaca dapat menghitung ulang tanpa rule tersebut.

`request_phase` di `summary_metrics.json` melakukan perhitungan ulang itu: confusion matrix, recall, dan FPR (+ Wilson CI) di mana sebuah kasus hanya dianggap terdeteksi bila ada rule inspeksi request (bukan `95xxxx`) yang terpicu, atau bila diblokir tanpa rule tercatat. Contoh penting: pada dataset diperluas, "deteksi" XXE di PL2 seluruhnya berasal dari `950100` karena aplikasi menjawab 500 — `request_phase` menunjukkan 0/10.
