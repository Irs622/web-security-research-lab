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

### D. F1-Score (Harmonic Mean)
Rata-rata harmonik antara Precision dan Recall untuk mengukur keseimbangan efektivitas.
$$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

---

## 2. Metrik Mitigasi & Pemblokiran

### Enforcement / Blocking Rate
Persentase request serangan berbahaya yang berhasil dicegah dan diputus sebelum dieksekusi oleh aplikasi target (mengembalikan status HTTP 403 / intervensi koneksi).
$$\text{Blocking Rate} = \frac{\text{Malicious Requests Blocked}}{\text{Total Malicious Requests Tested}}$$

---

## 3. Metrik Kinerja dan Latensi

1. **Mean Latency ($\bar{L}$):** Rata-rata waktu round-trip HTTP dalam milidetik.
2. **Median Latency ($p_{50}$):** Persentil ke-50 respon latensi.
3. **Tail Latency ($p_{95}$):** Persentil ke-95 respon latensi untuk mendeteksi lonjakan komputasi inspeksi regex ModSecurity.
4. **Inspection Overhead ($\Delta L$):** Selisih latensi tambahan yang diperkenalkan oleh lapisan reverse proxy dan evaluasi CRS:
$$\Delta L = \bar{L}_{\text{WAF}} - \bar{L}_{\text{Baseline}}$$

---

## 4. Penanganan Edge Cases & Keamanan Matematis

Pada skrip [`evaluation/analyze_results.py`](../evaluation/analyze_results.py), seluruh kalkulasi diproteksi dari pembagian dengan nol (*Division-by-Zero Guard*):
- Jika $\text{TP} + \text{FN} = 0$, Recall diatur ke `0.0`.
- Jika $\text{TP} + \text{FP} = 0$, Precision diatur ke `0.0`.
- Jika $\text{FP} + \text{TN} = 0$, FPR diatur ke `0.0`.
- Jika Precision + Recall = 0, F1-Score diatur ke `0.0`.

---

## 5. Ekslusi Rule ID dalam Kalkulasi Deteksi

Dua kelompok Rule ID dikecualikan dari variabel `attack_rules` (penentu `has_attack_detection`) sebelum klasifikasi TP/FP/TN/FN dilakukan:

### LAB_ENVIRONMENT_PROTOCOL_RULES: `{920350}`

Rule **920350** ("Request Header Host Is Numeric IP Address") terpicu pada **setiap** request dalam lab karena Host header berisi `127.0.0.1`. Rule ini memberikan anomaly score 3 poin — di bawah blocking threshold 5. Tidak ada kaitannya dengan deteksi pola serangan aplikasi. Jika tidak dikecualikan, seluruh 12 request benign akan salah diklasifikasikan sebagai FP.

### SCORING_META_RULES: `{949110}`

Rule **949110** ("Inbound Anomaly Score Exceeded") adalah meta-rule CRS yang terpicu ketika akumulasi skor dari rule-rule serangan lain melewati threshold. Rule ini **tidak mendeteksi pola serangan secara independen** — ia hanya mencerminkan hasil rule-rule yang sudah dihitung di atas. Menyertakannya dalam `has_attack_detection` akan menyebabkan double-counting pada setiap TP yang diblokir. Dikecualikan untuk menjaga keabsahan perhitungan confusion matrix.

## Interval Kepercayaan & Uji Statistik

- **Wilson 95% CI** dilaporkan untuk Recall, Precision, FPR, dan Blocking Rate (`confidence_intervals_95` di `summary_metrics.json`). Dengan sampel kecil (mis. 0/12 benign), FPR 0% masih kompatibel dengan FPR sebenarnya hingga ±24% — selalu sertakan interval saat menulis kesimpulan.
- **Pengulangan (`--repeat N`)**: deteksi dihitung sekali per kasus (`repeat_index = 0`), sedangkan seluruh pengulangan menjadi sampel latensi. Request warm-up (`--warmup`, default 5) tidak dicatat.
- **Latensi**: dilaporkan mean, p50, p95, dan IQR; perbedaan baseline vs WAF diuji dengan **Mann-Whitney U** dua sisi (aproksimasi normal, koreksi ties) karena distribusi latensi tidak normal.
- **Daftar FN/FP** (`misclassified`) mencantumkan path dan rule yang muncul untuk analisis kegagalan.

## Perbandingan Paranoia Level

`make experiment-matrix` menjalankan suite WAF pada Paranoia Level 1–4 (`REPEAT=3` default), menyimpan hasil di `results/paranoia/pl<N>/`, lalu `evaluation/compare_paranoia.py` membuat `paranoia_comparison.json` dan grafik `paranoia_tradeoff.png` (Recall vs FPR vs F1).

## Metadata Reproducibility

Setiap run menulis `<output>.meta.json` di samping CSV: `run_id`, git SHA, SHA-256 dataset, jumlah kasus, `repeat`/`warmup`, Paranoia Level & threshold, digest image container yang sedang berjalan (`docker inspect`), serta versi Python/platform. Lampirkan file ini bersama hasil saat menulis laporan.
