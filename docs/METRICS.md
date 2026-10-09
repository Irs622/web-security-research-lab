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

Pada skrip [`evaluation/analyze_results.py`](file:///Users/mac/Downloads/waf-research-lab/evaluation/analyze_results.py), seluruh kalkulasi diproteksi dari pembagian dengan nol (*Division-by-Zero Guard*):
- Jika $\text{TP} + \text{FN} = 0$, Recall diatur ke `0.0`.
- Jika $\text{TP} + \text{FP} = 0$, Precision diatur ke `0.0`.
- Jika $\text{FP} + \text{TN} = 0$, FPR diatur ke `0.0`.
- Jika Precision + Recall = 0, F1-Score diatur ke `0.0`.
