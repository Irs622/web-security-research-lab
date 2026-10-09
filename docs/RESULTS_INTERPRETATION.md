# Panduan Interpretasi Hasil dan Analisis Akademik

Dokumen ini menyediakan panduan bagi peneliti skripsi dalam menganalisis data mentah dan metrik yang dihasilkan oleh laboratorium WAF.

---

## 1. Interpretasi Matriks Konfusi (N=40 Kasus Uji)

Berdasarkan dataset uji berlabel yang dieksekusi:

| Metrik | Nilai Aktual | Interpretasi Ilmiah |
|---|---|---|
| **True Positives (TP)** | 27 | 27 dari 28 serangan terdeteksi secara tepat oleh rule CRS dan berhasil diblokir. |
| **False Positives (FP)** | 0 | 0 dari 12 request normal yang salah ditandai atau diblokir sebagai serangan aplikasi. |
| **True Negatives (TN)** | 12 | Seluruh 12 request normal berhasil diteruskan ke aplikasi Juice Shop tanpa gangguan pemblokiran. |
| **False Negatives (FN)** | 1 | 1 serangan lolos dari deteksi rule attack pada Paranoia Level 1 (`TRAV-004`). |
| **Detection Rate (Recall)** | 96.43% | Efektivitas deteksi terhadap vektor SQLi, XSS, dan Path Traversal sangat tinggi. |
| **Precision** | 100.00% | Setiap alert serangan yang dihasilkan terbukti valid (tidak ada false alarm). |
| **False Positive Rate** | 0.00% | Tingkat gangguan terhadap pengguna sah adalah nol pada konfigurasi Paranoia Level 1. |
| **Enforcement Blocking Rate** | 96.43% | Persentase pemblokiran aktif dari total serangan yang diajukan. |

---

## 2. Analisis Kasus False Negative (`TRAV-004`)

- **Payload:** `GET /ftp/eastere.gg%2500.md`
- **Tujuan:** Pengujian bypass ekstensi file menggunakan teknik *Double URL-Encoded Poison Null Byte* (`%2500`).
- **Observasi Runtime:**
  - Status WAF: `HTTP 200 OK`
  - Rule Terpicu: Hanya rule protokol `920350` (Score: 3), tidak ada rule path traversal (`930xxx`) yang aktif.
  - Akumulasi Skor: 3 < 5 (Threshold Inbound Anomaly).
  - Respon Backend: Request diteruskan ke backend dan diizinkan oleh Express/Juice Shop.
- **Temuan untuk Skripsi:**
  Aturan CRS pada **Paranoia Level 1** tidak melakukan normalisasi multi-layer decoding untuk double-encoded null byte pada parameter path tertentu. Peneliti dapat menyarankan peningkatan Paranoia Level ke level 2 atau tuning rule `930100` / `930110` sebagai rekomendasi mitigasi.

---

## 3. Analisis Baseline vs WAF: Mengapa Status 403 Saja Tidak Cukup?

Pada pengujian Baseline (`results/baseline.csv`), kasus traversal `TRAV-001`, `TRAV-002`, `TRAV-006`, dan `TRAV-007` mengembalikan status **HTTP 403** langsung dari OWASP Juice Shop!
- Hal ini terjadi karena router static file Juice Shop memiliki proteksi internal terhadap traversal di folder `/ftp`.
- Jika seorang peneliti hanya mengevaluasi WAF berdasarkan kode status HTTP tanpa pengujian baseline dan korelasi log CRS, peneliti tersebut akan melakukan **klaim palsu** bahwa WAF-lah yang memblokir serangan tersebut.
- Melalui korelasi log audit ModSecurity, terbukti bahwa pada jalur WAF, request tersebut memang diintervensi oleh ModSecurity di layer proxy (rule `930100` / `941100`) **sebelum** menyentuh Juice Shop. Ini memvalidasi peran defensif WAF sebagai *first line of defense*.

---

## 4. Pembedaan HTTP 400 vs HTTP 403 pada Kasus Path Traversal

Dari 8 kasus traversal yang diuji, terdapat perbedaan kode HTTP pada jalur WAF yang perlu dipahami:

| Kode HTTP | Ukuran Respons | Asal | Kasus |
|---|---|---|---|
| **403** + 146 B | Halaman error WAF | ModSecurity memblokir (CRS rule aktif) | TRAV-003, TRAV-006 |
| **400** + 150 B | Nginx 400 Bad Request | Nginx menolak URL malformed sebelum/selama WAF | TRAV-001, TRAV-002, TRAV-005, TRAV-008 |
| **403** + 1937 B | Juice Shop app | Aplikasi memblokir secara mandiri | TRAV-007 (lihat catatan) |

Untuk kasus HTTP **400**: Nginx me-reject URL yang mengandung sequence `../` yang tidak ter-resolve selama normalisasi path, sehingga ModSecurity dan aplikasi tidak pernah memproses request tersebut. Meskipun WAF audit log mencatat `is_interrupted: true` dan attack rules, layer Nginx secara independen juga akan menolak URL ini tanpa kehadiran WAF. Peneliti harus mendokumentasikan bahwa sebagian kasus traversal terblokir oleh **dua mekanisme berlapis** (Nginx URL normalization + WAF CRS inspection).

### Catatan Investigasi TRAV-007

TRAV-007 (`GET /ftp/....//....//etc/passwd`) mengembalikan HTTP 403 dengan ukuran 1937 byte — identik dengan respons 403 dari Juice Shop di jalur baseline, bukan halaman error WAF (146 byte). Namun `waf_intervention: True` karena `is_interrupted: true` di audit log WAF.

Ketidakkonsistenan ini berpotensi disebabkan oleh ambiguitas korelasi log: TRAV-007 dikirim 380ms setelah TRAV-006, dan keduanya memiliki base path `/ftp/`. Jika log correlator salah mengambil transaksi TRAV-006 (yang memiliki rules 930100+930110 dengan `is_interrupted: true`), maka TRAV-007 seharusnya adalah **FN** (missed), bukan TP. Penelitian selanjutnya disarankan untuk memverifikasi ulang kasus ini menggunakan mekanisme korelasi berbasis trace token unik per request.

---

## 5. Evaluasi Kinerja Latensi & Overhead

- **Baseline Latency:** Mean = 18.47 ms | p50 = 14.43 ms | p95 = 47.89 ms
- **WAF Latency:** Mean = 21.55 ms | p50 = 18.29 ms | p95 = 44.52 ms
- **Inspeksi Overhead:** Rata-rata **+3.07 ms** per request (satu run eksperimen).
- **Catatan Metodologis:**
  Angka overhead diperoleh dari satu run eksperimen dengan 40 request per jalur. Untuk klaim statistik yang lebih kuat, disarankan melakukan minimal 3 run dan melaporkan mean ± standar deviasi. Data ini cukup sebagai indikasi awal bahwa overhead inspeksi WAF berada di kisaran single-digit milidetik pada konfigurasi lab lokal.
