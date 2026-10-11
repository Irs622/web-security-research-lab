# Panduan Interpretasi Hasil dan Analisis Akademik

Dokumen ini menyediakan panduan bagi peneliti skripsi dalam menganalisis data mentah dan metrik yang dihasilkan oleh laboratorium WAF.

---

## 1. Interpretasi Matriks Konfusi (N=70 Kasus Uji, PL1)

| Metrik | Nilai Aktual (95% CI) | Interpretasi Ilmiah |
|---|---|---|
| **True Positives (TP)** | 22 | Seluruh SQLi (10) dan XSS (10), serta 2 dari 8 traversal, terdeteksi dan diblokir rule CRS. |
| **False Positives (FP)** | 0 | Tidak ada dari 42 request normal yang ditandai sebagai serangan. |
| **True Negatives (TN)** | 42 | Termasuk input pemicu FP klasik: apostrof (`O'Reilly`), kata `select`/`or`, `;`, `=`, Unicode, body JSON. |
| **False Negatives (FN)** | 6 | Semuanya path traversal; 4 di antaranya ditolak Nginx sebelum mencapai ModSecurity (lihat §2). |
| **Detection Rate (Recall)** | 78.57% (60.5–89.8%) | Sangat efektif untuk SQLi/XSS, lemah untuk traversal pada PL1. |
| **Precision** | 100.00% (85.1–100%) | Setiap alert valid. |
| **False Positive Rate** | 0.00% (0–8.4%) | Dengan 42 sampel benign, FPR sebenarnya kemungkinan besar < 8.4%. |
| **Blocking Rate** | 78.57% | 22/28 diputus HTTP 403 oleh ModSecurity. |
| **Mitigasi total** | 92.86% | Termasuk 4 request yang ditolak Nginx (HTTP 400). |

---

## 2. Analisis Kasus False Negative

### 2a. Ditolak Nginx sebelum ModSecurity (`TRAV-001`, `TRAV-002`, `TRAV-005`, `TRAV-008`)

URI seperti `/ftp/../../../../etc/passwd` atau varian `%2f`/`%2e` yang keluar dari root dinormalisasi Nginx dan langsung dijawab **HTTP 400 Bad Request** (halaman error bertanda `nginx`). ModSecurity tidak pernah memproses request ini sehingga **tidak ada audit log**. Simulator mencatatnya sebagai `observed_outcome = rejected_by_proxy`.

Serangan ini **termitigasi**, tetapi bukan oleh rule engine WAF — maka tetap dihitung FN untuk metrik deteksi CRS dan dilaporkan terpisah sebagai `malicious_rejected_by_proxy`.

> **Catatan metodologi penting:** hasil versi sebelumnya (N=40) melaporkan 7/8 traversal terdeteksi. Itu adalah artefak korelasi berbasis URI: request yang tidak punya audit log dicocokkan ke transaksi lain sehingga tercatat memicu rule XSS (`941xxx`) — mustahil untuk payload traversal. Korelasi berbasis trace ID memperbaiki hal ini.

### 2b. Lolos WAF (`TRAV-004`, `TRAV-007`)

- **`TRAV-004`** `GET /ftp/eastere.gg%2500.md` (double-encoded null byte): hanya rule `920350` (skor 3 < 5). Terdeteksi mulai **PL3**.
- **`TRAV-007`** `GET /ftp/....//....//etc/passwd`: tidak ada rule attack; HTTP 403 berasal dari guard Juice Shop sendiri, bukan WAF (audit log `is_interrupted = false`). Tidak terdeteksi bahkan pada PL4.

---

## 2c. Trade-off Paranoia Level

| PL | Recall | FPR | Precision | F1 | Rule FP dominan |
|---|---|---|---|---|---|
| 1 | 78.57% | 0.00% | 100.00% | 0.880 | — |
| 2 | 82.14% | 16.67% | 76.67% | 0.793 | `950100` (respons 5xx backend), `942xxx` |
| 3 | 85.71% | 23.81% | 70.59% | 0.774 | + `920272` (karakter di luar ASCII cetak) |
| 4 | 85.71% | 54.76% | 51.06% | 0.640 | `920273` (karakter spesial ketat), `942432` |

Kesimpulan: PL1 optimal untuk aplikasi ini tanpa tuning. PL2–PL3 hanya layak bila disertai rule exclusion (lihat `deploy/prod/waf/`). `950100` adalah rule outbound yang menandai respons error 5xx dari aplikasi — FP ini mencerminkan perilaku Juice Shop, bukan input pengguna.

> Simulator kini mengirim header `Accept` seperti browser. Tanpa header itu, rule `920300` (Missing Accept Header) terpicu di setiap request pada PL2+ dan menghasilkan FPR 100% semu.

---

## 3. Analisis Baseline vs WAF: Mengapa Status 403 Saja Tidak Cukup?

Pada pengujian Baseline (`results/baseline.csv`), kasus traversal `TRAV-001`, `TRAV-002`, `TRAV-006`, dan `TRAV-007` mengembalikan status **HTTP 403** langsung dari OWASP Juice Shop!
- Hal ini terjadi karena router static file Juice Shop memiliki proteksi internal terhadap traversal di folder `/ftp`.
- Jika seorang peneliti hanya mengevaluasi WAF berdasarkan kode status HTTP tanpa pengujian baseline dan korelasi log CRS, peneliti tersebut akan melakukan **klaim palsu** bahwa WAF-lah yang memblokir serangan tersebut.
- Korelasi audit log berbasis trace ID menunjukkan: `TRAV-006` benar diblokir ModSecurity (`930100`/`930110`); `TRAV-001`/`TRAV-002` ditolak Nginx (HTTP 400) tanpa audit log; `TRAV-007` **tidak** diintervensi WAF — 403-nya berasal dari Juice Shop. Tanpa korelasi log, keempatnya akan salah diklaim sebagai keberhasilan WAF.

---

## 4. Pembedaan HTTP 400 vs HTTP 403 pada Kasus Path Traversal

Dari 8 kasus traversal yang diuji, terdapat perbedaan kode HTTP pada jalur WAF yang perlu dipahami:

| Kode HTTP | Ukuran Respons | Asal | Kasus |
|---|---|---|---|
| **403** + 146 B | Halaman error WAF | ModSecurity memblokir (CRS rule aktif) | TRAV-003, TRAV-006 |
| **400** + 150 B | Nginx 400 Bad Request | Nginx menolak URL malformed sebelum/selama WAF | TRAV-001, TRAV-002, TRAV-005, TRAV-008 |
| **403** + 1937 B | Juice Shop app | Aplikasi memblokir secara mandiri | TRAV-007 (lihat catatan) |

Untuk kasus HTTP **400**: Nginx me-reject URL yang mengandung sequence `../` yang tidak ter-resolve selama normalisasi path, sehingga ModSecurity dan aplikasi tidak pernah memproses request tersebut. Run terbaru membuktikan **tidak ada transaksi audit log** untuk request ini — attack rule yang dulu tercatat adalah salah-korelasi. Mitigasinya murni dari normalisasi URL Nginx (`rejected_by_proxy`), bukan dari CRS.

### TRAV-007 (terkonfirmasi)

TRAV-007 (`GET /ftp/....//....//etc/passwd`) mengembalikan HTTP 403 berukuran sama dengan respons Juice Shop di jalur baseline. Dengan korelasi trace ID (`X-Lab-Trace-Id`), audit log menunjukkan `is_interrupted: false` dan hanya rule `920350`. Kesimpulan: **FN** — WAF tidak mendeteksinya pada PL1–PL4; perlindungan berasal dari aplikasi.

---

## 5. Evaluasi Kinerja Latensi & Overhead

70 kasus × 3 pengulangan = 210 sampel per mode, dengan 5 request warm-up yang tidak dicatat.

- **Baseline Latency:** Mean = 22.02 ms | p50 = 11.31 ms | p95 = 33.56 ms
- **WAF Latency:** Mean = 24.18 ms | p50 = 11.75 ms | p95 = 42.76 ms
- **Inspeksi Overhead:** rata-rata **+2.16 ms** per request.
- **Uji Mann-Whitney U (dua sisi):** z = 2.14, p = 0.032 → perbedaan distribusi latensi **signifikan** pada α = 0.05, tetapi secara praktis kecil (selisih median ≈ 0.4 ms).
- **Catatan:** baseline dan WAF dijalankan berurutan, bukan interleaved; fluktuasi beban host (Docker Desktop, RAM 3.8 GB) dapat memengaruhi ekor distribusi (p95). Untuk klaim lebih kuat, ulangi pada host yang idle dan laporkan beberapa run.
