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
| **2 + tuning** | **82.14%** | **2.38%** | **95.83%** | **0.885** | `950100` pada pencarian `O'Reilly` (sengaja tidak dikecualikan) |
| 3 | 85.71% | 23.81% | 70.59% | 0.774 | + `920272` (karakter di luar ASCII cetak) |
| 4 | 85.71% | 54.76% | 51.06% | 0.640 | `920273` (karakter spesial ketat), `942432` |

> **Koreksi metodologi (2026-10-15) — tabel di atas mengukur *detection* paranoia, bukan *blocking* paranoia.** Image `owasp/modsecurity-crs` 4.x memperlakukan `PARANOIA` sebagai variabel usang: `BLOCKING_PARANOIA` (default image = 1) yang berlaku untuk pemblokiran, sehingga `PARANOIA=N` hanya menaikkan `tx.detection_paranoia_level`. Diverifikasi di container (`crs-setup.conf`: `blocking_paranoia_level=1`, `detection_paranoia_level=2` saat `PARANOIA=2`) dan terlihat pada data: blocking rate tetap 78,57% di PL1–PL4. Rule PL N tetap dievaluasi dan dicatat, jadi recall/FPR berbasis alert di tabel ini sah sebagai "rule PL N yang **terpicu**", tetapi rule PL ≥ 2 tidak menambah skor anomali dan **tidak memblokir** — FP pada PL2+ adalah alert, bukan request pengguna yang ditolak. `docker-compose.yml` kini menyetel `BLOCKING_PARANOIA` dan `DETECTION_PARANOIA` dari `PARANOIA`. Hasil dataset asli di `results/paranoia/` dan `results/holdout/` **belum** dijalankan ulang dengan konfigurasi yang diperbaiki; hasil dataset diperluas di `results/extended/` sudah memakai konfigurasi yang benar (lihat [§7](#hasil-dataset-diperluas)).

Kesimpulan: tanpa tuning, PL1 optimal. Namun **PL2 dengan exclusion sempit memberikan F1 tertinggi (0.885)**.

### Skenario PL2 Tuned

Exclusion di [`lab/tuning/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`](../lab/tuning/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf) diturunkan langsung dari FP PL2. Setiap exclusion hanya menghapus **satu rule pada satu parameter di satu path**:

| ID | Path | Dikecualikan | Alasan |
|---|---|---|---|
| 1101 | `/api/Feedbacks` | `950100` (seluruh request); `932200`, `942200` pada `json.comment` | 500 karena captcha kosong adalah error aplikasi; komentar bebas memuat `I'd`, `5/5` |
| 1102 | `/rest/products/search` | `942440`, `942390` pada `q` | Istilah natural (`C# sticker`, `1 or 2 bottles`); rule SQLi lain (mis. `942100` libinjection) tetap aktif |

Hasil: FP turun dari 7 menjadi 1 (FPR 16.67% → 2.38%, CI 95%: 0.4–12.3%), sementara SQLi tetap 10/10 dan XSS 10/10 — exclusion tidak membuka celah pada payload uji. Satu FP tersisa (`BENIGN-013`, pencarian `O'Reilly`) **sengaja dipertahankan**: respons 500-nya adalah gejala nyata kerentanan SQL injection Juice Shop, sehingga rule outbound `950100` memberikan sinyal yang benar secara keamanan meskipun inputnya sah.

> Keterbatasan: exclusion disusun dari dataset yang sama dengan yang dievaluasi, sehingga FPR tuned cenderung optimistis. Validasi yang lebih kuat memerlukan set benign terpisah (hold-out) yang tidak dipakai saat tuning.

### Validasi Hold-out (20 kasus benign yang tidak dipakai saat tuning)

Set terpisah [`simulator/holdout_benign.json`](../simulator/holdout_benign.json) (dijamin tidak beririsan dengan dataset utama oleh `tests/test_dataset.py`) dijalankan dengan `make experiment-holdout`:

| Skenario | FPR in-sample (42 benign) | **FPR hold-out (20 benign)** | 95% CI hold-out |
|---|---|---|---|
| PL1 | 0.00% | **5.00%** (1/20) | 0.9–23.6% |
| PL2 | 16.67% | **40.00%** (8/20) | 21.9–61.3% |
| PL2 tuned | 2.38% | **20.00%** (4/20) | 8.1–41.6% |

FP hold-out pada PL2 tuned:

| Kasus | Rule | Penjelasan |
|---|---|---|
| `HOLDOUT-001/002` (`Bob's`, `don't`) | `950100` | Apostrof memicu error SQL Juice Shop (500) — gejala kerentanan nyata, sama seperti `O'Reilly`; sengaja tidak dikecualikan |
| `HOLDOUT-009` (`50% off -- today`) | `942100` | **Diblokir (403) bahkan pada PL1** — libinjection membaca `--` sebagai komentar SQL. FP murni yang berdampak ke pengguna |
| `HOLDOUT-018` (`Order #1234 ... (late)`) | `942440` | Rule ini hanya dikecualikan pada `q`, bukan pada `json.comment` → bukti exclusion **overfit** ke dataset tuning |

**Kesimpulan yang jujur:** keunggulan PL2 tuned (FPR 2.38%) sebagian besar adalah efek *in-sample*. Pada data baru, FPR PL2 tuned (20%) tetap jauh lebih baik dari PL2 tanpa tuning (40%), tetapi lebih buruk dari PL1 (5%). Tuning per-endpoint membutuhkan iterasi pada trafik nyata (mode `DetectionOnly`) sebelum dapat mengalahkan PL1. Bila kasus 950100 (gejala kerentanan) dikeluarkan dari hitungan, FP yang berdampak ke pengguna pada PL2 tuned adalah 2/20 (10%).

Catatan: `950100` adalah rule outbound yang menandai respons error 5xx dari aplikasi — FP ini mencerminkan perilaku Juice Shop, bukan input pengguna.

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

---

<a id="hasil-dataset-diperluas"></a>
## 7. Hasil Dataset Diperluas (N=217, 3× pengulangan)

Sumber: `results/extended/` (dihasilkan `make experiment-extended` pada commit `771ce7b`, `git_dirty: false`; setiap run 651/651 request selesai, 0 error transport). Versi terverifikasi dari audit log: ModSecurity v3.0.17, ModSecurity-nginx v1.0.4, OWASP CRS 4.25.2; Juice Shop v17.1.1. `BLOCKING_PARANOIA` dan `DETECTION_PARANOIA` di container sesuai Paranoia Level setiap skenario (tercatat di `waf_runtime`). Ringkasan `summary_metrics.json` dihitung ulang dari CSV yang sama setelah metrik `request_phase` ditambahkan; CSV tidak diubah. Klasifikasi identik pada dua run lengkap berturut-turut (sebelum dan sesudah perbaikan atribusi `backend_outcome`).

### 7.1 Matriks Paranoia Level

Interval Wilson 95% dalam kurung. Blocking rate = intervensi terkonfirmasi audit log (tidak ada blokir berbasis status saja di run ini).

| Skenario | TP/FP/TN/FN | Recall | FPR | Precision | F1 | Blocking | Recall / FPR fase request saja |
|---|---|---|---|---|---|---|---|
| PL1 | 111/1/64/41 | 73.03% (65.5–79.5) | 1.54% (0.3–8.2) | 99.11% | 0.841 | 73.03% | 73.03% / 1.54% |
| PL2 | 134/15/50/18 | 88.16% (82.1–92.4) | 23.08% (14.5–34.6) | 89.93% | 0.890 | 88.16% | 81.58% / 13.85% |
| PL2 tuned | 134/8/57/18 | 88.16% (82.1–92.4) | 12.31% (6.4–22.5) | 94.37% | **0.912** | 88.16% | 81.58% / 9.23% |
| PL3 | 137/18/47/15 | 90.13% (84.4–93.9) | 27.69% (18.3–39.6) | 88.39% | 0.893 | 90.13% | 84.21% / 20.00% |
| PL4 | 140/38/27/12 | 92.11% (86.7–95.4) | 58.46% (46.3–69.6) | 78.65% | 0.849 | 92.11% | 92.11% / 58.46% |

"Fase request saja" tidak menghitung kasus yang hanya memicu rule `95xxxx` (respons 5xx Juice Shop). Pada PL2 seluruh 10 "deteksi" XXE (PL3: 9 dari 10) berasal dari `950100`, bukan dari inspeksi body XML — lihat §7.3.

### 7.2 Per keluarga (PL1 → PL4, deteksi = blokir terkonfirmasi)

| Keluarga | n | PL1 | PL2 | PL3 | PL4 | Rule dominan (PL1) |
|---|---|---|---|---|---|---|
| sqli | 19 | 19 | 19 | 19 | 19 | `942100` (libinjection) |
| xss | 18 | 18 | 18 | 18 | 18 | `941xxx` |
| lfi | 10 | 10 | 10 | 10 | 10 | `930120`, `933140` |
| ssrf | 10 | 10 | 10 | 10 | 10 | `934110`, `931100` |
| php-injection | 10 | 9 | 10 | 10 | 10 | `933100`, `933160` |
| nosqli | 10 | 9 | 9 | 9 | 10 | `942290` |
| java-injection | 12 | 9 | 11 | 11 | 12 | `932130`, `933135`, `944150` |
| protocol-violation | 9 | 7 | 7 | 7 | 7 | `920170`, `920190`, `920270`, `920450`, `920480`, `921160` |
| cmdi | 10 | 6 | 9 | 10 | 10 | `932235` |
| scanner-detection | 12 | 6 | 6 | 7 | 7 | `913100` (UA), `930130` (`.env`, `.git`), `920440` |
| path-traversal | 12 | 5 | 6 | 7 | 7 | `930100`, `930110`; 5 ditolak Nginx |
| rfi | 10 | 3 | 9 | 9 | 10 | PL2: `931130` |
| xxe | 10 | **0** | 10* | 10* | 10 | *PL2: hanya `950100`; PL3: 9× `950100` + 1× `920272`; PL4: `920273` |

Per applicability (PL1): `sink_present` 26/33 (78.8%, CI 62.3–89.3%), `pattern_only` 85/119 (71.4%, CI 62.7–78.8%). Perbedaan keduanya tidak signifikan dan **tidak** boleh dibaca sebagai "WAF lebih baik melindungi kerentanan nyata": komposisi keluarganya berbeda.

### 7.3 Temuan Utama

1. **XXE praktis tidak dideteksi oleh inspeksi request di PL1–PL3** (0/10, 0/10, 1/10). Body `application/xml` di-parse ModSecurity (rule `200000`), tetapi `DOCTYPE`/`ENTITY SYSTEM` berada di DTD, bukan di node teks yang diinspeksi CRS. Sisa "deteksi" PL2–PL3 terjadi karena Juice Shop menjawab 500 untuk POST XML ke `/rest/products/search` dan rule outbound `950100` memblokir **respons** (`backend_outcome = reached_response_blocked`): request sudah diproses aplikasi. Baru PL4 (`920273`, karakter spesial ketat) yang memblokir di fase request — dengan FPR 58%.
2. **RFI ke domain** (`http://example.invalid/...`, `//host`, UNC) lolos di PL1; hanya IP literal (`931100`) dan URL berakhiran `?` (`931120`) yang terdeteksi. PL2 menambah `931130` (*off-domain reference*).
3. **Payload double-encoded** (`CMDI-008…010`, `PHP-006`, `JAVA-007`, `RFI-004`) umumnya lolos di PL1: setelah satu lapis decoding oleh ModSecurity, nilainya masih ter-encode dan rule keluarga tersebut tidak mengenalinya, sedangkan `SQLI-016` tetap tertangkap libinjection (`942100`). PL2+ menangkap keenamnya lewat `920230` (*multiple URL encoding detected*) — deteksi anomali encoding, bukan signature keluarga serangan.
4. **Path discovery umum** (`/wp-admin/`, `/phpmyadmin/`, `/server-status`, `/cgi-bin/`, `/backup.zip`) dan header override (`X-Original-URL`, `X-Forwarded-Host`) tidak terdeteksi di PL mana pun. Ini sesuai desain CRS (tidak ada signature path generik); deteksi scanner CRS berbasis User-Agent (`913100`) dan berkas terlarang (`930130`).
5. **Satu FP di semua PL: `BENIGN-045`** (GET tanpa body dengan `Content-Type: application/xml`) diblokir oleh rule engine `200002` (gagal mem-parse body XML kosong) dari `modsecurity.conf`, bukan oleh CRS. Klien sah jarang mengirimnya, tetapi ini menunjukkan bahwa tidak semua blokir berasal dari CRS.
6. **Atribusi 401/403 aplikasi**: di baseline, 17 kasus menerima 401/403 dari Juice Shop sendiri (mis. guard `/ftp`, login NoSQL `NOSQLI-002…010`). `NOSQLI-009` (`$nin`) lolos WAF dan ditolak aplikasi (401) — tercatat `block_source = application`, bukan blokir WAF.
7. **Tuning tidak menggeneralisasi ke keluarga baru.** Exclusion PL2 tuned (dari dataset asli) menurunkan FPR 23.08% → 12.31%, tetapi FP baru dari kontrol benign keluarga baru tetap ada: `932236` pada kata `echo`, `php`, `java`, `$`, `file` (`BENIGN-051/053/054/057`) dan `931130` pada URL sah di feedback (`BENIGN-060`).
8. **Hold-out** (`results/extended/holdout/`, 20 benign, kini dengan blocking PL yang benar): PL1 5% (1/20), PL2 40% (8/20), PL2 tuned 20% (4/20) — FP yang sama dengan hasil hold-out sebelumnya; kini benar-benar diblokir. Tanpa rule fase respons: 5% / 20% / 10%.

### 7.4 Latensi

PL1 (`results/extended/summary_metrics.json`, 651 sampel per mode): p50 baseline 9.42 ms vs WAF 12.19 ms (Δp50 +2.77 ms), mean +3.56 ms, Mann-Whitney U p < 0.001. Run PL1 kedua dalam matriks memberi Δp50 +2.54 ms. Rata-rata dan p95 pada PL2–PL4 bervariasi besar antar-run karena beban host (macOS Docker Desktop, run berurutan); **gunakan p50** dan jangan membandingkan mean antar-PL tanpa run berulang.

### 7.5 Yang Tidak Dapat Disimpulkan

- Eksploitabilitas aplikasi untuk keluarga mana pun (tidak diukur; lihat [SCENARIO_MATRIX.md §4](SCENARIO_MATRIX.md#4-tiga-klaim-yang-berbeda)).
- Perbedaan recall antar-keluarga yang lebih kecil dari lebar intervalnya (n = 9–19 per keluarga).
- Bahwa XXE "dicegah" di PL2–PL3: hampir seluruhnya adalah efek samping error aplikasi.
- FPR produksi: kontrol benign adalah request sintetis, bukan trafik nyata.
