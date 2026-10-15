# Metodologi Penelitian: Evaluasi Efektivitas WAF

Dokumen ini menguraikan metodologi penelitian akademik (*experimental security research*) untuk mengevaluasi efektivitas Web Application Firewall (ModSecurity + OWASP Core Rule Set) dalam mendeteksi dan memitigasi serangan terhadap aplikasi web rentan (OWASP Juice Shop).

---

## 1. Desain Eksperimen

Penelitian ini menggunakan pendekatan **Controlled Experimental Benchmark** dengan arsitektur komparatif dua jalur (*Dual-Path Comparison*):

1. **Jalur Kontrol (Baseline Path):**
   - Target: `http://127.0.0.1:3001` (Akses langsung ke OWASP Juice Shop).
   - Fungsi: Menetapkan perilaku alami (*ground truth behavior*) aplikasi terhadap payload uji, mengukur latensi inheren aplikasi, dan memverifikasi respon alami sebelum difilter oleh WAF.

2. **Jalur Perlakuan (WAF Path):**
   - Target: `http://127.0.0.1:8080` (Akses melalui Nginx + ModSecurity v3 + OWASP CRS v4.25 LTS).
   - Fungsi: Mengukur responsivitas WAF, aktivasi aturan deteksi (*Rule IDs*), akumulasi skor anomali (*Anomaly Score*), dan aksi pemblokiran (*Enforcement Blocking*).

---

## 2. Definisi Ground Truth

Setiap kasus uji diklasifikasikan ke dalam label kelas ground truth sebelum eksekusi:
- **`benign`**: Request normal yang menyerupai lalu lintas pengguna yang sah (pencarian produk, login berformat benar, pembacaan halaman statis).
- **`malicious`**: Request yang mengandung pola sintaks eksploitasi atau pengintaian (SQL Injection, Cross-Site Scripting, Path Traversal; pada dataset diperluas juga Command Injection, LFI, RFI, PHP, Java/JNDI, NoSQL, SSRF, XXE, pelanggaran protokol HTTP, dan scanner).

Label adalah ground truth **input**, bukan ekspektasi terhadap WAF. Header yang lazim dikirim proxy atau klien sah (mis. `X-Forwarded-For`, `Accept: */*`) dilabel benign walaupun tampak "tidak biasa". Request pengintaian (`/.git/config`, User-Agent scanner) dilabel malicious karena pengguna sah aplikasi ini tidak pernah mengirimnya.

### 2a. Variabel yang Dipisahkan

| Variabel | Sumber | Arti |
|---|---|---|
| `expected_class` | Dataset | Ground truth input |
| `waf_alert` | Audit log (rule serangan selain `920350`/`949110`) | WAF *mengenali* request |
| `waf_intervention` + `intervention_evidence` | Audit log `is_interrupted` | WAF *memutus* request; hanya `audit_log` yang dihitung sebagai blokir terkonfirmasi |
| `block_source` | Turunan | `waf`, `proxy` (Nginx 400 sebelum ModSecurity), `application` (401/403 dari Juice Shop sendiri), `none` |
| `backend_outcome` | Status HTTP | `not_reached`, `reached_response_blocked`, `2xx`…`5xx`, `transport_error` — **bukan** bukti eksploitasi |
| `scenario_applicability` | Dataset | `sink_present`, `pattern_only`, `benign_control` |

### 2b. Tiga Klaim yang Tidak Boleh Dicampur

1. **Deteksi pola** — diukur (recall, precision, FPR, F1).
2. **Pencegahan** — diukur (blocking rate dari intervensi terkonfirmasi audit log).
3. **Eksploitabilitas aplikasi** — **tidak diukur**. Harness tidak memverifikasi apakah payload berhasil. Untuk kasus `pattern_only` (mis. SSRF, XXE, RFI, LFI, PHP, CMDi, Java/JNDI, NoSQL ke rute yang tidak mengimplementasikan fungsi tersebut) hasil hanya bermakna sebagai deteksi signature WAF. Rincian per keluarga: [SCENARIO_MATRIX.md](SCENARIO_MATRIX.md).

---

## 3. Matriks Klasifikasi (Confusion Matrix)

Berdasarkan ground truth dan observasi WAF:

| Ground Truth | WAF Alert / Rule Terpicu | WAF Bersih (No Attack Alert) |
|---|---|---|
| **Malicious (Positif)** | **True Positive (TP)**: Serangan berhasil diidentifikasi oleh aturan CRS | **False Negative (FN)**: Serangan lolos tanpa terdeteksi oleh aturan CRS |
| **Benign (Negatif)** | **False Positive (FP)**: Request normal salah dideteksi sebagai serangan | **True Negative (TN)**: Request normal diizinkan tanpa memicu peringatan serangan |

> **Catatan Metodologis Penting:**
> Aturan protokol lingkungan lab (Rule `920350: Host header is a numeric IP address`) dicatat secara terpisah dari Aturan Serangan Aplikasi (Rule `930xxx` s.d. `944xxx`) agar tidak menimbulkan bias False Positive artifisial akibat pengujian loopback port IP.

---

## 4. Dua Dimensi Evaluasi: Deteksi vs Mitigasi

Penelitian memisahkan secara ketat dua konsep keamanan:
1. **Kemampuan Deteksi (*Detection Capability*):**
   - Apakah WAF mampu mengenali pola berbahaya dalam payload dan mencatat alert/Rule ID pada log audit?
   - Metrik: Detection Rate / Recall (`TP / (TP + FN)`), Precision (`TP / (TP + FP)`), FPR (`FP / (FP + TN)`).

2. **Kemampuan Mitigasi / Pemblokiran (*Mitigation & Blocking Capability*):**
   - Apakah WAF mengintervensi koneksi HTTP dan menghentikan request berbahaya agar tidak mencapai backend (`is_interrupted: true` / HTTP 403 Forbidden)?
   - Metrik: Blocking Rate (`malicious blocked / total malicious`).

---

## 4a. Korelasi Request ↔ Audit Log

Untuk memastikan setiap baris hasil dikaitkan dengan transaksi ModSecurity yang benar:
1. Setiap request membawa header unik `X-Lab-Trace-Id` (UUID v4) yang dicatat di kolom CSV `trace_id`.
2. Korelator mencari transaksi audit log dengan header tersebut (`log_match = trace_id`). Bila tidak ditemukan, korelator jatuh ke pencocokan method + URI persis (`log_match = uri`).
3. Atribusi blokir (`waf_intervention`) diambil dari flag `is_interrupted` audit log. HTTP 403 dari aplikasi backend **tidak** dihitung sebagai blokir WAF.
4. Bila tidak ada bukti audit log (`log_match = none` atau korelasi dimatikan), dipakai heuristik status HTTP 403/406 dan baris tersebut perlu ditinjau manual.

---

## 5. Parameter Pengendalian

- **Ukuran Sampel:**
  - Dataset asli: N=70 kasus uji terkontrol (42 Benign, 10 SQLi, 10 XSS, 8 Path Traversal).
  - Dataset diperluas: N=217 (65 benign, 152 malicious dalam 13 keluarga) — lihat [DATASET.md](DATASET.md).
  - Hold-out benign: N=80 (20 asli + 60 ditambahkan sebelum exclusion v2), dijalankan terpisah dan tidak dipakai untuk menyusun exclusion.
  - Pengulangan (`--repeat`) hanya menambah sampel latensi; setiap kasus dihitung satu kali untuk metrik deteksi.
- **Concurrency & Rate:** Sequential execution dengan inter-request delay 0.25 detik.
- **Hardware Environment:** Apple Silicon M3 (ARM64), 8 GB RAM, macOS Darwin.
- **Software Pinning:**
  - OWASP Juice Shop: `v17.1.1`
  - ModSecurity Engine: `v3.0.17`
  - OWASP CRS: `v4.25.2 LTS` (Paranoia Level: 1, Inbound Anomaly Threshold: 5)
  - OWASP ZAP: `v2.16.0`

---

## 6. Desain Eksperimen per Konfigurasi

| # | Konfigurasi | Target Make | Keluaran (dataset asli / diperluas) |
|---|---|---|---|
| 1 | Baseline tanpa WAF | `test-baseline` | `results/baseline.csv` / `results/extended/baseline.csv` |
| 2–5 | ModSecurity + CRS PL1–PL4 (`BLOCKING_PARANOIA` = `DETECTION_PARANOIA` = N), ambang inbound 5 | `experiment-matrix` | `results/paranoia/pl<N>/` / `results/extended/paranoia/pl<N>/` |
| 6 | PL2 + exclusion sempit (`lab/tuning/`) | `experiment-tuned` | `results/paranoia/pl2-tuned/` / `results/extended/paranoia/pl2-tuned/` |
| H | Hold-out benign vs PL1, PL2, PL2 tuned | `experiment-holdout` | `results/holdout/` / `results/extended/holdout/` |
| L | Latensi: 5 ronde baseline/WAF PL1, urutan bergantian | `experiment-latency` | — / `results/extended/latency/` |

`make experiment-extended` menjalankan 1–6 dan H untuk dataset diperluas. Exclusion PL2 tuned terdiri atas dua versi: v1 (1101–1102) diturunkan dari FP PL2 dataset asli, v2 (1103–1104) dari FP PL2 dataset diperluas. FPR tuned pada dataset tuning-nya sendiri adalah angka *in-sample*; generalisasi dinilai **hanya** dari set hold-out, yang disusun sebelum v2 dan tidak pernah dipakai untuk tuning.

Latensi diukur terpisah (L) karena run deteksi berurutan mencampur beban host dengan efek WAF. Setiap ronde menjalankan baseline dan WAF berurutan dengan urutan bergantian, dan overhead dilaporkan sebagai median antar-ronde dari Δp50 request benign beserta rentangnya ([METRICS.md](METRICS.md#latensi-multi-ronde)).

Setiap run menulis `*.meta.json` (lihat [OUTPUT_FORMAT.md](OUTPUT_FORMAT.md)): path dan SHA-256 dataset, git SHA + status *dirty*, image beserta digest, environment dan mount container WAF yang benar-benar berjalan (Paranoia Level, ambang anomali, file exclusion), versi ModSecurity/CRS dari field `producer` audit log, jumlah request dicoba/berhasil, status korelasi audit log, dan stempel waktu.
