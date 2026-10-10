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
- **`malicious`**: Request yang mengandung pola sintaks eksploitasi serangan siber terverifikasi (SQL Injection, Cross-Site Scripting, Directory/Path Traversal).

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

- **Ukuran Sampel:** N=40 kasus uji terkontrol (12 Benign, 10 SQLi, 10 XSS, 8 Path Traversal).
- **Concurrency & Rate:** Sequential execution dengan inter-request delay 0.25 detik.
- **Hardware Environment:** Apple Silicon M3 (ARM64), 8 GB RAM, macOS Darwin.
- **Software Pinning:**
  - OWASP Juice Shop: `v17.1.1`
  - ModSecurity Engine: `v3.0.17`
  - OWASP CRS: `v4.25.2 LTS` (Paranoia Level: 1, Inbound Anomaly Threshold: 5)
  - OWASP ZAP: `v2.16.0`
