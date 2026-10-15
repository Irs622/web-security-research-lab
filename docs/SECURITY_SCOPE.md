# Batasan Keamanan dan Panduan Containment Lab

Laboratorium ini dirancang secara khusus untuk keperluan penelitian skripsi akademik. Karena target yang digunakan adalah aplikasi yang sengaja dibuat rentan (**OWASP Juice Shop**), kepatuhan terhadap batasan keamanan (*containment*) adalah kewajiban mutlak.

---

## 1. Prinsip Utama Containment

1. **Strict Loopback Binding:**
   - Semua port yang diekspos ke host diikat secara ketat pada interface loopback (`127.0.0.1:3001` dan `127.0.0.1:8080`).
   - Dilarang keras mengganti binding menjadi `0.0.0.0` atau mengekspos port aplikasi rentan ke interface publik (Ethernet, Wi-Fi, atau IP publik VPS).

2. **Isolasi Jaringan Internal Docker:**
   - Komunikasi antara WAF dan Juice Shop berlangsung secara eksklusif dalam jaringan virtual Docker bridge berisolasi (`waflab-internal`).
   - Aplikasi backend tidak dapat diakses langsung oleh pihak luar tanpa melalui firewall kecuali melalui port loopback lokal penelitian.

3. **Batasan Hak Akses Container:**
   - Container dilarang dijalankan dalam mode privileged.
   - Opsi `security_opt: [no-new-privileges:true]` diterapkan untuk mencegah eskalasi privilege di dalam container.
   - Socket Docker host (`/var/run/docker.sock`) **dilarang keras** di-mount ke dalam container aplikasi atau WAF.

4. **Pencegahan Out-of-Scope Requests & Redirection:**
   - Simulator Python wajib menolak target di luar allowlist loopback.
   - Simulator wajib menonaktifkan fitur automatic redirect untuk mencegah kebocoran request ke jaringan eksternal/SSRF.
   - Dilarang mengirimkan request ke domain publik, internet, atau infrastruktur pihak ketiga.

---

## 1a. Keamanan Payload Dataset Diperluas

Dataset [`attack_cases_extended.json`](../simulator/attack_cases_extended.json) memuat pola SSRF, RFI, XXE, LFI, PHP, Java/JNDI, dan command injection. Seluruhnya adalah **teks inert**:

1. **Harness tidak pernah mengambil URL di dalam payload.** Satu-satunya koneksi keluar adalah ke `base_url` yang sudah divalidasi; redirect tidak diikuti. Diuji di `tests/test_runner_integration.py::test_payload_urls_are_never_contacted`.
2. **Host di dalam payload dibatasi** pada loopback, `::1`, link-local `169.254.169.254`, TEST-NET-1 `192.0.2.0/24`, dan nama cadangan (`.invalid`, `.test`, `.local`, `example.*`). Diuji di `tests/test_dataset.py`.
3. **Tidak ada eksekusi perintah.** Payload CMDi/PHP hanya `echo WAF_TEST`, `id`, atau ekspresi aritmetika, dikirim sebagai string ke rute yang tidak mengeksekusinya. Harness tidak pernah mengevaluasi isi payload.
4. **XML**: harness tidak mem-parse XML. Validasi well-formedness di unit test memakai expat tanpa resolusi entity eksternal/parameter. Satu-satunya parser di jalur request adalah libxml2 di ModSecurity (rule `200000`); referensi eksternal di payload hanya menunjuk berkas non-sensitif (`/etc/hostname`, `win.ini`), `expect://id`, atau loopback. Tidak ada payload *billion laughs*.
5. **Sink nyata yang merusak tidak diuji**: NoSQL `$where` pada `/rest/track-order` (DoS), `PATCH` review produk (mengubah data), SSRF `/profile/image/url` (fetch keluar), dan upload XML `/file-upload`. Akibatnya keluarga tersebut hanya mengukur deteksi pola — lihat [SCENARIO_MATRIX.md](SCENARIO_MATRIX.md).
6. **Tidak ada metode `PUT`/`DELETE`** dan tidak ada pengujian volume/DoS. Pembatasan jeda minimum 0,1 detik dan timeout tetap berlaku.

---

## 2. Prosedur Deployment VPS yang Aman

Jika penelitian dipindahkan atau direplikasi pada Virtual Private Server (VPS), ikuti prosedur berikut:

1. **Konfigurasi Firewall VPS (UFW / iptables):**
   - Pastikan hanya port SSH (misal port 22) yang terbuka untuk IP peneliti.
   - Jangan pernah membuka port 3000, 3001, atau 8080 pada firewall publik VPS.

2. **Akses Melalui SSH Port Forwarding (Tunneling):**
   Hubungkan terminal lokal ke VPS menggunakan SSH tunnel loopback terenkripsi:
   ```bash
   ssh -N -L 8080:127.0.0.1:8080 -L 3001:127.0.0.1:3001 user@vps-ip-address
   ```
   Dengan tunnel ini:
   - Akses WAF diakses melalui browser/runner lokal di `http://127.0.0.1:8080`.
   - Akses baseline diakses melalui browser/runner lokal di `http://127.0.0.1:3001`.
   - Seluruh lalu lintas terenkripsi dan tidak ada port rentan yang terekspos ke internet publik.

---

## 3. Batasan Uji Eksperimen

1. **Volume Rendah (Low Concurrency):**
   - Pengujian dijalankan secara terkontrol dengan delay terukur (default 0.25 detik).
   - Dilarang melakukan serangan DoS/DDoS volume tinggi atau *brute force* yang membebani CPU/RAM secara destruktif.

2. **Perlindungan Data & Kerahasiaan:**
   - Dilarang menyematkan kredensial pribadi, API key, token otentikasi nyata, atau data identitas pribadi (PII) ke dalam test case atau laporan CSV.
   - Hasil log hanya menyimpan indikator teknis (metode, path, rule ID CRS, kode HTTP status, latency).

3. **Non-Destructive Testing:**
   - Pengujian hanya berfokus pada evaluasi kemampuan deteksi (*detection rate*) dan mitigasi (*blocking rate*) WAF.
   - Tidak melakukan persistensi eksploitasi, perusakan database, atau *lateral movement*.

---

## 4. Ruang Lingkup Profil Produksi

Batasan loopback di atas berlaku untuk **lab riset** (`docker-compose.yml`) karena targetnya aplikasi yang sengaja rentan. Profil produksi (`deploy/prod/`) memang mengekspos port 80/443 ke publik, dengan ketentuan:

1. **Hanya untuk aplikasi milik sendiri** atau yang dikelola dengan izin tertulis. Jangan pernah menaruh Juice Shop di belakang profil produksi.
2. **Backend tidak boleh terekspos langsung.** Aplikasi harus listen di `127.0.0.1` atau hanya di jaringan Docker, sehingga satu-satunya jalur masuk adalah melalui Caddy → WAF.
3. **Simulator tetap terkunci ke loopback.** `simulator/target_validator.py` tidak boleh dilonggarkan untuk menyerang domain publik. Pengujian serangan terhadap sistem nyata dilakukan di lingkungan staging dengan otorisasi tertulis.
4. **Rahasia tidak di-commit.** File `deploy/prod/.env` sudah tercantum di `.gitignore`.
5. **WAF bukan satu-satunya kontrol.** Tetap lakukan patching aplikasi, hardening server, rate limiting/CDN, dan backup.
