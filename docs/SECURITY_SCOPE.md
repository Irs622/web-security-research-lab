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
