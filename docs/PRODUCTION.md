# Deployment Produksi

Panduan memakai WAF (ModSecurity v3 + OWASP CRS 4.25 LTS) untuk melindungi website nyata **milik Anda sendiri**.
Konfigurasi lab skripsi (`docker-compose.yml`) tidak diubah; semua file produksi ada di `deploy/prod/`.

```
Internet ──443──> Caddy (TLS otomatis, security headers) ──> ModSecurity+CRS ──> Aplikasi Anda
```

---

## 1. Struktur File

| File | Fungsi |
|---|---|
| `deploy/prod/docker-compose.prod.yml` | Definisi service `caddy` dan `waf` |
| `deploy/prod/.env.example` | Template konfigurasi (salin ke `.env`) |
| `deploy/prod/caddy/Caddyfile` | TLS otomatis, security headers, batas body, log JSON |
| `deploy/prod/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` | Exclusion runtime per URL/argumen (dievaluasi sebelum CRS) |
| `deploy/prod/waf/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` | Exclusion startup-time (`SecRuleRemoveById`, `SecRuleUpdateTargetById`) |

---

## 2. Prasyarat

- Server Linux (VPS) dengan Docker Engine + Compose v2, RAM minimal 2 GB.
- Record DNS `A`/`AAAA` domain sudah mengarah ke IP server.
- Firewall server membuka port **80** dan **443** (TCP, serta UDP 443 untuk HTTP/3).
- Aplikasi yang dilindungi **tidak** terekspos langsung ke publik (listen di `127.0.0.1` atau hanya di jaringan Docker).

---

## 3. Konfigurasi `.env`

```bash
cp deploy/prod/.env.example deploy/prod/.env
```

| Variabel | Contoh | Keterangan |
|---|---|---|
| `DOMAIN` | `example.com` | Domain yang dilayani Caddy (sertifikat diterbitkan otomatis) |
| `ACME_EMAIL` | `admin@example.com` | Email pendaftaran Let's Encrypt |
| `BACKEND_URL` | `http://host.docker.internal:8000` | Upstream aplikasi dari sudut pandang container WAF |
| `MODSEC_RULE_ENGINE` | `DetectionOnly` | `DetectionOnly` (hanya log) atau `On` (blokir) |
| `PARANOIA` | `1` | Paranoia Level CRS 1–4; makin tinggi makin ketat dan makin banyak false positive |
| `ANOMALY_INBOUND` | `5` | Ambang skor anomali request untuk pemblokiran |
| `ANOMALY_OUTBOUND` | `4` | Ambang skor anomali response |
| `MODSEC_REQ_BODY_LIMIT` | `13107200` | Batas body request dalam byte (selaraskan dengan `request_body max_size` di Caddyfile) |

**Menentukan `BACKEND_URL`:**
- Aplikasi di host yang sama → `http://host.docker.internal:<port>`.
- Aplikasi di container lain → hubungkan container tersebut ke network `wafprod-edge`, lalu gunakan `http://<nama-service>:<port>`.
- Aplikasi di server lain (jaringan privat) → `http://<ip-privat>:<port>`; batasi firewall agar hanya menerima dari server WAF.

> Nilai `.env` lain di compose (`REAL_IP_HEADER`, `SET_REAL_IP_FROM`, `SERVER_TOKENS`) mengikuti variabel image `owasp/modsecurity-crs`. Verifikasi namanya di README image untuk tag yang dipakai sebelum go-live.

---

## 4. Menjalankan

```bash
make prod-up        # jalankan stack
make prod-logs      # ikuti log WAF
make prod-down      # hentikan stack
```

Verifikasi:
```bash
curl -I https://DOMAIN/                               # 200
curl -I "https://DOMAIN/?q=%27%20OR%201%3D1--"        # 200 saat DetectionOnly, 403 saat On
```

---

## 5. Fase Tuning False Positive (wajib, 1–2 minggu)

Default `MODSEC_RULE_ENGINE=DetectionOnly`: serangan hanya dicatat, tidak diblokir. Hasil lab (FPR 0% dari 12 request benign) **tidak** mewakili traffic nyata, sehingga tuning wajib dilakukan.

1. Biarkan traffic asli mengalir, lalu lihat rule yang paling sering terpicu:
   ```bash
   make prod-fp
   ```
2. Telusuri detail transaksi untuk rule tertentu (contoh 942100):
   ```bash
   docker compose -f deploy/prod/docker-compose.prod.yml --env-file deploy/prod/.env \
     exec waf grep 942100 /var/log/modsecurity/audit.log | head
   ```
3. Bila terbukti traffic sah, tambahkan exclusion **sesempit mungkin** (per URL + per argumen) di `REQUEST-900-...conf`. Gunakan ID rule lokal 1000–9999. Contoh:
   ```apache
   SecRule REQUEST_FILENAME "@streq /login" \
       "id:1001,phase:1,pass,nolog,\
       ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:password"
   ```
4. `make prod-restart`, ulangi sampai traffic normal bersih dari alert.
5. Ubah `MODSEC_RULE_ENGINE=On` di `.env`, lalu `make prod-up`.
6. Opsional: naikkan `PARANOIA=2` dan ulangi tuning (menutup kasus seperti `TRAV-004` pada hasil lab).

**Hindari:** menonaktifkan seluruh kategori rule, `SecRuleRemoveById` global tanpa alasan kuat, atau menaikkan `ANOMALY_INBOUND` secara drastis.

**Plugin platform:** CRS v4 menyediakan plugin exclusion siap pakai (WordPress, Drupal, Nextcloud, phpMyAdmin, dll.) di organisasi GitHub `coreruleset`.

---

## 6. Operasional

| Aspek | Rekomendasi |
|---|---|
| **Log** | Audit log JSON di volume `waf_logs`; log container dirotasi 5×50 MB. Kirim ke Loki/ELK/Wazuh untuk retensi panjang. |
| **Monitoring** | Pantau jumlah 403/menit dan rasio blokir; pasang alert untuk lonjakan. |
| **Rate limit / DDoS** | ModSecurity bukan anti-DDoS. Gunakan CDN (mis. Cloudflare) atau fail2ban berbasis audit log. |
| **CDN di depan Caddy** | Atur `trusted_proxies` di Caddyfile agar IP klien asli terbaca. |
| **Update** | Perbarui tag image CRS & Caddy berkala, uji di staging dulu. |
| **Backup** | Backup volume `caddy_data` (sertifikat) dan file `deploy/prod/`. |

### Rollback Darurat
Jika WAF memblokir traffic sah setelah go-live:
```bash
# Ubah MODSEC_RULE_ENGINE=DetectionOnly di deploy/prod/.env, lalu:
make prod-up
```

---

## 7. Troubleshooting

| Gejala | Penyebab Umum | Solusi |
|---|---|---|
| Sertifikat gagal terbit | DNS belum mengarah / port 80 tertutup | Cek `dig DOMAIN`, buka port 80, lihat `docker logs wafprod-caddy` |
| `502 Bad Gateway` | WAF tidak bisa menjangkau `BACKEND_URL` | Pastikan aplikasi berjalan & alamat benar dari dalam container |
| Semua request tercatat dari satu IP | Real IP tidak diteruskan | Periksa `SET_REAL_IP_FROM` dan `trusted_proxies` (bila ada CDN) |
| Upload file gagal (413) | Body melebihi batas | Naikkan `MODSEC_REQ_BODY_LIMIT` dan `request_body max_size` bersamaan |
| `make prod-fp` kosong | Belum ada alert atau format log berbeda | Cek isi `/var/log/modsecurity/audit.log` di container |

---

## 8. Checklist Go-Live

- [ ] `.env` terisi dan **tidak** ter-commit
- [ ] Aplikasi backend tidak bisa diakses langsung dari internet
- [ ] HTTPS aktif, HTTP otomatis redirect ke HTTPS
- [ ] Minimal 1 minggu DetectionOnly dengan traffic nyata
- [ ] False positive utama sudah diberi exclusion
- [ ] `MODSEC_RULE_ENGINE=On` dan uji payload SQLi → 403
- [ ] Log & alert terpantau; prosedur rollback dipahami

---

## 9. Batasan Etika

Simulator di `simulator/` tetap dibatasi ke loopback. Uji serangan hanya pada sistem yang Anda miliki
atau yang sudah mendapat izin tertulis, sebaiknya pada lingkungan staging. Lihat juga [SECURITY_SCOPE.md](SECURITY_SCOPE.md).
