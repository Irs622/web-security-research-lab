# Deployment Produksi

Panduan memakai WAF (ModSecurity v3 + OWASP CRS 4.25) untuk melindungi website nyata **milik Anda sendiri**.
Konfigurasi lab skripsi (`docker-compose.yml`) tidak diubah; semua file produksi ada di `deploy/prod/`.

```
Internet ──443──> Caddy (TLS otomatis, security headers) ──> ModSecurity+CRS ──> Aplikasi Anda
```

## 1. Persiapan
1. Server Linux dengan Docker Compose v2, DNS domain sudah mengarah ke IP server, port 80/443 terbuka.
2. `cp deploy/prod/.env.example deploy/prod/.env` lalu isi `DOMAIN`, `ACME_EMAIL`, `BACKEND_URL`.
   - Aplikasi di host yang sama: `http://host.docker.internal:<port>` (pastikan aplikasi hanya listen di 127.0.0.1 / tidak terbuka publik).
   - Aplikasi di container lain: gabungkan ke network `wafprod-edge` dan gunakan nama service-nya.
3. `make prod-up`

## 2. Fase tuning (wajib, 1–2 minggu)
Default `MODSEC_RULE_ENGINE=DetectionOnly`: serangan hanya dicatat, tidak diblokir.
1. Pantau false positive: `make prod-fp` (ringkasan rule ID yang paling sering terpicu).
2. Untuk setiap false positive yang sah, tambahkan exclusion sempit (per URL + per argumen) di
   `deploy/prod/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`. Hindari `SecRuleRemoveById` global.
3. `make prod-restart`, ulangi sampai log bersih dari traffic normal.
4. Ubah `MODSEC_RULE_ENGINE=On` di `.env`, `make prod-up`.
5. Opsional: naikkan `PARANOIA=2` lalu ulangi tuning.

## 3. Operasional
- **Log**: audit log JSON di volume `waf_logs`; container log dirotasi (5×50 MB). Disarankan dikirim ke Loki/ELK/Wazuh.
- **Rate limit / brute force**: ModSecurity bukan anti-DDoS. Gunakan CDN (mis. Cloudflare) atau fail2ban yang membaca audit log.
- **Jika memakai CDN di depan Caddy**: konfigurasikan `trusted_proxies` di Caddyfile agar IP klien asli terbaca.
- **Update**: perbarui tag image CRS secara berkala (cek rilis LTS), uji di staging, lalu deploy.
- **Rollback darurat**: set `MODSEC_RULE_ENGINE=DetectionOnly` lalu `make prod-up`.

## 4. Verifikasi
```bash
curl -I https://DOMAIN/                               # 200
curl -I "https://DOMAIN/?q=%27%20OR%201%3D1--"        # 403 bila engine=On
```

## 5. Batasan etika
Simulator di `simulator/` tetap dibatasi ke loopback. Uji serangan hanya pada sistem yang Anda miliki
atau yang sudah mendapat izin tertulis, sebaiknya pada lingkungan staging.
