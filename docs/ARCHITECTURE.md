# Arsitektur WAF Research Lab

Dokumen ini mendefinisikan arsitektur sistem, topologi jaringan, spesifikasi container, dan batas keamanan untuk penelitian evaluasi Web Application Firewall (WAF) ModSecurity dan OWASP Core Rule Set (CRS) terhadap OWASP Juice Shop.

---

## 1. Topologi Komponen & Alur Jaringan

```mermaid
flowchart TD
    subgraph Host["Host Machine (macOS / VPS)"]
        subgraph Runners["Eksekutor Pengujian"]
            PySim["Python Simulator\n(simulator/run_tests.py)"]
        end
        PortBaseline["127.0.0.1:3001\n(Baseline Port)"]
        PortWAF["127.0.0.1:8080\n(WAF Port)"]
    end

    subgraph DockerNet["Docker Internal Network (waflab-internal)"]
        subgraph WAFContainer["WAF Reverse Proxy (waflab-modsecurity)"]
            Nginx["Nginx Reverse Proxy"]
            ModSec["ModSecurity v3 Engine"]
            CRS["OWASP CRS v4.25 LTS\n(Paranoia Level 1, Inbound: 5)"]
        end

        subgraph AppContainer["Target Aplikasi (waflab-juice-shop)"]
            JuiceShop["OWASP Juice Shop v17.1.1\n(Node.js / Express :3000)"]
        end

        subgraph ZAPContainer["Passive Scanner (waflab-zap-baseline)"]
            ZAP["OWASP ZAP 2.16.0\n(Profile: scan)"]
        end
    end

    PySim -->|"Mode baseline\n(Direct Access)"| PortBaseline
    PySim -->|"Mode waf\n(Inspected Access)"| PortWAF

    PortBaseline -->|"Bridge NAT"| JuiceShop
    PortWAF -->|"Bridge NAT"| Nginx
    Nginx --> ModSec
    ModSec --> CRS
    ModSec -->|"Allowed Request\n(Anomaly < 5)"| JuiceShop
    ModSec -.->|"Blocked Request (403)\n(Anomaly >= 5)"| Nginx
    ZAP -->|"Internal HTTP"| Nginx
```

---

## 2. Alur Pengujian & Dua Jalur Komparasi

Untuk menjamin validitas metodologi penelitian ilmiah (*experimental research*), sistem menyediakan dua jalur request:

1. **Jalur Baseline (`http://127.0.0.1:3001`):**
   - Request langsung diteruskan ke OWASP Juice Shop tanpa perantara WAF.
   - Digunakan untuk mengukur:
     - Perilaku default aplikasi rentan terhadap serangan (ground truth baseline).
     - Latensi dasar respon aplikasi tanpa overhead WAF.
     - HTTP status alami aplikasi terhadap payload.

2. **Jalur WAF (`http://127.0.0.1:8080`):**
   - Request masuk ke Nginx reverse proxy, diinspeksi oleh engine ModSecurity dan dicocokkan dengan rule OWASP CRS.
   - Digunakan untuk mengukur:
     - Kemampuan deteksi (rule matching & anomaly scoring).
     - Kemampuan pemblokiran (HTTP 403 / connection drop).
     - Overhead latensi tambahan yang ditimbulkan oleh inspeksi WAF.

3. **Jalur Passive Scanner ZAP:**
   - Dijalankan terpisah dalam container Docker pada jaringan internal yang sama (`http://waf:8080`).
   - Bertujuan memetakan kerentanan secara pasif tanpa eksploitasi aktif.

---

## 3. Spesifikasi Service & Pinned Versions

Semua versi image di-pin secara eksplisit untuk menjamin reproduksibilitas:

| Service | Container Name | Base Image Tag | Healthcheck | Resource Limits |
|---|---|---|---|---|
| **juice-shop** | `waflab-juice-shop` | `bkimminich/juice-shop:v17.1.1` | Node.js HTTP ping ke port 3000 (`/`) | CPU 1.5, RAM 1024 MB |
| **waf** | `waflab-modsecurity` | `owasp/modsecurity-crs:4.25.2-nginx-alpine-lts` | Script bawaan image `/usr/local/bin/healthcheck` | CPU 1.5, RAM 512 MB |
| **zap-baseline**| `waflab-zap-baseline`| `ghcr.io/zaproxy/zaproxy:2.16.0` | N/A (One-off task profile) | CPU 1.5, RAM 1024 MB |

---

## 4. Konfigurasi WAF & Core Rule Set

Konfigurasi lingkungan WAF disetel melalui environment variables:
* `BACKEND`: `http://juice-shop:3000` (target upstream internal)
* `PORT`: `8080` (listening port reverse proxy)
* `MODSEC_RULE_ENGINE`: `On` (enforcement mode aktif, request berbahaya diblokir dengan HTTP 403)
* `PARANOIA`: `1` (Paranoia Level 1 - CRS baseline untuk minimalisir false positive). Diteruskan juga ke `BLOCKING_PARANOIA` dan `DETECTION_PARANOIA`, karena image CRS 4 memakai `BLOCKING_PARANOIA` untuk pemblokiran
* `ANOMALY_INBOUND`: `5` (Threshold skor anomali inbound untuk memicu pemblokiran)
* `ANOMALY_OUTBOUND`: `4` (Threshold skor anomali outbound untuk kebocoran data)
* `MODSEC_AUDIT_ENGINE`: `RelevantOnly` (pencatatan log audit untuk request yang memicu intervensi/peringatan)

---

## 5. Perintah Operasional

### Menjalankan Lab
```bash
# Tarik image yang telah ter-pin
docker compose pull

# Jalankan service aplikasi dan WAF
docker compose up -d juice-shop waf

# Pantau status container dan healthcheck
docker compose ps
```

### Memeriksa Log Real-time
```bash
# Log gabungan
docker compose logs -f

# Log spesifik WAF (melihat rule CRS yang terpicu)
docker compose logs -f waf

# Log aplikasi Juice Shop
docker compose logs -f juice-shop
```

### Menghentikan dan Membersihkan Lab
```bash
# Hentikan container
docker compose down

# Hentikan dan hapus volume serta network jika reset total diperlukan
docker compose down -v
```

---

## 6. Arsitektur Deployment Produksi

Selain lab riset, repository menyediakan profil produksi di `deploy/prod/` untuk melindungi website nyata:

```mermaid
flowchart LR
    Client["Pengguna Internet"] -->|"HTTPS :443"| Caddy
    subgraph Edge["Docker Network wafprod-edge (172.30.0.0/24)"]
        Caddy["Caddy 2.8\nTLS Let's Encrypt\nSecurity Headers"] -->|"HTTP :8080\nX-Forwarded-For"| WAF["ModSecurity v3 + CRS 4.25\n(DetectionOnly → On)"]
    end
    WAF -->|"BACKEND_URL"| App["Aplikasi Anda"]
    WAF -.-> Logs[("Volume waf_logs\naudit.log JSON")]
```

| Service | Container | Image | Fungsi |
|---|---|---|---|
| **caddy** | `wafprod-caddy` | `caddy:2.8.4-alpine` | Terminasi TLS, redirect HTTP→HTTPS, HSTS & security headers, batas body 12 MB |
| **waf** | `wafprod-modsecurity` | `owasp/modsecurity-crs:4.25.2-nginx-alpine-lts` | Inspeksi CRS, real IP dari Caddy, audit log JSON ke volume |

Perbedaan utama terhadap lab:

| Aspek | Lab Riset | Produksi |
|---|---|---|
| Paparan | `127.0.0.1` saja | Publik port 80/443 |
| TLS | Tidak ada | Otomatis (Caddy + Let's Encrypt) |
| Rule engine | `On` | `DetectionOnly` saat tuning, lalu `On` |
| Backend | Juice Shop | Aplikasi milik sendiri (`BACKEND_URL`) |
| Rule exclusion | Tidak ada | `deploy/prod/waf/*.conf` |
| Log | Di dalam container | Volume `waf_logs` + rotasi log container |

Detail operasional: [PRODUCTION.md](PRODUCTION.md).
