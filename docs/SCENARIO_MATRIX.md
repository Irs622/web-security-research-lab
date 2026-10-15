# Matriks Skenario Dataset Diperluas

Dokumen ini menjelaskan [`simulator/attack_cases_extended.json`](../simulator/attack_cases_extended.json): asal-usulnya, komposisi, koreksi yang dilakukan saat audit, klaim apa yang boleh dan tidak boleh ditarik per keluarga serangan, serta hasil terukur.

---

## 1. Asal-usul dan Prinsip Penyusunan

Dataset diperluas disusun dari paket `waf_scenario_expansion_bundle.zip` (161 kasus: 31 benign, 130 malicious, 13 keluarga). Paket tersebut **tidak** dipakai apa adanya; hasil audit (§3) menunjukkan masalah ID, label, dan kebocoran hold-out. Prinsip yang dipakai:

1. **Superset dari dataset asli.** Seluruh 70 kasus `attack_cases.json` disertakan **identik** (field asli tidak diubah), kecuali `BENIGN-029` dan `BENIGN-030` yang merupakan request identik dengan `BENIGN-006` dan `BENIGN-008`. Dengan begitu `test_id` yang sama selalu berarti request yang sama di kedua dataset, dan hasil per kasus dapat dibandingkan langsung.
2. **Satu `test_id` = satu request unik.** Request identik (method, path, params, headers, body ter-normalisasi) di bawah ID berbeda dilarang, karena menambah sampel yang tidak independen.
3. **Hold-out tetap independen.** Tidak ada request maupun teks bebas (setelah normalisasi huruf/tanda baca) yang sama dengan `holdout_benign.json`.
4. **Label mengikuti niat dan bentuk request, bukan ekspektasi WAF.** Header yang lazim dikirim proxy atau klien sah (mis. `Accept: */*`) adalah benign walaupun ada di keluarga "protocol".
5. **Setiap kasus memiliki `scenario_applicability`** yang menyatakan apakah rute target benar-benar memproses input pada sink yang diserang (§4).

Seluruh aturan di atas diuji otomatis di [`tests/test_dataset.py`](../tests/test_dataset.py).

---

## 2. Komposisi Terverifikasi

Total **217 kasus**: **65 benign**, **152 malicious** (dihitung dari berkas, bukan ditetapkan manual). SHA-256 berkas: `6433cacf7373fa52cf4d11beb3fcc8874687b25e55b2298d0c637d713434b177`.

| Kategori | Kelas | n | `scenario_applicability` | Rute target |
|---|---|---:|---|---|
| `normal` | benign | 65 | `benign_control` | Pencarian, detail produk, feedback, login, `/ftp`, aset statis, header kontrol, body XML sah |
| `sqli` | malicious | 19 | `sink_present` | `/rest/products/search`, `/rest/user/login` |
| `xss` | malicious | 18 | 2 `sink_present`, 16 `pattern_only` | Feedback (tersimpan) vs. API pencarian / root |
| `path-traversal` | malicious | 12 | `sink_present` | `/ftp/…`, `/assets/public/images/…` |
| `cmdi` | malicious | 10 | `pattern_only` | `q` pencarian |
| `lfi` | malicious | 10 | `pattern_only` | `q` pencarian |
| `rfi` | malicious | 10 | `pattern_only` | `q` pencarian |
| `php-injection` | malicious | 10 | `pattern_only` | `q` pencarian / body JSON |
| `java-injection` | malicious | 12 | `pattern_only` | `q` pencarian |
| `nosqli` | malicious | 10 | `pattern_only` | Body JSON login, `q` pencarian |
| `ssrf` | malicious | 10 | `pattern_only` | `q` pencarian, komentar feedback |
| `xxe` | malicious | 10 | `pattern_only` | Body `application/xml` ke pencarian |
| `protocol-violation` | malicious | 9 | `pattern_only` | Header/encoding/metode pada pencarian & feedback |
| `scanner-detection` | malicious | 12 | `pattern_only` | User-Agent scanner, path discovery |

Setiap keluarga malicious memiliki ≥ 9 kasus; ini tetap sampel kecil. Interval Wilson 95% untuk recall 10/10 adalah 72–100%, sehingga **perbedaan antar-keluarga di bawah ±25 poin tidak boleh disimpulkan** dari dataset ini saja. Ringkasan metrik menandai kategori dengan n < 10 (`small_sample`).

---

## 3. Temuan Audit atas Paket ZIP dan Koreksinya

| Temuan pada paket | Dampak | Koreksi |
|---|---|---|
| 59 `test_id` (`BENIGN-001…031`, `SQLI-*`, `XSS-*`, `TRAV-001…008`) sama dengan dataset asli tetapi berisi request **berbeda** | Hasil "SQLI-002" dari dua dataset tidak dapat dibandingkan; laporan bisa tertukar | Kasus asli dipertahankan dengan ID asli; kasus baru diberi nomor lanjutan (`SQLI-011…019`, `XSS-011…018`, `TRAV-009…012`, `BENIGN-043…067`) |
| 11 benign asli (`BENIGN-032…042`) hilang | Kontrol FP berkurang | Dikembalikan (superset) |
| `BENIGN-006` ("50% off -- today") dan `BENIGN-031` ("2 for 1 deal") identik dengan `HOLDOUT-009`/`HOLDOUT-008`; `BENIGN-025` identik dengan `HOLDOUT-018` (body string vs objek); `BENIGN-023` hampir identik dengan `HOLDOUT-015` | **Kebocoran hold-out**: FPR hold-out tidak lagi independen | Dikeluarkan. Uji hold-out kini menormalisasi body JSON dan membandingkan teks bebas |
| 26 dari 31 benign paket adalah duplikat request benign asli | Inflasi n benign tanpa informasi baru | Hanya "green smoothie" (tanpa tanda kutip) yang dipakai (`BENIGN-043`); 24 kontrol benign baru disusun per keluarga serangan |
| `SCAN-001` `GET /robots.txt` berlabel malicious, sementara `BENIGN-018` paket (dan `BENIGN-036` asli) adalah request yang sama berlabel benign | Ground truth kontradiktif | `SCAN-001` diganti User-Agent Nikto |
| `PROTO-006` `Accept: */*`, `PROTO-008` UA riset, `PROTO-009` `X-Forwarded-Proto`, `PROTO-010` `X-Request-ID`, `PROTO-001` `X-Forwarded-For`, `PROTO-005` `Content-Type` yang diizinkan tanpa body berlabel malicious | Header sah dihitung sebagai serangan → FN palsu | Dilabel ulang benign (`BENIGN-044…049`) |
| `XXE-001` body XML biasa tanpa DOCTYPE/entity berlabel malicious | Idem | Dilabel ulang benign (`BENIGN-050`) |
| `SSRF-007` = `LFI-001` (`file:///etc/hostname`) dan `SSRF-006` = `RFI-009` (`http://example.invalid/`) — request identik di dua kategori | Satu request dihitung dua kali | `SSRF-006` → loopback desimal `http://2130706433/`; `SSRF-007` → `gopher://127.0.0.1:6379/_PING` |
| Hampir-duplikat (`JAVA-001`/`009`, `PHP-001`/`009`, `PHP-001`/`007`, `RFI-001`/`007`/`010`, `RFI-002`/`009`, `XXE-002`/`010`, `XXE-003`/`009`) | Variasi semu | Diganti varian yang menguji hal lain: JNDI via RMI, `file_get_contents()`, `eval(base64_decode())`, URL berakhiran `?`, IP literal TEST-NET-1, skema campuran huruf, `expect://`, path Windows |
| Nilai `params` yang sudah ter-encode (`%27%20OR…`, `%3C%3Fphp…`, dst.) dideskripsikan sebagai "URL-encoded" | Simulator meng-encode ulang → di jaringan menjadi **double-encoded** | Deskripsi diperbaiki ("double URL-encoded on the wire") |
| `PROTO-*` hanya berisi header tunggal yang tidak melanggar protokol | Keluarga protokol tidak menguji pelanggaran protokol | Ditambah `PROTO-011…015`: GET dengan body, charset UTF-7, byte NUL, CRLF + nama header, header `Range` tidak valid |

Pemetaan ID paket → dataset akhir untuk kasus yang dipertahankan: `SQLI-002/003/004/006/008/009/010` → `SQLI-011…017`; `XSS-001/004/005/008/009/010` → `XSS-011…016`; `TRAV-008/010` → `TRAV-009/010`; `PROTO-001/005/006/008/009/010` → `BENIGN-044/045/046/047/048/049`; `XXE-001` → `BENIGN-050`; `BENIGN-012` → `BENIGN-043`. Kasus `CMDI`, `LFI`, `RFI`, `PHP`, `JAVA`, `NOSQLI`, `SSRF`, `XXE-002…010`, `PROTO-002/003/004/007`, `SCAN-002…010` mempertahankan ID paket.

---

## 4. Tiga Klaim yang Berbeda

| Klaim | Diukur oleh | Bukti |
|---|---|---|
| **1. Deteksi pola** — WAF mengenali request sebagai mencurigakan | `waf_alert`, `waf_rule_ids`, recall | Rule ID serangan di audit log (selain `920350`, `949110`) |
| **2. Pencegahan** — WAF memutus request sebelum mencapai aplikasi | `waf_intervention` dengan `intervention_evidence = audit_log`, blocking rate | `is_interrupted: true` di audit log ModSecurity |
| **3. Eksploitabilitas** — payload benar-benar berhasil pada aplikasi tanpa WAF | **Tidak diukur** | `backend_outcome` hanya kelas status HTTP; harness tidak memverifikasi efek eksploitasi |

`scenario_applicability` membatasi klaim 2 dan menutup klaim 3:

- **`sink_present`** — rute memproses input pada sink yang diserang (SQLi pada pencarian/login Juice Shop yang memang rentan; traversal pada rute penyaji berkas; XSS tersimpan di feedback). Pemblokiran di sini relevan sebagai pencegahan terhadap kelas kerentanan yang ada. Keberhasilan eksploitasi payload spesifik tetap **tidak** dibuktikan.
- **`pattern_only`** — rute tidak mengimplementasikan fungsi yang diserang (Juice Shop adalah aplikasi Node.js: tidak ada interpreter PHP, tidak ada Log4j, pencarian tidak mengambil URL, tidak mem-parse XML, dan login memakai SQL, bukan MongoDB). Hasilnya **hanya** mengukur deteksi signature WAF. Request lolos pada kategori ini **bukan** bukti aplikasi rentan, dan request yang diblokir **bukan** bukti WAF mencegah eksploitasi nyata.
- **`benign_control`** — kasus benign untuk FPR.

Sink nyata Juice Shop untuk beberapa keluarga sengaja **tidak** dipakai karena bersifat merusak atau membutuhkan autentikasi: NoSQL (`PATCH /rest/products/reviews` mengubah data; `$where` pada `/rest/track-order` adalah vektor DoS), XXE (`/file-upload` multipart), SSRF (`/profile/image/url` melakukan fetch keluar). Lihat [SECURITY_SCOPE.md](SECURITY_SCOPE.md).

---

## 5. Keamanan Eksekusi per Keluarga

- **Semua payload adalah teks inert.** Harness hanya mengirim request ke `base_url` yang lolos `validate_target_url` (loopback, port 3001/8080), tidak mengikuti redirect, dan tidak pernah mengambil URL di dalam parameter (diuji: `test_payload_urls_are_never_contacted`).
- **Host di dalam payload** hanya loopback, `::1`, link-local `169.254.169.254` (sebagai string), TEST-NET-1 `192.0.2.0/24`, atau nama cadangan RFC 2606/6761 (`.invalid`, `.test`, `.local`, `example.*`). Diuji otomatis; satu pengecualian terdokumentasi adalah `XSS-006` asli (`evil.site`, teks pada API pencarian yang tidak merender HTML).
- **CMDi/PHP** hanya `echo WAF_TEST`, `id`, atau ekspresi aritmetika — tidak ada aplikasi target yang mengeksekusinya.
- **XXE**: body divalidasi well-formed dengan expat tanpa resolusi entity eksternal maupun parameter entity. Entity bersarang `XXE-005` hanya dua tingkat (bukan *billion laughs*). Referensi eksternal hanya ke `file:///etc/hostname`, `win.ini`, `expect://id`, atau loopback `127.0.0.1:8080`. Di sisi WAF, body `application/xml` di-parse oleh libxml2 ModSecurity (rule `200000`; `SecXmlExternalEntity` tidak diaktifkan di `modsecurity.conf` image). Verifikasi empiris (2026-10-15): `XXE-004/006/007/008/011` dikirim ke WAF, lalu access log Nginx diperiksa — tidak ada request ke `/xxe.dtd` atau `/p.dtd`, artinya parser tidak mengambil DTD/entity eksternal lewat jaringan. Pembacaan berkas lokal oleh parser tidak dapat diamati dengan cara ini; berkas yang dirujuk sengaja tidak sensitif.
- **Tidak ada metode `PUT`/`DELETE`**. POST yang mengubah state hanya membuat feedback/akun di database in-memory Juice Shop yang di-reset saat container dibuat ulang.

---

## 6. Hasil Terukur

Ekspektasi `expected_waf_behavior` di dataset adalah **hipotesis**, bukan hasil. Hasil terukur (`results/extended/`, PL1–PL4, PL2 tuned, hold-out) beserta analisis FN/FP ada di [RESULTS_INTERPRETATION.md §7](RESULTS_INTERPRETATION.md#hasil-dataset-diperluas). Ringkas (PL1): recall 73.03% (111/152), FPR 1.54% (1/65), seluruh blokir terkonfirmasi audit log; XXE 0/10, RFI 3/10, path discovery umum dan header override tidak terdeteksi di PL mana pun.
