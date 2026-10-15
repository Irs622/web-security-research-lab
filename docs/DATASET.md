# Dataset Kasus Uji

Dokumen ini menjelaskan skema, komposisi, dan aturan penambahan kasus uji yang dipakai simulator.

---

## 1. Berkas Dataset

| Berkas | Isi | Dipakai oleh |
|---|---|---|
| [`simulator/attack_cases.json`](../simulator/attack_cases.json) | **Dataset asli (baseline reproducibility)**: 70 kasus berlabel, 42 benign, 28 malicious. Tidak diubah agar hash dan hasil di `results/` tetap valid | `make test-baseline`, `make test-waf`, `make experiment-matrix`, `make experiment-tuned` (default) |
| [`simulator/attack_cases_extended.json`](../simulator/attack_cases_extended.json) | **Dataset diperluas**: 217 kasus, 65 benign, 152 malicious, 13 keluarga serangan. Superset dari dataset asli | `make experiment-extended`, atau target mana pun dengan `CASES=simulator/attack_cases_extended.json OUT=results/extended` |
| [`simulator/holdout_benign.json`](../simulator/holdout_benign.json) | 20 kasus benign yang **tidak pernah** dipakai saat menyusun rule exclusion | `make experiment-holdout` |

Penyusunan, koreksi audit, dan batas klaim dataset diperluas dijelaskan di [SCENARIO_MATRIX.md](SCENARIO_MATRIX.md).

Komposisi `attack_cases.json`:

| Kategori | Kelas | Jumlah |
|---|---|---|
| `normal` | benign | 42 |
| `sqli` | malicious | 10 |
| `xss` | malicious | 10 |
| `path-traversal` | malicious | 8 |

Komposisi `attack_cases_extended.json` (dihitung dari berkas; diverifikasi `tests/test_dataset.py`):

| Kategori | Kelas | Jumlah | | Kategori | Kelas | Jumlah |
|---|---|---|---|---|---|---|
| `normal` | benign | 65 | | `php-injection` | malicious | 10 |
| `sqli` | malicious | 19 | | `java-injection` | malicious | 12 |
| `xss` | malicious | 18 | | `nosqli` | malicious | 10 |
| `path-traversal` | malicious | 12 | | `ssrf` | malicious | 10 |
| `cmdi` | malicious | 10 | | `xxe` | malicious | 10 |
| `lfi` | malicious | 10 | | `protocol-violation` | malicious | 9 |
| `rfi` | malicious | 10 | | `scanner-detection` | malicious | 12 |

### Perbedaan dataset asli dan diperluas

- 68 dari 70 kasus asli ada di dataset diperluas dengan field identik; `BENIGN-029`/`BENIGN-030` dihilangkan karena request-nya identik dengan `BENIGN-006`/`BENIGN-008`. Dataset asli sendiri tidak diubah.
- Dataset diperluas menambah field `scenario_applicability` pada setiap kasus.
- Hasil kedua dataset **tidak boleh digabung**. `analyze_results.py` menolak pasangan CSV WAF dan baseline yang `dataset_sha256`-nya berbeda; hasil dataset diperluas disimpan terpisah di `results/extended/`.

---

## 2. Skema Kasus

Setiap berkas adalah array JSON. Contoh satu kasus:

```json
{
  "test_id": "SQLI-001",
  "category": "sqli",
  "expected_class": "malicious",
  "method": "GET",
  "path": "/rest/products/search",
  "params": {"q": "' OR '1'='1"},
  "headers": {},
  "body": null,
  "description": "Classic tautology boolean-based SQL injection",
  "expected_waf_behavior": "block"
}
```

| Field | Wajib | Nilai yang valid | Keterangan |
|---|---|---|---|
| `test_id` | ya | unik di seluruh berkas | Prefiks mengikuti kategori (`BENIGN-`, `SQLI-`, `XSS-`, `TRAV-`, `CMDI-`, `LFI-`, `RFI-`, `PHP-`, `JAVA-`, `NOSQLI-`, `SSRF-`, `XXE-`, `PROTO-`, `SCAN-`, `HOLDOUT-`). ID yang sama di dua dataset harus berarti request yang sama |
| `category` | ya | `normal`, `sqli`, `xss`, `path-traversal`, `cmdi`, `lfi`, `rfi`, `php-injection`, `java-injection`, `nosqli`, `ssrf`, `xxe`, `protocol-violation`, `scanner-detection` | Kategori tambahan menyesuaikan keluarga rule CRS agar kasus dari regression suite CRS dapat dilabeli konsisten |
| `expected_class` | ya | `benign`, `malicious` | **Ground truth** untuk confusion matrix |
| `method` | ya | `GET`, `POST`, `PUT`, `DELETE` | |
| `path` | ya | diawali `/`, relatif | URL absolut ditolak (containment) |
| `params` | ya | objek | Di-encode menjadi query string (`urlencode`, `doseq=True`) |
| `headers` | ya | objek | `User-Agent` dan `Accept` diisi default bila kosong; `X-Lab-Trace-Id` selalu ditimpa simulator |
| `body` | ya | `null`, string, atau objek | Objek dikirim sebagai JSON dengan `Content-Type: application/json` bila belum diset |
| `description` | ya | teks | Penjelasan singkat untuk laporan |
| `expected_waf_behavior` | ya | `allow`, `block` | **Hipotesis**, bukan hasil; harus konsisten dengan kelas (benign ⇔ `allow`). Metrik dihitung dari `expected_class` |
| `scenario_applicability` | opsional (wajib di dataset diperluas) | `sink_present`, `pattern_only`, `benign_control` | Apakah rute target benar-benar memproses input pada sink yang diserang. Disalin ke CSV; kasus tanpa field ini dilaporkan `unspecified`. Lihat [SCENARIO_MATRIX.md §4](SCENARIO_MATRIX.md#4-tiga-klaim-yang-berbeda) |

Kasus benign selalu berkategori `normal`, sehingga recall per kategori tidak tercampur dengan FPR.

---

## 3. Validasi

Dataset divalidasi di dua tempat:

1. **Saat runtime** — `load_cases()` di [`simulator/run_tests.py`](../simulator/run_tests.py) menolak berkas kosong, `path` non-relatif, `expected_class` tidak dikenal, dan `test_id` ganda (ID ganda akan merusak metrik per kasus).
2. **Unit test** — [`tests/test_dataset.py`](../tests/test_dataset.py) memeriksa:
   - field wajib, nilai enumerasi, tipe `params`/`headers`/`body`, path relatif, konsistensi label ↔ ekspektasi ↔ kategori;
   - set hold-out seluruhnya benign dan **tidak beririsan** dengan kedua dataset utama — dibandingkan per request ter-normalisasi (body JSON sebagai string atau objek dianggap sama) dan per teks bebas;
   - dataset diperluas: tidak ada request identik di bawah dua ID, kasus asli identik dengan dataset asli, setiap keluarga malicious terwakili (≥ 8 kasus), body JSON valid, body XML well-formed (expat tanpa resolusi entity eksternal), host di dalam payload hanya loopback/cadangan, dan tidak ada metode `PUT`/`DELETE`.

---

## 4. Menambah Kasus Baru

1. Tambahkan objek baru dengan `test_id` unik dan seluruh field di atas.
2. Payload malicious harus menargetkan Juice Shop lokal saja; jangan menambahkan payload yang bersifat destruktif (DoS, penghapusan data) — lihat [SECURITY_SCOPE.md](SECURITY_SCOPE.md).
3. Jalankan `make check` untuk memvalidasi skema.
4. Jalankan ulang eksperimen. Hash SHA-256 dataset tercatat otomatis di `*.meta.json`, sehingga hasil lama dan baru dapat dibedakan.
5. Jangan memindahkan kasus dari `holdout_benign.json` ke dataset utama atau memakainya untuk menyusun exclusion — itu menghilangkan fungsinya sebagai data validasi independen.
6. Jangan menggunakan ulang `test_id` yang sudah ada untuk request lain; beri nomor baru.
7. Isi `scenario_applicability` berdasarkan perilaku rute Juice Shop yang sebenarnya, bukan berdasarkan jenis payload.

### Kecukupan sampel benign

Dengan 0 FP dari n benign, batas atas Wilson 95% FPR adalah ±8,4% (n = 42), ±5,6% (n = 65), dan ±16,1% (n = 20, hold-out). Jadi hold-out 20 kasus hanya dapat menunjukkan regresi FPR yang besar; klaim FPR "mendekati nol" membutuhkan set hold-out yang lebih besar. Set hold-out sengaja tidak diperbesar dalam perubahan ini agar hasil hold-out yang sudah dilaporkan tetap valid; memperbesarnya adalah pekerjaan lanjutan yang harus dilakukan **sebelum** tuning baru disusun.
