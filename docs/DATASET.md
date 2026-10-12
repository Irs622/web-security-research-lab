# Dataset Kasus Uji

Dokumen ini menjelaskan skema, komposisi, dan aturan penambahan kasus uji yang dipakai simulator.

---

## 1. Berkas Dataset

| Berkas | Isi | Dipakai oleh |
|---|---|---|
| [`simulator/attack_cases.json`](../simulator/attack_cases.json) | 70 kasus berlabel: 42 benign, 28 malicious | `make test-baseline`, `make test-waf`, `make experiment-matrix`, `make experiment-tuned` |
| [`simulator/holdout_benign.json`](../simulator/holdout_benign.json) | 20 kasus benign yang **tidak pernah** dipakai saat menyusun rule exclusion | `make experiment-holdout` |

Komposisi `attack_cases.json`:

| Kategori | Kelas | Jumlah |
|---|---|---|
| `normal` | benign | 42 |
| `sqli` | malicious | 10 |
| `xss` | malicious | 10 |
| `path-traversal` | malicious | 8 |

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
| `test_id` | ya | unik di seluruh berkas | Prefiks mengikuti kategori (`BENIGN-`, `SQLI-`, `XSS-`, `TRAV-`, `HOLDOUT-`) |
| `category` | ya | `normal`, `sqli`, `xss`, `path-traversal`, `cmdi`, `lfi`, `rfi`, `php-injection`, `java-injection`, `nosqli`, `ssrf`, `xxe`, `protocol-violation`, `scanner-detection` | Kategori tambahan menyesuaikan keluarga rule CRS agar kasus dari regression suite CRS dapat dilabeli konsisten |
| `expected_class` | ya | `benign`, `malicious` | **Ground truth** untuk confusion matrix |
| `method` | ya | `GET`, `POST`, `PUT`, `DELETE` | |
| `path` | ya | diawali `/`, relatif | URL absolut ditolak (containment) |
| `params` | ya | objek | Di-encode menjadi query string (`urlencode`, `doseq=True`) |
| `headers` | ya | objek | `User-Agent` dan `Accept` diisi default bila kosong; `X-Lab-Trace-Id` selalu ditimpa simulator |
| `body` | ya | `null`, string, atau objek | Objek dikirim sebagai JSON dengan `Content-Type: application/json` bila belum diset |
| `description` | ya | teks | Penjelasan singkat untuk laporan |
| `expected_waf_behavior` | ya | `allow`, `block` | Dokumentasi ekspektasi; metrik dihitung dari `expected_class` |

---

## 3. Validasi

Dataset divalidasi di dua tempat:

1. **Saat runtime** — `load_cases()` di [`simulator/run_tests.py`](../simulator/run_tests.py) menolak berkas kosong, `path` non-relatif, `expected_class` tidak dikenal, dan `test_id` ganda (ID ganda akan merusak metrik per kasus).
2. **Unit test** — [`tests/test_dataset.py`](../tests/test_dataset.py) memeriksa seluruh field wajib, nilai enumerasi, serta memastikan set hold-out seluruhnya benign dan **tidak beririsan** dengan dataset utama.

---

## 4. Menambah Kasus Baru

1. Tambahkan objek baru dengan `test_id` unik dan seluruh field di atas.
2. Payload malicious harus menargetkan Juice Shop lokal saja; jangan menambahkan payload yang bersifat destruktif (DoS, penghapusan data) — lihat [SECURITY_SCOPE.md](SECURITY_SCOPE.md).
3. Jalankan `make check` untuk memvalidasi skema.
4. Jalankan ulang eksperimen. Hash SHA-256 dataset tercatat otomatis di `*.meta.json`, sehingga hasil lama dan baru dapat dibedakan.
5. Jangan memindahkan kasus dari `holdout_benign.json` ke dataset utama atau memakainya untuk menyusun exclusion — itu menghilangkan fungsinya sebagai data validasi independen.
