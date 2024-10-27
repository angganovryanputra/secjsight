### SecJSight - JavaScript Security Insight

SecJSight adalah tools open-source yang dirancang untuk menganalisis keamanan JavaScript pada aplikasi web. Dengan kemampuan pemindaian endpoint, deteksi parameter, dan pemindaian kerentanan berbasis aturan, SecJSight membantu pengembang dan profesional keamanan dalam mendeteksi potensi risiko seperti XSS (Cross-Site Scripting), injeksi kode, dan data exposure.

SecJSight memudahkan pengguna dalam menemukan pola-pola berbahaya pada file JavaScript yang sering dijadikan titik serangan oleh peretas. Dengan aturan deteksi yang dapat dikonfigurasi, pengguna dapat menyesuaikan tools ini untuk mendeteksi berbagai jenis kerentanan.
Fitur Utama

- Pemindaian Statis untuk Kerentanan JavaScript:
	- Mengidentifikasi pola kerentanan umum, seperti penggunaan eval, innerHTML, document.write, dan lainnya.

- Ekstraksi Endpoint API:
	- Melakukan crawling pada halaman web untuk mendeteksi endpoint API yang digunakan dalam file JavaScript.

- Deteksi Parameter Entry Point:
	- Mendeteksi parameter dalam URL sebagai titik entry point yang dapat menjadi target eksploitasi.

- Aturan Deteksi yang Dapat Dikonfigurasi:
    - Menggunakan file vulnerability_rules.yaml yang dapat diperbarui dan disesuaikan untuk menambah atau mengubah aturan deteksi kerentanan.

### Instalasi
#### Prasyarat
Python 3.9+ harus sudah terinstal di sistem Anda.
#### Langkah Instalasi

1. Clone Repository:

```bash
git clone https://github.com/username/secjsight.git
cd secjsight
```

2. Buat dan Aktifkan Virtual Environment:

```bash
python3 -m venv venv
source venv/bin/activate  # Di macOS/Linux
venv\Scripts\activate     # Di Windows
```

3. Install Dependencies:

```bash

    pip install -r requirements.txt
```

4. Konfigurasi Aturan Deteksi (Opsional):
	- Tools ini menggunakan file vulnerability_rules.yaml untuk aturan deteksi kerentanan. Anda dapat mengedit atau menambahkan aturan di file ini sesuai kebutuhan.

#### Cara Menggunakan

1. Menjalankan SecJSight:

```python
python secjsight.py
```

2. Pilih Mode Pemindaian:
	- Extract Endpoints: Mendeteksi dan mencatat endpoint API serta parameter URL yang mungkin rentan.
	- Vulnerability Scanning: Melakukan pemindaian kerentanan pada file JavaScript berdasarkan aturan yang telah dikonfigurasi.

3. Laporan:
	- Setelah pemindaian selesai, Anda akan diminta untuk memilih apakah ingin menyimpan hasil dalam format JSON. Laporan ini akan disimpan di folder reports/.

#### Contoh Output

Berikut adalah contoh output dalam format JSON yang dihasilkan oleh SecJSight:

```json
{
  "domain": "https://example.com",
  "js_files": ["https://example.com/static/js/main.js"],
  "endpoints": {
    "https://example.com/static/js/main.js": [
      "https://example.com/api/data"
    ]
  },
  "vulnerabilities": {
    "https://example.com/static/js/main.js": [
      {
        "type": "eval",
        "line": 35,
        "code": "eval(userInput);",
        "description": "Penggunaan eval() dapat menyebabkan serangan XSS.",
        "reference": "https://cwe.mitre.org/data/definitions/95.html"
      }
    ]
  },
  "parameters": {
    "https://example.com/page?param1=value1": ["param1"]
  }
}
```

#### Pengembangan Selanjutnya

Fitur yang direncanakan untuk pengembangan berikutnya:

- Dynamic Analysis: Menambahkan kemampuan pemindaian dinamis menggunakan Selenium atau Playwright untuk mengeksekusi JavaScript di browser dan mengidentifikasi endpoint atau API yang dipanggil secara dinamis.
- Integrasi Machine Learning untuk Deteksi Pola Kerentanan: Menggunakan model pembelajaran mesin untuk mendeteksi pola kerentanan yang lebih kompleks.
- Integrasi CI/CD: Menyediakan pipeline CI/CD untuk otomatisasi pemindaian dalam siklus pengembangan, menggunakan platform seperti GitHub Actions atau GitLab CI.
- Dashboard Visualisasi Hasil: Membuat antarmuka visual berbasis web untuk menampilkan hasil pemindaian dan analisis kerentanan.

### Lisensi

Tools ini dirilis di bawah MIT License.

### Kontribusi

Kami menyambut kontribusi dari komunitas untuk membantu pengembangan lebih lanjut. Jika Anda tertarik untuk berkontribusi, silakan lihat panduan kontribusi di CONTRIBUTING.md (jika ada) atau ajukan pull request.
Referensi

    OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
    Regex for Web Security: https://regex101.com/
    Playwright for Dynamic Analysis: https://playwright.dev/python/docs/intro
    Python Requests Documentation: https://docs.python-requests.org/
    BeautifulSoup Documentation: https://www.crummy.com/software/BeautifulSoup/bs4/doc/

Dengan README ini, pengunjung repository Anda akan mendapatkan pengenalan yang lengkap tentang SecJSight, mulai dari tujuan, fitur, hingga cara instalasi dan penggunaan. Jangan lupa mengganti username pada URL GitHub dengan username GitHub Anda yang sebenarnya.
