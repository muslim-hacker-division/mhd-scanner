# 🛡️ MHD Eagle Eye - Web Security Auditor

**MHD Eagle Eye** adalah alat audit keamanan web yang dikembangkan oleh **Muslim Hacker Division (MHD)** untuk membantu pemeriksaan konfigurasi pertahanan aset digital secara pasif dan aman.

> Gunakan hanya pada domain milik Anda atau yang telah memberikan izin tertulis. Scanner memblokir target localhost, IP private, link-local, dan reserved.

## 🚀 Fitur

- Security headers: CSP, HSTS, nosniff, frame protection, Referrer-Policy, Permissions-Policy
- Analisis cookie: Secure, HttpOnly, dan SameSite
- Deteksi redirect dan redirect lintas host
- Pemeriksaan XML-RPC WordPress secara pasif
- Deteksi `robots.txt`, `security.txt`, dan `.well-known/security.txt`
- Hasil terminal dan ekspor JSON
- Mode CLI dan pemblokiran target jaringan internal

## Instalasi

```bash
python3 -m pip install requests
```

## Cara penggunaan

Mode interaktif:

```bash
python3 mhd_scanner.py
```

Mode argumen:

```bash
python3 mhd_scanner.py https://example.com
python3 mhd_scanner.py example.com --json laporan.json
```

## Output JSON

Gunakan opsi `--json` untuk menyimpan hasil audit:

```bash
python3 mhd_scanner.py https://example.com --json laporan.json
```

## Batasan

Versi ini merupakan scanner pasif. Tidak melakukan brute force, exploit, port scan, credential attack, atau pengujian destruktif.
