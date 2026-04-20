# 🛡️ MHD Eagle Eye - Web Security Auditor

**MHD Eagle Eye** adalah alat audit keamanan web sederhana yang dikembangkan oleh **Muslim Hacker Division (MHD)**. Proyek ini bertujuan untuk menjaga marwah aset digital dakwah dari ancaman serangan siber seperti SEO Spam, Defacement, dan Brute Force.

## 🚀 Fitur Utama
* **Security Header Scanner:** Mengecek lapisan pertahanan web (CSP, HSTS, X-Frame-Options).
* **XML-RPC Vulnerability Check:** Mendeteksi celah pada pintu belakang WordPress.
* **Server Masking Check:** Memastikan informasi versi server tidak terekspos.
* **MHD Guard Module:** Memberikan rekomendasi perbaikan langsung bagi Admin IT.

## 🛠️ Cara Penggunaan
1. Pastikan Python 3 terpasang.
2. Jalankan scanner:
   ```bash
   python3 mhd_scanner.py

### 📱 Cara Jalankan di Termux (Android)
1. Install Termux dari F-Droid.
2. Jalankan perintah berikut:
   ```bash
   pkg update && pkg upgrade
   pkg install python git
   pip install requests
   git clone [https://github.com/muslim-hacker-division/mhd-scanner](https://github.com/muslim-hacker-division/mhd-scanner)
   cd mhd-scanner
   python mhd_scanner.py
