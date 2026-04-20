import requests
import time
import sys

# Warna untuk tampilan terminal
HIJAU = '\033[92m'
MERAH = '\033[91m'
BIRU = '\033[94m'
KUNING = '\033[93m'
RESET = '\033[0m'

def teks_jalan(teks, delay=0.03):
    """Fungsi untuk membuat efek teks mengetik"""
    for char in teks:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def banner():
    """Tampilan pembuka ala hacker"""
    logo = f"""
{HIJAU}
  __  __ _    _ _____    _____                            
 |  \/  | |  | |  __ \  / ____|                           
 | \  / | |__| | |  | | | (___   ___ __ _ _ __  _ __   ___ _ __ 
 | |\/| |  __  | |  | |  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |  | | |  | | |__| |  ____) | (_| (_| | | | | | | |  __/ |   
 |_|  |_|_|  |_|_____/  |_____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                
     ~ MUSLIM HACKER DIVISION - EAGLE EYE AUDITOR v1.0 ~
{RESET}"""
    print(logo)

def scan_web(url):
    banner()
    if not url.startswith('http'):
        url = 'https://' + url
    
    teks_jalan(f"{BIRU}[*] Menghubungkan ke server {url}...{RESET}")
    time.sleep(1)
    
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        
        teks_jalan(f"{KUNING}[!] Memulai inspeksi paket data...{RESET}")
        time.sleep(0.5)

        # 1. Cek Security Headers
        header_list = {
            "Content-Security-Policy": "MISSING (SEO Spam Risk)",
            "Strict-Transport-Security": "MISSING (MitM Risk)",
            "X-Frame-Options": "MISSING (Clickjacking Risk)"
        }
        
        print(f"\n{HIJAU}[ RESULT: SECURITY HEADERS ]{RESET}")
        for h, msg in header_list.items():
            time.sleep(0.3)
            if h in headers:
                print(f" [+] {h:<30} : {HIJAU}SECURE{RESET}")
            else:
                print(f" [-] {h:<30} : {MERAH}{msg}{RESET}")
        
        # 2. Cek Server Version
        time.sleep(0.5)
        server = headers.get('Server', 'Hidden')
        print(f"\n{HIJAU}[ RESULT: INFRASTRUCTURE ]{RESET}")
        teks_jalan(f" [!] Server Software: {KUNING}{server}{RESET}")
        
        # 3. Cek XML-RPC
        time.sleep(0.5)
        xml_url = url.rstrip('/') + '/xmlrpc.php'
        print(f"\n{HIJAU}[ RESULT: VULNERABILITY CHECK ]{RESET}")
        teks_jalan(f" [*] Testing XML-RPC Endpoint: {xml_url}...")
        
        xml_check = requests.get(xml_url, timeout=10)
        if xml_check.status_code == 405 or "XML-RPC" in xml_check.text:
            print(f" [!] STATUS: {MERAH}VULNERABLE (Brute Force Risk){RESET}")
        else:
            print(f" [!] STATUS: {HIJAU}PROTECTED{RESET}")

        print(f"\n{HIJAU}--- AUDIT SELESAI ---{RESET}")

    except Exception as e:
        print(f"\n{MERAH}[!] ERROR: Tidak dapat mengakses target. {e}{RESET}")

if __name__ == "__main__":
    try:
        target = input(f"{HIJAU}MHD-Scanner > Masukkan URL target: {RESET}")
        scan_web(target)
    except KeyboardInterrupt:
        print(f"\n{MERAH}[!] Berhenti paksa oleh user.{RESET}")
