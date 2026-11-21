import argparse
import json
import socket
import sys
import time
from ipaddress import ip_address
from urllib.parse import urljoin, urlparse

import requests


HIJAU = "\033[92m"
MERAH = "\033[91m"
BIRU = "\033[94m"
KUNING = "\033[93m"
RESET = "\033[0m"

VERSION = "MHD Eagle Eye Auditor v1.1"
HEADERS_TO_CHECK = {
    "Content-Security-Policy": "Aktifkan CSP dengan default-src 'self'",
    "Strict-Transport-Security": "Aktifkan HSTS untuk memaksa HTTPS",
    "X-Content-Type-Options": "Tambahkan nosniff untuk mencegah MIME sniffing",
    "X-Frame-Options": "Tambahkan DENY atau SAMEORIGIN",
    "Referrer-Policy": "Batasi informasi referrer",
    "Permissions-Policy": "Batasi fitur browser yang tidak diperlukan",
}


def teks_jalan(teks, delay=0.02):
    for char in teks:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def banner():
    print(f"""
{HIJAU}  __  __  _   _  _____    _____  
 |  \/  || | | ||  __ \  / ____|
 | \  / || |_| || |  | || (___  
 | |\/| ||  _  || |  | | \___ \
 | |  | || | | || |__| | ____) |
 |_|  |_||_| |_||_____/ |_____/

      ~ MUSLIM HACKER DIVISION - {VERSION} ~
{RESET}""")


def normalize_url(value):
    value = value.strip()
    if not value:
        raise ValueError("URL tidak boleh kosong")
    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Format URL tidak valid")
    if parsed.username or parsed.password:
        raise ValueError("URL dengan kredensial tidak diperbolehkan")

    return parsed.geturl()


def reject_internal_host(hostname):
    """Prevent accidentally scanning localhost or private network addresses."""
    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ValueError(f"Hostname tidak dapat diselesaikan: {exc}")

    for address in addresses:
        ip = ip_address(address[4][0].split("%")[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError("Target internal/private tidak diperbolehkan")


def safe_get(session, url, timeout=10, allow_redirects=True):
    return session.get(
        url,
        timeout=timeout,
        allow_redirects=allow_redirects,
        headers={"User-Agent": "MHD-Eagle-Eye-Auditor/1.1 (authorized audit)"},
    )


def analyze_headers(headers):
    findings = []
    for name, recommendation in HEADERS_TO_CHECK.items():
        value = headers.get(name)
        if value:
            findings.append({"severity": "INFO", "check": name, "status": "PASS", "detail": value})
        else:
            findings.append({"severity": "MEDIUM", "check": name, "status": "MISSING", "detail": recommendation})

    server = headers.get("Server")
    if server:
        findings.append({"severity": "LOW", "check": "Server Disclosure", "status": "INFO", "detail": server})
    else:
        findings.append({"severity": "INFO", "check": "Server Disclosure", "status": "HIDDEN", "detail": "Header Server tidak terekspos"})

    return findings


def analyze_cookies(response):
    findings = []
    cookies = response.cookies

    if not cookies:
        return [{"severity": "INFO", "check": "Cookies", "status": "NONE", "detail": "Tidak ada cookie respons yang terdeteksi"}]

    for cookie in cookies:
        missing = []
        if not cookie.secure:
            missing.append("Secure")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            missing.append("HttpOnly")
        if not cookie.has_nonstandard_attr("SameSite"):
            missing.append("SameSite")

        if missing:
            findings.append({
                "severity": "MEDIUM",
                "check": f"Cookie: {cookie.name}",
                "status": "WEAK",
                "detail": "Atribut belum ada: " + ", ".join(missing),
            })
        else:
            findings.append({
                "severity": "INFO",
                "check": f"Cookie: {cookie.name}",
                "status": "PASS",
                "detail": "Cookie memiliki Secure, HttpOnly, dan SameSite",
            })

    return findings


def analyze_redirects(response):
    findings = []
    if len(response.history) >= 5:
        findings.append({"severity": "LOW", "check": "Redirect", "status": "LONG_CHAIN", "detail": f"{len(response.history)} redirect terdeteksi"})

    if response.history:
        origin = urlparse(response.history[0].url)
        final = urlparse(response.url)
        if origin.scheme == "http" and final.scheme == "https":
            findings.append({"severity": "INFO", "check": "HTTP to HTTPS", "status": "PASS", "detail": "Permintaan dialihkan ke HTTPS"})
        if origin.hostname != final.hostname:
            findings.append({"severity": "MEDIUM", "check": "Cross-host Redirect", "status": "INFO", "detail": f"{origin.hostname} -> {final.hostname}"})

    return findings


def check_wordpress_xmlrpc(base_url, session):
    xml_url = urljoin(base_url.rstrip("/") + "/", "xmlrpc.php")

    try:
        response = safe_get(session, xml_url)
        text = response.text[:1500].lower()

        if response.status_code == 405:
            return {"severity": "LOW", "check": "XML-RPC", "status": "EXPOSED", "detail": "Endpoint aktif tetapi metode HTTP dibatasi"}
        if "xml-rpc" in text or "xmlrpc" in text:
            return {"severity": "MEDIUM", "check": "XML-RPC", "status": "EXPOSED", "detail": "Endpoint XML-RPC terdeteksi"}
        if response.status_code in (401, 403):
            return {"severity": "INFO", "check": "XML-RPC", "status": "BLOCKED", "detail": "Akses endpoint dibatasi oleh server"}
        return {"severity": "INFO", "check": "XML-RPC", "status": "NOT_DETECTED", "detail": f"Tidak terdeteksi jelas (HTTP {response.status_code})"}
    except requests.RequestException as exc:
        return {"severity": "INFO", "check": "XML-RPC", "status": "CHECK_FAILED", "detail": str(exc)}


def check_public_files(base_url, session):
    findings = []
    paths = ("robots.txt", ".well-known/security.txt", "security.txt")

    for path in paths:
        target = urljoin(base_url.rstrip("/") + "/", path)
        try:
            response = safe_get(session, target)
            if response.status_code == 200:
                findings.append({"severity": "INFO", "check": path, "status": "FOUND", "detail": target})
        except requests.RequestException:
            pass

    return findings


def print_findings(findings):
    for item in findings:
        if item["severity"] == "MEDIUM":
            color = MERAH
        elif item["severity"] == "LOW":
            color = KUNING
        else:
            color = HIJAU

        print(f" {color}[{item['severity']}]{RESET} {item['check']}: {item['status']} — {item['detail']}")


def scan_web(url):
    banner()
    url = normalize_url(url)
    parsed = urlparse(url)
    reject_internal_host(parsed.hostname)

    teks_jalan(f"{BIRU}[*] Menghubungkan ke target {url}...{RESET}")
    with requests.Session() as session:
        response = safe_get(session, url)

        print(f"\n{HIJAU}[ RESULT: HTTP & REDIRECT ]{RESET}")
        print(f" HTTP Status: {response.status_code} | Final URL: {response.url}")

        findings = []
        findings += analyze_redirects(response)
        findings += analyze_headers(response.headers)
        findings += analyze_cookies(response)

        print(f"\n{HIJAU}[ RESULT: SECURITY HEADERS & COOKIE ]{RESET}")
        print_findings(findings)

        print(f"\n{HIJAU}[ RESULT: WORDPRESS XML-RPC ]{RESET}")
        xml_result = check_wordpress_xmlrpc(response.url, session)
        print_findings([xml_result])

        print(f"\n{HIJAU}[ RESULT: PUBLIC SECURITY FILES ]{RESET}")
        public_files = check_public_files(response.url, session)
        print_findings(public_files or [{"severity": "INFO", "check": "Public files", "status": "NONE", "detail": "Tidak ada robots.txt/security.txt yang terbaca"}])

        return {
            "target": url,
            "final_url": response.url,
            "http_status": response.status_code,
            "findings": findings + [xml_result] + public_files,
        }


def main():
    parser = argparse.ArgumentParser(description="MHD Eagle Eye passive web security auditor")
    parser.add_argument("target", nargs="?", help="URL atau hostname target")
    parser.add_argument("--json", metavar="FILE", help="Simpan hasil sebagai JSON")
    args = parser.parse_args()

    try:
        target = args.target or input(f"{HIJAU}MHD-Scanner > Masukkan URL target: {RESET}")
        report = scan_web(target)

        if args.json:
            with open(args.json, "w", encoding="utf-8") as output:
                json.dump(report, output, ensure_ascii=False, indent=2)
            print(f"\n{HIJAU}[+] Laporan JSON disimpan ke {args.json}{RESET}")

        print(f"\n{HIJAU}--- AUDIT SELESAI ---{RESET}")
    except (requests.RequestException, ValueError) as exc:
        print(f"\n{MERAH}[!] ERROR: {exc}{RESET}")
        return 1
    except KeyboardInterrupt:
        print(f"\n{MERAH}[!] Berhenti oleh user.{RESET}")
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
