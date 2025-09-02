# Web-Security-Scanner
Scan websites like a pro: security headers, sensitive files, and basic vulnerabilities


## ⚡ Features

This scanner can detect:

- Missing or insecure **security headers**:
  - `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`
- Potential **open redirect vulnerabilities**
- **Common endpoints** (`/admin`, `/login`, `/robots.txt`, `/.git/`)
- Publicly accessible **sensitive files** (`.env`, `config.php`, `backup.zip`, `db.sql`, `wp-config.php`)
- Basic **web vulnerabilities**:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Local File Inclusion (LFI)
- **Server banner grabbing** to identify server type
- **SSL/TLS checks** to verify HTTPS enforcement
- Generates **color-coded terminal output** for clarity
- Produces **JSON and HTML reports** with timestamps and scan duration

> ⚠️ Note: This tool is intended for **educational use and authorized security testing only**. Never scan sites without permission.

---

## ⚙️ Requirements

- Python 3.x  
- `requests`  
- `colorama`  

Install dependencies with:

 ``` bash
pip install -r requirement.txt

python scanner.py https://google.com
```
##Output
[*] Scanning: https://google.com

=== Status Code ===
200

=== All Response Headers ===
Date: Tue, 02 Sep 2025 12:28:23 GMT
Expires: -1
Cache-Control: private, max-age=0
Content-Type: text/html; charset=ISO-8859-1
Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-H2aUydq7bH6vzd6RqF06NA' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
Accept-CH: Sec-CH-Prefers-Color-Scheme
P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
Content-Encoding: gzip
Server: gws
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
Set-Cookie: AEC=AVh_V2hazJ1d3kvcVViK8hHc8_PCVue5M1-1jv0zrdU7cYMZt9hnFJLmzk8; expires=Sun, 01-Mar-2026 12:28:23 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax, NID=525=Nfc-5iYkSGsqwrSI3nw362NC33WvVBwiHipWml7qP_R4M8EUEbQbSzoXezll_nJSwyk9bgoho7D7TtywV5-Qo7f-UNHdqvxy-vyd_1d6hl4Ke00Aaig59Bn5Rch3Wt7VuBFD1KM6cX3hXKlxDBUwmdZMcTYYnjQuhlTUK9q-YGgSgPqE_2raEM0cADVD7cDz-mNdktSHAGTq1vYKVqI; expires=Wed, 04-Mar-2026 12:28:23 GMT; path=/; domain=.google.com; HttpOnly
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
Transfer-Encoding: chunked

=== Security Headers Check ===
[-] Content-Security-Policy: Missing ⚠️
[-] Strict-Transport-Security: Missing ⚠️
[-] X-Content-Type-Options: Missing ⚠️
[+] X-Frame-Options: Present ✅
[+] X-XSS-Protection: Present ✅

=== Open Redirect Test ===
[!] Potential open redirect detected: https://google.com?next=https://evil.com redirects to https://www.google.com/?next=https://evil.com

=== Common Endpoint Scan ===
[-] Endpoint https://google.com/login returned status 404
[-] Endpoint https://google.com/admin returned status 404
[-] Endpoint https://google.com/.git/ returned status 404
[+] Reachable endpoint: https://google.com/robots.txt (200 OK)

=== Banner Grabbing ===
Server: gws

=== SSL/TLS Check ===
[+] HTTPS is enforced

=== Sensitive Files Scan ===
[-] File https://google.com/config.php not found (404)
[-] File https://google.com/db.sql not found (404)
[-] File https://google.com/.env not found (404)
[-] File https://google.com/wp-config.php not found (404)
[-] File https://google.com/backup.zip not found (404)

=== Vulnerability Scan ===
Testing SQLI:
[!] Potential SQLI vulnerability with payload: ?id=' OR '1'='1
[!] Potential SQLI vulnerability with payload: ?id=' UNION SELECT 1 --
Testing XSS:
[!] Potential XSS vulnerability with payload: ?q=<script>alert(1)</script>
[!] Potential XSS vulnerability with payload: ?q=<img src=x onerror=alert(1)>
Testing LFI:
[!] Potential LFI vulnerability with payload: ?file=../../../../etc/passwd
[!] Potential LFI vulnerability with payload: ?file=../../../../windows/system32/drivers/etc/hosts

=== Report Exported ===
Results saved to scan_report.json and scan_report.html


##For installation
``` bash
git clone https://github.com/azmil666/webvul_scanner.git
cd webvul_scanner
pip install -r requirement.txt
```






