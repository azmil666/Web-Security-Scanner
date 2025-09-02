import requests
import argparse
from urllib.parse import urljoin, urlparse
import json
import concurrent.futures
import time
from colorama import Fore, Style, init

init(autoreset=True)

# --- Security Headers to Check ---
REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection"
]

COMMON_ENDPOINTS = [
    "/admin",
    "/login",
    "/robots.txt",
    "/.git/"
]

SENSITIVE_FILES = [
    "/.env",
    "/config.php",
    "/backup.zip",
    "/db.sql",
    "/wp-config.php"
]

VULN_PAYLOADS = {
    "sqli": ["?id=' OR '1'='1", "?id=' UNION SELECT 1 --"],
    "xss": ["?q=<script>alert(1)</script>", "?q=<img src=x onerror=alert(1)>"],
    "lfi": ["?file=../../../../etc/passwd", "?file=../../../../windows/system32/drivers/etc/hosts"]
}

def normalize_url(url):
    """Ensure URL has scheme."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
    return url

def fetch_site(url, retries=2):
    """Send GET request and return response or None if error, with retries."""
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=5)
            return response
        except requests.exceptions.RequestException as e:
            print(f"[!] Error fetching {url} (attempt {attempt+1}): {e}")
            time.sleep(1)
    return None

def scan_headers(response):
    """Check for important security headers."""
    print(Fore.CYAN + "\n=== Security Headers Check ===")
    headers = response.headers
    security_results = {}

    for header in REQUIRED_HEADERS:
        if header in headers:
            print(Fore.GREEN + f"[+] {header}: Present ✅")
            security_results[header] = "Present"
        else:
            print(Fore.RED + f"[-] {header}: Missing ⚠️")
            security_results[header] = "Missing"
    return security_results

def scan_redirects(url):
    """Check for open redirect vulnerability with multiple payloads."""
    print(Fore.CYAN + "\n=== Open Redirect Test ===")
    payloads = ["?next=https://evil.com", "?redirect=https://evil.com", "?url=https://evil.com"]
    redirect_result = "No open redirect detected"
    for payload in payloads:
        test_url = url + payload
        try:
            response = requests.get(test_url, allow_redirects=False, timeout=5)
            if response.is_redirect or response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get("Location", "")
                if "evil.com" in location:
                    print(Fore.RED + f"[!] Potential open redirect detected: {test_url} redirects to {location}")
                    redirect_result = f"Potential open redirect to {location}"
                    break
                else:
                    print(Fore.YELLOW + f"[-] Redirect detected but not to evil.com: {location}")
            else:
                print(Fore.GREEN + f"[-] No redirect for {payload}")
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[!] Error testing {payload}: {e}")
    return redirect_result

def scan_endpoints(url):
    """Scan common endpoints and print if reachable using parallel requests."""
    print(Fore.CYAN + "\n=== Common Endpoint Scan ===")
    reachable = []

    def check_endpoint(endpoint):
        full_url = urljoin(url, endpoint)
        try:
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200:
                print(Fore.GREEN + f"[+] Reachable endpoint: {full_url} (200 OK)")
                return full_url
            else:
                print(Fore.YELLOW + f"[-] Endpoint {full_url} returned status {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[!] Error accessing {full_url}: {e}")
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(check_endpoint, COMMON_ENDPOINTS)
        reachable = [r for r in results if r]
    return reachable

def scan_sensitive_files(url):
    """Scan for sensitive files."""
    print(Fore.CYAN + "\n=== Sensitive Files Scan ===")
    found = []

    def check_file(file):
        full_url = urljoin(url, file)
        try:
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200:
                print(Fore.RED + f"[!] Sensitive file found: {full_url} (200 OK)")
                return full_url
            else:
                print(Fore.GREEN + f"[-] File {full_url} not found ({response.status_code})")
        except requests.exceptions.RequestException as e:
            print(Fore.YELLOW + f"[?] Error accessing {full_url}: {e}")
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(check_file, SENSITIVE_FILES)
        found = [r for r in results if r]
    return found

def scan_vulnerabilities(url):
    """Scan for basic vulnerabilities."""
    print(Fore.CYAN + "\n=== Vulnerability Scan ===")
    vuln_results = {}

    for vuln_type, payloads in VULN_PAYLOADS.items():
        print(Fore.BLUE + f"Testing {vuln_type.upper()}:")
        vuln_results[vuln_type] = []
        for payload in payloads:
            test_url = url + payload
            try:
                response = requests.get(test_url, timeout=5)
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    print(Fore.RED + f"[!] Potential {vuln_type.upper()} vulnerability with payload: {payload}")
                    vuln_results[vuln_type].append(payload)
                else:
                    print(Fore.GREEN + f"[-] No {vuln_type.upper()} detected with {payload}")
            except requests.exceptions.RequestException as e:
                print(Fore.YELLOW + f"[?] Error testing {payload}: {e}")
    return vuln_results

def banner_grab(response):
    """Print server banner from headers."""
    print(Fore.CYAN + "\n=== Banner Grabbing ===")
    server = response.headers.get("Server", "Unknown")
    print(Fore.BLUE + f"Server: {server}")
    return server

def check_ssl(url):
    """Check if HTTPS is enforced."""
    print(Fore.CYAN + "\n=== SSL/TLS Check ===")
    if url.startswith("https://"):
        print(Fore.GREEN + "[+] HTTPS is enforced")
        return "HTTPS enforced"
    else:
        print(Fore.RED + "[-] HTTP is used, consider enforcing HTTPS")
        return "HTTP used"

def export_report(url, status_code, headers, security_headers, redirects, endpoints, server, ssl_status, start_time, sensitive_files, vuln_results):
    """Export scan results to JSON file with timestamp and duration."""
    duration = time.time() - start_time
    report = {
        "url": url,
        "status_code": status_code,
        "headers": dict(headers),
        "security_headers": security_headers,
        "open_redirect": redirects,
        "endpoints": endpoints,
        "server": server,
        "ssl_status": ssl_status,
        "sensitive_files_found": sensitive_files,
        "vulnerabilities": vuln_results,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "scan_duration_seconds": round(duration, 2)
    }
    with open("scan_report.json", "w") as f:
        json.dump(report, f, indent=4)

    # Export HTML report
    html_content = f"""
    <html>
    <head><title>Web Vulnerability Scan Report</title></head>
    <body>
    <h1>Scan Report for {url}</h1>
    <p><strong>Status Code:</strong> {status_code}</p>
    <p><strong>Timestamp:</strong> {report['timestamp']}</p>
    <p><strong>Scan Duration:</strong> {report['scan_duration_seconds']} seconds</p>
    <h2>Security Headers</h2>
    <ul>
    {"".join(f"<li>{k}: {v}</li>" for k, v in security_headers.items())}
    </ul>
    <h2>Open Redirect</h2>
    <p>{redirects}</p>
    <h2>Endpoints</h2>
    <ul>
    {"".join(f"<li>{e}</li>" for e in endpoints)}
    </ul>
    <h2>Sensitive Files</h2>
    <ul>
    {"".join(f"<li>{f}</li>" for f in sensitive_files)}
    </ul>
    <h2>Vulnerabilities</h2>
    <ul>
    {"".join(f"<li>{k}: {v}</li>" for k, v in vuln_results.items())}
    </ul>
    </body>
    </html>
    """
    with open("scan_report.html", "w") as f:
        f.write(html_content)

    print(Fore.CYAN + "\n=== Report Exported ===")
    print(Fore.GREEN + "Results saved to scan_report.json and scan_report.html")

def main():
    parser = argparse.ArgumentParser(description="Scan website for security headers and vulnerabilities.")
    parser.add_argument("url", help="URL to scan")
    args = parser.parse_args()

    url = normalize_url(args.url)
    start_time = time.time()
    print(Fore.MAGENTA + f"[*] Scanning: {url}")

    response = fetch_site(url)
    if not response:
        return

    # Status Code
    print(Fore.CYAN + "\n=== Status Code ===")
    print(Fore.WHITE + str(response.status_code))

    # All Headers
    print(Fore.CYAN + "\n=== All Response Headers ===")
    for header, value in response.headers.items():
        print(Fore.WHITE + f"{header}: {value}")

    # Security Header Analysis
    security_headers = scan_headers(response)

    # Open Redirect Test
    redirect_result = scan_redirects(url)

    # Common Endpoint Scan
    reachable_endpoints = scan_endpoints(url)

    # Banner Grabbing
    server = banner_grab(response)

    # SSL Check
    ssl_status = check_ssl(url)

    # Sensitive Files Scan
    sensitive_files_found = scan_sensitive_files(url)

    # Vulnerability Scan
    vuln_results = scan_vulnerabilities(url)

    # Export Report
    export_report(url, response.status_code, response.headers, security_headers, redirect_result, reachable_endpoints, server, ssl_status, start_time, sensitive_files_found, vuln_results)

if __name__ == "__main__":
    main()
