import argparse
import requests
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor

# Function to load payloads from a .txt file
def load_payloads_from_txt(file_path):
    payloads = {}
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            # Assume the file contains a payload per line
            payloads = { 'general': [line.strip() for line in lines if line.strip()] }
    except Exception as e:
        print(f"[-] Error loading payloads from file: {e}")
    return payloads

# Vulnerability Detection Functions with Execution Details

def check_xss(url, payload):
    response = requests.get(url + payload)
    if payload in response.text:
        print(f"[!] XSS vulnerability found on {url}")
        print(f"    Path: {url}")
        print(f"    Payload: {payload}")
    else:
        print(f"[-] No XSS vulnerability on {url}")

def check_sql_injection(url, payloads):
    for payload in payloads:
        full_url = f"{url}?id={payload}"
        response = requests.get(full_url)
        if "SQL syntax" in response.text:
            print(f"[!] SQL Injection vulnerability found on {full_url}")
            print(f"    Path: {full_url}")
            print(f"    Payload: {payload}")
            return
    print(f"[-] No SQL Injection vulnerability on {url}")

def check_open_redirect(url, payload):
    response = requests.get(url + payload)
    if "https://malicious.com" in response.url:
        print(f"[!] Open Redirect vulnerability found on {url}")
        print(f"    Path: {url + payload}")
        print(f"    Payload: {payload}")
    else:
        print(f"[-] No Open Redirect vulnerability on {url}")

def check_ssrf(url, payload):
    response = requests.get(url + "?url=" + payload)
    if response.status_code == 200:
        print(f"[!] SSRF vulnerability found on {url}")
        print(f"    Path: {url + '?url=' + payload}")
        print(f"    Payload: {payload}")
    else:
        print(f"[-] No SSRF vulnerability on {url}")

def check_csrf(url, payload):
    response = requests.get(url + payload)
    if "malicious.com" in response.text:
        print(f"[!] CSRF vulnerability found on {url}")
        print(f"    Path: {url + payload}")
        print(f"    Payload: {payload}")
    else:
        print(f"[-] No CSRF vulnerability on {url}")

def check_cors(url):
    response = requests.options(url)
    if "Access-Control-Allow-Origin" not in response.headers:
        print(f"[!] CORS misconfiguration found on {url}")
        print(f"    Path: {url}")
    else:
        print(f"[-] CORS configured properly on {url}")

def check_path_traversal(url, payload):
    response = requests.get(url + "?file=" + payload)
    if "root:" in response.text:
        print(f"[!] Path Traversal vulnerability found on {url}")
        print(f"    Path: {url + '?file=' + payload}")
        print(f"    Payload: {payload}")
    else:
        print(f"[-] No Path Traversal vulnerability on {url}")

def check_shell_injection(url, payload):
    response = requests.get(url + "?cmd=" + payload)
    if "vulnerable" in response.text:
        print(f"[!] Shell Injection vulnerability found on {url}")
        print(f"    Path: {url + '?cmd=' + payload}")
        print(f"    Payload: {payload}")
    else:
        print(f"[-] No Shell Injection vulnerability on {url}")

def check_clickjacking(url):
    response = requests.get(url)
    if 'X-Frame-Options' not in response.headers:
        print(f"[!] Clickjacking vulnerability found on {url}")
        print(f"    Path: {url}")
    else:
        print(f"[-] No Clickjacking vulnerability on {url}")

def check_rce(url, payload):
    response = requests.get(url + "?file=" + payload)
    if "malware.sh" in response.text:
        print(f"[!] Remote Code Execution vulnerability found on {url}")
        print(f"    Path: {url + '?file=' + payload}")
        print(f"    Payload: {payload}")
    else:
        print(f"[-] No RCE vulnerability on {url}")

def check_sensitive_info(url):
    response = requests.get(url)
    if "password" in response.text or "key" in response.text:
        print(f"[!] Sensitive information leakage found on {url}")
        print(f"    Path: {url}")
    else:
        print(f"[-] No sensitive information leakage on {url}")

def check_broken_access_control(url):
    response = requests.get(url + "/admin")
    if "admin" in response.text:
        print(f"[!] Broken Access Control vulnerability found on {url}")
        print(f"    Path: {url + '/admin'}")
    else:
        print(f"[-] No Broken Access Control vulnerability on {url}")

# Additional Functions for Tool

def update_tool():
    subprocess.run(["git", "pull", "origin", "main"])
    print("[+] Tool updated to the latest version.")

def run_nuclei(url, template):
    subprocess.run(["nuclei", "-u", url, "-t", template])

# Command-Line Argument Parsing

def scan_web_app(url, payloads):
    print(f"[+] Scanning {url}...")
    # Apply the general payloads from the .txt file to different vulnerabilities
    for payload in payloads['general']:
        check_xss(url, payload)
        check_sql_injection(url, payloads['general'])
        check_open_redirect(url, payload)
        check_ssrf(url, payload)
        check_csrf(url, payload)
        check_path_traversal(url, payload)
        check_shell_injection(url, payload)
        check_rce(url, payload)
    check_cors(url)
    check_clickjacking(url)
    check_sensitive_info(url)
    check_broken_access_control(url)

def scan_urls(file, threads, payloads):
    with open(file, 'r') as f:
        urls = f.readlines()
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(lambda url: scan_web_app(url.strip(), payloads), urls)

def main():
    parser = argparse.ArgumentParser(description="Web Application Security Scanner")
    parser.add_argument('-u', '--url', help="URL of the web application to scan")
    parser.add_argument('-l', '--list', help="File containing list of URLs to scan")
    parser.add_argument('-t', '--threads', help="Number of threads to use", default=1, type=int)
    parser.add_argument('-up', '--update', action='store_true', help="Update the scanner tool")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
    parser.add_argument('--version', action='version', version='WebApp Scanner 1.0')
    parser.add_argument('-ip', '--ip-address', help="Scan specific IP address for vulnerabilities")
    parser.add_argument('--template', help="Run specific nuclei templateS")
    parser.add_argument('-p', '--payload', help="Custom payloads in JSON format (e.g., {'xss': ['<script>alert(1)</script>']})")
    parser.add_argument('-pl', '--payload-file', help="Payloads file in .txt format")

    args = parser.parse_args()

    # Load payloads from file if -pl is used, otherwise use -p
    payloads = {'general': []}
    if args.payload_file:
        payloads = load_payloads_from_txt(args.payload_file)
    elif args.payload:
        try:
            payloads = json.loads(args.payload)
        except json.JSONDecodeError:
            print("[-] Invalid payload format. Please provide a valid JSON format.")
            return

    if args.update:
        update_tool()
        return

    if args.url:
        scan_web_app(args.url, payloads)
    
    if args.list:
        scan_urls(args.list, args.threads, payloads)

    if args.template:
        run_nuclei(args.url, args.template)

if __name__ == '__main__':
    main()

