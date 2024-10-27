import argparse
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import re
import json
import yaml
from urllib.parse import urljoin, urlparse
import urllib3
from requests_toolbelt.adapters import SSLAdapter
import ssl

# Mengabaikan peringatan SSL yang tidak diverifikasi
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_session_with_tls():
    session = requests.Session()
    session.mount('https://', SSLAdapter(ssl.PROTOCOL_TLSv1_2))  # Paksa penggunaan TLSv1.2
    session.verify = False
    return session

def load_vulnerability_rules(filepath="vulnerability_rules.yaml"):
    with open(filepath, "r") as file:
        data = yaml.safe_load(file)
    return data.get("rules", [])

def ensure_protocol(domain_url):
    if not domain_url.startswith(('http://', 'https://')):
        domain_url = 'https://' + domain_url
    return domain_url

def is_internal_link(url, base_url):
    return urlparse(url).netloc == urlparse(base_url).netloc

def create_session():
    session = requests.Session()
    retry = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.verify = False
    return session

session = create_session()

def fetch_js_files(domain_url, max_depth=2):
    visited_urls = set()
    js_files = set()
    urls_to_visit = [(domain_url, 0)]

    while urls_to_visit:
        current_url, depth = urls_to_visit.pop(0)
        if current_url in visited_urls or depth > max_depth:
            continue

        try:
            response = session.get(current_url)
            response.raise_for_status()
            visited_urls.add(current_url)

            soup = BeautifulSoup(response.text, 'html.parser')
            for script in soup.find_all('script', src=True):
                src = script['src']
                js_file_url = urljoin(current_url, src)
                if js_file_url.startswith(('http://', 'https://')) and is_internal_link(js_file_url, domain_url):
                    js_files.add(js_file_url)

        except requests.exceptions.SSLError as ssl_err:
            print(f"SSL error ignored for {current_url}: {ssl_err}")
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {current_url}: {e}")

    return list(js_files)

def extract_endpoints(js_code, js_file_name):
    """
    Mengekstrak endpoint dari kode JavaScript dan memberikan informasi
    baris di mana setiap endpoint ditemukan.
    """
    url_patterns = [
        r'(https?://[^\s\'";]+)',         # URL langsung
        r'["\'](/[^\'"]+)',               # URL relatif
        r'["\']([^\'":]+\.com/[^\s\'";]+)'  # URL domain dalam variabel
    ]
    
    endpoints = []
    lines = js_code.splitlines()
    for line_number, line in enumerate(lines, start=1):
        for pattern in url_patterns:
            matches = re.findall(pattern, line)
            for match in matches:
                endpoints.append({
                    "endpoint": match,
                    "file": js_file_name,
                    "line": line_number
                })

    return endpoints

def extract_endpoints_from_js_file(js_files, display_mode):
    endpoints_report = []
    
    for js_file in js_files:
        try:
            response = requests.get(js_file, verify=False)
            response.raise_for_status()
            js_code = response.text
            
            endpoints = extract_endpoints(js_code, js_file)
            endpoints_report.extend(endpoints)
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {js_file}: {e}")

    print("\nExtraction Complete. Endpoints extracted from JS file contents:")
    for endpoint_info in endpoints_report:
        if display_mode == "endpoint":
            print(f"Endpoint: {endpoint_info['endpoint']}")
        elif display_mode == "source":
            print(f"File: {endpoint_info['file']}")
        elif display_mode == "full":
            print(f"File: {endpoint_info['file']}, Line: {endpoint_info['line']}, Endpoint: {endpoint_info['endpoint']}")
    
    return endpoints_report

def extract_endpoints_from_crawling(domain_url, max_depth=2):
    visited_urls = set()
    endpoints = set()
    urls_to_visit = [(domain_url, 0)]

    while urls_to_visit:
        current_url, depth = urls_to_visit.pop(0)
        if current_url in visited_urls or depth > max_depth:
            continue

        try:
            response = session.get(current_url)
            response.raise_for_status()
            visited_urls.add(current_url)

            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(current_url, href)
                if is_internal_link(full_url, domain_url):
                    endpoints.add(full_url)
                    urls_to_visit.append((full_url, depth + 1))

        except requests.exceptions.RequestException as e:
            print(f"Error fetching {current_url}: {e}")

    print("\nExtraction Complete. Endpoints from Crawling:")
    print(json.dumps(list(endpoints), indent=2))
    return list(endpoints)

def save_report(report, domain_url, report_type="report"):
    filename = f"{domain_url.replace('https://', '').replace('http://', '').replace('/', '_')}_{report_type}.json"
    with open(filename, "w") as file:
        json.dump(report, file, indent=2)
    print(f"{report_type.capitalize()} saved as {filename}")

def main():
    parser = argparse.ArgumentParser(description="SecJSight - A tool for JavaScript vulnerability scanning and endpoint extraction.")
    parser.add_argument("-u", "--url", required=True, help="URL of the application to be scanned.")
    parser.add_argument("--extract-endpoint-js", action="store_true", help="Extract endpoints from the contents of JavaScript files only.")
    parser.add_argument("--extract-endpoint-crawl", action="store_true", help="Extract endpoints from web crawling.")
    parser.add_argument("--display-mode", choices=["endpoint", "source", "full"], default="full", help="Choose display mode for endpoints: 'endpoint', 'source', or 'full'.")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawling depth (default is 2).")

    args = parser.parse_args()
    domain_url = ensure_protocol(args.url)
    max_depth = args.max_depth

    if args.extract_endpoint_js:
        js_files = fetch_js_files(domain_url, max_depth)
        endpoints_report = extract_endpoints_from_js_file(js_files, args.display_mode)
        save_choice = input("Would you like to save the endpoints report from JS file? (yes/no): ").strip().lower()
        if save_choice == 'yes':
            save_report(endpoints_report, domain_url, report_type="endpoints_js")
    
    if args.extract_endpoint_crawl:
        endpoints_report = extract_endpoints_from_crawling(domain_url, max_depth)
        save_choice = input("Would you like to save the endpoints report from crawling? (yes/no): ").strip().lower()
        if save_choice == 'yes':
            save_report(endpoints_report, domain_url, report_type="endpoints_crawl")
    
    if not args.extract_endpoint_js and not args.extract_endpoint_crawl:
        print("Please specify --extract-endpoint-js or --extract-endpoint-crawl to perform endpoint extraction.")

if __name__ == "__main__":
    main()
