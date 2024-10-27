import requests
from bs4 import BeautifulSoup
import re
import json
import os
import yaml
from urllib.parse import urljoin, urlparse

def load_vulnerability_rules(filepath="vulnerability_rules.yaml"):
    """
    Memuat aturan kerentanan dari file YAML.
    """
    with open(filepath, "r") as file:
        data = yaml.safe_load(file)
    return data.get("rules", [])

def ensure_protocol(domain_url):
    """
    Menambahkan protokol https ke URL jika tidak disertakan.
    """
    if not domain_url.startswith(('http://', 'https://')):
        domain_url = 'https://' + domain_url
    return domain_url

def is_internal_link(url, base_url):
    """
    Mengecek apakah URL adalah tautan internal dari domain utama.
    """
    return urlparse(url).netloc == urlparse(base_url).netloc

def fetch_js_files(domain_url, max_depth=2):
    """
    Mengambil file-file JavaScript dari halaman web hingga kedalaman yang ditentukan.
    """
    visited_urls = set()
    js_files = set()
    urls_to_visit = [(domain_url, 0)]
    parameters_found = {}

    parameter_regex = re.compile(r'[?&]([^=&]+)=([^&]*)')  # Regex untuk mendeteksi parameter

    while urls_to_visit:
        current_url, depth = urls_to_visit.pop(0)

        if current_url in visited_urls or depth > max_depth:
            continue

        try:
            response = requests.get(current_url)
            response.raise_for_status()
            visited_urls.add(current_url)

            # Parsing halaman untuk menemukan file JS dan tautan internal
            soup = BeautifulSoup(response.text, 'html.parser')

            # Tambahkan semua file JS ke dalam set js_files
            for script in soup.find_all('script', src=True):
                src = script['src']
                js_file_url = urljoin(current_url, src)
                if js_file_url.startswith(('http://', 'https://')):
                    js_files.add(js_file_url)

            # Analisis URL untuk parameter query dengan regex
            matches = parameter_regex.findall(current_url)
            if matches:
                parameters_found[current_url] = {param[0]: param[1] for param in matches}

            # Tambahkan tautan internal untuk kedalaman crawling lebih lanjut
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(current_url, href)
                if is_internal_link(full_url, domain_url) and full_url not in visited_urls:
                    urls_to_visit.append((full_url, depth + 1))

        except requests.exceptions.RequestException as e:
            print(f"Error fetching {current_url}: {e}")

    return list(js_files), parameters_found

def extract_endpoints(js_code):
    """
    Mengekstrak endpoint dari kode JavaScript menggunakan beberapa pola regex.
    """
    # Regex untuk berbagai pola URL
    url_patterns = [
        r'(https?://[^\s\'";]+)',         # URL langsung
        r'["\'](/[^\'"]+)',               # URL relatif
        r'["\']([^\'":]+\.com/[^\s\'";]+)'  # URL domain dalam variabel
    ]
    
    endpoints = []
    for pattern in url_patterns:
        matches = re.findall(pattern, js_code)
        endpoints.extend(matches)

    # Hapus duplikasi endpoint
    return list(set(endpoints))

def scan_for_vulnerabilities(js_code, rules):
    """
    Memindai kode JavaScript berdasarkan aturan kerentanan.
    """
    vulnerabilities = []
    lines = js_code.splitlines()

    for rule in rules:
        pattern = rule['pattern']
        for i, line in enumerate(lines, start=1):
            if pattern in line:
                vulnerabilities.append({
                    'type': rule['type'],
                    'line': i,
                    'code': line.strip(),
                    'description': rule['description'],
                    'reference': rule['reference']
                })

    return vulnerabilities

def save_report(report, domain_url, report_type="report"):
    """
    Menyimpan laporan sebagai file JSON.
    """
    filename = f"{domain_url.replace('https://', '').replace('http://', '').replace('/', '_')}_{report_type}.json"
    with open(filename, "w") as file:
        json.dump(report, file, indent=2)
    print(f"{report_type.capitalize()} saved as {filename}")

def extract_endpoints_mode(domain_url, max_depth=2):
    """
    Mode untuk hanya mengekstrak endpoint dari file JavaScript.
    """
    js_files, parameters_found = fetch_js_files(domain_url, max_depth=max_depth)
    endpoints_report = {
        'domain': domain_url,
        'js_files': js_files,
        'endpoints': {},
        'parameters': parameters_found
    }
    
    for js_file in js_files:
        try:
            response = requests.get(js_file)
            response.raise_for_status()
            js_code = response.text
            
            endpoints = extract_endpoints(js_code)
            endpoints_report['endpoints'][js_file] = endpoints
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {js_file}: {e}")

    print("\nExtraction Complete. Endpoints and parameters found:")
    print(json.dumps(endpoints_report, indent=2))

    save_choice = input("Would you like to save the endpoints report? (yes/no): ").strip().lower()
    if save_choice == 'yes':
        save_report(endpoints_report, domain_url, report_type="endpoints")

def vulnerability_scan_mode(domain_url, max_depth=2):
    """
    Mode untuk melakukan vulnerability scanning pada file JavaScript dan mencatat parameter.
    """
    rules = load_vulnerability_rules()
    js_files, parameters_found = fetch_js_files(domain_url, max_depth=max_depth)
    vulnerabilities_report = {
        'domain': domain_url,
        'js_files': js_files,
        'vulnerabilities': {},
        'parameters': parameters_found
    }
    
    vulnerabilities_found = False

    for js_file in js_files:
        try:
            response = requests.get(js_file)
            response.raise_for_status()
            js_code = response.text
            
            vulnerabilities = scan_for_vulnerabilities(js_code, rules)
            if vulnerabilities:
                vulnerabilities_found = True
                vulnerabilities_report['vulnerabilities'][js_file] = vulnerabilities
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {js_file}: {e}")

    if vulnerabilities_found or parameters_found:
        print("\nVulnerability Scanning Complete. Vulnerabilities and parameters that need validation:")
        print(json.dumps(vulnerabilities_report, indent=2))

        save_choice = input("Would you like to save the vulnerabilities report? (yes/no): ").strip().lower()
        if save_choice == 'yes':
            save_report(vulnerabilities_report, domain_url, report_type="vulnerabilities")
    else:
        print("No vulnerabilities or parameters needing validation found.")

def main_menu():
    """
    Menu utama untuk memilih antara mode extract endpoints atau vulnerability scanning.
    """
    domain_url = input("Masukkan URL aplikasi yang akan dipindai: ").strip()
    domain_url = ensure_protocol(domain_url)
    
    if not re.match(r'^https?://', domain_url):
        print("URL tidak valid. Harap masukkan URL dengan format yang benar.")
        return

    max_depth = int(input("Masukkan kedalaman crawling (misal: 1 atau 2): ").strip())
    
    print("\nPilih mode operasi:")
    print("1. Extract Endpoints")
    print("2. Vulnerability Scanning")

    choice = input("Masukkan pilihan (1/2): ").strip()

    if choice == "1":
        extract_endpoints_mode(domain_url, max_depth=max_depth)
    elif choice == "2":
        vulnerability_scan_mode(domain_url, max_depth=max_depth)
    else:
        print("Pilihan tidak valid. Silakan coba lagi.")

# Menjalankan menu utama
main_menu()
