import requests
from bs4 import BeautifulSoup
import re
import argparse
import concurrent.futures
from urllib.parse import urljoin

# =========================== Passive Extraction ===========================

def extract_urls_from_script(script_content):
    """Extract URLs embedded in JavaScript."""
    return re.findall(r'(https?://[^\s"<>]+)', script_content)

def extract_urls_from_styles(styles_content):
    """Extract URLs from CSS styles."""
    return re.findall(r'url\(["\']?(https?://[^\s"<>]+)["\']?\)', styles_content)

def extract_links_from_html(soup, base_url):
    """Extract all links from the HTML."""
    links = set()
    
    for link in soup.find_all('a', href=True):
        full_url = urljoin(base_url, link['href'])
        links.add(full_url)

    for tag in soup.find_all(True):
        for attr in ['src', 'data-src', 'action', 'formaction']:
            url = tag.get(attr)
            if url:
                full_url = urljoin(base_url, url)
                links.add(full_url)

    return links

def scrape_links(url, proxies=None):
    """Scrape all found links, including hidden URLs."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False)
        
        if response.status_code != 200:
            print(f"Failed to retrieve {url} (status {response.status_code})")
            return set()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        links = extract_links_from_html(soup, url)
        
        for script in soup.find_all('script'):
            if script.string:
                links.update(extract_urls_from_script(script.string))

        for style in soup.find_all('style'):
            if style.string:
                links.update(extract_urls_from_styles(style.string))

        return links
    
    except Exception as e:
        print(f"Error scraping {url}: {e}")
        return set()

# =========================== Google Dorking & OSINT ===========================

def google_dorking(domain):
    """Find indexed URLs using Google Dorking (without API key)."""
    dork_url = f"https://www.google.com/search?q=site:{domain}"
    print(f"[Google Dorking] Searching: {dork_url}")

def wayback_machine(domain):
    """Find archived URLs from the Wayback Machine."""
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            results = response.json()[1:]  # Skip headers
            wayback_urls = {entry[2] for entry in results}
            print(f"[Wayback] Found {len(wayback_urls)} archived URLs.")
            return wayback_urls
        else:
            print("[Wayback] No data found.")
    except:
        print("[Wayback] Failed to retrieve data.")
    return set()

# =========================== Subdomain Enumeration ===========================

def extract_subdomains(domain):
    """Extract subdomains using Certificate Transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10, verify=False)
        if response.status_code == 200:
            subdomains = {entry["name_value"] for entry in response.json()}
            print(f"[Subdomains] Found {len(subdomains)} subdomains.")
            return subdomains
    except:
        print("[Subdomains] Failed to retrieve data.")
    return set()

# =========================== Multithreading ===========================

def process_target(url, proxies=None):
    """Process a single target URL."""
    print(f"\n[Processing] Target: {url}")
    found_links = scrape_links(url, proxies)
    for link in found_links:
        print(f"  [Passive] Found: {link}")

def process_file(subdomains_file, proxies=None):
    """Process each subdomain from the file using multithreading."""
    try:
        with open(subdomains_file, 'r') as file:
            subdomains = [line.strip() for line in file.readlines() if line.strip()]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(lambda subdomain: process_target(f"http://{subdomain}", proxies), subdomains)
    
    except Exception as e:
        print(f"Error reading file: {e}")

# =========================== CLI Arguments ===========================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Recon & URL Scraper")
    
    parser.add_argument("-f", "--file", help="File with subdomains", type=str, required=False)
    parser.add_argument("-d", "--host", help="Single target host (e.g., example.com)", type=str, required=False)
    parser.add_argument("--proxy", help="Proxy IP (e.g., http://192.168.1.100:8080)", type=str, default=None)
    
    args = parser.parse_args()
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    
    if args.host:
        print("\n[Recon] Running passive recon...")
        google_dorking(args.host)
        archived_urls = wayback_machine(args.host)
        subdomains = extract_subdomains(args.host)
        
        print("\n[Crawling] Extracting URLs...")
        process_target(f"http://{args.host}", proxies)
    
    elif args.file:
        process_file(args.file, proxies)
    
    else:
        print("Error: You must specify either a --host or --file.")
