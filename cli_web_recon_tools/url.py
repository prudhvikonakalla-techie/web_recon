import requests
from bs4 import BeautifulSoup
import re
import argparse
from art import text2art

ascii_art = text2art("Sub Enum", font="3d")
print(ascii_art)

# =========================== Passive Extraction ===========================

def extract_urls_from_script(script_content):
    """Extract URLs embedded in JavaScript."""
    return re.findall(r'(https?://[^\s"<>]+)', script_content)

def extract_urls_from_styles(styles_content):
    """Extract URLs from CSS styles (e.g., background images)."""
    return re.findall(r'url\((https?://[^\s"<>]+)\)', styles_content)

def extract_links_from_html(soup):
    """Extract all links from the HTML."""
    links = set()
    
    for link in soup.find_all('a', href=True):
        links.add(link['href'])

    for tag in soup.find_all(True):
        for attr in ['src', 'data-src', 'action', 'formaction']:
            url = tag.get(attr)
            if url:
                links.add(url)

    return links

def scrape_links(url, proxies=None):
    """Scrape all found links, including hidden URLs."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
        
        if response.status_code != 200:
            print(f"Failed to retrieve {url} (status {response.status_code})")
            return set()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        links = extract_links_from_html(soup)
        
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

# =========================== Main Processing ===========================

def process_target(url, proxies=None):
    """Process a single target URL."""
    print(f"\nProcessing Target: {url}")
    found_links = scrape_links(url, proxies)
    for link in found_links:
        print(f"  [Passive] Found: {link}")

def process_file(subdomains_file, proxies=None):
    """Process each subdomain from the file."""
    try:
        with open(subdomains_file, 'r') as file:
            subdomains = file.readlines()
        
        for subdomain in subdomains:
            subdomain = subdomain.strip()
            if subdomain:
                url = f"http://{subdomain}"
                process_target(url, proxies)
    
    except Exception as e:
        print(f"Error reading file: {e}")

# =========================== CLI Arguments ===========================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scrape all links from subdomains")
    
    parser.add_argument("-f", "--file", help="Path to the file containing subdomains", type=str, required=False)
    parser.add_argument("-d", "--host", help="Single target host (e.g., example.com)", type=str, required=False)
    parser.add_argument("--proxy", help="Proxy IP and Port (e.g., http://192.168.1.100:8080)", type=str, default=None)
    
    args = parser.parse_args()
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    
    if args.host:
        process_target(f"http://{args.host}", proxies)
    elif args.file:
        process_file(args.file, proxies)
    else:
        print("Error: You must specify either a --host or --file.")
