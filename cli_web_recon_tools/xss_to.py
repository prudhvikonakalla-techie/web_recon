import requests
import re
import argparse
import threading
from urllib.parse import urlparse, parse_qs
from art import text2art

def load_payloads(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"[-] Payload file not found: {file_path}")
        return []

def extract_parameters(url):
    """Extracts parameter names from a given URL."""
    parsed_url = urlparse(url)
    return list(parse_qs(parsed_url.query).keys())

def test_xss(url, method, param, payload, headers, proxy, check_reflected):
    """Tests a single parameter for XSS vulnerability."""
    params = {param: payload}
    
    try:
        if method == "GET":
            response = requests.get(url, params=params, headers=headers, proxies=proxy, timeout=10)
        else:
            response = requests.post(url, data=params, headers=headers, proxies=proxy, timeout=10)
        
        if check_reflected and payload in response.text:
            print(f"[!!!] Vulnerable ({method}) on parameter '{param}'! Payload: {payload}")
            print(f"[>>>] Open this URL to test manually: {response.url}")
        
        if not check_reflected:
            print(f"[+] Blind XSS Payload Sent: {payload}")
    except requests.RequestException as e:
        print(f"[-] Error testing payload {payload}: {e}")

def run_tests(url, payload_file, proxy, check_reflected):
    headers = {"User-Agent": "Advanced-XSS-Scanner/3.0"}
    proxy_dict = {"http": proxy, "https": proxy} if proxy else None
    
    print(f"[+] Extracting parameters from {url}")
    parameters = extract_parameters(url)
    
    if not parameters:
        print("[-] No parameters found. Using default 'input' parameter.")
        parameters = ["input"]
    
    print(f"[+] Found parameters: {', '.join(parameters)}")
    print("[+] Starting XSS tests...")
    
    threads = []
    payloads = load_payloads(payload_file)
    for param in parameters:
        for payload in payloads:
            t1 = threading.Thread(target=test_xss, args=(url, "GET", param, payload, headers, proxy_dict, check_reflected))
            t2 = threading.Thread(target=test_xss, args=(url, "POST", param, payload, headers, proxy_dict, check_reflected))
            t1.start()
            t2.start()
            threads.append(t1)
            threads.append(t2)
    
    for thread in threads:
        thread.join()
    print("[+] Scanning completed!")

if __name__ == "__main__":
    print(text2art("XSS Scanner"))
    parser = argparse.ArgumentParser(description="Advanced Reflected & Blind XSS Scanner")
    parser.add_argument("-u", "--url", type=str, required=True, help="Target URL to scan")
    parser.add_argument("-w", "--wordlist", type=str, required=True, help="Path to the XSS payload wordlist")
    parser.add_argument("--proxy", type=str, help="Optional proxy (e.g., http://127.0.0.1:8080)", default=None)
    parser.add_argument("--blind", action='store_true', help="Enable blind XSS testing")
    args = parser.parse_args()
    run_tests(args.url, args.wordlist, args.proxy, not args.blind)
