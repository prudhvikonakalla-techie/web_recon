import requests
import sys

def fuzz_directories(target_url, wordlist_path):
    try:
        with open(wordlist_path, "r") as wordlist:
            for line in wordlist:
                directory = line.strip()
                url = f"{target_url}/{directory}"
                response = requests.get(url)
                
                if response.status_code == 200:
                    print(f"[+] Found: {url} (Status: {response.status_code})")
                elif response.status_code == 301 or response.status_code == 302:
                    print(f"[>] Redirected: {url} (Status: {response.status_code})")
                elif response.status_code == 403:
                    print(f"[!] Forbidden: {url} (Status: {response.status_code})")
                elif response.status_code == 404:
                    print(f"[-] Not found: {url} (Status: {response.status_code})")
                elif response.status_code == 500:
                    print(f"[X] Server Error: {url} (Status: {response.status_code})")
                else:
                    print(f"[?] Other: {url} (Status: {response.status_code})")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 dir_fuzzer.py <target_url> <wordlist>")
        sys.exit(1)
    
    target = sys.argv[1]
    wordlist = sys.argv[2]
    fuzz_directories(target, wordlist)
